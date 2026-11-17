//! LiquiDEX swap and order-book commands over the templar-core
//! engine (`liquid::liquidex`) and book client (`liquid::book`).
//!
//! The book is browsed read-only by the wallet; offers are published to its
//! public `POST /api/offers`. Its URLs come from `AppState::endpoints` (env,
//! then the test server, then the local `127.0.0.1:3210`). The make/take
//! engine signs and broadcasts on the active Liquid testnet or regtest chain,
//! through the backend the same resolver picks.
//!
//! My-offers persist to `<data_dir>/swap_offers.json` (plain JSON, keyed per
//! wallet, no secrets) with the same atomic temp+fsync+rename pattern as the
//! wallet registry and the peg store.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use templar_core::liquid::book::{
    fetch_book, fetch_markets, publish_offer, BookEntry, BookError, BookLeg, MarketBookEntry,
    MarketBookLeg,
};
#[cfg(test)]
use templar_core::liquid::book::{LOCAL_BOOK_URL, LOCAL_MARKETS_URL};
use templar_core::liquid::liquidex::verify_proposal_on;
use templar_core::{broadcast_transaction_with, proposal_utxo_unspent_with, verify_proposal_with};
use templar_core::{
    build_cancel_tx, first_frozen, make_proposal, take_preview_excluding, take_proposal_excluding,
    CoinChain, LiquidError, LiquidexLeg, LiquidexProposal, SwapLeg, SwapNetwork, TakePreview,
    VerifyCheck, VerifyResult,
};

use crate::handlers::asset_names::{self, FROM_FEED, FROM_NONE};
use crate::state::AppState;

const STORE_FILE: &str = "swap_offers.json";

// ── DTOs (wire shapes fixed by the host contract) ────────────────────────────

/// One asset/amount side of a swap, enriched for display. `amount_sats`
/// (base units) is the source of truth; the rest is how it is shown.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SwapLegDto {
    pub asset_id: String,
    pub ticker: String,
    pub amount_sats: u64,
    pub display_amount: String,
    /// The asset's name.
    #[serde(default)]
    pub name: String,
    /// Decimal places `display_amount` uses.
    #[serde(default = "eight")]
    pub precision: u8,
    /// Who named the asset: `wallet` | `book` (the active order book's
    /// registry: show the short asset id beside it) | `feed` (the row's own
    /// display data) | `none` (nobody: short asset id, 8 decimals).
    #[serde(default = "from_feed")]
    pub metadata_source: String,
    /// The order book's own provenance of a `book` name; null otherwise.
    #[serde(default)]
    pub book_source: Option<String>,
}

fn eight() -> u8 {
    8
}

fn from_feed() -> String {
    FROM_FEED.to_string()
}

/// One order-book row, oriented for the taker: `receive` is the maker's
/// input leg (what the taker gets), `pay` the maker's output leg.
#[derive(Serialize, Debug, Clone)]
pub struct SwapRowDto {
    pub id: u64,
    pub available: bool,
    pub receive: SwapLegDto,
    pub pay: SwapLegDto,
    pub price: f64,
    pub price_display: String,
    pub created: String,
    /// All offline verification checks passed.
    pub verified: bool,
    /// First failing check's note (null when verified).
    pub verify_note: Option<String>,
    pub proposal_json: String,
    /// "testnet" | "mainnet" | "unknown" (offline heuristic).
    pub network: String,
    pub takeable: bool,
    /// Offer kind — only "swap" today; "loan" arrives with the lending protocol.
    pub kind: String,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct MarketLegDto {
    pub chain: String,
    pub network: String,
    pub asset_id: String,
    pub ticker: String,
    pub name: String,
    pub precision: u8,
    pub amount_sats: u64,
    pub display_amount: String,
    /// Who named the asset (see [`SwapLegDto::metadata_source`]); a Liquid
    /// leg the wallet or the registry knows is shown their way, never the
    /// feed's.
    pub metadata_source: String,
    /// The order book's own provenance of a `book` name; null otherwise.
    pub book_source: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct MarketRowDto {
    pub id: String,
    pub source_id: u64,
    pub status: String,
    pub settlement: String,
    pub demo: bool,
    pub available: bool,
    pub maker_gives: MarketLegDto,
    pub maker_wants: MarketLegDto,
    pub price_display: String,
    pub note: String,
    pub created_at: u64,
    pub proposal_json: String,
    pub verified: bool,
    pub takeable: bool,
    pub block_reason: Option<String>,
}

/// `swap_verify` result: the engine's `VerifyResult` with display-enriched legs.
#[derive(Serialize, Debug, Clone)]
pub struct SwapAnalysisDto {
    pub valid: bool,
    pub checks: Vec<VerifyCheck>,
    pub maker_offers: SwapLegDto,
    pub maker_wants: SwapLegDto,
    pub network: String,
    pub takeable: bool,
    pub take_block_reason: Option<String>,
}

/// `swap_take_preview` result — honest fee/change from the real built tx.
#[derive(Serialize, Debug, Clone)]
pub struct TakePreviewDto {
    pub you_receive: SwapLegDto,
    pub you_pay: SwapLegDto,
    pub fee_sats: u64,
    pub fee_display: String,
    pub change: Vec<SwapLegDto>,
    pub analysis: SwapAnalysisDto,
}

/// One of this wallet's own published offers.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyOfferDto {
    /// `of_<8hex>`.
    pub offer_id: String,
    pub kind: String,
    /// "open" | "closed" (utxo spent by a taker) | "cancelled".
    pub status: String,
    /// Unix seconds.
    pub created_at: u64,
    /// What this wallet gives away (the offered UTXO's leg).
    pub offers: SwapLegDto,
    /// What this wallet asks for.
    pub wants: SwapLegDto,
    pub proposal_json: String,
    /// The offered prevout, `"txid:vout"`.
    pub utxo: String,
}

// ── Params (deserialized by dispatch.rs) ─────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct ListSwapsParams {
    #[serde(default)]
    pub include_unavailable: bool,
}

#[derive(Deserialize, Debug)]
pub struct ListMarketsParams {
    #[serde(default)]
    pub include_unavailable: bool,
}

#[derive(Deserialize, Debug)]
pub struct SwapVerifyParams {
    pub proposal_json: String,
    #[serde(default)]
    pub deep: bool,
}

/// Shared by `swap_take_preview` and `swap_take`.
#[derive(Deserialize, Debug)]
pub struct SwapTakeParams {
    pub wallet_id: String,
    pub proposal_json: String,
    #[serde(default)]
    pub fee_rate: Option<f32>,
}

#[derive(Deserialize, Debug)]
pub struct SwapMakeParams {
    pub wallet_id: String,
    /// `"txid:vout"` of the wallet UTXO to offer (its full amount).
    pub utxo: String,
    pub want_asset_id: String,
    pub want_amount_sats: u64,
}

#[derive(Deserialize, Debug)]
pub struct SwapMakePrepareParams {
    pub wallet_id: String,
    pub asset_id: String,
    pub amount_sats: u64,
    /// Accepted for wire compatibility; the Liquid flat-fee builder that
    /// backs the self-send does not take a rate.
    #[serde(default)]
    pub fee_rate: Option<f32>,
}

#[derive(Deserialize, Debug)]
pub struct ListMyOffersParams {
    pub wallet_id: String,
}

#[derive(Deserialize, Debug)]
pub struct SwapCancelParams {
    pub wallet_id: String,
    pub offer_id: String,
}

#[derive(Deserialize, Debug)]
pub struct SwapPublishParams {
    pub proposal_json: String,
    #[serde(default)]
    pub note: String,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// Fetches the order book and maps each entry to a display row.
/// URL: `TEMPLAR_SWAP_BOOK_URL`, else the test server's order book, else the
/// localhost service. The active Liquid network is always sent so testnet
/// and regtest stay apart.
pub fn list_swaps(state: &AppState, include_unavailable: bool) -> Result<Vec<SwapRowDto>, String> {
    let base = state.endpoints().book_url().value;
    let entries = fetch_book(&feed_url(
        &base,
        include_unavailable,
        state.liquid_network.name(),
    ))
    .map_err(|e| e.to_string())?;
    Ok(rows_from_entries(state, &entries))
}

/// Unified local market: real LiquiDEX and HTLC-v1 rows, plus optional legacy
/// design demos. Demo rows never become takeable or reach a signing path.
pub fn list_markets(
    state: &AppState,
    include_unavailable: bool,
) -> Result<Vec<MarketRowDto>, String> {
    let base = state.endpoints().markets_url().value;
    let entries = fetch_markets(&feed_url(
        &base,
        include_unavailable,
        state.liquid_network.name(),
    ))
    .map_err(|e| e.to_string())?;
    Ok(entries
        .iter()
        .map(|entry| market_row(state, entry))
        .collect())
}

/// Parses and verifies a proposal (offline, or deep with chain access on the
/// active Liquid network), enriching the maker legs for display.
pub fn verify(
    state: &AppState,
    proposal_json: &str,
    deep: bool,
) -> Result<SwapAnalysisDto, String> {
    let proposal = LiquidexProposal::from_json(proposal_json).map_err(|e| e.to_string())?;
    let result = if deep {
        verify_proposal_with(&proposal, &state.liquid_chain()?)
    } else {
        verify_proposal_on(&proposal, false, &state.liquid_network)
    }
    .map_err(|e| e.to_string())?;
    Ok(analysis_dto(state, &result))
}

/// Deep-verifies and builds the real taker transaction (unsigned broadcast-
/// wise — nothing hits the chain) to report honest fee and change.
pub fn take_preview(
    state: &AppState,
    proposal_json: &str,
    fee_rate: Option<f32>,
) -> Result<TakePreviewDto, String> {
    let liq = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
    let proposal = LiquidexProposal::from_json(proposal_json).map_err(|e| e.to_string())?;
    let frozen = state.frozen_on(CoinChain::Liquid);
    let preview =
        take_preview_excluding(liq, &proposal, fee_rate, &frozen).map_err(|e| e.to_string())?;
    Ok(preview_dto(state, &preview))
}

/// Takes a proposal: the engine deep-verifies internally and refuses
/// non-takeable orders (mainnet, failed checks) with the block reason as the
/// error; on success the signed transaction is broadcast on the active
/// Liquid network, through the wallet's own chain backend.
pub fn take(
    state: &AppState,
    proposal_json: &str,
    fee_rate: Option<f32>,
) -> Result<String, String> {
    let liq = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
    let proposal = LiquidexProposal::from_json(proposal_json).map_err(|e| e.to_string())?;
    let frozen = state.frozen_on(CoinChain::Liquid);
    let result =
        take_proposal_excluding(liq, &proposal, fee_rate, &frozen).map_err(|e| e.to_string())?;
    // Backstop: the selection above already left frozen coins out, and a
    // signed swap must never reach the network if that ever changes.
    let spent = result
        .tx
        .input
        .iter()
        .map(|i| i.previous_output.to_string());
    if let Some(op) = first_frozen(spent, &frozen) {
        return Err(LiquidError::FrozenCoin(op).to_string());
    }
    let chain = liq.chain().map_err(|e| e.to_string())?;
    broadcast_transaction_with(&result.tx, &chain).map_err(|e| e.to_string())
}

/// Builds and signs a proposal offering one wallet UTXO's full amount, then
/// persists it to the my-offers store. Offline (broadcast happens when a
/// taker takes it).
pub fn make(
    state: &AppState,
    wallet_id: &str,
    utxo: &str,
    want_asset_id: &str,
    want_amount_sats: u64,
) -> Result<MyOfferDto, String> {
    if let Some(op) = first_frozen([utxo], &state.frozen_on(CoinChain::Liquid)) {
        return Err(LiquidError::FrozenCoin(op).to_string());
    }
    let liq = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
    let proposal =
        make_proposal(liq, utxo, want_asset_id, want_amount_sats).map_err(|e| e.to_string())?;
    let proposal_json = proposal.to_json().map_err(|e| e.to_string())?;
    let offers = proposal
        .inputs
        .first()
        .map(|l| liquidex_leg_dto(state, l))
        .ok_or("Built proposal has no input leg")?;
    let wants = proposal
        .outputs
        .first()
        .map(|l| liquidex_leg_dto(state, l))
        .ok_or("Built proposal has no output leg")?;

    let mut store = load_store(&state.data_dir)?;
    let offer = MyOfferDto {
        offer_id: new_offer_id(&store),
        kind: "swap".to_string(),
        status: "open".to_string(),
        created_at: now_secs(),
        offers,
        wants,
        proposal_json,
        utxo: utxo.to_string(),
    };
    store.offers.push(StoredOffer {
        wallet_id: wallet_id.to_string(),
        network: Some(state.liquid_network.name().to_string()),
        offer: offer.clone(),
    });
    save_store(&state.data_dir, &store)?;
    Ok(offer)
}

/// Publishes an already-signed proposal to the order book's public
/// `POST /api/offers` (or the route `TEMPLAR_SWAP_ADMIN_URL` names). Only
/// the proposal and optional public note leave the wallet process. Refusals
/// map to tagged errors ([`publish_error`]).
pub fn publish(state: &AppState, proposal_json: &str, note: &str) -> Result<u64, String> {
    let proposal = LiquidexProposal::from_json(proposal_json).map_err(|e| e.to_string())?;
    let analysis =
        verify_proposal_on(&proposal, false, &state.liquid_network).map_err(|e| e.to_string())?;
    if !analysis.valid {
        return Err(first_failure_note(&analysis)
            .unwrap_or_else(|| "Proposal failed offline verification".to_string()));
    }
    if analysis.network == SwapNetwork::Mainnet {
        return Err("Liquid mainnet proposals cannot be published".to_string());
    }
    let url = state.endpoints().publish_url().value;
    let network = state.liquid_network.name();
    publish_offer(&url, network, proposal_json, note.trim())
        .map_err(|e| publish_error(e, &url, network))
}

/// An order-book publish refusal as a tagged engine error. The tag follows
/// the HTTP status (the order book's contract: match on the status, not the
/// text); the book's own message is appended for people.
pub(crate) fn publish_error(e: BookError, url: &str, network: &str) -> String {
    // The publish URL may come from TEMPLAR_SWAP_ADMIN_URL with a login in
    // it: never echo credentials.
    let url = templar_core::endpoints::redact_userinfo(url);
    let (status, message, retry_after) = match e {
        BookError::Rejected {
            status,
            message,
            retry_after,
        } => (status, message, retry_after),
        BookError::Network(msg) => {
            return format!("BOOK_UNREACHABLE: Cannot reach the order book at {url}: {msg}")
        }
        other => return format!("BOOK_UNAVAILABLE: {other}"),
    };
    let retry = retry_after
        .map(|s| format!(" Try again in {s} seconds."))
        .unwrap_or_else(|| " Try again later.".to_string());
    match status {
        400 => format!("BOOK_REJECTED: The order book refused the offer: {message}"),
        401 => format!(
            "BOOK_REJECTED: {url} wants an admin login. TEMPLAR_SWAP_ADMIN_URL points at the \
             admin route of a protected order book; unset it to publish through the public \
             POST /api/offers."
        ),
        403 => format!(
            "BOOK_PUBLISH_DISABLED: This order book does not take public offers for {network}: \
             {message}"
        ),
        404 | 405 => format!(
            "BOOK_UNAVAILABLE: {url} has no publish route (HTTP {status}); the order book needs \
             an update to take offers from wallets"
        ),
        409 => "BOOK_DUPLICATE: This offer is already in the order book".to_string(),
        413 => "BOOK_REJECTED: The offer is too large for the order book".to_string(),
        415 | 422 => format!(
            "BOOK_REJECTED: The order book could not read the request (HTTP {status}): {message}"
        ),
        429 => format!("BOOK_RATE_LIMITED: Too many offers published from here.{retry}"),
        503 => format!(
            "BOOK_CHAIN_UNREACHABLE: The order book cannot verify offers on {network} right \
             now, so nothing was stored.{retry} ({message})"
        ),
        _ => format!("BOOK_UNAVAILABLE: The order book answered HTTP {status}: {message}"),
    }
}

/// Exact-amount self-send: creates a UTXO of exactly `amount_sats` of
/// `asset_id` at a fresh own address, for the "offer amount X but no exact
/// coin" path. Signs and broadcasts; the UI re-syncs afterwards.
pub fn make_prepare(
    state: &mut AppState,
    asset_id: &str,
    amount_sats: u64,
    _fee_rate: Option<f32>,
) -> Result<String, String> {
    if amount_sats == 0 {
        return Err("Amount must be greater than zero".to_string());
    }
    let frozen = state.frozen_on(CoinChain::Liquid);
    let liq = state.liquid.as_mut().ok_or("Liquid wallet not open")?;
    let address = liq.get_new_address().map_err(|e| e.to_string())?;
    let mut pset = liq
        .create_tx_multi(
            &[(address, amount_sats, asset_id.to_string())],
            None,
            &frozen,
        )
        .map_err(|e| e.to_string())?;
    liq.sign(&mut pset).map_err(|e| e.to_string())?;
    liq.broadcast(&mut pset).map_err(|e| e.to_string())
}

/// This wallet's offers on the active Liquid network, newest first (offers
/// stored before the network was recorded show on both). Open offers get a
/// best-effort status refresh: an offered UTXO seen spent on the active
/// chain closes the offer (persisted); network errors and foreign-network
/// prevouts keep the stored status.
pub fn list_my_offers(state: &AppState, wallet_id: &str) -> Result<Vec<MyOfferDto>, String> {
    let mut store = load_store(&state.data_dir)?;
    let mut changed = false;
    let network = state.liquid_network.name();
    let chain = state.liquid_chain().ok();
    for stored in store
        .offers
        .iter_mut()
        .filter(|o| o.wallet_id == wallet_id && o.is_on(network))
    {
        if stored.offer.status != "open" {
            continue;
        }
        let Ok(proposal) = LiquidexProposal::from_json(&stored.offer.proposal_json) else {
            continue;
        };
        // Some(false) = spent → closed. Some(true) = still open.
        // None (prevout unknown to this chain) and Err (network) keep the
        // stored status — never guess an offer's fate offline.
        let Some(chain) = &chain else { continue };
        if let Ok(Some(false)) = proposal_utxo_unspent_with(&proposal, chain) {
            stored.offer.status = "closed".to_string();
            changed = true;
        }
    }
    if changed {
        save_store(&state.data_dir, &store)?;
    }
    // Each leg is named now, not as it was when the offer was stored: the
    // wallet's own asset store first, then the order book's registry.
    let mut out: Vec<MyOfferDto> = store
        .offers
        .into_iter()
        .filter(|o| o.wallet_id == wallet_id && o.is_on(network))
        .map(|o| {
            let mut offer = o.offer;
            offer.offers = leg_dto(state, &offer.offers.asset_id, offer.offers.amount_sats);
            offer.wants = leg_dto(state, &offer.wants.asset_id, offer.wants.amount_sats);
            offer
        })
        .collect();
    out.sort_by_key(|o| std::cmp::Reverse(o.created_at));
    Ok(out)
}

/// Cancels an open offer by broadcasting a self-spend of the offered UTXO —
/// the double-spend invalidates the signed proposal. Marks it "cancelled".
///
/// A frozen offered coin is still cancellable on purpose: the signed offer
/// can be taken whatever this wallet thinks of the coin, and this self-spend
/// is the only thing that stops that.
pub fn cancel(state: &AppState, wallet_id: &str, offer_id: &str) -> Result<String, String> {
    let liq = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
    let mut store = load_store(&state.data_dir)?;
    // Only an offer of the active network: another network's coin cannot
    // be spent on this chain.
    let network = state.liquid_network.name();
    let stored = store
        .offers
        .iter_mut()
        .find(|o| o.wallet_id == wallet_id && o.offer.offer_id == offer_id && o.is_on(network))
        .ok_or_else(|| format!("Unknown swap offer on {network}: {offer_id}"))?;
    if stored.offer.status != "open" {
        return Err(format!(
            "Offer can no longer be cancelled (status: {})",
            stored.offer.status
        ));
    }
    let tx = build_cancel_tx(liq, &stored.offer.utxo).map_err(|e| e.to_string())?;
    let chain = liq.chain().map_err(|e| e.to_string())?;
    let txid = broadcast_transaction_with(&tx, &chain).map_err(|e| e.to_string())?;
    stored.offer.status = "cancelled".to_string();
    save_store(&state.data_dir, &store)?;
    Ok(txid)
}

// ── Row / leg mapping ────────────────────────────────────────────────────────

/// A book or markets feed URL for one network, with `all` for unavailable
/// rows too.
fn feed_url(base: &str, include_unavailable: bool, network: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    let mut url = format!("{base}{separator}network={network}");
    if include_unavailable {
        url.push_str("&all=1");
    }
    url
}

fn market_row(state: &AppState, entry: &MarketBookEntry) -> MarketRowDto {
    let local = &state.liquid_network;
    let (verified, takeable, block_reason) = if entry.settlement == "htlc-v1" {
        let network_ok = local.name() == "liquid-testnet"
            && entry.maker_gives.network.contains("testnet")
            && entry.maker_wants.network.contains("testnet");
        (
            network_ok,
            network_ok && entry.available && entry.status == "open",
            (!network_ok)
                .then(|| "HTLC v1 is restricted to Bitcoin testnet and Liquid testnet".to_string()),
        )
    } else if entry.demo {
        (
            false,
            false,
            Some("HTLC settlement is intentionally disabled in this UI/UX demo build".to_string()),
        )
    } else {
        match LiquidexProposal::from_json(&entry.proposal_json) {
            Ok(proposal) => match verify_proposal_on(&proposal, false, local) {
                Ok(result) => {
                    let here = SwapNetwork::of(local);
                    let detected = if result.network == SwapNetwork::Unknown {
                        here
                    } else {
                        result.network
                    };
                    let verified = result.valid && detected == here;
                    let reason = if verified {
                        None
                    } else {
                        first_failure_note(&result)
                            .or_else(|| Some("Offer belongs to another Liquid network".to_string()))
                    };
                    (verified, verified && entry.available, reason)
                }
                Err(error) => (false, false, Some(error.to_string())),
            },
            Err(error) => (false, false, Some(error.to_string())),
        }
    };
    MarketRowDto {
        id: entry.id.clone(),
        source_id: entry.source_id,
        status: entry.status.clone(),
        settlement: entry.settlement.clone(),
        demo: entry.demo,
        available: entry.available,
        maker_gives: market_leg(state, &entry.maker_gives),
        maker_wants: market_leg(state, &entry.maker_wants),
        price_display: entry.price_display.clone(),
        note: entry.note.clone(),
        created_at: entry.created_at,
        proposal_json: entry.proposal_json.clone(),
        verified,
        takeable,
        block_reason,
    }
}

/// A markets-feed leg. A Liquid asset the wallet or the order book's
/// registry knows is named and scaled their way (the policy asset always
/// the wallet's); otherwise the feed's own display data is kept, printable
/// and bounded.
fn market_leg(state: &AppState, leg: &MarketBookLeg) -> MarketLegDto {
    let shown_as = (leg.chain == "liquid")
        .then(|| asset_names::display(state, &leg.asset_id))
        .filter(|d| d.source != FROM_NONE);
    match shown_as {
        Some(d) => MarketLegDto {
            chain: leg.chain.clone(),
            network: leg.network.clone(),
            asset_id: leg.asset_id.clone(),
            display_amount: d.format(leg.amount_sats),
            ticker: d.ticker,
            name: d.name,
            precision: d.precision,
            amount_sats: leg.amount_sats,
            metadata_source: d.source.to_string(),
            book_source: d.book_source,
        },
        None => MarketLegDto {
            chain: leg.chain.clone(),
            network: leg.network.clone(),
            asset_id: leg.asset_id.clone(),
            ticker: printable(&leg.ticker, 24),
            name: printable(&leg.name, 255),
            precision: leg.precision.min(8),
            amount_sats: leg.amount_sats,
            display_amount: printable(&leg.display_amount, 64),
            metadata_source: FROM_FEED.to_string(),
            book_source: None,
        },
    }
}

fn printable(s: &str, max: usize) -> String {
    templar_core::http::printable(s, max)
}

/// Pure mapping + ordering (available first, then id descending) — the
/// network fetch stays out so this is unit-testable.
fn rows_from_entries(state: &AppState, entries: &[BookEntry]) -> Vec<SwapRowDto> {
    let mut rows: Vec<SwapRowDto> = entries.iter().map(|entry| book_row(state, entry)).collect();
    rows.sort_by(|a, b| b.available.cmp(&a.available).then(b.id.cmp(&a.id)));
    rows
}

fn book_row(state: &AppState, entry: &BookEntry) -> SwapRowDto {
    let local = &state.liquid_network;
    let receive = book_leg_dto(state, entry.inputs.first());
    let pay = book_leg_dto(state, entry.outputs.first());
    // Ratio is the book's own input/output price; the display convention is
    // "<price> PAY/RECEIVE" (how much of the paid asset per received unit).
    let price_display = format!("{:.8} {}/{}", entry.ratio, pay.ticker, receive.ticker);

    // Offline verification. A proposal that does not even parse is still
    // listed — visibly unverified and never takeable.
    let (verified, verify_note, network, takeable) =
        match LiquidexProposal::from_json(&entry.proposal_json) {
            Ok(proposal) => match verify_proposal_on(&proposal, false, local) {
                Ok(res) => {
                    let note = first_failure_note(&res);
                    // Token-to-token proposals cannot identify a chain from a
                    // policy asset. The local book's network partition is the
                    // offline hint; take still performs deep chain checks.
                    let here = SwapNetwork::of(local);
                    let detected = if res.network == SwapNetwork::Unknown {
                        here
                    } else {
                        res.network
                    };
                    let takeable = res.valid && detected == here;
                    (res.valid, note, detected.as_str().to_string(), takeable)
                }
                Err(e) => (false, Some(e.to_string()), "unknown".to_string(), false),
            },
            Err(e) => (false, Some(e.to_string()), "unknown".to_string(), false),
        };

    SwapRowDto {
        id: entry.id,
        available: entry.available,
        receive,
        pay,
        price: entry.ratio,
        price_display,
        created: entry.creation_timestamp.clone(),
        verified,
        verify_note,
        proposal_json: entry.proposal_json.clone(),
        network,
        takeable,
        kind: "swap".to_string(),
    }
}

/// Note of the first failing check, if any.
fn first_failure_note(res: &VerifyResult) -> Option<String> {
    res.checks.iter().find(|c| c.ok == Some(false)).map(|c| {
        c.note
            .clone()
            .unwrap_or_else(|| format!("{} check failed", c.name))
    })
}

/// A legacy book row's leg. An asset the wallet or the order book's
/// registry knows is shown their way; otherwise the row's own display data
/// (ticker from the book's display name, amount as published).
fn book_leg_dto(state: &AppState, leg: Option<&BookLeg>) -> SwapLegDto {
    let Some(l) = leg else {
        return SwapLegDto {
            asset_id: String::new(),
            ticker: String::new(),
            amount_sats: 0,
            display_amount: String::new(),
            name: String::new(),
            precision: 8,
            metadata_source: FROM_NONE.to_string(),
            book_source: None,
        };
    };
    let known = asset_names::display(state, &l.asset);
    if known.source != FROM_NONE {
        return leg_dto(state, &l.asset, l.sats);
    }
    // The published amount's decimals are the book's precision.
    let precision = l
        .amount
        .split_once('.')
        .map_or(0, |(_, frac)| frac.len().min(8) as u8);
    SwapLegDto {
        asset_id: l.asset.clone(),
        ticker: printable(&l.ticker(), 24),
        amount_sats: l.sats,
        display_amount: printable(&l.amount, 64),
        name: printable(&l.name, 255),
        precision,
        metadata_source: FROM_FEED.to_string(),
        book_source: None,
    }
}

/// `amount_sats` of `asset_id`, named the wallet's way first, then the
/// active order book's registry ([`asset_names::display`]); a short
/// asset-id prefix with 8 decimals for an asset nobody named.
fn leg_dto(state: &AppState, asset_id: &str, amount_sats: u64) -> SwapLegDto {
    let shown_as = asset_names::display(state, asset_id);
    SwapLegDto {
        asset_id: asset_id.to_string(),
        display_amount: shown_as.format(amount_sats),
        ticker: shown_as.ticker,
        amount_sats,
        name: shown_as.name,
        precision: shown_as.precision,
        metadata_source: shown_as.source.to_string(),
        book_source: shown_as.book_source,
    }
}

fn registry_leg(state: &AppState, leg: &SwapLeg) -> SwapLegDto {
    leg_dto(state, &leg.asset_id, leg.amount_sats)
}

fn liquidex_leg_dto(state: &AppState, leg: &LiquidexLeg) -> SwapLegDto {
    leg_dto(state, &leg.asset, leg.amount)
}

fn analysis_dto(state: &AppState, res: &VerifyResult) -> SwapAnalysisDto {
    SwapAnalysisDto {
        valid: res.valid,
        checks: res.checks.clone(),
        maker_offers: registry_leg(state, &res.maker_offers),
        maker_wants: registry_leg(state, &res.maker_wants),
        network: res.network.as_str().to_string(),
        takeable: res.takeable,
        take_block_reason: res.take_block_reason.clone(),
    }
}

fn preview_dto(state: &AppState, preview: &TakePreview) -> TakePreviewDto {
    TakePreviewDto {
        you_receive: registry_leg(state, &preview.you_receive),
        you_pay: registry_leg(state, &preview.you_pay),
        fee_sats: preview.fee_sats,
        fee_display: format!("{} sats", preview.fee_sats),
        change: preview
            .change
            .iter()
            .map(|l| registry_leg(state, l))
            .collect(),
        analysis: analysis_dto(state, &preview.analysis),
    }
}

// ── Persistence ──────────────────────────────────────────────────────────────

/// One stored offer: the wire DTO plus the owning wallet and the Liquid
/// network it was made on (kept out of the wire shape via flatten).
#[derive(Serialize, Deserialize, Debug, Clone)]
struct StoredOffer {
    wallet_id: String,
    /// `liquid-testnet` | `liquid-regtest`; absent on offers stored before
    /// the network was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(flatten)]
    offer: MyOfferDto,
}

impl StoredOffer {
    /// Whether the offer belongs on `network` (unknown = shown everywhere).
    fn is_on(&self, network: &str) -> bool {
        self.network.as_deref().is_none_or(|n| n == network)
    }
}

/// Forgets every stored offer made on `network` — a reset regtest chain
/// takes its offers with it. Returns how many were dropped.
pub(crate) fn drop_offers_on(data_dir: &Path, network: &str) -> Result<usize, String> {
    if !store_path(data_dir).exists() {
        return Ok(0);
    }
    let mut store = load_store(data_dir)?;
    let before = store.offers.len();
    store
        .offers
        .retain(|o| o.network.as_deref() != Some(network));
    let dropped = before - store.offers.len();
    if dropped > 0 {
        save_store(data_dir, &store)?;
    }
    Ok(dropped)
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SwapOfferStore {
    offers: Vec<StoredOffer>,
}

fn store_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(STORE_FILE)
}

fn load_store(data_dir: &Path) -> Result<SwapOfferStore, String> {
    let path = store_path(data_dir);
    if !path.exists() {
        return Ok(SwapOfferStore::default());
    }
    let raw = fs::read_to_string(&path).map_err(|e| format!("Cannot read {STORE_FILE}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| {
        format!("{STORE_FILE} is corrupt: {e}. Delete the file to reset your swap offers.")
    })
}

fn save_store(data_dir: &Path, store: &SwapOfferStore) -> Result<(), String> {
    fs::create_dir_all(data_dir).map_err(|e| format!("Cannot create data dir: {e}"))?;
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| format!("Cannot serialize swap offers: {e}"))?;
    atomic_write(&store_path(data_dir), &json)
}

/// Atomic write (temp file + fsync + rename) through templar-core's helper, which
/// also creates the file owner-only (A3) — these stores sit in the same
/// directory as the registry and used to land as `0644`.
fn atomic_write(path: &Path, contents: &str) -> Result<(), String> {
    templar_core::registry::atomic_write(path, contents).map_err(|e| e.to_string())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// FNV-1a 64-bit — stable across platforms and Rust versions.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// `of_<8hex>` id, unique within the store. Seeded from wall clock + pid —
/// offer ids need uniqueness, not unpredictability (the proposal itself
/// carries the cryptographic material).
fn new_offer_id(store: &SwapOfferStore) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut salt = 0u64;
    loop {
        let h = fnv1a64(format!("of:{nanos}:{pid}:{salt}").as_bytes());
        let id = format!("of_{:08x}", (h as u32) ^ ((h >> 32) as u32));
        if !store.offers.iter().any(|o| o.offer.offer_id == id) {
            return id;
        }
        salt += 1;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use templar_core::verify_proposal;

    /// Real proposal from the liquidex.it book (offer id 9, mainnet): DBEER
    /// offered for LBTC. Offline checks pass against this genuine data.
    pub(crate) const PROPOSAL_ID_9: &str = r#"{"version":0,"tx":"02000000010162457676604122dc2c3ab6b9ac5a787411cc90f07edd8651c656fd5ed5dfd45c000000001716001461362b692acf41e26c88c58abcd633cbbe06f420feffffff010b90f4a0ea769100ad4200aabb115f6ead24ba5180eea84f231f3c51c047f02f57092c307774be067befd563d6eb23ca185f963e22f9e96b3f224e94d28ed3cd2fd2020ea96dbab999be940e62be9ff1d8525f354730a3546d71a70696e1f40082996c17a914ea94f77a850e4b018d67c8c4ba087977ec63e1db8700000000000002473044022053a7107a113adffe78e556aa5fa0391b3a2301277630d77febd5398f7a834d520220484feb14c5b0b313759b79501a36d471985b5fe33a346cbcd3d059a0d32214a283210247fa74dbe2fe4f4d0d8e5cc16573f097cb9909670eedd733b50f37e343c9b08a000000","inputs":[{"asset":"002452cb8f56a0a5628240edfb3d1e966c9b1959adcfb95b5726e5e9688611bf","asset_blinder":"10abf182945667b6aae98a79535b91f2343eb6a920d8d99d3de06fa024e38c77","amount_blinder":"6cce12bfa4cd11818de662104e61f6be53275e21c343e984bb06c6749669ad2f","amount":1000}],"outputs":[{"asset":"6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d","asset_blinder":"e8bfdc63d9750f16a2934b42466c1bfd171e5f3bcd8eafcd9e3ef954cf8a6d58","amount_blinder":"8e2d5cb748d14d5edb06643da6b05208671fbca875682a67690e3436d3ceb22a","amount":1000}]}"#;

    fn fixture_entry_9() -> BookEntry {
        BookEntry {
            id: 9,
            available: true,
            creation_timestamp: "Wed, 09 Jun 2021 16:37:38 GMT".to_string(),
            ratio: 1.0,
            version: 0,
            proposal_json: PROPOSAL_ID_9.to_string(),
            inputs: vec![BookLeg {
                asset: "002452cb8f56a0a5628240edfb3d1e966c9b1959adcfb95b5726e5e9688611bf"
                    .to_string(),
                name: "DBEER - Dex Beer (liquid.beer)".to_string(),
                amount: "10.00".to_string(),
                sats: 1000,
            }],
            outputs: vec![BookLeg {
                asset: "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d"
                    .to_string(),
                name: "LBTC - Liquid Bitcoin ()".to_string(),
                amount: "0.00001000".to_string(),
                sats: 1000,
            }],
        }
    }

    fn broken_entry(id: u64, available: bool) -> BookEntry {
        BookEntry {
            id,
            available,
            creation_timestamp: "Thu, 10 Jun 2021 00:00:00 GMT".to_string(),
            ratio: 2.5,
            version: 0,
            proposal_json: "{ not a proposal".to_string(),
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    fn demo_market_entry() -> MarketBookEntry {
        MarketBookEntry {
            id: "demo:7".to_string(),
            source_id: 7,
            status: "open".to_string(),
            settlement: "htlc-demo".to_string(),
            demo: true,
            available: true,
            maker_gives: MarketBookLeg {
                chain: "bitcoin".to_string(),
                network: "bitcoin-testnet".to_string(),
                asset_id: "btc-testnet".to_string(),
                ticker: "BTC".to_string(),
                name: "Bitcoin".to_string(),
                precision: 8,
                amount_sats: 100_000,
                display_amount: "0.00100000".to_string(),
            },
            maker_wants: MarketBookLeg {
                chain: "liquid".to_string(),
                network: "liquid-testnet".to_string(),
                asset_id: "aa".repeat(32),
                ticker: "USDT".to_string(),
                name: "Test USD".to_string(),
                precision: 2,
                amount_sats: 2_500,
                display_amount: "25.00".to_string(),
            },
            price_display: "0.00100000 → 25.00".to_string(),
            note: "demo".to_string(),
            created_at: 42,
            proposal_json: String::new(),
        }
    }

    /// An engine on Liquid testnet with nothing open, on its own directory.
    fn test_state() -> AppState {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = test_dir(&format!("state_{}", SEQ.fetch_add(1, Ordering::Relaxed)));
        AppState::new_for_test(dir)
    }

    fn test_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("templar_swaps_{}_{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_offer(id: &str, created_at: u64) -> MyOfferDto {
        MyOfferDto {
            offer_id: id.to_string(),
            kind: "swap".to_string(),
            status: "open".to_string(),
            created_at,
            offers: SwapLegDto {
                asset_id: "aa".repeat(32),
                ticker: "AAAAAAAA".to_string(),
                amount_sats: 1000,
                display_amount: "0.00001000".to_string(),
                name: String::new(),
                precision: 8,
                metadata_source: FROM_NONE.to_string(),
                book_source: None,
            },
            wants: SwapLegDto {
                asset_id: templar_core::LBTC_TESTNET_ASSET_ID.to_string(),
                ticker: "LBTC".to_string(),
                amount_sats: 500,
                display_amount: "0.00000500".to_string(),
                name: "Liquid Bitcoin".to_string(),
                precision: 8,
                metadata_source: "wallet".to_string(),
                book_source: None,
            },
            proposal_json: PROPOSAL_ID_9.to_string(),
            utxo: format!("{}:0", "cc".repeat(32)),
        }
    }

    #[test]
    fn book_row_maps_real_entry() {
        let row = book_row(&test_state(), &fixture_entry_9());
        assert_eq!(row.id, 9);
        assert!(row.available);
        // Taker orientation: receive = maker input, pay = maker output.
        assert_eq!(row.receive.ticker, "DBEER");
        assert_eq!(row.receive.amount_sats, 1000);
        assert_eq!(row.receive.display_amount, "10.00");
        assert_eq!(row.pay.ticker, "LBTC");
        assert_eq!(row.pay.display_amount, "0.00001000");
        assert_eq!(row.price, 1.0);
        assert_eq!(row.price_display, "1.00000000 LBTC/DBEER");
        assert_eq!(row.created, "Wed, 09 Jun 2021 16:37:38 GMT");
        // Real mainnet data: offline checks pass, but a mainnet order is
        // never takeable by this testnet-signing wallet.
        assert!(row.verified, "offline checks must pass on real data");
        assert!(row.verify_note.is_none());
        assert_eq!(row.network, "mainnet");
        assert!(!row.takeable);
        assert_eq!(row.kind, "swap");
        assert_eq!(row.proposal_json, PROPOSAL_ID_9);
    }

    #[test]
    fn unparseable_proposal_is_listed_but_unverified() {
        let row = book_row(&test_state(), &broken_entry(3, true));
        assert!(!row.verified);
        assert!(!row.takeable);
        assert!(row.verify_note.is_some());
        assert_eq!(row.network, "unknown");
        // Missing legs degrade to empty placeholders, not a panic.
        assert_eq!(row.receive.asset_id, "");
        assert_eq!(row.pay.amount_sats, 0);
    }

    #[test]
    fn rows_sort_available_first_then_id_desc() {
        let mut old_available = fixture_entry_9();
        old_available.id = 2;
        let entries = vec![
            broken_entry(7, false),
            old_available,
            fixture_entry_9(), // id 9, available
            broken_entry(11, false),
        ];
        let ids: Vec<(u64, bool)> = rows_from_entries(&test_state(), &entries)
            .iter()
            .map(|r| (r.id, r.available))
            .collect();
        assert_eq!(ids, vec![(9, true), (2, true), (11, false), (7, false)]);
    }

    #[test]
    fn swap_row_wire_shape_matches_contract_keys() {
        let v = serde_json::to_value(book_row(&test_state(), &fixture_entry_9())).unwrap();
        for key in [
            "id",
            "available",
            "receive",
            "pay",
            "price",
            "price_display",
            "created",
            "verified",
            "verify_note",
            "proposal_json",
            "network",
            "takeable",
            "kind",
        ] {
            assert!(v.get(key).is_some(), "missing key {key}");
        }
        for key in ["asset_id", "ticker", "amount_sats", "display_amount"] {
            assert!(v["receive"].get(key).is_some(), "missing leg key {key}");
        }
        assert_eq!(v["kind"], "swap");
        assert!(v["verify_note"].is_null());
    }

    #[test]
    fn cross_chain_market_demo_is_visible_but_never_takeable() {
        let row = market_row(&test_state(), &demo_market_entry());
        assert!(row.demo);
        assert!(!row.verified);
        assert!(!row.takeable);
        assert_eq!(row.maker_gives.chain, "bitcoin");
        assert_eq!(row.maker_wants.ticker, "USDT");
        assert!(row.block_reason.unwrap().contains("disabled"));
    }

    #[test]
    fn market_row_wire_shape_is_stable() {
        let value = serde_json::to_value(market_row(&test_state(), &demo_market_entry())).unwrap();
        for key in [
            "id",
            "source_id",
            "status",
            "settlement",
            "demo",
            "available",
            "maker_gives",
            "maker_wants",
            "price_display",
            "note",
            "created_at",
            "proposal_json",
            "verified",
            "takeable",
            "block_reason",
        ] {
            assert!(value.get(key).is_some(), "missing key {key}");
        }
    }

    #[test]
    fn analysis_enriches_legs_via_registry() {
        let state = test_state();
        let proposal = LiquidexProposal::from_json(PROPOSAL_ID_9).unwrap();
        let result = verify_proposal(&proposal, false).unwrap();
        let dto = analysis_dto(&state, &result);
        assert!(dto.valid);
        assert_eq!(dto.network, "mainnet");
        assert!(!dto.takeable);
        assert_eq!(dto.checks.len(), 6);
        // Mainnet assets are unknown to the testnet registry: prefix ticker
        // + 8-decimal fallback formatting.
        assert_eq!(dto.maker_offers.ticker, "002452cb");
        assert_eq!(dto.maker_offers.display_amount, "0.00001000");
        assert_eq!(dto.maker_offers.amount_sats, 1000);
        // A testnet LBTC leg resolves through the registry defaults.
        let lbtc = registry_leg(
            &state,
            &SwapLeg {
                asset_id: templar_core::LBTC_TESTNET_ASSET_ID.to_string(),
                amount_sats: 12_345,
            },
        );
        assert_eq!(lbtc.ticker, "LBTC");
        assert_eq!(lbtc.display_amount, "0.00012345");
    }

    #[test]
    fn store_round_trips_atomically_per_wallet() {
        let dir = test_dir("roundtrip");
        // Missing file = empty store.
        assert!(load_store(&dir).unwrap().offers.is_empty());

        let mut store = SwapOfferStore::default();
        store.offers.push(StoredOffer {
            wallet_id: "w1".to_string(),
            network: None,
            offer: sample_offer("of_00000001", 100),
        });
        store.offers.push(StoredOffer {
            wallet_id: "w2".to_string(),
            network: None,
            offer: sample_offer("of_00000002", 200),
        });
        save_store(&dir, &store).unwrap();
        assert!(dir.join(STORE_FILE).exists());
        assert!(!dir.join("swap_offers.tmp").exists());

        let reloaded = load_store(&dir).unwrap();
        assert_eq!(reloaded.offers.len(), 2);
        assert_eq!(reloaded.offers[0].wallet_id, "w1");
        assert_eq!(reloaded.offers[0].offer.offer_id, "of_00000001");
        assert_eq!(reloaded.offers[0].offer.status, "open");
        assert_eq!(reloaded.offers[0].offer.offers.ticker, "AAAAAAAA");
        assert_eq!(reloaded.offers[1].offer.created_at, 200);

        // The stored record flattens the DTO next to wallet_id — the wire
        // shape (no wallet_id) survives the round-trip intact.
        let raw: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.join(STORE_FILE)).unwrap()).unwrap();
        let first = &raw["offers"][0];
        for key in [
            "wallet_id",
            "offer_id",
            "kind",
            "status",
            "created_at",
            "offers",
            "wants",
            "proposal_json",
            "utxo",
        ] {
            assert!(first.get(key).is_some(), "missing stored key {key}");
        }
        let wire = serde_json::to_value(&reloaded.offers[0].offer).unwrap();
        assert!(wire.get("wallet_id").is_none());
        assert_eq!(wire["offer_id"], "of_00000001");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_store_is_a_clear_error() {
        let dir = test_dir("corrupt");
        fs::write(dir.join(STORE_FILE), "{ not json").unwrap();
        let err = load_store(&dir).unwrap_err();
        assert!(err.contains("corrupt"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn offer_ids_are_unique_and_well_formed() {
        let mut store = SwapOfferStore::default();
        let id1 = new_offer_id(&store);
        assert!(id1.starts_with("of_"));
        assert_eq!(id1.len(), 11);
        assert!(id1[3..].chars().all(|c| c.is_ascii_hexdigit()));
        store.offers.push(StoredOffer {
            wallet_id: "w".to_string(),
            network: None,
            offer: sample_offer(&id1, 1),
        });
        let id2 = new_offer_id(&store);
        assert_ne!(id1, id2);
    }

    #[test]
    fn feed_urls_carry_the_network_and_all_suffix() {
        assert_eq!(
            feed_url(LOCAL_BOOK_URL, false, "liquid-testnet"),
            format!("{LOCAL_BOOK_URL}?network=liquid-testnet")
        );
        assert_eq!(
            feed_url(LOCAL_BOOK_URL, true, "liquid-regtest"),
            format!("{LOCAL_BOOK_URL}?network=liquid-regtest&all=1")
        );
        assert_eq!(
            feed_url(&format!("{LOCAL_MARKETS_URL}?x=1"), false, "liquid-testnet"),
            format!("{LOCAL_MARKETS_URL}?x=1&network=liquid-testnet")
        );
    }

    #[test]
    fn publish_refusals_map_to_tags_by_status() {
        let refusal = |status, retry_after| BookError::Rejected {
            status,
            message: "server text".into(),
            retry_after,
        };
        let url = "http://127.0.0.1:3210/api/offers";
        for (status, retry, tag) in [
            (400, None, "BOOK_REJECTED:"),
            (401, None, "BOOK_REJECTED:"),
            (403, None, "BOOK_PUBLISH_DISABLED:"),
            (404, None, "BOOK_UNAVAILABLE:"),
            (409, None, "BOOK_DUPLICATE:"),
            (413, None, "BOOK_REJECTED:"),
            (415, None, "BOOK_REJECTED:"),
            (429, Some(42), "BOOK_RATE_LIMITED:"),
            (503, Some(30), "BOOK_CHAIN_UNREACHABLE:"),
            (500, None, "BOOK_UNAVAILABLE:"),
        ] {
            let msg = publish_error(refusal(status, retry), url, "liquid-regtest");
            assert!(msg.starts_with(tag), "{status}: {msg}");
            if let Some(s) = retry {
                assert!(msg.contains(&format!("{s} seconds")), "{msg}");
            }
        }
        let msg = publish_error(BookError::Network("refused".into()), url, "liquid-testnet");
        assert!(msg.starts_with("BOOK_UNREACHABLE:"), "{msg}");
        // A login in the URL is never echoed.
        let secret = "http://admin:hunter2@127.0.0.1:3210/api/admin/offers";
        for e in [
            BookError::Network("refused".into()),
            refusal(401, None),
            refusal(404, None),
        ] {
            let msg = publish_error(e, secret, "liquid-testnet");
            assert!(!msg.contains("hunter2") && !msg.contains("admin:"), "{msg}");
            assert!(msg.contains("***@127.0.0.1:3210"), "{msg}");
        }
    }

    #[test]
    fn offers_are_kept_per_network_and_dropped_with_a_reset_chain() {
        let dir = test_dir("per_network");
        let mut store = SwapOfferStore::default();
        for (id, network) in [
            ("of_00000001", Some("liquid-testnet")),
            ("of_00000002", Some("liquid-regtest")),
            ("of_00000003", None),
        ] {
            store.offers.push(StoredOffer {
                wallet_id: "w".into(),
                network: network.map(str::to_string),
                offer: sample_offer(id, 1),
            });
        }
        save_store(&dir, &store).unwrap();
        let loaded = load_store(&dir).unwrap();
        assert!(loaded.offers[0].is_on("liquid-testnet"));
        assert!(!loaded.offers[0].is_on("liquid-regtest"));
        assert!(loaded.offers[2].is_on("liquid-regtest"));
        assert_eq!(drop_offers_on(&dir, "liquid-regtest").unwrap(), 1);
        let ids: Vec<String> = load_store(&dir)
            .unwrap()
            .offers
            .into_iter()
            .map(|o| o.offer.offer_id)
            .collect();
        assert_eq!(ids, ["of_00000001", "of_00000003"]);
        let _ = fs::remove_dir_all(&dir);
    }
}
