//! Real testnet Bitcoin <-> Liquid atomic-swap workflow.
//!
//! The order book is only a public state coordinator, and an untrusted one.
//! Swap keys and the maker preimage are deterministically recovered from the
//! software-wallet seed and never sent to the server. The terms a wallet
//! created or accepted (legs, amounts, hash, keys, timeouts) are kept in
//! `atomic_swaps.json`; every fund, claim and refund rebuilds both HTLCs from
//! them and refuses a coordinator row that disagrees, so a lying coordinator
//! can stall a swap but never redirect a payment.

use std::fs;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use bdk::bitcoin::consensus::encode::serialize as serialize_bitcoin;
use bdk::bitcoin::{Address as BitcoinAddress, Network as BitcoinNetwork};
use serde::{Deserialize, Serialize};

use templar_core::registry::WalletProfile;
use templar_core::{
    bitcoin_contract, derive_swap_secret_key, liquid_contract, spend_bitcoin_htlc,
    spend_liquid_htlc, swap_public_key, BitcoinSpendRequest, HtlcTerms, LiquidHtlcSpendRequest,
    MAKER_TIMEOUT_SECS, TAKER_TIMEOUT_SECS,
};

use crate::state::AppState;

const STORE_FILE: &str = "atomic_swaps.json";
const NETWORK: &str = "liquid-testnet";
const DEFAULT_BTC_FEE_RATE: f32 = 2.0;
const CLAIM_FEE_SATS: u64 = 500;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AtomicSwapState {
    pub offered_chain: String,
    pub offered_asset_id: String,
    pub offered_ticker: String,
    pub offered_name: String,
    pub offered_precision: u8,
    pub offered_amount_sats: u64,
    pub wanted_chain: String,
    pub wanted_asset_id: String,
    pub wanted_ticker: String,
    pub wanted_name: String,
    pub wanted_precision: u8,
    pub wanted_amount_sats: u64,
    pub payment_hash: String,
    pub maker_refund_pubkey: String,
    pub taker_claim_pubkey: Option<String>,
    pub maker_timeout: u64,
    pub taker_timeout: Option<u64>,
    pub maker_contract_address: Option<String>,
    pub maker_contract_script: Option<String>,
    pub taker_contract_address: Option<String>,
    pub taker_contract_script: Option<String>,
    pub maker_funding_txid: Option<String>,
    pub maker_funding_tx_hex: Option<String>,
    pub maker_funding_vout: Option<u32>,
    pub taker_funding_txid: Option<String>,
    pub taker_funding_tx_hex: Option<String>,
    pub taker_funding_vout: Option<u32>,
    pub preimage_hex: Option<String>,
    pub maker_claim_txid: Option<String>,
    pub taker_claim_txid: Option<String>,
    pub maker_refund_txid: Option<String>,
    pub taker_refund_txid: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicSwapRow {
    pub id: u64,
    pub network: String,
    pub status: String,
    pub state: AtomicSwapState,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyAtomicSwap {
    pub offer_id: u64,
    pub wallet_id: String,
    pub role: String,
    pub key_index: u32,
    pub row: AtomicSwapRow,
    pub next_action: String,
    pub can_fund: bool,
    pub can_claim: bool,
    pub can_refund: bool,
    /// Whether `row` is the active coordinator's live row of this swap:
    /// [`LIVE`], or why not ([`NOT_ON_THIS_BOOK`], [`BOOK_MISMATCH`],
    /// [`OTHER_BOOK`], [`BOOK_UNREACHABLE`]). A row that is not live is
    /// built from what this wallet stored (`status` [`UNAVAILABLE`], every
    /// `can_*` false, `next_action` `wait`).
    #[serde(default = "live")]
    pub availability: String,
    /// Why the row is not live, for people; null when it is.
    #[serde(default)]
    pub availability_note: Option<String>,
    /// The coordinator the stored record names (credentials masked); null
    /// for a record written before coordinators were kept.
    #[serde(default)]
    pub coordinator: Option<String>,
}

/// `availability` of a row fetched from the active coordinator and checked
/// as this wallet's swap.
pub const LIVE: &str = "live";
/// The active coordinator does not know the swap (HTTP 404), or its row
/// with that id is not this wallet's swap.
pub const NOT_ON_THIS_BOOK: &str = "not_on_this_book";
/// The active coordinator's row disagrees with the terms this wallet
/// accepted (nothing would be signed against it).
pub const BOOK_MISMATCH: &str = "book_mismatch";
/// The record names another coordinator; it was not contacted.
pub const OTHER_BOOK: &str = "other_book";
/// The coordinator could not be reached or read.
pub const BOOK_UNREACHABLE: &str = "book_unreachable";
/// `row.status` of a row that is not live.
pub const UNAVAILABLE: &str = "unavailable";

fn live() -> String {
    LIVE.to_string()
}

/// One record of `atomic_swaps.json`. A record this engine cannot read (a
/// field missing or of the wrong type) is kept exactly as it was and written
/// back unchanged: it may hold the key index of a funded HTLC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum StoredRecord {
    Swap(Box<StoredAtomicSwap>),
    Unreadable(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAtomicSwap {
    offer_id: u64,
    wallet_id: String,
    role: String,
    key_index: u32,
    /// The coordinator the swap lives on; another one's row with the same
    /// id is not this swap.
    #[serde(default)]
    coordinator: Option<String>,
    /// The terms this wallet created or accepted. Every action rebuilds
    /// both contracts from them and the wallet's own key; the coordinator's
    /// row must agree, or nothing is paid, claimed or refunded.
    #[serde(default)]
    terms: Option<AcceptedTerms>,
}

/// What a swap is, as this wallet created (maker) or accepted (taker) it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AcceptedTerms {
    offered_chain: String,
    offered_asset_id: String,
    offered_amount_sats: u64,
    wanted_chain: String,
    wanted_asset_id: String,
    wanted_amount_sats: u64,
    payment_hash: String,
    maker_pubkey: String,
    maker_timeout: u64,
    /// Learned by the maker when the taker reserves the swap.
    #[serde(default)]
    taker_pubkey: Option<String>,
    #[serde(default)]
    taker_timeout: Option<u64>,
}

/// Least time the maker keeps after the taker's timeout, as `join` asks.
const TIMEOUT_GAP_SECS: u64 = 3_600;

impl AcceptedTerms {
    fn from_state(s: &AtomicSwapState) -> Self {
        Self {
            offered_chain: s.offered_chain.clone(),
            offered_asset_id: s.offered_asset_id.to_ascii_lowercase(),
            offered_amount_sats: s.offered_amount_sats,
            wanted_chain: s.wanted_chain.clone(),
            wanted_asset_id: s.wanted_asset_id.to_ascii_lowercase(),
            wanted_amount_sats: s.wanted_amount_sats,
            payment_hash: s.payment_hash.to_ascii_lowercase(),
            maker_pubkey: s.maker_refund_pubkey.clone(),
            maker_timeout: s.maker_timeout,
            taker_pubkey: s.taker_claim_pubkey.clone(),
            taker_timeout: s.taker_timeout,
        }
    }

    /// The maker's contract (on the offered chain): the taker claims with
    /// the preimage, the maker refunds after `maker_timeout`.
    fn maker_contract(&self) -> Result<templar_core::HtlcContract, String> {
        let taker = self
            .taker_pubkey
            .clone()
            .ok_or("The taker has not joined yet")?;
        contract(
            &self.offered_chain,
            HtlcTerms {
                payment_hash: self.payment_hash.clone(),
                claim_pubkey: taker,
                refund_pubkey: self.maker_pubkey.clone(),
                timeout: self.maker_timeout,
            },
        )
    }

    /// The taker's contract (on the wanted chain): the maker claims with
    /// the preimage, the taker refunds after `taker_timeout`.
    fn taker_contract(&self) -> Result<templar_core::HtlcContract, String> {
        let taker = self
            .taker_pubkey
            .clone()
            .ok_or("The taker has not joined yet")?;
        contract(
            &self.wanted_chain,
            HtlcTerms {
                payment_hash: self.payment_hash.clone(),
                claim_pubkey: self.maker_pubkey.clone(),
                refund_pubkey: taker,
                timeout: self.taker_timeout.ok_or("The taker has not joined yet")?,
            },
        )
    }
}

/// Refuses a coordinator row that disagrees with the accepted terms: the
/// legs, the hash, the keys, the timeouts, and any contract it publishes
/// (which must be the one rebuilt from the terms).
fn check_row(row: &AtomicSwapRow, terms: &AcceptedTerms) -> Result<(), String> {
    let s = &row.state;
    let mut wrong = Vec::new();
    let mut same = |what: &str, ok: bool| {
        if !ok {
            wrong.push(what.to_string());
        }
    };
    same("offered chain", s.offered_chain == terms.offered_chain);
    same(
        "offered asset",
        s.offered_asset_id
            .eq_ignore_ascii_case(&terms.offered_asset_id),
    );
    same(
        "offered amount",
        s.offered_amount_sats == terms.offered_amount_sats,
    );
    same("wanted chain", s.wanted_chain == terms.wanted_chain);
    same(
        "wanted asset",
        s.wanted_asset_id
            .eq_ignore_ascii_case(&terms.wanted_asset_id),
    );
    same(
        "wanted amount",
        s.wanted_amount_sats == terms.wanted_amount_sats,
    );
    same(
        "payment hash",
        s.payment_hash.eq_ignore_ascii_case(&terms.payment_hash),
    );
    same("maker key", s.maker_refund_pubkey == terms.maker_pubkey);
    same("maker timeout", s.maker_timeout == terms.maker_timeout);
    if terms.taker_pubkey.is_some() {
        same("taker key", s.taker_claim_pubkey == terms.taker_pubkey);
        same("taker timeout", s.taker_timeout == terms.taker_timeout);
        let maker = terms.maker_contract()?;
        let taker = terms.taker_contract()?;
        let matches =
            |addr: &Option<String>, script: &Option<String>, c: &templar_core::HtlcContract| {
                addr.as_deref().is_none_or(|a| a == c.address)
                    && script
                        .as_deref()
                        .is_none_or(|x| x.eq_ignore_ascii_case(&c.script_hex))
            };
        same(
            "maker contract",
            matches(&s.maker_contract_address, &s.maker_contract_script, &maker),
        );
        same(
            "taker contract",
            matches(&s.taker_contract_address, &s.taker_contract_script, &taker),
        );
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "The swap coordinator's record of swap {} no longer matches the terms this wallet \
             accepted ({}); nothing was signed.",
            row.id,
            wrong.join(", ")
        ))
    }
}

/// The accepted terms of `local`, checked against the coordinator's `row`.
/// A maker learns (and keeps) the taker's key and timeout once, when the
/// swap is reserved, after checking the timeout leaves it time to claim.
/// A record written before terms were kept adopts the row's, but only if
/// the wallet's own part of it (its key, and for a maker the hash of its
/// preimage) is what its seed derives.
fn accepted_terms(
    state: &AppState,
    local: &mut StoredAtomicSwap,
    row: &AtomicSwapRow,
) -> Result<AcceptedTerms, String> {
    let coordinator = api(state);
    if local
        .coordinator
        .as_deref()
        .is_some_and(|c| c != coordinator)
    {
        return Err(
            "This swap lives on another swap coordinator; join that test server to follow it."
                .into(),
        );
    }
    if row.id != local.offer_id {
        return Err("The swap coordinator answered for another swap".into());
    }
    let maker = local.role == "maker";
    let original_coordinator = local.coordinator.clone();
    let mut changed = false;
    let mut terms = match local.terms.clone() {
        Some(t) => t,
        None => {
            if !carries_own_key(state, local, row)? {
                return Err(format!(
                    "The swap coordinator's record of swap {} does not carry this wallet's key; \
                     nothing was signed.",
                    row.id
                ));
            }
            changed = true;
            AcceptedTerms::from_state(&row.state)
        }
    };
    if maker && terms.taker_pubkey.is_none() {
        if let (Some(key), Some(timeout)) = (&row.state.taker_claim_pubkey, row.state.taker_timeout)
        {
            bdk::bitcoin::secp256k1::PublicKey::from_str(key)
                .map_err(|_| "The taker's key is not a public key".to_string())?;
            if timeout.saturating_add(TIMEOUT_GAP_SECS) > terms.maker_timeout
                || timeout <= now_secs()
            {
                return Err(format!(
                    "The taker's timeout {timeout} leaves this wallet no safe time to claim before \
                     its own refund at {}; nothing was signed.",
                    terms.maker_timeout
                ));
            }
            terms.taker_pubkey = Some(key.clone());
            terms.taker_timeout = Some(timeout);
            changed = true;
        }
    }
    check_row(row, &terms)?;
    if changed {
        local.terms = Some(terms.clone());
        local.coordinator = Some(coordinator);
        save_local(state, local, original_coordinator.as_deref())?;
    }
    Ok(terms)
}

/// Whether the coordinator's `row` carries this wallet's own part of the
/// swap `local` (a record written before terms were kept): its key, and for
/// a maker the hash of the preimage its seed derives.
fn carries_own_key(
    state: &AppState,
    local: &StoredAtomicSwap,
    row: &AtomicSwapRow,
) -> Result<bool, String> {
    let maker = local.role == "maker";
    let mnemonic = mnemonic(state, &local.wallet_id)?;
    let key = derive_swap_secret_key(mnemonic, if maker { 0 } else { 1 }, local.key_index)
        .map_err(|e| e.to_string())?;
    let own = swap_public_key(&key).to_string();
    let t = AcceptedTerms::from_state(&row.state);
    Ok(if maker {
        t.maker_pubkey == own
            && t.payment_hash == sha256_hex(&deterministic_preimage(&key.secret_bytes()))
    } else {
        t.taker_pubkey.as_deref() == Some(own.as_str())
    })
}

/// Writes one swap record back over the record it was read from (same
/// wallet, swap id and coordinator `was_on`); never over another
/// coordinator's swap with the same id.
fn save_local(
    state: &AppState,
    local: &StoredAtomicSwap,
    was_on: Option<&str>,
) -> Result<(), String> {
    let mut store = load_store(state)?;
    let slot = store.swaps.iter_mut().find_map(|r| match r {
        StoredRecord::Swap(s)
            if s.wallet_id == local.wallet_id
                && s.offer_id == local.offer_id
                && s.coordinator.as_deref() == was_on =>
        {
            Some(s)
        }
        _ => None,
    });
    match slot {
        Some(slot) => **slot = local.clone(),
        None => store
            .swaps
            .push(StoredRecord::Swap(Box::new(local.clone()))),
    }
    save_store(state, &store)
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AtomicStore {
    swaps: Vec<StoredRecord>,
}

impl AtomicStore {
    /// The records this engine can read.
    fn readable(&self) -> impl Iterator<Item = &StoredAtomicSwap> {
        self.swaps.iter().filter_map(|r| match r {
            StoredRecord::Swap(s) => Some(&**s),
            StoredRecord::Unreadable(_) => None,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateParams {
    pub wallet_id: String,
    pub direction: String,
    pub btc_amount_sats: u64,
    pub liquid_asset_id: String,
    pub liquid_ticker: String,
    pub liquid_name: String,
    #[serde(default = "eight")]
    pub liquid_precision: u8,
    pub liquid_amount_sats: u64,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Deserialize)]
pub struct IdParams {
    pub wallet_id: String,
    pub offer_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub wallet_id: String,
}

fn eight() -> u8 {
    8
}

pub fn create(state: &AppState, p: CreateParams) -> Result<MyAtomicSwap, String> {
    require_testnet_software(state, &p.wallet_id)?;
    let mnemonic = mnemonic(state, &p.wallet_id)?;
    let mut store = load_store(state)?;
    let key_index = next_index(&store, &p.wallet_id);
    let maker_key = derive_swap_secret_key(mnemonic, 0, key_index).map_err(|e| e.to_string())?;
    let preimage = deterministic_preimage(&maker_key.secret_bytes());
    let payment_hash = sha256_hex(&preimage);
    let btc = Leg::btc(p.btc_amount_sats);
    let liquid = Leg {
        chain: "liquid".into(),
        asset_id: p.liquid_asset_id.to_ascii_lowercase(),
        ticker: p.liquid_ticker,
        name: p.liquid_name,
        precision: p.liquid_precision,
        amount: p.liquid_amount_sats,
    };
    let (offered, wanted) = match p.direction.as_str() {
        "btc-to-liquid" => (btc, liquid),
        "liquid-to-btc" => (liquid, btc),
        _ => return Err("Direction must be btc-to-liquid or liquid-to-btc".into()),
    };
    let state_public = AtomicSwapState::new(
        offered,
        wanted,
        payment_hash,
        swap_public_key(&maker_key).to_string(),
        p.note,
    );
    let terms = AcceptedTerms::from_state(&state_public);
    let row: AtomicSwapRow = post_json(
        &api(state),
        &serde_json::json!({
            "network": NETWORK,
            "state": state_public,
        }),
    )?;
    // The coordinator stores what it was given, or the swap is not made.
    check_row(&row, &terms)?;
    store
        .swaps
        .push(StoredRecord::Swap(Box::new(StoredAtomicSwap {
            offer_id: row.id,
            wallet_id: p.wallet_id.clone(),
            role: "maker".into(),
            key_index,
            coordinator: Some(api(state)),
            terms: Some(terms),
        })));
    save_store(state, &store)?;
    Ok(enrich(
        row,
        &p.wallet_id,
        "maker",
        key_index,
        Some(&api(state)),
    ))
}

pub fn join(state: &AppState, p: IdParams) -> Result<MyAtomicSwap, String> {
    require_testnet_software(state, &p.wallet_id)?;
    let mnemonic = mnemonic(state, &p.wallet_id)?;
    let mut row = fetch(state, p.offer_id)?;
    if row.id != p.offer_id {
        return Err("The swap coordinator answered for another swap".into());
    }
    if row.status != "open" {
        return Err("Offer is no longer open".into());
    }
    let mut store = load_store(state)?;
    // Swap ids are per coordinator: a record of another coordinator's swap
    // with this id is another swap. A record written before coordinators
    // were kept is this one only if this row carries its key.
    let coordinator = api(state);
    let already = store.readable().any(|s| {
        s.offer_id == p.offer_id
            && match s.coordinator.as_deref() {
                Some(c) => c == coordinator,
                None => carries_own_key(state, s, &row).unwrap_or(false),
            }
    });
    if already {
        return Err("This wallet already participates in the swap".into());
    }
    let key_index = next_index(&store, &p.wallet_id);
    let taker_key = derive_swap_secret_key(mnemonic, 1, key_index).map_err(|e| e.to_string())?;
    let taker_pubkey = swap_public_key(&taker_key).to_string();
    let now = now_secs();
    if row.state.maker_timeout <= now + TAKER_TIMEOUT_SECS + TIMEOUT_GAP_SECS {
        return Err("Maker refund window is too short; create a fresh offer".into());
    }
    bdk::bitcoin::secp256k1::PublicKey::from_str(&row.state.maker_refund_pubkey)
        .map_err(|_| "The maker's key is not a public key".to_string())?;
    // What the user accepts by joining: the offer as shown, with this
    // wallet's key and timeout. From here on these terms are the swap.
    row.state.taker_claim_pubkey = Some(taker_pubkey);
    row.state.taker_timeout = Some(now + TAKER_TIMEOUT_SECS);
    let terms = AcceptedTerms::from_state(&row.state);
    let maker_contract = terms.maker_contract()?;
    let taker_contract = terms.taker_contract()?;
    row.state.maker_contract_address = Some(maker_contract.address);
    row.state.maker_contract_script = Some(maker_contract.script_hex);
    row.state.taker_contract_address = Some(taker_contract.address);
    row.state.taker_contract_script = Some(taker_contract.script_hex);
    row = transition(state, &row, "reserved")?;
    check_row(&row, &terms)?;
    store
        .swaps
        .push(StoredRecord::Swap(Box::new(StoredAtomicSwap {
            offer_id: row.id,
            wallet_id: p.wallet_id.clone(),
            role: "taker".into(),
            key_index,
            coordinator: Some(coordinator.clone()),
            terms: Some(terms),
        })));
    save_store(state, &store)?;
    Ok(enrich(
        row,
        &p.wallet_id,
        "taker",
        key_index,
        Some(&coordinator),
    ))
}

/// This wallet's cross-chain swaps.
///
/// Cross-chain swaps exist only on Liquid testnet: on any other network the
/// answer is an empty list, at once — no server is contacted and the stored
/// records are not read.
///
/// On testnet one record never fails the list. Each record is judged on its
/// own ([`MyAtomicSwap::availability`]):
///
/// - a record naming another coordinator is listed as [`OTHER_BOOK`] from
///   what this wallet stored, without contacting anyone;
/// - the active coordinator's row is listed [`LIVE`] when it is this
///   wallet's swap: the terms it accepted, or (a record written before terms
///   were kept) a row carrying this wallet's key;
/// - a 404, or a row with that id that is someone else's swap, is
///   [`NOT_ON_THIS_BOOK`]; a row contradicting the accepted terms is
///   [`BOOK_MISMATCH`]. Both are listed when the record holds the terms (the
///   user learns a swap of theirs is elsewhere), and left out when it holds
///   none: without terms there is no contract to rebuild, so nothing the
///   wallet could fund, claim or refund;
/// - an unreachable coordinator (or an answer that cannot be read) lists
///   the record as [`BOOK_UNREACHABLE`], terms or not — it may be live — and
///   after a connection failure the remaining records are not tried again;
/// - a record that cannot be read at all is left out (it has no usable key
///   index or swap id) and kept on disk untouched.
///
/// Nothing is written: listing never deletes or rewrites a record.
pub fn list_mine(state: &AppState, wallet_id: &str) -> Result<Vec<MyAtomicSwap>, String> {
    if !available_on(&state.liquid_network) {
        return Ok(Vec::new());
    }
    list_against(state, wallet_id, &api(state))
}

/// Whether cross-chain swaps exist on `network` (Liquid testnet only).
pub fn available_on(network: &templar_core::LiquidNetwork) -> bool {
    network.name() == NETWORK
}

fn list_against(
    state: &AppState,
    wallet_id: &str,
    coordinator: &str,
) -> Result<Vec<MyAtomicSwap>, String> {
    let store = load_store(state)?;
    let mut out = Vec::new();
    let mut unreachable: Option<String> = None;
    for record in &store.swaps {
        let local = match record {
            StoredRecord::Swap(s) => s,
            StoredRecord::Unreadable(raw) => {
                if raw.get("wallet_id").and_then(|v| v.as_str()) == Some(wallet_id) {
                    eprintln!(
                        "[templarlib] {STORE_FILE}: a record of this wallet cannot be read; \
                         it is kept and left out of the list"
                    );
                }
                continue;
            }
        };
        if local.wallet_id != wallet_id {
            continue;
        }
        if !matches!(local.role.as_str(), "maker" | "taker") {
            eprintln!(
                "[templarlib] {STORE_FILE}: swap {} has an unknown role; left out of the list",
                local.offer_id
            );
            continue;
        }
        if let Some(other) = local.coordinator.as_deref().filter(|c| *c != coordinator) {
            out.push(not_live(
                state,
                local,
                OTHER_BOOK,
                format!(
                    "This swap lives on another order book ({}); join that test server to \
                     follow it.",
                    templar_core::endpoints::redact_userinfo(other)
                ),
            ));
            continue;
        }
        if let Some(why) = &unreachable {
            out.push(not_live(state, local, BOOK_UNREACHABLE, why.clone()));
            continue;
        }
        let not_here = |why: String| {
            if local.terms.is_some() {
                Some(not_live(state, local, NOT_ON_THIS_BOOK, why))
            } else {
                eprintln!(
                    "[templarlib] swap {} (stored without its terms) is not on the active \
                     order book; left out of the list",
                    local.offer_id
                );
                None
            }
        };
        match get_row(&format!("{coordinator}/{}", local.offer_id)) {
            Ok(row) => match is_ours(state, local, &row) {
                Ok(true) => out.push(enrich(
                    row,
                    wallet_id,
                    &local.role,
                    local.key_index,
                    local.coordinator.as_deref(),
                )),
                Ok(false) => out.extend(not_here(format!(
                    "The order book's swap {} is not this wallet's swap.",
                    local.offer_id
                ))),
                Err(why) => out.push(not_live(state, local, BOOK_MISMATCH, why)),
            },
            Err(RowFetch::NotFound) => out.extend(not_here(
                "The active order book does not know this swap.".to_string(),
            )),
            Err(RowFetch::Unreachable(e)) => {
                let why = format!("The order book could not be reached: {e}");
                unreachable = Some(why.clone());
                out.push(not_live(state, local, BOOK_UNREACHABLE, why));
            }
            Err(RowFetch::Failed(e)) => out.push(not_live(state, local, BOOK_UNREACHABLE, e)),
        }
    }
    Ok(out)
}

/// Whether the coordinator's `row` is the swap `local` records: `Ok(true)`
/// when it is (the accepted terms hold, or the row carries this wallet's
/// key), `Ok(false)` when the id belongs to another swap, `Err` when it is
/// this swap but contradicts the accepted terms.
fn is_ours(
    state: &AppState,
    local: &StoredAtomicSwap,
    row: &AtomicSwapRow,
) -> Result<bool, String> {
    if row.id != local.offer_id {
        return Ok(false);
    }
    match &local.terms {
        Some(terms) => {
            let own = if local.role == "maker" {
                row.state.maker_refund_pubkey == terms.maker_pubkey
            } else {
                row.state.taker_claim_pubkey == terms.taker_pubkey
            };
            if !own {
                return Ok(false);
            }
            check_row(row, terms).map(|()| true)
        }
        None => carries_own_key(state, local, row),
    }
}

/// A listed record whose row is not the coordinator's live one: built from
/// the terms the wallet stored (empty legs for a record without terms).
fn not_live(
    state: &AppState,
    local: &StoredAtomicSwap,
    availability: &str,
    note: String,
) -> MyAtomicSwap {
    let mut s = AtomicSwapState::default();
    if let Some(t) = &local.terms {
        let offered = leg_of(
            state,
            &t.offered_chain,
            &t.offered_asset_id,
            t.offered_amount_sats,
        );
        let wanted = leg_of(
            state,
            &t.wanted_chain,
            &t.wanted_asset_id,
            t.wanted_amount_sats,
        );
        s = AtomicSwapState::new(
            offered,
            wanted,
            t.payment_hash.clone(),
            t.maker_pubkey.clone(),
            String::new(),
        );
        s.maker_timeout = t.maker_timeout;
        s.taker_claim_pubkey = t.taker_pubkey.clone();
        s.taker_timeout = t.taker_timeout;
    }
    MyAtomicSwap {
        offer_id: local.offer_id,
        wallet_id: local.wallet_id.clone(),
        role: local.role.clone(),
        key_index: local.key_index,
        row: AtomicSwapRow {
            id: local.offer_id,
            network: NETWORK.to_string(),
            status: UNAVAILABLE.to_string(),
            state: s,
            created_at: 0,
            updated_at: 0,
        },
        next_action: "wait".to_string(),
        can_fund: false,
        can_claim: false,
        can_refund: false,
        availability: availability.to_string(),
        availability_note: Some(templar_core::http::printable(&note, 400)),
        coordinator: local
            .coordinator
            .as_deref()
            .map(templar_core::endpoints::redact_userinfo),
    }
}

/// A leg rebuilt from stored terms, named for display.
fn leg_of(state: &AppState, chain: &str, asset_id: &str, amount: u64) -> Leg {
    if chain == "bitcoin" {
        return Leg::btc(amount);
    }
    let info = state.asset_registry.resolve(asset_id);
    Leg {
        chain: chain.to_string(),
        asset_id: asset_id.to_string(),
        ticker: info.ticker,
        name: info.name,
        precision: info.precision,
        amount,
    }
}

/// Funds this wallet's side: the maker pays its contract on the offered
/// chain; the taker first checks the maker's funding on chain, then pays
/// its contract on the wanted chain. Both contracts are rebuilt from the
/// accepted terms; the coordinator's addresses are only compared.
pub fn fund(state: &AppState, p: IdParams) -> Result<MyAtomicSwap, String> {
    require_testnet_software(state, &p.wallet_id)?;
    let mut local = owned(state, &p.wallet_id, p.offer_id)?;
    let mut row = fetch(state, p.offer_id)?;
    let maker = local.role == "maker";
    if (maker && row.status != "reserved") || (!maker && row.status != "maker_funded") {
        return Err(format!(
            "{} cannot fund while swap is {}",
            local.role, row.status
        ));
    }
    let terms = accepted_terms(state, &mut local, &row)?;
    let maker_contract = terms.maker_contract()?;
    let taker_contract = terms.taker_contract()?;
    if !maker {
        verify_funding(
            state,
            &terms.offered_chain,
            &terms.offered_asset_id,
            terms.offered_amount_sats,
            &maker_contract.address,
            row.state
                .maker_funding_txid
                .as_deref()
                .ok_or("Maker funding txid missing")?,
            row.state
                .maker_funding_vout
                .ok_or("Maker funding vout missing")?,
        )?;
    }
    let (chain, asset, amount, address) = if maker {
        (
            &terms.offered_chain,
            &terms.offered_asset_id,
            terms.offered_amount_sats,
            &maker_contract.address,
        )
    } else {
        (
            &terms.wanted_chain,
            &terms.wanted_asset_id,
            terms.wanted_amount_sats,
            &taker_contract.address,
        )
    };
    let funded = fund_contract(state, chain, asset, amount, address)?;
    if maker {
        row.state.maker_funding_txid = Some(funded.txid);
        row.state.maker_funding_tx_hex = Some(funded.tx_hex);
        row.state.maker_funding_vout = Some(funded.vout);
        row = transition(state, &row, "maker_funded")?;
    } else {
        row.state.taker_funding_txid = Some(funded.txid);
        row.state.taker_funding_tx_hex = Some(funded.tx_hex);
        row.state.taker_funding_vout = Some(funded.vout);
        row = transition(state, &row, "taker_funded")?;
    }
    Ok(enrich(
        row,
        &p.wallet_id,
        &local.role,
        local.key_index,
        local.coordinator.as_deref(),
    ))
}

/// Claims the counterparty's contract with the preimage: the maker its
/// own (derived from its seed), the taker the one the maker revealed,
/// checked against the accepted hash.
pub fn claim(state: &AppState, p: IdParams) -> Result<MyAtomicSwap, String> {
    require_testnet_software(state, &p.wallet_id)?;
    let mut local = owned(state, &p.wallet_id, p.offer_id)?;
    let mut row = fetch(state, p.offer_id)?;
    let maker = local.role == "maker";
    if (maker && row.status != "taker_funded") || (!maker && row.status != "maker_claimed") {
        return Err(format!(
            "{} cannot claim while swap is {}",
            local.role, row.status
        ));
    }
    let terms = accepted_terms(state, &mut local, &row)?;
    let mnemonic = mnemonic(state, &p.wallet_id)?;
    let key = derive_swap_secret_key(mnemonic, if maker { 0 } else { 1 }, local.key_index)
        .map_err(|e| e.to_string())?;
    let preimage: [u8; 32] = if maker {
        deterministic_preimage(&key.secret_bytes())
    } else {
        let raw = row
            .state
            .preimage_hex
            .as_deref()
            .ok_or("Maker preimage is not published")?;
        let bytes = hex::decode(raw).map_err(|e| format!("Invalid preimage: {e}"))?;
        bytes
            .try_into()
            .map_err(|_| "Preimage must be 32 bytes".to_string())?
    };
    if sha256_hex(&preimage) != terms.payment_hash {
        return Err("The preimage does not match the swap's payment hash".into());
    }
    let (chain, asset, amount, txid, vout, c) = if maker {
        (
            &terms.wanted_chain,
            &terms.wanted_asset_id,
            terms.wanted_amount_sats,
            row.state.taker_funding_txid.clone(),
            row.state.taker_funding_vout,
            terms.taker_contract()?,
        )
    } else {
        (
            &terms.offered_chain,
            &terms.offered_asset_id,
            terms.offered_amount_sats,
            row.state.maker_funding_txid.clone(),
            row.state.maker_funding_vout,
            terms.maker_contract()?,
        )
    };
    let txid = txid.ok_or("Funding txid missing")?;
    let vout = vout.ok_or("Funding vout missing")?;
    verify_funding(state, chain, asset, amount, &c.address, &txid, vout)?;
    let spend_txid = spend_contract(
        state,
        SpendSpec {
            chain,
            asset,
            amount,
            funding_txid: &txid,
            funding_vout: vout,
            script_hex: &c.script_hex,
            terms: c.terms.clone(),
            preimage: Some(hex::encode(preimage)),
            key: key.secret_bytes(),
        },
    )?;
    if maker {
        row.state.preimage_hex = Some(hex::encode(preimage));
        row.state.maker_claim_txid = Some(spend_txid);
        row = transition(state, &row, "maker_claimed")?;
    } else {
        row.state.taker_claim_txid = Some(spend_txid);
        row = transition(state, &row, "completed")?;
    }
    Ok(enrich(
        row,
        &p.wallet_id,
        &local.role,
        local.key_index,
        local.coordinator.as_deref(),
    ))
}

/// Takes this wallet's own contract back after its timeout (from the
/// accepted terms, not the coordinator's).
pub fn refund(state: &AppState, p: IdParams) -> Result<MyAtomicSwap, String> {
    require_testnet_software(state, &p.wallet_id)?;
    let mut local = owned(state, &p.wallet_id, p.offer_id)?;
    let mut row = fetch(state, p.offer_id)?;
    let maker = local.role == "maker";
    let terms = accepted_terms(state, &mut local, &row)?;
    let timeout = if maker {
        terms.maker_timeout
    } else {
        terms.taker_timeout.ok_or("Taker timeout missing")?
    };
    if now_secs() < timeout {
        return Err(format!("Refund unlocks at Unix time {timeout}"));
    }
    let mnemonic = mnemonic(state, &p.wallet_id)?;
    let key = derive_swap_secret_key(mnemonic, if maker { 0 } else { 1 }, local.key_index)
        .map_err(|e| e.to_string())?;
    let (chain, asset, amount, txid, vout, c) = if maker {
        (
            &terms.offered_chain,
            &terms.offered_asset_id,
            terms.offered_amount_sats,
            row.state.maker_funding_txid.clone(),
            row.state.maker_funding_vout,
            terms.maker_contract()?,
        )
    } else {
        (
            &terms.wanted_chain,
            &terms.wanted_asset_id,
            terms.wanted_amount_sats,
            row.state.taker_funding_txid.clone(),
            row.state.taker_funding_vout,
            terms.taker_contract()?,
        )
    };
    let txid = txid.ok_or("Funding txid missing")?;
    let vout = vout.ok_or("Funding vout missing")?;
    verify_funding(state, chain, asset, amount, &c.address, &txid, vout)?;
    let refund_txid = spend_contract(
        state,
        SpendSpec {
            chain,
            asset,
            amount,
            funding_txid: &txid,
            funding_vout: vout,
            script_hex: &c.script_hex,
            terms: c.terms.clone(),
            preimage: None,
            key: key.secret_bytes(),
        },
    )?;
    let next = if maker {
        row.state.maker_refund_txid = Some(refund_txid);
        "maker_refunded"
    } else {
        row.state.taker_refund_txid = Some(refund_txid);
        "taker_refunded"
    };
    row = transition(state, &row, next)?;
    Ok(enrich(
        row,
        &p.wallet_id,
        &local.role,
        local.key_index,
        local.coordinator.as_deref(),
    ))
}

#[derive(Clone)]
struct Leg {
    chain: String,
    asset_id: String,
    ticker: String,
    name: String,
    precision: u8,
    amount: u64,
}
impl Leg {
    fn btc(amount: u64) -> Self {
        Self {
            chain: "bitcoin".into(),
            asset_id: "btc-testnet".into(),
            ticker: "BTC".into(),
            name: "Bitcoin Testnet".into(),
            precision: 8,
            amount,
        }
    }
}

impl AtomicSwapState {
    fn new(
        offered: Leg,
        wanted: Leg,
        payment_hash: String,
        maker_key: String,
        note: String,
    ) -> Self {
        Self {
            offered_chain: offered.chain,
            offered_asset_id: offered.asset_id,
            offered_ticker: offered.ticker,
            offered_name: offered.name,
            offered_precision: offered.precision,
            offered_amount_sats: offered.amount,
            wanted_chain: wanted.chain,
            wanted_asset_id: wanted.asset_id,
            wanted_ticker: wanted.ticker,
            wanted_name: wanted.name,
            wanted_precision: wanted.precision,
            wanted_amount_sats: wanted.amount,
            payment_hash,
            maker_refund_pubkey: maker_key,
            taker_claim_pubkey: None,
            maker_timeout: now_secs() + MAKER_TIMEOUT_SECS,
            taker_timeout: None,
            maker_contract_address: None,
            maker_contract_script: None,
            taker_contract_address: None,
            taker_contract_script: None,
            maker_funding_txid: None,
            maker_funding_tx_hex: None,
            maker_funding_vout: None,
            taker_funding_txid: None,
            taker_funding_tx_hex: None,
            taker_funding_vout: None,
            preimage_hex: None,
            maker_claim_txid: None,
            taker_claim_txid: None,
            maker_refund_txid: None,
            taker_refund_txid: None,
            note,
        }
    }
}

struct Funded {
    txid: String,
    tx_hex: String,
    vout: u32,
}

fn fund_contract(
    state: &AppState,
    chain: &str,
    asset: &str,
    amount: u64,
    address: &str,
) -> Result<Funded, String> {
    if chain == "bitcoin" {
        let wallet = state.bitcoin.as_ref().ok_or("Bitcoin wallet not open")?;
        let mut psbt = wallet
            .create_tx(address, amount, DEFAULT_BTC_FEE_RATE, None, None)
            .map_err(|e| e.to_string())?;
        if !wallet.sign(&mut psbt).map_err(|e| e.to_string())? {
            return Err("Bitcoin funding PSBT did not finalize".into());
        }
        let tx = psbt.extract_tx();
        let target = BitcoinAddress::from_str(address)
            .map_err(|e| e.to_string())?
            .require_network(BitcoinNetwork::Testnet)
            .map_err(|e| e.to_string())?
            .script_pubkey();
        let vout = tx
            .output
            .iter()
            .position(|o| o.value == amount && o.script_pubkey == target)
            .ok_or("Bitcoin funding output missing from signed transaction")?
            as u32;
        let tx_hex = hex::encode(serialize_bitcoin(&tx));
        let txid = wallet.broadcast(tx).map_err(|e| e.to_string())?.to_string();
        Ok(Funded { txid, tx_hex, vout })
    } else {
        use lwk_wollet::elements::{encode::serialize_hex, Address, AssetId};
        let wallet = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
        let mut pset = wallet
            .create_tx(address, amount, asset)
            .map_err(|e| e.to_string())?;
        wallet.sign(&mut pset).map_err(|e| e.to_string())?;
        let tx = wallet.finalize(&mut pset).map_err(|e| e.to_string())?;
        let target = Address::parse_with_params(address, state.liquid_network.address_params())
            .map_err(|e| e.to_string())?
            .script_pubkey();
        let asset_id = AssetId::from_str(asset).map_err(|e| e.to_string())?;
        let vout = tx
            .output
            .iter()
            .position(|o| {
                o.script_pubkey == target
                    && o.value.explicit() == Some(amount)
                    && o.asset.explicit() == Some(asset_id)
            })
            .ok_or("Liquid explicit HTLC output missing from signed transaction")?
            as u32;
        let tx_hex = serialize_hex(&tx);
        let txid =
            templar_core::liquid::liquidex::broadcast_transaction_on(&tx, &state.liquid_network)
                .map_err(|e| e.to_string())?;
        Ok(Funded { txid, tx_hex, vout })
    }
}

fn verify_funding(
    state: &AppState,
    chain: &str,
    asset: &str,
    amount: u64,
    address: &str,
    txid: &str,
    vout: u32,
) -> Result<(), String> {
    if chain == "bitcoin" {
        let wallet = state.bitcoin.as_ref().ok_or("Bitcoin wallet not open")?;
        let parsed = txid.parse().map_err(|e| format!("Funding txid: {e}"))?;
        let tx = wallet
            .fetch_transaction(&parsed)
            .map_err(|e| e.to_string())?
            .ok_or("Maker Bitcoin funding transaction is not visible on Electrum yet")?;
        if tx.txid().to_string() != txid {
            return Err("Bitcoin funding txid mismatch".into());
        }
        let target = BitcoinAddress::from_str(address)
            .map_err(|e| e.to_string())?
            .require_network(BitcoinNetwork::Testnet)
            .map_err(|e| e.to_string())?
            .script_pubkey();
        let output = tx
            .output
            .get(vout as usize)
            .ok_or("Bitcoin funding vout missing")?;
        if output.value != amount || output.script_pubkey != target {
            return Err("Bitcoin funding output does not match the signed swap terms".into());
        }
    } else {
        use lwk_wollet::elements::{Address, AssetId, Txid};
        let wallet = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
        let parsed = Txid::from_str(txid).map_err(|e| format!("Funding txid: {e}"))?;
        let tx = wallet
            .chain()
            .map_err(|e| e.to_string())?
            .fetch_transaction(&parsed)
            .map_err(|e| e.to_string())?
            .ok_or("Maker Liquid funding transaction is not visible yet")?;
        let target = Address::parse_with_params(address, state.liquid_network.address_params())
            .map_err(|e| e.to_string())?
            .script_pubkey();
        let asset_id = AssetId::from_str(asset).map_err(|e| e.to_string())?;
        let output = tx
            .output
            .get(vout as usize)
            .ok_or("Liquid funding vout missing")?;
        if output.script_pubkey != target
            || output.value.explicit() != Some(amount)
            || output.asset.explicit() != Some(asset_id)
        {
            return Err("Liquid funding output does not match the signed swap terms".into());
        }
    }
    Ok(())
}

struct SpendSpec<'a> {
    chain: &'a str,
    asset: &'a str,
    amount: u64,
    funding_txid: &'a str,
    funding_vout: u32,
    script_hex: &'a str,
    terms: HtlcTerms,
    preimage: Option<String>,
    key: [u8; 32],
}

fn spend_contract(state: &AppState, s: SpendSpec<'_>) -> Result<String, String> {
    let rebuilt = templar_core::htlc_script(&s.terms).map_err(|e| e.to_string())?;
    if hex::encode(rebuilt.as_bytes()) != s.script_hex {
        return Err("HTLC script does not match swap state".into());
    }
    if s.chain == "bitcoin" {
        let wallet = state.bitcoin.as_ref().ok_or("Bitcoin wallet not open")?;
        let destination = wallet
            .get_fresh_address()
            .map_err(|e| e.to_string())?
            .address
            .to_string();
        let secret =
            bdk::bitcoin::secp256k1::SecretKey::from_slice(&s.key).map_err(|e| e.to_string())?;
        let tx = spend_bitcoin_htlc(
            &BitcoinSpendRequest {
                funding_txid: s.funding_txid.into(),
                funding_vout: s.funding_vout,
                amount_sats: s.amount,
                destination,
                terms: s.terms,
                preimage_hex: s.preimage,
                fee_sats: CLAIM_FEE_SATS,
            },
            &secret,
        )
        .map_err(|e| e.to_string())?;
        wallet
            .broadcast(tx)
            .map(|t| t.to_string())
            .map_err(|e| e.to_string())
    } else {
        let wallet = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
        let tx = spend_liquid_htlc(
            wallet,
            &LiquidHtlcSpendRequest {
                funding_txid: s.funding_txid.into(),
                funding_vout: s.funding_vout,
                asset_id: s.asset.into(),
                amount_sats: s.amount,
                script_hex: s.script_hex.into(),
                payment_hash: s.terms.payment_hash.clone(),
                timeout: s.terms.timeout,
                preimage_hex: s.preimage,
                fee_sats: CLAIM_FEE_SATS,
            },
            &s.key,
        )
        .map_err(|e| e.to_string())?;
        templar_core::liquid::liquidex::broadcast_transaction_on(&tx, &state.liquid_network)
            .map_err(|e| e.to_string())
    }
}

fn contract(chain: &str, terms: HtlcTerms) -> Result<templar_core::HtlcContract, String> {
    match chain {
        "bitcoin" => bitcoin_contract(terms),
        "liquid" => liquid_contract(terms),
        _ => return Err("Unknown chain".into()),
    }
    .map_err(|e| e.to_string())
}

fn require_testnet_software(state: &AppState, wallet_id: &str) -> Result<(), String> {
    if state.liquid_network.name() != NETWORK {
        return Err("Cross-chain swaps v1 require Liquid testnet".into());
    }
    let entry = state.registry.find(wallet_id).ok_or("Wallet not found")?;
    if !matches!(entry.profile, WalletProfile::Software { .. }) {
        return Err("Cross-chain swaps v1 currently require a software wallet".into());
    }
    if state.bitcoin.is_none() || state.liquid.is_none() {
        return Err("Open a wallet with both Bitcoin and Liquid enabled".into());
    }
    Ok(())
}

fn mnemonic<'a>(state: &'a AppState, wallet_id: &str) -> Result<&'a str, String> {
    match &state
        .registry
        .find(wallet_id)
        .ok_or("Wallet not found")?
        .profile
    {
        WalletProfile::Software { mnemonic } => Ok(mnemonic),
        _ => Err("Software wallet required".into()),
    }
}

/// This wallet's record of swap `offer_id`: the one on the active
/// coordinator first, else one written before coordinators were kept, else
/// one of another coordinator (which [`accepted_terms`] then refuses).
fn owned(state: &AppState, wallet_id: &str, offer_id: u64) -> Result<StoredAtomicSwap, String> {
    let coordinator = api(state);
    let store = load_store(state)?;
    let mut mine: Vec<&StoredAtomicSwap> = store
        .readable()
        .filter(|s| s.wallet_id == wallet_id && s.offer_id == offer_id)
        .collect();
    mine.sort_by_key(|s| match s.coordinator.as_deref() {
        Some(c) if c == coordinator => 0,
        None => 1,
        Some(_) => 2,
    });
    mine.first()
        .map(|s| (*s).clone())
        .ok_or_else(|| "This wallet is not a participant in the swap".into())
}

fn enrich(
    row: AtomicSwapRow,
    wallet_id: &str,
    role: &str,
    key_index: u32,
    coordinator: Option<&str>,
) -> MyAtomicSwap {
    let now = now_secs();
    let can_fund = (role == "maker" && row.status == "reserved")
        || (role == "taker" && row.status == "maker_funded");
    let can_claim = (role == "maker" && row.status == "taker_funded")
        || (role == "taker" && row.status == "maker_claimed");
    let timeout = if role == "maker" {
        Some(row.state.maker_timeout)
    } else {
        row.state.taker_timeout
    };
    let funded = if role == "maker" {
        row.state.maker_funding_txid.is_some()
    } else {
        row.state.taker_funding_txid.is_some()
    };
    let can_refund = funded
        && timeout.is_some_and(|t| now >= t)
        && !matches!(
            row.status.as_str(),
            "completed" | "maker_refunded" | "taker_refunded"
        );
    let next_action = if can_fund {
        "fund"
    } else if can_claim {
        "claim"
    } else if can_refund {
        "refund"
    } else {
        "wait"
    }
    .to_string();
    MyAtomicSwap {
        offer_id: row.id,
        wallet_id: wallet_id.into(),
        role: role.into(),
        key_index,
        row,
        next_action,
        can_fund,
        can_claim,
        can_refund,
        availability: LIVE.to_string(),
        availability_note: None,
        coordinator: coordinator.map(templar_core::endpoints::redact_userinfo),
    }
}

/// The HTLC coordinator on the active order book (`AppState::endpoints`).
fn api(state: &AppState) -> String {
    state.endpoints().atomic_swaps_url().value
}
fn transition(
    state: &AppState,
    row: &AtomicSwapRow,
    status: &str,
) -> Result<AtomicSwapRow, String> {
    put_json(
        &format!("{}/{}", api(state), row.id),
        &serde_json::json!({ "status": status, "state": row.state }),
    )
}
fn fetch(state: &AppState, id: u64) -> Result<AtomicSwapRow, String> {
    get_json(&format!("{}/{id}", api(state)))
}

/// Largest coordinator answer read (a swap row with two funding
/// transactions is a few kB).
const MAX_COORDINATOR_BYTES: u64 = 1024 * 1024;

fn client() -> Result<reqwest::blocking::Client, String> {
    templar_core::http::client(std::time::Duration::from_secs(15))
}
/// Sends a coordinator request through `templar_core::http` (no redirects,
/// bounded body, no URL or unbounded body in errors) and decodes the JSON.
fn response<T: for<'de> Deserialize<'de>>(
    request: reqwest::blocking::RequestBuilder,
) -> Result<T, String> {
    let answer = templar_core::http::send(request, MAX_COORDINATOR_BYTES)
        .map_err(|e| format!("Order book: {e}"))?;
    if !answer.status.is_success() {
        return Err(format!(
            "Order book HTTP {}: {}",
            answer.status.as_u16(),
            templar_core::http::excerpt(&answer.body)
        ));
    }
    serde_json::from_str(&answer.body).map_err(|e| format!("Order book response: {e}"))
}
fn get_json<T: for<'de> Deserialize<'de>>(url: &str) -> Result<T, String> {
    response(client()?.get(url))
}

/// Why a row could not be listed.
enum RowFetch {
    /// HTTP 404: the coordinator does not know the swap.
    NotFound,
    /// No answer (connection, timeout, redirect, oversize body).
    Unreachable(String),
    /// An answer that is neither the row nor a 404.
    Failed(String),
}

/// Whole-request bound of one row read while listing: the list holds the
/// engine for every row it reads, so it is shorter than a step's.
const LIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Reads one coordinator row for the list, telling a 404 apart.
fn get_row(url: &str) -> Result<AtomicSwapRow, RowFetch> {
    let client = templar_core::http::client(LIST_TIMEOUT).map_err(RowFetch::Unreachable)?;
    let answer = templar_core::http::send(client.get(url), MAX_COORDINATOR_BYTES)
        .map_err(RowFetch::Unreachable)?;
    match answer.status.as_u16() {
        200..=299 => serde_json::from_str(&answer.body).map_err(|e| {
            RowFetch::Failed(format!(
                "The order book's answer could not be read: {}",
                templar_core::http::printable(&e.to_string(), 160)
            ))
        }),
        404 => Err(RowFetch::NotFound),
        status => Err(RowFetch::Failed(format!(
            "The order book answered HTTP {status}: {}",
            templar_core::http::excerpt(&answer.body)
        ))),
    }
}
fn post_json<T: for<'de> Deserialize<'de>>(
    url: &str,
    body: &serde_json::Value,
) -> Result<T, String> {
    response(client()?.post(url).json(body))
}
fn put_json<T: for<'de> Deserialize<'de>>(
    url: &str,
    body: &serde_json::Value,
) -> Result<T, String> {
    response(client()?.put(url).json(body))
}

fn store_path(state: &AppState) -> std::path::PathBuf {
    state.data_dir.join(STORE_FILE)
}
fn load_store(state: &AppState) -> Result<AtomicStore, String> {
    let path = store_path(state);
    if !path.exists() {
        return Ok(AtomicStore::default());
    }
    serde_json::from_str(&fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{STORE_FILE}: {e}"))
}
fn save_store(state: &AppState, store: &AtomicStore) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(store).map_err(|e| e.to_string())?;
    templar_core::registry::atomic_write(&store_path(state), &raw).map_err(|e| e.to_string())
}
/// The next unused swap key index of a wallet. Records this engine cannot
/// read count too when they show a key index (and do not name another
/// wallet): reusing a key would reuse a maker's preimage.
fn next_index(store: &AtomicStore, wallet_id: &str) -> u32 {
    store
        .swaps
        .iter()
        .filter_map(|r| match r {
            StoredRecord::Swap(s) => (s.wallet_id == wallet_id).then_some(s.key_index),
            StoredRecord::Unreadable(raw) => {
                let other = raw
                    .get("wallet_id")
                    .and_then(|v| v.as_str())
                    .is_some_and(|w| w != wallet_id);
                (!other)
                    .then(|| raw.get("key_index").and_then(|v| v.as_u64()))
                    .flatten()
                    .map(|i| u32::try_from(i).unwrap_or(u32::MAX))
            }
        })
        .max()
        .map_or(0, |i| i.saturating_add(1))
}
fn deterministic_preimage(key: &[u8; 32]) -> [u8; 32] {
    use bdk::bitcoin::hashes::{sha256, Hash, HashEngine};
    let mut e = sha256::Hash::engine();
    e.input(b"Templar atomic swap preimage v1");
    e.input(key);
    sha256::Hash::from_engine(e).to_byte_array()
}
fn sha256_hex(data: &[u8]) -> String {
    use bdk::bitcoin::hashes::{sha256, Hash};
    sha256::Hash::hash(data).to_string()
}
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http::{closed_port_url, MockHttp, Reply};

    #[test]
    fn deterministic_secret_is_stable_and_domain_separated() {
        let key = [7u8; 32];
        assert_eq!(deterministic_preimage(&key), deterministic_preimage(&key));
        assert_ne!(deterministic_preimage(&key), key);
        assert_eq!(sha256_hex(&deterministic_preimage(&key)).len(), 64);
    }

    /// The record found on the owner's machine: written by an older engine
    /// against a local order book whose database no longer exists.
    const LEGACY: &str =
        r#"{"swaps":[{"key_index":0,"offer_id":1,"role":"maker","wallet_id":"w1"}]}"#;

    fn test_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "templar_xswap_{}_{}_{}",
            tag,
            std::process::id(),
            now_secs()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        AppState::new_for_test(dir)
    }

    fn store_text(state: &AppState) -> String {
        fs::read_to_string(store_path(state)).unwrap()
    }

    /// A public key for test terms (any valid point).
    fn pubkey(seed: u8) -> String {
        let secret = bdk::bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        swap_public_key(&secret).to_string()
    }

    fn terms(maker_seed: u8, amount: u64) -> AcceptedTerms {
        AcceptedTerms {
            offered_chain: "bitcoin".into(),
            offered_asset_id: "btc-testnet".into(),
            offered_amount_sats: amount,
            wanted_chain: "liquid".into(),
            wanted_asset_id: templar_core::TESTNET_POLICY_ASSET.into(),
            wanted_amount_sats: 40_000,
            payment_hash: "ab".repeat(32),
            maker_pubkey: pubkey(maker_seed),
            maker_timeout: 4_000_000_000,
            taker_pubkey: None,
            taker_timeout: None,
        }
    }

    /// The coordinator's row of `t` (as created, not yet joined).
    fn row_of(id: u64, t: &AcceptedTerms) -> serde_json::Value {
        serde_json::json!({
            "id": id, "network": NETWORK, "status": "open", "created_at": 5, "updated_at": 6,
            "state": {
                "offered_chain": t.offered_chain, "offered_asset_id": t.offered_asset_id,
                "offered_ticker": "BTC", "offered_name": "Bitcoin Testnet",
                "offered_precision": 8, "offered_amount_sats": t.offered_amount_sats,
                "wanted_chain": t.wanted_chain, "wanted_asset_id": t.wanted_asset_id,
                "wanted_ticker": "LBTC", "wanted_name": "Liquid Bitcoin",
                "wanted_precision": 8, "wanted_amount_sats": t.wanted_amount_sats,
                "payment_hash": t.payment_hash, "maker_refund_pubkey": t.maker_pubkey,
                "taker_claim_pubkey": null, "maker_timeout": t.maker_timeout,
                "taker_timeout": null, "maker_contract_address": null,
                "maker_contract_script": null, "taker_contract_address": null,
                "taker_contract_script": null, "maker_funding_txid": null,
                "maker_funding_tx_hex": null, "maker_funding_vout": null,
                "taker_funding_txid": null, "taker_funding_tx_hex": null,
                "taker_funding_vout": null, "preimage_hex": null, "maker_claim_txid": null,
                "taker_claim_txid": null, "maker_refund_txid": null, "taker_refund_txid": null,
                "note": ""
            }
        })
    }

    fn record(id: u64, coordinator: Option<&str>, t: Option<AcceptedTerms>) -> StoredRecord {
        StoredRecord::Swap(Box::new(StoredAtomicSwap {
            offer_id: id,
            wallet_id: "w1".into(),
            role: "maker".into(),
            key_index: id as u32,
            coordinator: coordinator.map(str::to_string),
            terms: t,
        }))
    }

    #[test]
    fn the_legacy_record_on_regtest_lists_nothing_and_contacts_nobody() {
        let mut state = test_state("legacy_regtest");
        state.liquid_network = templar_core::LiquidNetwork::regtest_default();
        fs::write(store_path(&state), LEGACY).unwrap();
        let listed = list_mine(&state, "w1").unwrap();
        assert!(listed.is_empty());
        assert_eq!(store_text(&state), LEGACY, "the record is never touched");
        // Even a store this engine cannot parse at all does not matter there.
        fs::write(store_path(&state), "{ not json").unwrap();
        assert!(list_mine(&state, "w1").unwrap().is_empty());
    }

    #[test]
    fn the_legacy_record_unknown_to_the_book_is_left_out_and_kept() {
        let state = test_state("legacy_404");
        fs::write(store_path(&state), LEGACY).unwrap();
        let book = MockHttp::start(|_| Reply::json(404, r#"{"error":"Unknown atomic swap: 1"}"#));
        let coordinator = format!("{}/api/atomic-swaps", book.url);
        let listed = list_against(&state, "w1", &coordinator).unwrap();
        // No terms, unknown to the book: nothing the wallet could act on.
        assert!(listed.is_empty(), "{listed:?}");
        assert_eq!(book.requests()[0].target, "/api/atomic-swaps/1");
        assert_eq!(store_text(&state), LEGACY, "never deleted or rewritten");
    }

    #[test]
    fn an_unreachable_book_lists_every_record_once_tried() {
        let state = test_state("unreachable");
        let store = AtomicStore {
            swaps: vec![
                record(1, None, None),
                record(2, None, Some(terms(2, 10_000))),
            ],
        };
        save_store(&state, &store).unwrap();
        let before = store_text(&state);
        let coordinator = format!("{}/api/atomic-swaps", closed_port_url());
        let listed = list_against(&state, "w1", &coordinator).unwrap();
        assert_eq!(listed.len(), 2, "both kept: either may be live");
        for row in &listed {
            assert_eq!(row.availability, BOOK_UNREACHABLE);
            assert_eq!(row.row.status, UNAVAILABLE);
            assert_eq!(row.next_action, "wait");
            assert!(!row.can_fund && !row.can_claim && !row.can_refund);
            assert!(row
                .availability_note
                .as_deref()
                .unwrap()
                .contains("reached"));
        }
        // The record with terms shows what it is.
        assert_eq!(listed[1].row.state.offered_amount_sats, 10_000);
        assert_eq!(listed[1].row.state.offered_ticker, "BTC");
        assert_eq!(listed[1].row.state.wanted_ticker, "LBTC");
        assert_eq!(store_text(&state), before);
    }

    #[test]
    fn a_mixed_list_keeps_the_live_rows_and_explains_the_others() {
        let state = test_state("mixed");
        let live = terms(3, 30_000);
        let moved = terms(4, 40_000);
        let lied = terms(5, 50_000);
        let someone_else = terms(6, 60_000);
        let book = {
            let live = live.clone();
            let lied_row = {
                let mut t = lied.clone();
                t.offered_amount_sats = 5_000_000;
                row_of(5, &t)
            };
            MockHttp::start(move |r| match r.target.as_str() {
                "/api/atomic-swaps/3" => Reply::json(200, row_of(3, &live).to_string()),
                "/api/atomic-swaps/5" => Reply::json(200, lied_row.to_string()),
                "/api/atomic-swaps/6" => Reply::json(200, row_of(6, &terms(9, 1)).to_string()),
                "/api/atomic-swaps/7" => Reply::json(500, "boom"),
                _ => Reply::json(404, r#"{"error":"Unknown atomic swap"}"#),
            })
        };
        let coordinator = format!("{}/api/atomic-swaps", book.url);
        let unreadable: serde_json::Value =
            serde_json::json!({"wallet_id": "w1", "offer_id": 8, "role": "maker"});
        let store = AtomicStore {
            swaps: vec![
                record(1, None, None), // legacy, 404: left out
                record(
                    2,
                    Some("http://elsewhere:1/api/atomic-swaps"),
                    Some(moved.clone()),
                ),
                record(3, Some(&coordinator), Some(live.clone())), // live
                record(4, Some(&coordinator), Some(moved)),        // 404 with terms
                record(5, Some(&coordinator), Some(lied)),         // contradicts the terms
                record(6, Some(&coordinator), Some(someone_else)), // another swap at id 6
                record(7, Some(&coordinator), Some(terms(7, 7))),  // HTTP 500
                StoredRecord::Unreadable(unreadable),
            ],
        };
        save_store(&state, &store).unwrap();
        let before = store_text(&state);
        let listed = list_against(&state, "w1", &coordinator).unwrap();
        let got: Vec<(u64, &str)> = listed
            .iter()
            .map(|s| (s.offer_id, s.availability.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (2, OTHER_BOOK),
                (3, LIVE),
                (4, NOT_ON_THIS_BOOK),
                (5, BOOK_MISMATCH),
                (6, NOT_ON_THIS_BOOK),
                (7, BOOK_UNREACHABLE),
            ]
        );
        let live_row = &listed[1];
        assert_eq!(live_row.row.status, "open");
        assert_eq!(live_row.row.created_at, 5);
        assert!(live_row.availability_note.is_none());
        assert_eq!(live_row.coordinator.as_deref(), Some(coordinator.as_str()));
        assert!(listed[0]
            .availability_note
            .as_deref()
            .unwrap()
            .contains("elsewhere"));
        assert!(listed[3]
            .availability_note
            .as_deref()
            .unwrap()
            .contains("offered amount"));
        // The other coordinator was not contacted; nothing was written.
        let asked: Vec<String> = book.requests().into_iter().map(|r| r.target).collect();
        assert!(!asked.iter().any(|t| t.ends_with("/2")), "{asked:?}");
        assert_eq!(store_text(&state), before);
        // The unreadable record still reserves its key index? It has none:
        // the next key follows the readable records.
        assert_eq!(next_index(&load_store(&state).unwrap(), "w1"), 8);
    }

    #[test]
    fn unreadable_records_round_trip_and_keep_their_key_index() {
        let state = test_state("unreadable");
        let raw = r#"{"swaps":[{"wallet_id":"w1","offer_id":"nine","key_index":12},{"key_index":0,"offer_id":1,"role":"maker","wallet_id":"w1"}]}"#;
        fs::write(store_path(&state), raw).unwrap();
        let store = load_store(&state).unwrap();
        assert!(matches!(store.swaps[0], StoredRecord::Unreadable(_)));
        assert_eq!(
            next_index(&store, "w1"),
            13,
            "an unread key index is not reused"
        );
        assert_eq!(next_index(&store, "w2"), 0);
        // Writing the store back keeps the unreadable record as it was.
        save_local(
            &state,
            &StoredAtomicSwap {
                offer_id: 1,
                wallet_id: "w1".into(),
                role: "maker".into(),
                key_index: 0,
                coordinator: Some("http://book/api/atomic-swaps".into()),
                terms: None,
            },
            None,
        )
        .unwrap();
        let back: serde_json::Value = serde_json::from_str(&store_text(&state)).unwrap();
        assert_eq!(back["swaps"][0]["offer_id"], "nine");
        assert_eq!(
            back["swaps"].as_array().unwrap().len(),
            2,
            "replaced, not added"
        );
        assert_eq!(
            back["swaps"][1]["coordinator"],
            "http://book/api/atomic-swaps"
        );
    }

    #[test]
    fn a_record_is_saved_over_its_own_coordinators_copy_only() {
        let state = test_state("scoped_save");
        let store = AtomicStore {
            swaps: vec![
                record(1, Some("http://a/api/atomic-swaps"), Some(terms(1, 1))),
                record(1, None, None),
            ],
        };
        save_store(&state, &store).unwrap();
        let mut adopted = match &store.swaps[1] {
            StoredRecord::Swap(s) => (**s).clone(),
            _ => unreachable!(),
        };
        adopted.coordinator = Some("http://b/api/atomic-swaps".into());
        save_local(&state, &adopted, None).unwrap();
        let back = load_store(&state).unwrap();
        let coordinators: Vec<Option<String>> =
            back.readable().map(|s| s.coordinator.clone()).collect();
        assert_eq!(
            coordinators,
            vec![
                Some("http://a/api/atomic-swaps".to_string()),
                Some("http://b/api/atomic-swaps".to_string())
            ]
        );
    }
}
