//! The native provider: the Elements peg of a Templar test server's regtest
//! (`templar-testlab/docs/api-config.md`).
//!
//! **Peg-in.** `peg_start` reads the federation from the Liquid chain
//! (the full dynafed header of the current epoch) and derives a Bitcoin
//! address bound to one of this wallet's claim scripts; the order keeps the
//! derivation index, the epoch height and the federation script, so the
//! very same address can be rebuilt at claim time. The address is only
//! guaranteed valid through a Liquid height: once past it, a status check
//! renews it while the federation is unchanged and expires the order if it
//! changed — nobody is shown an expired address. The deposit is followed on
//! the wallet's Bitcoin Electrum server. `peg_claim` (never a status check)
//! fetches the raw deposit and its merkle proof from the lab's Esplora,
//! verifies them against the wallet's own chain view
//! ([`core_peg::verify_pegin_evidence`]), builds the claim with LWK's
//! `add_pegin_input`, signs it with the wallet's software signer (the
//! Liquid signing guard runs) and broadcasts it.
//!
//! **Peg-out.** `peg_fund` builds a Liquid transaction with one explicit
//! L-BTC output whose script is `OP_RETURN <Bitcoin genesis> <Bitcoin
//! scriptPubKey>` (an ordinary LWK recipient without a blinding key, as a
//! burn is), the wallet's change and one fee output; signs it with the
//! software signer and broadcasts it. The lab's federation pays the same
//! amount on Bitcoin after its confirmations; the order completes when that
//! payment confirms at the payout address.
//!
//! Every signed transaction is written to the order before its broadcast,
//! and a retry rebroadcasts those bytes — a lost answer never pays twice.

use std::str::FromStr;

use lwk_wollet::elements::{self, bitcoin, encode};
use serde::{Deserialize, Serialize};
use templar_core::peg::{self as core_peg, BitcoinChainView, DepositFacts};
use templar_core::{CoinChain, NativePegTerms, PegError, PegProvider, WalletProfile};

use super::{
    now_secs, persist, set_status, PegDepositDto, PegOrderDto, PegQuoteDto, PegStatusEntryDto,
    StoredOrder, AWAITING_DEPOSIT, CLAIMABLE, COMPLETED, CONFIRMING, DEPOSIT_SEEN, EXPIRED,
    SETTLING,
};
use crate::state::AppState;

/// Liquid fee of a peg-in claim at LWK's default rate (0.1 sat/vB): one
/// explicit peg-in input carrying the deposit transaction and its merkle
/// proof, one confidential output, the fee. Measured on the testlab: 31
/// sats; the margin covers a larger deposit transaction or proof.
pub(super) const CLAIM_FEE_ESTIMATE_SATS: u64 = 35;
/// Liquid fee of a peg-out at LWK's default rate: the explicit peg-out
/// output, confidential change, the fee. Measured on the testlab with one
/// input: 30 sats; the margin covers a second input.
pub(super) const PEGOUT_FEE_ESTIMATE_SATS: u64 = 35;
/// Nominal block intervals the ETA is derived from (the lab mines on
/// demand; its chains have no fixed interval).
const BITCOIN_BLOCK_MINUTES: u32 = 10;
const LIQUID_BLOCK_MINUTES: u32 = 1;
/// Fee rate of a peg-in deposit the wallet pays itself, unless given.
const DEFAULT_DEPOSIT_FEE_RATE: f32 = 1.0;

/// What the native provider keeps beside the DTO. Nothing secret: the
/// claim script is a public scriptPubKey and its index a derivation step.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct NativeState {
    /// The test server the order belongs to, and its chain instance.
    pub lab_url: String,
    pub instance_id: String,
    // ── peg-in ──
    #[serde(default)]
    pub claim_index: Option<u32>,
    #[serde(default)]
    pub claim_script_hex: Option<String>,
    /// The epoch-boundary height whose dynafed header carried the
    /// federation the address was derived from.
    #[serde(default)]
    pub fedpeg_height: Option<u32>,
    #[serde(default)]
    pub fedpeg_script_hex: Option<String>,
    #[serde(default)]
    pub fedpeg_program_hex: Option<String>,
    // ── peg-out ──
    /// The Bitcoin scriptPubKey the federation pays.
    #[serde(default)]
    pub payout_script_hex: Option<String>,
    /// The peg-out output's script.
    #[serde(default)]
    pub pegout_script_hex: Option<String>,
    /// A script of the peg-out transaction's change, to find it on Electrum.
    #[serde(default)]
    pub watch_script_hex: Option<String>,
    /// Transactions the payout address had before the peg-out: none of
    /// them is the federation's payment.
    #[serde(default)]
    pub payout_known_txids: Vec<String>,
    // ── signed, written before their broadcast ──
    #[serde(default)]
    pub pending_deposit_tx: Option<String>,
    /// Orders written before per-deposit claims: their one claim. Moved
    /// onto the order's deposit at the next status check.
    #[serde(default)]
    pub pending_claim_tx: Option<String>,
    // ── peg-in deposits ──
    /// Every output that paid the deposit address.
    #[serde(default)]
    pub deposits: Vec<StoredDeposit>,
    /// The deposit the order follows (`txid:vout`): the one this wallet
    /// paid, else the first that carried at least the expected amount.
    #[serde(default)]
    pub primary: Option<String>,
}

/// Most deposits followed per order: a flood of dust to the address must
/// not make every status check fetch thousands of transactions.
const MAX_DEPOSITS: usize = 64;

/// One output paying a peg-in's deposit address, and its claim.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct StoredDeposit {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    /// Bitcoin confirmation height; `None` in the mempool.
    #[serde(default)]
    pub height: Option<u32>,
    /// Why this wallet cannot claim it; `None` = it can.
    #[serde(default)]
    pub unclaimable: Option<String>,
    #[serde(default)]
    pub claim_txid: Option<String>,
    /// The signed claim, kept until it is in a block and rebroadcast as is
    /// on a retry.
    #[serde(default)]
    pub pending_claim_tx: Option<String>,
    /// The Bitcoin block the claim's merkle proof is anchored in.
    #[serde(default)]
    pub claim_block: Option<String>,
    /// Liquid confirmations of the claim; `None` = not seen.
    #[serde(default)]
    pub claim_confirmations: Option<u32>,
}

impl StoredDeposit {
    fn outpoint(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }

    fn confirmations(&self, tip: u32) -> u32 {
        self.height
            .map(|h| tip.saturating_sub(h).saturating_add(1))
            .unwrap_or(0)
    }

    fn claimed(&self) -> bool {
        self.claim_confirmations.is_some_and(|c| c >= 1)
    }

    /// This deposit's status (see `PegDepositDto::status`).
    fn status(&self, tip: u32, required: u32) -> &'static str {
        if self.unclaimable.is_some() {
            return UNCLAIMABLE;
        }
        if self.claimed() {
            return COMPLETED;
        }
        if self.claim_txid.is_some() {
            return SETTLING;
        }
        pegin_status(self.confirmations(tip), required)
    }
}

/// Status of a deposit this wallet cannot claim.
pub(super) const UNCLAIMABLE: &str = "unclaimable";

/// Records every output of `history` paying `spk`, fetching each
/// transaction once. A transaction paying the address more than once is
/// recorded but unclaimable: LWK claims a transaction that pays the
/// address exactly once. Deposits the server no longer lists (replaced,
/// reorganised away) are dropped unless a claim was made for them.
fn scan_deposits(
    deposits: &mut Vec<StoredDeposit>,
    history: &[core_peg::ScriptHistoryItem],
    spk: &bitcoin::Script,
    mut fetch: impl FnMut(&bitcoin::Txid) -> Result<bitcoin::Transaction, String>,
) -> Result<(), String> {
    for item in history {
        let txid = item.txid.to_string();
        let mut known = false;
        for d in deposits.iter_mut().filter(|d| d.txid == txid) {
            d.height = item.height;
            known = true;
        }
        if known || deposits.len() >= MAX_DEPOSITS {
            continue;
        }
        let tx = fetch(&item.txid)?;
        let paying: Vec<(u32, u64)> = tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, out)| out.script_pubkey.as_script() == spk)
            .map(|(vout, out)| (vout as u32, out.value.to_sat()))
            .collect();
        let note = (paying.len() > 1).then(|| {
            format!(
                "transaction {txid} pays the deposit address {} times; this wallet claims only a                  transaction that pays it once (the test server's operator can recover it)",
                paying.len()
            )
        });
        for (vout, amount) in paying {
            deposits.push(StoredDeposit {
                txid: txid.clone(),
                vout,
                amount,
                height: item.height,
                unclaimable: note.clone(),
                ..StoredDeposit::default()
            });
        }
    }
    deposits
        .retain(|d| d.claim_txid.is_some() || history.iter().any(|i| i.txid.to_string() == d.txid));
    Ok(())
}

/// The deposit an order follows: the one this wallet paid (`funded`), else
/// the first claimable one, in chain order, carrying at least `expected`.
/// A smaller payment that arrives first (dust from whoever saw the address)
/// is listed and claimable on its own, but never becomes the order's.
fn choose_primary(
    deposits: &[StoredDeposit],
    funded: Option<&str>,
    expected: u64,
) -> Option<String> {
    let claimable = || deposits.iter().filter(|d| d.unclaimable.is_none());
    if let Some(txid) = funded {
        if let Some(d) = claimable().find(|d| d.txid == txid) {
            return Some(d.outpoint());
        }
    }
    let mut by_chain: Vec<&StoredDeposit> = claimable().filter(|d| d.amount >= expected).collect();
    by_chain.sort_by_key(|d| (d.height.unwrap_or(u32::MAX), d.txid.clone(), d.vout));
    by_chain.first().map(|d| d.outpoint())
}

fn s(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn not_ready(msg: impl Into<String>) -> String {
    PegError::NotReady(msg.into()).to_string()
}

fn eta_minutes(direction: &str, required: u32, seen: u32) -> u32 {
    let left = required.saturating_sub(seen);
    if direction == "in" {
        left.saturating_mul(BITCOIN_BLOCK_MINUTES)
            .saturating_add(LIQUID_BLOCK_MINUTES)
    } else {
        left.saturating_mul(LIQUID_BLOCK_MINUTES)
            .saturating_add(BITCOIN_BLOCK_MINUTES)
    }
}

/// The status a peg-in deposit with `confirmations` has.
pub(super) fn pegin_status(confirmations: u32, required: u32) -> &'static str {
    match confirmations {
        0 => DEPOSIT_SEEN,
        c if c < required => CONFIRMING,
        _ => CLAIMABLE,
    }
}

/// The status a broadcast peg-out with `confirmations` has.
pub(super) fn pegout_status(confirmations: u32, required: u32) -> &'static str {
    match confirmations {
        0 => DEPOSIT_SEEN,
        c if c < required => CONFIRMING,
        _ => SETTLING,
    }
}

// ── Quote and start ──────────────────────────────────────────────────────────

pub(super) fn quote(
    t: &NativePegTerms,
    direction: &str,
    amount_sats: u64,
) -> Result<PegQuoteDto, String> {
    let pegin = direction == "in";
    let (min, max, fee, required) = if pegin {
        (
            core_peg::MIN_PEG_SATS,
            core_peg::MAX_MONEY_SATS,
            CLAIM_FEE_ESTIMATE_SATS,
            t.pegin_confirmations,
        )
    } else {
        // Below the lab's minimum the output is never paid: the L-BTC would
        // be burned.
        (
            core_peg::MIN_PEG_SATS.max(t.pegout_min_sat),
            t.pegout_max_sat,
            PEGOUT_FEE_ESTIMATE_SATS,
            t.pegout_confirmations,
        )
    };
    check_limits(amount_sats, min, max)?;
    Ok(PegQuoteDto {
        direction: direction.to_string(),
        amount_sats,
        rate: 1.0,
        service_fee_sats: 0,
        network_fee_sats: fee,
        // MIN_PEG_SATS keeps this from underflowing.
        receive_sats: if pegin {
            amount_sats - fee
        } else {
            amount_sats
        },
        min_sats: min,
        max_sats: max,
        eta_minutes: eta_minutes(direction, required, 0),
        simulated: false,
        provider: "native".into(),
        confirmations_required: required,
        network_fee_included: pegin,
    })
}

/// The amount limits, with the texts the quote has always used.
fn check_limits(amount: u64, min: u64, max: u64) -> Result<(), String> {
    if amount < min {
        return Err(format!("Amount is below the minimum of {min} sats"));
    }
    if amount > max {
        return Err(format!("Amount is above the maximum of {max} sats"));
    }
    Ok(())
}

pub(super) struct NewOrder<'a> {
    pub order_id: String,
    pub wallet_id: &'a str,
    pub direction: &'static str,
    pub amount_sats: u64,
    pub payout_address: &'a str,
    /// Claim indexes of this wallet's other native peg-ins.
    pub taken_indexes: Vec<u32>,
}

/// Claim indexes the wallet's native peg-in orders use.
pub(super) fn claim_indexes(store: &super::PegStore, wallet_id: &str) -> Vec<u32> {
    store
        .orders
        .iter()
        .filter(|o| o.order.wallet_id == wallet_id)
        .filter_map(|o| o.native.as_ref()?.claim_index)
        .collect()
}

pub(super) fn start(
    state: &mut AppState,
    t: &NativePegTerms,
    n: NewOrder<'_>,
) -> Result<StoredOrder, String> {
    let q = quote(t, n.direction, n.amount_sats)?;
    open_software_wallet(state, n.wallet_id)?;
    let mut native = NativeState {
        lab_url: t.lab_url.clone(),
        instance_id: t.instance_id.clone(),
        ..NativeState::default()
    };
    let (deposit_address, valid_until) = if n.direction == "in" {
        state
            .liquid_network
            .parse_address(n.payout_address)
            .map_err(|e| format!("Payout address: {e}"))?;
        let fed = state.liquid_chain()?.fed_peg(None).map_err(s)?;
        let liq = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
        let index = liq.free_pegin_index(n.taken_indexes).map_err(s)?;
        let address = liq.pegin_address(index, &fed).map_err(s)?;
        native.claim_index = Some(index);
        native.claim_script_hex = Some(hex::encode(address.claim_script().as_bytes()));
        native.fedpeg_height = Some(fed.epoch_start_height());
        native.fedpeg_script_hex = Some(fed.script().to_hex_string());
        native.fedpeg_program_hex = Some(fed.program().to_hex_string());
        (
            address.address().to_string(),
            Some(fed.guaranteed_valid_until_height()),
        )
    } else {
        let dest =
            core_peg::bitcoin_script_for(n.payout_address, bitcoin::Network::Regtest).map_err(s)?;
        let genesis = state.liquid_network.elements().parent_genesis_hash();
        let script = core_peg::pegout_script(&genesis, &dest);
        native.payout_script_hex = Some(dest.to_hex_string());
        native.pegout_script_hex = Some(hex::encode(script.as_bytes()));
        (String::new(), None)
    };
    let now = now_secs();
    Ok(StoredOrder {
        order: PegOrderDto {
            order_id: n.order_id,
            wallet_id: n.wallet_id.to_string(),
            direction: n.direction.to_string(),
            status: AWAITING_DEPOSIT.to_string(),
            deposit_address,
            deposit_expected_sats: n.amount_sats,
            payout_address: n.payout_address.to_string(),
            payout_expected_sats: q.receive_sats,
            created_at: now,
            updated_at: now,
            eta_minutes: q.eta_minutes,
            txid_deposit: None,
            txid_payout: None,
            simulated: false,
            status_history: vec![PegStatusEntryDto {
                status: AWAITING_DEPOSIT.to_string(),
                at: now,
            }],
            provider: "native".into(),
            confirmations: 0,
            confirmations_required: q.confirmations_required,
            deposit_received_sats: None,
            txid_claim: None,
            valid_until_liquid_height: valid_until,
            last_error: None,
            expires_at: None,
            deposits: Vec::new(),
        },
        native: Some(native),
        sideswap: None,
    })
}

/// Opens `wallet_id` (as every *opens* method does) and checks it can sign
/// both sides with this app's own keys.
fn open_software_wallet(state: &mut AppState, wallet_id: &str) -> Result<(), String> {
    let entry = state.registry.find(wallet_id).ok_or("Wallet not found")?;
    if !matches!(entry.profile, WalletProfile::Software { .. }) {
        return Err(
            "The native peg signs with this app's own keys: it needs a software wallet (not a \
             hardware, watch-only or multisig wallet)."
                .into(),
        );
    }
    if state.active_wallet_id.as_deref() != Some(wallet_id) {
        crate::handlers::wallet_ops::open_wallet(state, wallet_id)?;
    }
    if !state.liquid.as_ref().is_some_and(|l| l.can_sign()) {
        return Err("This wallet has no Liquid side; enable Liquid to use the peg.".into());
    }
    Ok(())
}

fn native_of(o: &StoredOrder) -> Result<&NativeState, String> {
    o.native
        .as_ref()
        .ok_or_else(|| "The order has no native peg data".to_string())
}

fn native_mut(o: &mut StoredOrder) -> Result<&mut NativeState, String> {
    o.native
        .as_mut()
        .ok_or_else(|| "The order has no native peg data".to_string())
}

fn hex_field<'a>(v: &'a Option<String>, what: &str) -> Result<&'a str, String> {
    v.as_deref()
        .ok_or_else(|| format!("The order is missing its {what}"))
}

fn bitcoin_script(hex_str: &str) -> Result<bitcoin::ScriptBuf, String> {
    bitcoin::ScriptBuf::from_hex(hex_str).map_err(|e| format!("Stored Bitcoin script: {e}"))
}

fn liquid_script(hex_str: &str) -> Result<elements::Script, String> {
    hex::decode(hex_str)
        .map(elements::Script::from)
        .map_err(|e| format!("Stored Liquid script: {e}"))
}

/// The deposit address's scriptPubKey (peg-in).
fn deposit_script(o: &StoredOrder) -> Result<bitcoin::ScriptBuf, String> {
    core_peg::bitcoin_script_for(&o.order.deposit_address, bitcoin::Network::Regtest).map_err(s)
}

fn liquid_txid_of(v: &Option<String>, what: &str) -> Result<elements::Txid, String> {
    elements::Txid::from_str(hex_field(v, what)?).map_err(|e| format!("Stored {what}: {e}"))
}

// ── Following an order (never signs) ─────────────────────────────────────────

/// The provider terms an order can be followed with: the active provider
/// must be the same lab on the same chain instance. A lab that reset its
/// chains expires the order — its chain no longer exists.
fn terms_for(state: &AppState, o: &mut StoredOrder) -> Result<NativePegTerms, String> {
    let (lab, instance) = {
        let n = native_of(o)?;
        (n.lab_url.clone(), n.instance_id.clone())
    };
    match super::provider(state) {
        Ok(PegProvider::Native(t)) if t.lab_url == lab && t.instance_id == instance => Ok(t),
        Ok(PegProvider::Native(t)) if t.lab_url == lab => {
            set_status(&mut o.order, EXPIRED, now_secs());
            Err("The test server reset its chains; this order's chain no longer exists.".into())
        }
        _ => Err(PegError::Unavailable(format!(
            "this order belongs to the test server {lab} (chain {}…); join it, on Liquid \
             regtest, to follow the order.",
            instance.get(..12).unwrap_or(&instance)
        ))
        .to_string()),
    }
}

/// Whether a completed native peg-in is still followed: it has a deposit
/// that can still be claimed (or whose claim is not yet in a block).
pub(super) fn follows_after_completion(o: &StoredOrder) -> bool {
    o.order.status == COMPLETED
        && o.order.direction == "in"
        && o.native.as_ref().is_some_and(|n| {
            n.deposits
                .iter()
                .any(|d| d.unclaimable.is_none() && !d.claimed())
        })
}

/// Reads the order's progress from the chains; a failure is left in
/// `last_error`.
pub(super) fn refresh(state: &mut AppState, o: &mut StoredOrder, payouts_taken: &[String]) {
    let result = terms_for(state, o).and_then(|t| refresh_with(state, &t, o, payouts_taken));
    o.order.last_error = result.err();
}

fn refresh_with(
    state: &mut AppState,
    t: &NativePegTerms,
    o: &mut StoredOrder,
    payouts_taken: &[String],
) -> Result<(), String> {
    if o.order.direction == "in" {
        refresh_pegin(state, t, o)
    } else {
        refresh_pegout(state, t, o, payouts_taken)
    }
}

fn refresh_pegin(state: &AppState, t: &NativePegTerms, o: &mut StoredOrder) -> Result<(), String> {
    match o.order.status.as_str() {
        AWAITING_DEPOSIT | DEPOSIT_SEEN | CONFIRMING | CLAIMABLE | SETTLING | COMPLETED => {}
        _ => return Ok(()),
    }
    let view = BitcoinChainView::connect(&state.bitcoin_backend()).map_err(s)?;
    let spk = deposit_script(o)?;
    let history = view.history(&spk).map_err(s)?;
    let tip = view.tip_height().map_err(s)?;
    let funded = o.order.txid_deposit.clone();
    let expected = o.order.deposit_expected_sats;
    let legacy_claim = o.order.txid_claim.clone();
    {
        let n = native_mut(o)?;
        scan_deposits(&mut n.deposits, &history, &spk, |txid| {
            view.transaction(txid).map_err(s)
        })?;
        if n.primary
            .as_ref()
            .is_some_and(|p| !n.deposits.iter().any(|d| &d.outpoint() == p))
        {
            n.primary = None;
        }
        if n.primary.is_none() {
            n.primary = choose_primary(&n.deposits, funded.as_deref(), expected);
        }
        // An order written before per-deposit claims: its claim belongs to
        // the deposit it followed.
        if let Some(primary) = n.primary.clone() {
            let legacy_pending = n.pending_claim_tx.take();
            if let Some(d) = n.deposits.iter_mut().find(|d| d.outpoint() == primary) {
                if d.claim_txid.is_none() {
                    d.claim_txid = legacy_claim;
                    d.pending_claim_tx = legacy_pending;
                }
            }
        }
        if n.deposits
            .iter()
            .any(|d| d.txid == funded.clone().unwrap_or_default())
        {
            n.pending_deposit_tx = None;
        }
    }
    // Claims first: a claim already signed (maybe broadcast, maybe lost) is
    // followed by its txid, never signed again.
    refresh_claims(state, o)?;
    let required = t.pegin_confirmations;
    let n = native_of(o)?.clone();
    let primary = n
        .primary
        .as_ref()
        .and_then(|p| n.deposits.iter().find(|d| &d.outpoint() == p));
    match primary {
        Some(d) => {
            let confirmations = d.confirmations(tip);
            o.order.txid_deposit = Some(d.txid.clone());
            o.order.deposit_received_sats = Some(d.amount);
            o.order.confirmations = confirmations;
            o.order.txid_claim = d.claim_txid.clone();
            let status = d.status(tip, required);
            o.order.eta_minutes = match status {
                COMPLETED => 0,
                SETTLING => LIQUID_BLOCK_MINUTES,
                _ => eta_minutes("in", required, confirmations),
            };
            if status == COMPLETED {
                o.order.txid_payout = d.claim_txid.clone();
            }
            set_status(&mut o.order, status, now_secs());
        }
        None if n.deposits.is_empty()
            && o.order.status == AWAITING_DEPOSIT
            && n.pending_deposit_tx.is_none() =>
        {
            o.order.deposits = Vec::new();
            return renew_or_expire(state, o);
        }
        None => {}
    }
    o.order.deposits = n
        .deposits
        .iter()
        .map(|d| PegDepositDto {
            outpoint: d.outpoint(),
            amount_sats: d.amount,
            confirmations: d.confirmations(tip),
            status: d.status(tip, required).to_string(),
            txid_claim: d.claim_txid.clone(),
            primary: n.primary.as_deref() == Some(d.outpoint().as_str()),
            note: d.unclaimable.clone(),
        })
        .collect();
    Ok(())
}

/// Reads the Liquid confirmations of every claim made and not yet in a
/// block. A claim seen in a block drops its stored bytes.
fn refresh_claims(state: &AppState, o: &mut StoredOrder) -> Result<(), String> {
    let open: Vec<usize> = native_of(o)?
        .deposits
        .iter()
        .enumerate()
        .filter(|(_, d)| d.claim_txid.is_some() && !d.claimed())
        .map(|(i, _)| i)
        .collect();
    if open.is_empty() {
        return Ok(());
    }
    let payout = state
        .liquid_network
        .parse_address(&o.order.payout_address)
        .map_err(s)?
        .script_pubkey();
    let chain = state.liquid_chain()?;
    let n = native_mut(o)?;
    for i in open {
        let d = &mut n.deposits[i];
        let txid = liquid_txid_of(&d.claim_txid, "claim txid")?;
        d.claim_confirmations = chain.tx_confirmations(&txid, &payout).map_err(s)?;
        if d.claimed() {
            d.pending_claim_tx = None;
        }
    }
    Ok(())
}

/// A peg-in address past its guaranteed window: renewed while the
/// federation is unchanged (the address is the same), expired otherwise.
fn renew_or_expire(state: &AppState, o: &mut StoredOrder) -> Result<(), String> {
    let chain = state.liquid_chain()?;
    let tip = chain.tip_height().map_err(s)?;
    if o.order
        .valid_until_liquid_height
        .is_some_and(|until| tip <= until)
    {
        return Ok(());
    }
    let fed = chain.fed_peg(None).map_err(s)?;
    let n = native_mut(o)?;
    let same = n.fedpeg_script_hex.as_deref() == Some(fed.script().to_hex_string().as_str())
        && n.fedpeg_program_hex.as_deref() == Some(fed.program().to_hex_string().as_str());
    if same {
        n.fedpeg_height = Some(fed.epoch_start_height());
        o.order.valid_until_liquid_height = Some(fed.guaranteed_valid_until_height());
        return Ok(());
    }
    set_status(&mut o.order, EXPIRED, now_secs());
    Err(PegError::Expired(
        "the federation changed since this deposit address was issued; do not pay it. Start a \
         new peg-in."
            .into(),
    )
    .to_string())
}

fn refresh_pegout(
    state: &AppState,
    t: &NativePegTerms,
    o: &mut StoredOrder,
    payouts_taken: &[String],
) -> Result<(), String> {
    match o.order.status.as_str() {
        AWAITING_DEPOSIT if native_of(o)?.pending_deposit_tx.is_none() => return Ok(()),
        AWAITING_DEPOSIT | DEPOSIT_SEEN | CONFIRMING => {}
        SETTLING => return find_payout(state, o, payouts_taken),
        _ => return Ok(()),
    }
    let txid = liquid_txid_of(&o.order.txid_deposit, "peg-out txid")?;
    let watch = liquid_script(hex_field(&native_of(o)?.watch_script_hex, "change script")?)?;
    let Some(confirmations) = state
        .liquid_chain()?
        .tx_confirmations(&txid, &watch)
        .map_err(s)?
    else {
        return Ok(());
    };
    native_mut(o)?.pending_deposit_tx = None;
    o.order.confirmations = confirmations;
    o.order.eta_minutes = eta_minutes("out", t.pegout_confirmations, confirmations);
    let next = pegout_status(confirmations, t.pegout_confirmations);
    set_status(&mut o.order, next, now_secs());
    if next == SETTLING {
        find_payout(state, o, payouts_taken)?;
    }
    Ok(())
}

/// The federation's payment: a transaction new to the payout address
/// (not known before the peg-out, not another order's) paying it exactly
/// the peg-out amount. Completes the order once it is in a block.
fn find_payout(
    state: &AppState,
    o: &mut StoredOrder,
    payouts_taken: &[String],
) -> Result<(), String> {
    let n = native_of(o)?;
    let spk = bitcoin_script(hex_field(&n.payout_script_hex, "payout script")?)?;
    let view = BitcoinChainView::connect(&state.bitcoin_backend()).map_err(s)?;
    let history = view.history(&spk).map_err(s)?;
    let amount = o.order.deposit_expected_sats;
    let recorded = o.order.txid_payout.clone();
    for item in history {
        let txid = item.txid.to_string();
        let is_recorded = recorded.as_deref() == Some(txid.as_str());
        if !is_recorded && (n.payout_known_txids.contains(&txid) || payouts_taken.contains(&txid)) {
            continue;
        }
        let tx = view.transaction(&item.txid).map_err(s)?;
        let pays = tx
            .output
            .iter()
            .any(|out| out.script_pubkey == spk && out.value.to_sat() == amount);
        if !pays {
            continue;
        }
        o.order.txid_payout = Some(txid);
        if item.height.is_some() {
            o.order.eta_minutes = 0;
            set_status(&mut o.order, COMPLETED, now_secs());
        }
        break;
    }
    Ok(())
}

// ── The signing steps ────────────────────────────────────────────────────────

/// The order must belong to the active lab and chain.
fn require_same_chain(t: &NativePegTerms, o: &StoredOrder) -> Result<(), String> {
    let n = native_of(o)?;
    if n.lab_url != t.lab_url || n.instance_id != t.instance_id {
        return Err(PegError::Unavailable(format!(
            "this order belongs to the test server {} on another chain instance.",
            n.lab_url
        ))
        .to_string());
    }
    Ok(())
}

pub(super) fn fund(
    state: &mut AppState,
    t: &NativePegTerms,
    o: &mut StoredOrder,
    fee_rate: Option<f32>,
) -> Result<(), String> {
    require_same_chain(t, o)?;
    // Up to date first: a peg-in address may have expired or been paid.
    let fresh = refresh_with(state, t, o, &[]);
    o.order.last_error = fresh.as_ref().err().cloned();
    persist(&state.data_dir, o)?;
    fresh?;
    match o.order.status.as_str() {
        AWAITING_DEPOSIT => {}
        EXPIRED => {
            return Err(PegError::Expired(
                "the deposit address of this order expired; start a new one.".into(),
            )
            .to_string())
        }
        super::CANCELLED => return Err(not_ready("this order was cancelled.")),
        other => {
            return Err(not_ready(format!(
                "this order's deposit was already made (status: {other})."
            )))
        }
    }
    open_software_wallet(state, &o.order.wallet_id)?;
    if o.order.direction == "in" {
        fund_pegin(state, o, fee_rate)
    } else {
        fund_pegout(state, t, o)
    }
}

/// Pays the peg-in address from the wallet's own Bitcoin.
fn fund_pegin(state: &AppState, o: &mut StoredOrder, fee_rate: Option<f32>) -> Result<(), String> {
    let view = BitcoinChainView::connect(&state.bitcoin_backend()).map_err(s)?;
    if let Some(raw) = native_of(o)?.pending_deposit_tx.clone() {
        // Signed before but not seen on chain: the same bytes again.
        let bytes = hex::decode(raw).map_err(|e| format!("Stored deposit: {e}"))?;
        view.broadcast_raw(&bytes).map_err(s)?;
    } else {
        let btc = state.bitcoin.as_ref().ok_or("Bitcoin wallet not open")?;
        let frozen = state.frozen_on(CoinChain::Bitcoin);
        let amount = o.order.deposit_expected_sats;
        let mut psbt = btc
            .create_tx_multi(
                &[(o.order.deposit_address.clone(), amount, false)],
                fee_rate.unwrap_or(DEFAULT_DEPOSIT_FEE_RATE),
                None,
                None,
                &frozen,
            )
            .map_err(s)?;
        if !btc.sign(&mut psbt).map_err(s)? {
            return Err("The deposit could not be fully signed by this wallet.".into());
        }
        let tx = psbt.extract_tx();
        let spk = deposit_script(o)?;
        if !tx
            .output
            .iter()
            .any(|out| out.value == amount && out.script_pubkey.as_bytes() == spk.as_bytes())
        {
            return Err("The signed deposit does not pay the deposit address.".into());
        }
        let raw = bdk::bitcoin::consensus::encode::serialize(&tx);
        o.order.txid_deposit = Some(tx.txid().to_string());
        native_mut(o)?.pending_deposit_tx = Some(hex::encode(&raw));
        persist(&state.data_dir, o)?;
        btc.broadcast(tx).map_err(s)?;
    }
    eprintln!(
        "[templarlib] peg-in {} deposit broadcast: {}",
        o.order.order_id,
        o.order.txid_deposit.as_deref().unwrap_or("?")
    );
    set_status(&mut o.order, DEPOSIT_SEEN, now_secs());
    persist(&state.data_dir, o)
}

/// Builds, signs and broadcasts the peg-out transaction.
fn fund_pegout(state: &AppState, t: &NativePegTerms, o: &mut StoredOrder) -> Result<(), String> {
    let amount = o.order.deposit_expected_sats;
    // The lab's terms may have changed since the order was opened.
    check_limits(
        amount,
        core_peg::MIN_PEG_SATS.max(t.pegout_min_sat),
        t.pegout_max_sat,
    )?;
    let chain = state.liquid_chain()?;
    if let Some(raw) = native_of(o)?.pending_deposit_tx.clone() {
        let bytes = hex::decode(raw).map_err(|e| format!("Stored peg-out: {e}"))?;
        let tx: elements::Transaction =
            encode::deserialize(&bytes).map_err(|e| format!("Stored peg-out: {e}"))?;
        chain.broadcast(&tx).map_err(s)?;
    } else {
        let n = native_of(o)?;
        let dest = bitcoin_script(hex_field(&n.payout_script_hex, "payout script")?)?;
        let script = liquid_script(hex_field(&n.pegout_script_hex, "peg-out script")?)?;
        let genesis = state.liquid_network.elements().parent_genesis_hash();
        let view = BitcoinChainView::connect(&state.bitcoin_backend()).map_err(s)?;
        if view.block_hash_at(0).map_err(s)? != genesis {
            return Err(PegError::Build(
                "the Bitcoin chain's genesis is not the one this Liquid chain is pegged to".into(),
            )
            .to_string());
        }
        let known: Vec<String> = view
            .history(&dest)
            .map_err(s)?
            .into_iter()
            .map(|i| i.txid.to_string())
            .collect();
        let liq = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
        let frozen = state.frozen_on(CoinChain::Liquid);
        let mut pset = liq
            .create_pegout(amount, script.clone(), &frozen)
            .map_err(s)?;
        liq.sign(&mut pset).map_err(s)?;
        let tx = liq.finalize(&mut pset).map_err(s)?;
        check_pegout_tx(&tx, &script, amount, &genesis, &dest, &liq.policy_asset())?;
        let watch = tx
            .output
            .iter()
            .find(|out| !out.script_pubkey.is_empty() && out.script_pubkey != script)
            .ok_or("The peg-out has no change output to follow it by")?
            .script_pubkey
            .clone();
        o.order.txid_deposit = Some(tx.txid().to_string());
        o.order.deposit_received_sats = Some(amount);
        let n = native_mut(o)?;
        n.watch_script_hex = Some(hex::encode(watch.as_bytes()));
        n.payout_known_txids = known;
        n.pending_deposit_tx = Some(encode::serialize_hex(&tx));
        persist(&state.data_dir, o)?;
        chain.broadcast(&tx).map_err(s)?;
    }
    eprintln!(
        "[templarlib] peg-out {} broadcast: {}",
        o.order.order_id,
        o.order.txid_deposit.as_deref().unwrap_or("?")
    );
    set_status(&mut o.order, DEPOSIT_SEEN, now_secs());
    persist(&state.data_dir, o)
}

/// The finalized peg-out holds exactly one peg-out, of `amount` explicit
/// L-BTC, to `dest` on the chain whose genesis is `genesis`.
fn check_pegout_tx(
    tx: &elements::Transaction,
    script: &elements::Script,
    amount: u64,
    genesis: &bitcoin::BlockHash,
    dest: &bitcoin::Script,
    policy_asset: &elements::AssetId,
) -> Result<(), String> {
    let pegouts: Vec<_> = tx.output.iter().filter_map(|o| o.pegout_data()).collect();
    let ok = pegouts.len() == 1
        && pegouts[0].value == amount
        && pegouts[0].asset.explicit() == Some(*policy_asset)
        && pegouts[0].genesis_hash == *genesis
        && pegouts[0].script_pubkey.as_script() == dest
        && pegouts[0].extra_data.is_empty()
        && tx
            .output
            .iter()
            .filter(|o| o.script_pubkey == *script)
            .count()
            == 1;
    if !ok {
        return Err(PegError::Build(
            "the signed peg-out does not carry exactly the intended peg-out output".into(),
        )
        .to_string());
    }
    Ok(())
}

/// What `peg_claim` does for one deposit.
#[derive(Debug, PartialEq, Eq)]
enum ClaimStep {
    /// Sign and broadcast a new claim.
    Build,
    /// A claim was signed before and is not in a block: send those bytes
    /// again, never a second claim.
    Rebroadcast(String),
}

fn claim_step(d: &StoredDeposit, tip: u32, required: u32) -> Result<ClaimStep, String> {
    if let Some(why) = &d.unclaimable {
        return Err(PegError::Unavailable(format!(
            "deposit {} cannot be claimed by this wallet: {why}",
            d.outpoint()
        ))
        .to_string());
    }
    if d.claimed() || d.claim_confirmations == Some(0) {
        return Err(not_ready(format!(
            "deposit {} was already claimed ({}).",
            d.outpoint(),
            d.claim_txid.as_deref().unwrap_or("?")
        )));
    }
    if let Some(raw) = &d.pending_claim_tx {
        return Ok(ClaimStep::Rebroadcast(raw.clone()));
    }
    let confirmations = d.confirmations(tip);
    if confirmations < required {
        return Err(not_ready(format!(
            "the deposit has {confirmations} of the {required} Bitcoin confirmations a claim needs."
        )));
    }
    Ok(ClaimStep::Build)
}

/// Claims one deposit of a native peg-in (`outpoint`, default the order's
/// own) — the user-confirmed signing step.
pub(super) fn claim(
    state: &mut AppState,
    t: &NativePegTerms,
    o: &mut StoredOrder,
    outpoint: Option<&str>,
) -> Result<(), String> {
    if o.order.direction != "in" {
        return Err(not_ready(
            "only a peg-in is claimed; a peg-out is paid by the federation.",
        ));
    }
    require_same_chain(t, o)?;
    let fresh = refresh_with(state, t, o, &[]);
    o.order.last_error = fresh.as_ref().err().cloned();
    persist(&state.data_dir, o)?;
    fresh?;
    if o.order.status == EXPIRED {
        return Err(PegError::Expired("this order expired.".into()).to_string());
    }
    let n = native_of(o)?.clone();
    let target = match outpoint {
        Some(op) => op.trim().to_string(),
        None => n.primary.clone().ok_or_else(|| {
            not_ready(if n.deposits.is_empty() {
                "no deposit has arrived yet.".to_string()
            } else {
                "no deposit of the expected amount has arrived yet; claim one of the listed \
                 deposits by its outpoint."
                    .to_string()
            })
        })?,
    };
    let d = n
        .deposits
        .iter()
        .find(|d| d.outpoint() == target)
        .ok_or_else(|| not_ready(format!("no deposit {target} on this order.")))?
        .clone();
    let view = BitcoinChainView::connect(&state.bitcoin_backend()).map_err(s)?;
    let tip = view.tip_height().map_err(s)?;
    match claim_step(&d, tip, t.pegin_confirmations)? {
        ClaimStep::Build => build_claim(state, t, o, &d, &view),
        ClaimStep::Rebroadcast(raw) => {
            let bytes = hex::decode(raw).map_err(|e| format!("Stored claim: {e}"))?;
            let tx: elements::Transaction =
                encode::deserialize(&bytes).map_err(|e| format!("Stored claim: {e}"))?;
            match state.liquid_chain()?.broadcast(&tx) {
                Ok(_) => {
                    eprintln!(
                        "[templarlib] peg-in {} claim rebroadcast: {}",
                        o.order.order_id,
                        tx.txid()
                    );
                    after_claim(o, &d.outpoint(), &tx.txid().to_string());
                    persist(&state.data_dir, o)
                }
                Err(e) => {
                    // Refused: the claim may rest on a block no longer in the
                    // chain (a reorg). Read the evidence again; only a moved
                    // block justifies a new claim.
                    let txid = bitcoin::Txid::from_str(&d.txid).map_err(s)?;
                    let facts = DepositFacts::read(&view, &deposit_script(o)?, &txid).map_err(s)?;
                    if d.claim_block.as_deref() == Some(facts.block_hash.to_string().as_str()) {
                        return Err(format!("The node refused the claim {}: {e}", tx.txid()));
                    }
                    let mut fresh = d.clone();
                    fresh.claim_txid = None;
                    fresh.pending_claim_tx = None;
                    fresh.claim_block = None;
                    fresh.claim_confirmations = None;
                    if let Some(slot) = native_mut(o)?
                        .deposits
                        .iter_mut()
                        .find(|x| x.outpoint() == d.outpoint())
                    {
                        *slot = fresh.clone();
                    }
                    persist(&state.data_dir, o)?;
                    build_claim(state, t, o, &fresh, &view)
                }
            }
        }
    }
}

/// The order after a claim (`claim_txid`) of `outpoint` went out: its row
/// in `deposits` shows it, and the order is settling if it was its own
/// deposit.
fn after_claim(o: &mut StoredOrder, outpoint: &str, claim_txid: &str) {
    if let Some(row) = o.order.deposits.iter_mut().find(|d| d.outpoint == outpoint) {
        row.txid_claim = Some(claim_txid.to_string());
        row.status = SETTLING.to_string();
    }
    let primary = o.native.as_ref().and_then(|n| n.primary.as_deref()) == Some(outpoint);
    if primary {
        o.order.eta_minutes = LIQUID_BLOCK_MINUTES;
        set_status(&mut o.order, SETTLING, now_secs());
    }
}

/// Verifies the evidence of deposit `d` against the wallet's chain view,
/// then signs and broadcasts its claim. The signed claim is stored on the
/// deposit before the broadcast.
fn build_claim(
    state: &mut AppState,
    t: &NativePegTerms,
    o: &mut StoredOrder,
    d: &StoredDeposit,
    view: &BitcoinChainView,
) -> Result<(), String> {
    open_software_wallet(state, &o.order.wallet_id)?;
    let n = native_of(o)?.clone();
    let index = n
        .claim_index
        .ok_or("The order is missing its claim index")?;
    let fedpeg_height = n
        .fedpeg_height
        .ok_or("The order is missing its federation height")?;
    let txid = bitcoin::Txid::from_str(&d.txid).map_err(|e| format!("Deposit txid: {e}"))?;

    // The wallet's own chain view, then the evidence, checked against it.
    let facts = DepositFacts::read(view, &deposit_script(o)?, &txid).map_err(s)?;
    let (tx_bytes, proof_bytes) =
        core_peg::fetch_pegin_evidence(&t.esplora_url, &txid).map_err(s)?;

    // The very address of this order, rebuilt from the federation it was
    // derived from.
    let chain = state.liquid_chain()?;
    let fed = chain.fed_peg(Some(fedpeg_height)).map_err(s)?;
    let liq = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
    let address = liq.pegin_address(index, &fed).map_err(s)?;
    if address.address().to_string() != o.order.deposit_address
        || Some(hex::encode(address.claim_script().as_bytes())) != n.claim_script_hex
    {
        return Err(PegError::ProofRejected(
            "the federation recorded for this order no longer yields its deposit address".into(),
        )
        .to_string());
    }
    let tip = chain.tip_height().map_err(s)?;
    if !fed.is_guaranteed_valid_at(tip) {
        let now = chain.fed_peg(None).map_err(s)?;
        if now.script() != fed.script() || now.program() != fed.program() {
            return Err(PegError::Expired(
                "the federation changed since this deposit address was issued; the wallet \
                 cannot claim it any more (the lab operator can)."
                    .into(),
            )
            .to_string());
        }
    }
    let funding = core_peg::verify_pegin_evidence(
        address,
        &facts,
        &tx_bytes,
        &proof_bytes,
        t.pegin_confirmations,
    )
    .map_err(s)?;
    if funding.deposit().outpoint().vout != d.vout {
        return Err(PegError::ProofRejected(format!(
            "the evidence is for output {} of {txid}, not {}",
            funding.deposit().outpoint().vout,
            d.vout
        ))
        .to_string());
    }
    let deposit = funding.deposit().amount().to_sat();

    let mut pset = liq
        .create_pegin_claim(
            lwk_wollet::PeginInput::from(funding),
            &o.order.payout_address,
        )
        .map_err(s)?;
    templar_core::liquid::wallet::refuse_frozen_inputs(
        &pset,
        &state.frozen_on(CoinChain::Liquid),
        true,
    )
    .map_err(s)?;
    // The one route that signs a peg-in: judged against this order's own
    // record (deposit, claim index, claim script), never against the PSET.
    let claim_script = n
        .claim_script_hex
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .map(elements::Script::from)
        .ok_or("The order is missing its claim script")?;
    liq.sign_own_pegin_claim(
        &mut pset,
        &bitcoin::OutPoint::new(txid, d.vout),
        index,
        &claim_script,
    )
    .map_err(s)?;
    let tx = liq.finalize(&mut pset).map_err(s)?;
    let payout = state
        .liquid_network
        .parse_address(&o.order.payout_address)
        .map_err(s)?
        .script_pubkey();
    let fee: u64 = tx
        .output
        .iter()
        .filter(|o| o.is_fee())
        .filter_map(|o| o.value.explicit())
        .sum();
    if tx.input.len() != 1
        || !tx.input[0].is_pegin
        || !tx.output.iter().any(|o| o.script_pubkey == payout)
    {
        return Err(PegError::Build(
            "the signed claim does not spend the peg-in to the payout address".into(),
        )
        .to_string());
    }
    let outpoint = d.outpoint();
    let is_primary = n.primary.as_deref() == Some(outpoint.as_str());
    {
        let n = native_mut(o)?;
        let slot = n
            .deposits
            .iter_mut()
            .find(|x| x.outpoint() == outpoint)
            .ok_or("The deposit vanished from the order")?;
        slot.claim_txid = Some(tx.txid().to_string());
        slot.pending_claim_tx = Some(encode::serialize_hex(&tx));
        slot.claim_block = Some(facts.block_hash.to_string());
        slot.claim_confirmations = None;
    }
    if is_primary {
        o.order.txid_claim = Some(tx.txid().to_string());
        o.order.deposit_received_sats = Some(deposit);
        o.order.payout_expected_sats = deposit.saturating_sub(fee);
    }
    persist(&state.data_dir, o)?;
    chain.broadcast(&tx).map_err(s)?;
    eprintln!(
        "[templarlib] peg-in {} claim of {outpoint} broadcast: {}",
        o.order.order_id,
        tx.txid()
    );
    after_claim(o, &outpoint, &tx.txid().to_string());
    persist(&state.data_dir, o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lwk_wollet::elements::bitcoin::hashes::Hash;

    fn terms() -> NativePegTerms {
        NativePegTerms {
            lab_url: "http://127.0.0.1:8096".into(),
            instance_id: "11".repeat(32),
            esplora_url: "http://127.0.0.1:19070".into(),
            pegin_confirmations: 2,
            pegout_confirmations: 3,
            pegout_max_sat: 100_000_000,
            pegout_min_sat: 100_000,
        }
    }

    fn tx_paying(spk: &bitcoin::Script, amounts: &[u64], salt: u8) -> bitcoin::Transaction {
        let mut output: Vec<bitcoin::TxOut> = amounts
            .iter()
            .map(|a| bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(*a),
                script_pubkey: spk.to_owned(),
            })
            .collect();
        output.push(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1_000 + u64::from(salt)),
            script_pubkey: bitcoin::ScriptBuf::new_op_return([salt; 4]),
        });
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output,
        }
    }

    fn item(tx: &bitcoin::Transaction, height: Option<u32>) -> core_peg::ScriptHistoryItem {
        core_peg::ScriptHistoryItem {
            txid: tx.compute_txid(),
            height,
        }
    }

    #[test]
    fn every_deposit_is_tracked_and_dust_first_does_not_take_the_order() {
        let spk = bitcoin::ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array([4u8; 20]));
        let dust = tx_paying(&spk, &[546], 1);
        let real = tx_paying(&spk, &[200_000], 2);
        let twice = tx_paying(&spk, &[30_000, 40_000], 3);
        let later = tx_paying(&spk, &[500_000], 4);
        let txs = [dust.clone(), real.clone(), twice.clone(), later.clone()];
        let fetch = |txid: &bitcoin::Txid| {
            txs.iter()
                .find(|t| t.compute_txid() == *txid)
                .cloned()
                .ok_or_else(|| "unknown".to_string())
        };
        let history = vec![
            item(&dust, Some(100)),
            item(&real, Some(101)),
            item(&twice, Some(102)),
            item(&later, None),
        ];
        let mut deposits = Vec::new();
        scan_deposits(&mut deposits, &history, &spk, fetch).unwrap();
        assert_eq!(deposits.len(), 5, "{deposits:?}");
        // The dust came first; the order follows the deposit of its amount.
        let primary = choose_primary(&deposits, None, 200_000).unwrap();
        assert_eq!(primary, format!("{}:0", real.compute_txid()));
        // The wallet's own payment wins whatever came first.
        let own = choose_primary(&deposits, Some(&later.compute_txid().to_string()), 200_000);
        assert_eq!(own, Some(format!("{}:0", later.compute_txid())));
        // A transaction paying the address twice: both outputs listed,
        // neither claimable, with the reason.
        let both: Vec<_> = deposits
            .iter()
            .filter(|d| d.txid == twice.compute_txid().to_string())
            .collect();
        assert_eq!(both.len(), 2);
        assert!(both.iter().all(|d| d.status(103, 2) == UNCLAIMABLE));
        assert!(both[0].unclaimable.as_deref().unwrap().contains("2 times"));
        // Later payments stay tracked and claimable on their own.
        let dust_d = deposits.iter().find(|d| d.amount == 546).unwrap();
        assert_eq!(dust_d.status(103, 2), CLAIMABLE);
        let later_d = deposits.iter().find(|d| d.amount == 500_000).unwrap();
        assert_eq!(later_d.status(103, 2), DEPOSIT_SEEN);
        // A rescan does not fetch known transactions again and updates
        // heights; a deposit gone from the server's history is dropped
        // unless a claim was made for it.
        deposits
            .iter_mut()
            .find(|d| d.amount == 546)
            .unwrap()
            .claim_txid = Some("aa".repeat(32));
        let history = vec![item(&real, Some(101)), item(&later, Some(104))];
        scan_deposits(&mut deposits, &history, &spk, |_| Err("no fetch".into())).unwrap();
        assert_eq!(deposits.len(), 3);
        assert_eq!(
            deposits
                .iter()
                .find(|d| d.amount == 500_000)
                .unwrap()
                .height,
            Some(104)
        );
        assert!(deposits.iter().any(|d| d.amount == 546));
    }

    #[test]
    fn a_signed_claim_is_sent_again_never_signed_again() {
        let mut d = StoredDeposit {
            txid: "bb".repeat(32),
            vout: 1,
            amount: 200_000,
            height: Some(100),
            ..StoredDeposit::default()
        };
        // Too shallow, then deep enough.
        let err = claim_step(&d, 100, 2).unwrap_err();
        assert!(
            err.starts_with("PEG_NOT_READY:") && err.contains("1 of the 2"),
            "{err}"
        );
        assert_eq!(claim_step(&d, 101, 2).unwrap(), ClaimStep::Build);
        // A claim was signed and stored, and its broadcast answer lost:
        // the same bytes go out again, not a second claim.
        d.claim_txid = Some("cc".repeat(32));
        d.pending_claim_tx = Some("00ff".into());
        assert_eq!(
            claim_step(&d, 101, 2).unwrap(),
            ClaimStep::Rebroadcast("00ff".into())
        );
        assert_eq!(d.status(101, 2), SETTLING);
        // In the mempool, or in a block: already claimed.
        d.claim_confirmations = Some(0);
        assert!(claim_step(&d, 101, 2)
            .unwrap_err()
            .starts_with("PEG_NOT_READY:"));
        d.claim_confirmations = Some(1);
        assert_eq!(d.status(101, 2), COMPLETED);
        assert!(claim_step(&d, 101, 2)
            .unwrap_err()
            .contains("already claimed"));
        // Never claimable.
        let bad = StoredDeposit {
            unclaimable: Some("pays twice".into()),
            ..d.clone()
        };
        assert!(claim_step(&bad, 101, 2)
            .unwrap_err()
            .starts_with("PEG_UNAVAILABLE:"));
    }

    #[test]
    fn native_quotes_carry_real_terms_and_no_service_fee() {
        let q = quote(&terms(), "in", 100_000).unwrap();
        assert_eq!(q.provider, "native");
        assert!(!q.simulated);
        assert_eq!(q.service_fee_sats, 0);
        assert_eq!(q.network_fee_sats, CLAIM_FEE_ESTIMATE_SATS);
        assert!(q.network_fee_included);
        assert_eq!(q.receive_sats, 100_000 - CLAIM_FEE_ESTIMATE_SATS);
        assert_eq!(q.confirmations_required, 2);
        assert_eq!(q.eta_minutes, 2 * 10 + 1);
        assert_eq!(q.max_sats, core_peg::MAX_MONEY_SATS);

        let q = quote(&terms(), "out", 100_000).unwrap();
        assert!(!q.network_fee_included);
        assert_eq!(
            q.receive_sats, 100_000,
            "the federation pays the whole output"
        );
        assert_eq!(q.network_fee_sats, PEGOUT_FEE_ESTIMATE_SATS);
        assert_eq!(q.max_sats, 100_000_000);
        assert_eq!(q.confirmations_required, 3);
        assert_eq!(q.eta_minutes, 3 + 10);
    }

    #[test]
    fn native_limits_are_enforced() {
        let err = quote(&terms(), "in", 9_999).unwrap_err();
        assert!(err.contains("below the minimum of 10000"), "{err}");
        let err = quote(&terms(), "out", 100_000_001).unwrap_err();
        assert!(err.contains("above the maximum of 100000000"), "{err}");
        assert!(quote(&terms(), "in", 100_000_001).is_ok());
        // Below the lab's pegout_min_sat a peg-out would be burned, not
        // paid: refused, and the quote's minimum says so.
        let err = quote(&terms(), "out", 99_999).unwrap_err();
        assert!(err.contains("below the minimum of 100000"), "{err}");
        assert_eq!(quote(&terms(), "out", 100_000).unwrap().min_sats, 100_000);
        let mut low = terms();
        low.pegout_min_sat = 1_000;
        assert_eq!(
            quote(&low, "out", 20_000).unwrap().min_sats,
            core_peg::MIN_PEG_SATS,
            "never below the wallet's own floor"
        );
    }

    #[test]
    fn statuses_follow_confirmations() {
        assert_eq!(pegin_status(0, 2), DEPOSIT_SEEN);
        assert_eq!(pegin_status(1, 2), CONFIRMING);
        assert_eq!(pegin_status(2, 2), CLAIMABLE);
        assert_eq!(pegin_status(7, 2), CLAIMABLE);
        assert_eq!(pegout_status(0, 2), DEPOSIT_SEEN);
        assert_eq!(pegout_status(1, 2), CONFIRMING);
        assert_eq!(pegout_status(2, 2), SETTLING);
        assert_eq!(eta_minutes("in", 2, 1), 11);
        assert_eq!(eta_minutes("in", 2, 5), 1);
        // Huge confirmation counts saturate instead of overflowing.
        assert_eq!(eta_minutes("in", u32::MAX, 0), u32::MAX);
        assert_eq!(eta_minutes("out", u32::MAX, 0), u32::MAX);
    }

    #[test]
    fn a_pegout_is_checked_before_broadcast() {
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest)
            .header
            .block_hash();
        let dest = core_peg::bitcoin_script_for(
            "bcrt1ql2elf5cduwsuea5vl33lsctrl7vyzh7uq4vv4n",
            bitcoin::Network::Regtest,
        )
        .unwrap();
        let script = core_peg::pegout_script(&genesis, &dest);
        let asset = elements::AssetId::from_byte_array([7u8; 32]);
        let out = |value: u64, script: elements::Script| elements::TxOut {
            asset: elements::confidential::Asset::Explicit(asset),
            value: elements::confidential::Value::Explicit(value),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: script,
            witness: Default::default(),
        };
        let tx = |outputs: Vec<elements::TxOut>| elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: outputs,
        };
        let good = tx(vec![
            out(50_000, script.clone()),
            out(30, elements::Script::new()),
        ]);
        check_pegout_tx(&good, &script, 50_000, &genesis, &dest, &asset).unwrap();
        // Wrong amount, two peg-outs, another chain's genesis: refused.
        assert!(check_pegout_tx(&good, &script, 50_001, &genesis, &dest, &asset).is_err());
        let two = tx(vec![
            out(50_000, script.clone()),
            out(50_000, script.clone()),
        ]);
        assert!(check_pegout_tx(&two, &script, 50_000, &genesis, &dest, &asset).is_err());
        let other = bitcoin::BlockHash::from_byte_array([1u8; 32]);
        assert!(check_pegout_tx(&good, &script, 50_000, &other, &dest, &asset).is_err());
        let wrong_asset = elements::AssetId::from_byte_array([8u8; 32]);
        assert!(check_pegout_tx(&good, &script, 50_000, &genesis, &dest, &wrong_asset).is_err());
    }
}
