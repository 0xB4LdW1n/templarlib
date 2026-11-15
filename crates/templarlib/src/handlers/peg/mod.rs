//! Peg-in / peg-out orders.
//!
//! The wallet's peg orders live in `<data_dir>/peg_orders.json` (plain JSON,
//! no secrets: addresses, txids, a claim script and its derivation index),
//! written with the same atomic temp+fsync+rename pattern as the registry.
//! Who moves them is the provider of the active network
//! ([`templar_core::Endpoints::peg_provider`]):
//!
//! - **native** ([`native`]): the Elements peg of a Templar test server's
//!   regtest — a peg-in address bound to this wallet's claim script, a claim
//!   built from a verified merkle proof, a peg-out output the lab's
//!   federation pays.
//! - **sideswap** ([`sideswap`]): SideSwap's swap service on Liquid
//!   testnet, custodial and third-party (testnet has no parent chain).
//!
//! Orders the retired simulated provider created still load and list
//! (`simulated: true`); they never advance and nothing can be paid to them.
//!
//! Nothing is signed while polling: `peg_status` / `peg_list` only read the
//! chains. Signing happens in `peg_fund` and `peg_claim`, the explicit,
//! user-confirmed steps, through the wallet's normal signers.

mod native;
mod sideswap;

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use templar_core::{PegError, PegProvider};

use crate::state::AppState;

const STORE_FILE: &str = "peg_orders.json";

/// Waiting for the deposit (peg-in: BTC to the deposit address; peg-out:
/// `peg_fund` to sign and broadcast the peg-out).
pub const AWAITING_DEPOSIT: &str = "awaiting_deposit";
/// The deposit is in the mempool.
pub const DEPOSIT_SEEN: &str = "deposit_seen";
/// The deposit is in a block, not yet as deep as required.
pub const CONFIRMING: &str = "confirming";
/// Peg-in: the deposit is deep enough; waiting for the user's `peg_claim`.
pub const CLAIMABLE: &str = "claimable";
/// Peg-in: claim broadcast, not yet confirmed. Peg-out: deep enough,
/// waiting for (the confirmation of) the federation's payment.
pub const SETTLING: &str = "settling";
pub const COMPLETED: &str = "completed";
pub const CANCELLED: &str = "cancelled";
/// The deposit address (or the whole order) can no longer be used.
pub const EXPIRED: &str = "expired";
/// The provider will not complete the order (SideSwap: the deposit does not
/// cover its fees). `last_error` says why.
pub const FAILED: &str = "failed";

/// Statuses an order never leaves.
fn is_terminal(status: &str) -> bool {
    matches!(status, COMPLETED | CANCELLED | EXPIRED | FAILED)
}

// ── DTOs (wire shapes fixed by the host contract; new keys are additive) ────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PegQuoteDto {
    pub direction: String,
    pub amount_sats: u64,
    pub rate: f64,
    pub service_fee_sats: u64,
    pub network_fee_sats: u64,
    pub receive_sats: u64,
    pub min_sats: u64,
    pub max_sats: u64,
    pub eta_minutes: u32,
    pub simulated: bool,
    /// `native` | `sideswap`.
    #[serde(default)]
    pub provider: String,
    /// Deposit confirmations before the claim (peg-in, Bitcoin) or the
    /// payout (peg-out, Liquid).
    #[serde(default)]
    pub confirmations_required: u32,
    /// True when `network_fee_sats` comes out of `amount_sats` (a peg-in's
    /// claim fee); false when the wallet pays it on top (a peg-out's Liquid
    /// fee).
    #[serde(default)]
    pub network_fee_included: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PegStatusEntryDto {
    pub status: String,
    /// Unix seconds of the transition.
    pub at: u64,
}

fn provider_simulated() -> String {
    "simulated".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PegOrderDto {
    pub order_id: String,
    pub wallet_id: String,
    /// "in" (BTC → LBTC) or "out" (LBTC → BTC).
    pub direction: String,
    /// See the status constants of this module.
    pub status: String,
    /// Peg-in: the Bitcoin address to pay. Native peg-out: empty — there is
    /// nothing to pay by hand; `peg_fund` creates the peg-out output.
    pub deposit_address: String,
    pub deposit_expected_sats: u64,
    pub payout_address: String,
    pub payout_expected_sats: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub eta_minutes: u32,
    pub txid_deposit: Option<String>,
    pub txid_payout: Option<String>,
    pub simulated: bool,
    pub status_history: Vec<PegStatusEntryDto>,
    /// `native` | `sideswap` | `simulated` (orders of the retired simulated
    /// provider).
    #[serde(default = "provider_simulated")]
    pub provider: String,
    /// Confirmations of the deposit seen so far (Bitcoin for a peg-in,
    /// Liquid for a peg-out).
    #[serde(default)]
    pub confirmations: u32,
    #[serde(default)]
    pub confirmations_required: u32,
    /// What the deposit actually carried, once seen.
    #[serde(default)]
    pub deposit_received_sats: Option<u64>,
    /// Native peg-in: the Liquid claim transaction.
    #[serde(default)]
    pub txid_claim: Option<String>,
    /// Native peg-in: the last Liquid block height through which the
    /// deposit address is guaranteed valid. The wallet renews it while the
    /// federation is unchanged, and expires the order if it changed.
    #[serde(default)]
    pub valid_until_liquid_height: Option<u32>,
    /// Why the last status check failed (a server unreachable, an order of
    /// another chain); null when it succeeded.
    #[serde(default)]
    pub last_error: Option<String>,
    /// SideSwap: Unix seconds after which it no longer takes the deposit;
    /// null when the order does not expire.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

// ── Params (deserialized by dispatch.rs) ────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct PegQuoteParams {
    /// "in" | "out"
    pub direction: String,
    pub amount_sats: u64,
}

#[derive(Deserialize, Debug)]
pub struct PegStartParams {
    pub wallet_id: String,
    pub direction: String,
    pub amount_sats: u64,
    pub payout_address: String,
}

/// Shared by `peg_status`, `peg_cancel` and `peg_claim`.
#[derive(Deserialize, Debug)]
pub struct PegOrderIdParams {
    pub order_id: String,
}

#[derive(Deserialize, Debug)]
pub struct PegListParams {
    pub wallet_id: String,
}

#[derive(Deserialize, Debug)]
pub struct PegFundParams {
    pub order_id: String,
    /// Bitcoin fee rate (sat/vB) of a peg-in deposit; default 1. Ignored for
    /// a peg-out (the Liquid wallet's default rate).
    #[serde(default)]
    pub fee_rate: Option<f32>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// The peg provider of the active network, or a `PEG_UNAVAILABLE` error
/// saying why there is none.
fn provider(state: &AppState) -> Result<PegProvider, String> {
    state
        .endpoints()
        .peg_provider(&state.liquid_network)
        .map(|r| r.value)
        .map_err(|e| e.to_string())
}

/// The active provider's wire name, or why there is none — for
/// `get_liquid_network`.
pub fn provider_info(state: &AppState) -> (Option<String>, Option<String>) {
    match provider(state) {
        Ok(p) => (Some(p.name().to_string()), None),
        Err(e) => (None, Some(e)),
    }
}

/// Quote a peg without creating an order. Native reads no chain; SideSwap
/// asks for its terms.
pub fn quote(state: &AppState, direction: &str, amount_sats: u64) -> Result<PegQuoteDto, String> {
    let direction = normalize_direction(direction)?;
    match provider(state)? {
        PegProvider::Native(terms) => native::quote(&terms, direction, amount_sats),
        PegProvider::SideSwap { url } => sideswap::quote(&url, direction, amount_sats),
    }
}

/// Create a new order in `awaiting_deposit`.
pub fn start(
    state: &mut AppState,
    wallet_id: &str,
    direction: &str,
    amount_sats: u64,
    payout_address: &str,
) -> Result<PegOrderDto, String> {
    let direction = normalize_direction(direction)?;
    let provider = provider(state)?;
    if state.registry.find(wallet_id).is_none() {
        return Err(format!("Unknown wallet id: {wallet_id}"));
    }
    let payout_address = payout_address.trim();
    if payout_address.is_empty() {
        return Err("Payout address is required".to_string());
    }
    let mut store = load_store(&state.data_dir)?;
    let order_id = new_order_id(&store);
    let order = match provider {
        PegProvider::Native(terms) => {
            let taken = native::claim_indexes(&store, wallet_id);
            native::start(
                state,
                &terms,
                native::NewOrder {
                    order_id,
                    wallet_id,
                    direction,
                    amount_sats,
                    payout_address,
                    taken_indexes: taken,
                },
            )?
        }
        PegProvider::SideSwap { url } => sideswap::start(
            state,
            &url,
            native::NewOrder {
                order_id,
                wallet_id,
                direction,
                amount_sats,
                payout_address,
                taken_indexes: Vec::new(),
            },
        )?,
    };
    let dto = order.order.clone();
    store.orders.push(order);
    save_store(&state.data_dir, &store)?;
    Ok(dto)
}

/// Current state of one order, read from the chains first.
pub fn status(state: &mut AppState, order_id: &str) -> Result<PegOrderDto, String> {
    let mut store = load_store(&state.data_dir)?;
    let index = find_index(&store, order_id)?;
    let taken = payouts_taken(&store, order_id);
    let changed = refresh(state, &mut store.orders[index], &taken);
    let dto = store.orders[index].order.clone();
    if changed {
        save_store(&state.data_dir, &store)?;
    }
    Ok(dto)
}

/// All orders of a wallet, newest first; the open ones are read from the
/// chains first. A chain that cannot be read leaves `last_error` on the
/// order instead of failing the list.
pub fn list(state: &mut AppState, wallet_id: &str) -> Result<Vec<PegOrderDto>, String> {
    let mut store = load_store(&state.data_dir)?;
    let mut changed = false;
    for i in 0..store.orders.len() {
        if store.orders[i].order.wallet_id != wallet_id {
            continue;
        }
        let taken = payouts_taken(&store, &store.orders[i].order.order_id.clone());
        changed |= refresh(state, &mut store.orders[i], &taken);
    }
    if changed {
        save_store(&state.data_dir, &store)?;
    }
    let mut out: Vec<PegOrderDto> = store
        .orders
        .into_iter()
        .map(|o| o.order)
        .filter(|o| o.wallet_id == wallet_id)
        .collect();
    out.sort_by_key(|o| std::cmp::Reverse(o.created_at));
    Ok(out)
}

/// Cancel an order — only while nothing has been paid to it. A native
/// peg-in is read from the chain first: a deposit that already arrived
/// (or a chain that cannot be read) refuses the cancel.
pub fn cancel(state: &mut AppState, order_id: &str) -> Result<PegOrderDto, String> {
    let mut store = load_store(&state.data_dir)?;
    let index = find_index(&store, order_id)?;
    let taken = payouts_taken(&store, order_id);
    let order = &mut store.orders[index];
    refresh(state, order, &taken);
    if order.order.status != AWAITING_DEPOSIT {
        let status = order.order.status.clone();
        save_store(&state.data_dir, &store)?;
        return Err(format!(
            "Order can no longer be cancelled (status: {status})"
        ));
    }
    if let Some(e) = &order.order.last_error {
        return Err(format!(
            "Order cannot be cancelled now: its deposit could not be checked ({e})"
        ));
    }
    let now = now_secs();
    set_status(&mut order.order, CANCELLED, now);
    let dto = order.order.clone();
    save_store(&state.data_dir, &store)?;
    Ok(dto)
}

/// Pay an order's deposit from its wallet — the user-confirmed signing
/// step. Peg-in: a Bitcoin payment to the deposit address (the user may
/// also pay it from elsewhere). Peg-out: the peg-out transaction.
pub fn fund(
    state: &mut AppState,
    order_id: &str,
    fee_rate: Option<f32>,
) -> Result<PegOrderDto, String> {
    let store = load_store(&state.data_dir)?;
    let mut order = store.orders[find_index(&store, order_id)?].clone();
    refuse_simulated(&order)?;
    let provider = provider_of(state, &order)?;
    match provider {
        PegProvider::Native(terms) => native::fund(state, &terms, &mut order, fee_rate)?,
        PegProvider::SideSwap { .. } => sideswap::fund(state, &mut order, fee_rate)?,
    }
    Ok(order.order)
}

/// Claim a native peg-in once its deposit is deep enough — the
/// user-confirmed signing step of a peg-in.
pub fn claim(state: &mut AppState, order_id: &str) -> Result<PegOrderDto, String> {
    let store = load_store(&state.data_dir)?;
    let mut order = store.orders[find_index(&store, order_id)?].clone();
    refuse_simulated(&order)?;
    let provider = provider_of(state, &order)?;
    match provider {
        PegProvider::Native(terms) => native::claim(state, &terms, &mut order)?,
        PegProvider::SideSwap { .. } => {
            return Err(PegError::Unavailable(
                "SideSwap pays out by itself; there is nothing to claim.".into(),
            )
            .to_string())
        }
    }
    Ok(order.order)
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

fn normalize_direction(direction: &str) -> Result<&'static str, String> {
    match direction {
        "in" => Ok("in"),
        "out" => Ok("out"),
        other => Err(format!(
            "Unknown peg direction '{other}' — expected \"in\" or \"out\""
        )),
    }
}

/// The active provider, which must be the one that opened `order`.
fn provider_of(state: &AppState, order: &StoredOrder) -> Result<PegProvider, String> {
    let provider = provider(state)?;
    if provider.name() != order.order.provider {
        return Err(PegError::Unavailable(format!(
            "this order belongs to the {} provider, not to {}, the provider of the active network.",
            order.order.provider,
            provider.name()
        ))
        .to_string());
    }
    Ok(provider)
}

fn refuse_simulated(order: &StoredOrder) -> Result<(), String> {
    if order.order.simulated {
        return Err(PegError::Unavailable(
            "this order was created by the retired simulated provider; nothing can be paid \
             to it or claimed from it."
                .into(),
        )
        .to_string());
    }
    Ok(())
}

/// Moves `order` to `status` (recording it once) at `now`. Returns whether
/// the status changed.
fn set_status(order: &mut PegOrderDto, status: &str, now: u64) -> bool {
    if order.status == status {
        return false;
    }
    order.status = status.to_string();
    order.updated_at = now;
    order.status_history.push(PegStatusEntryDto {
        status: status.to_string(),
        at: now,
    });
    true
}

/// Reads an order's progress from the chains. Returns whether anything
/// about it changed (and must be saved). Never signs anything.
fn refresh(state: &mut AppState, order: &mut StoredOrder, payouts_taken: &[String]) -> bool {
    if is_terminal(&order.order.status) {
        return false;
    }
    if order.order.simulated {
        return retire_simulated(&mut order.order, now_secs());
    }
    let before = order.clone();
    if order.native.is_some() {
        native::refresh(state, order, payouts_taken);
    } else if order.sideswap.is_some() {
        sideswap::refresh(state, order);
    }
    *order != before
}

/// An open order of the retired simulated provider: closed as `expired`
/// (it never had a real deposit address), once.
fn retire_simulated(order: &mut PegOrderDto, now: u64) -> bool {
    if is_terminal(&order.status) {
        return false;
    }
    set_status(order, EXPIRED, now);
    order.last_error =
        Some("The simulated peg provider was retired; this order was never real.".into());
    true
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// FNV-1a 64-bit — stable across platforms and Rust versions, unlike
/// `DefaultHasher`.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// `pg_<8hex>` id, unique within the store. Seeded from wall clock + pid —
/// order ids need uniqueness, not unpredictability.
fn new_order_id(store: &PegStore) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut salt = 0u64;
    loop {
        let h = fnv1a64(format!("{nanos}:{pid}:{salt}").as_bytes());
        let id = format!("pg_{:08x}", (h as u32) ^ ((h >> 32) as u32));
        if !store.orders.iter().any(|o| o.order.order_id == id) {
            return id;
        }
        salt += 1;
    }
}

// ── Persistence ──────────────────────────────────────────────────────────────

/// One order as stored: the host's DTO plus the provider's own state. The
/// DTO is flattened, so files written before the provider state existed
/// (the simulated provider's) load unchanged.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct StoredOrder {
    #[serde(flatten)]
    order: PegOrderDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native: Option<native::NativeState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sideswap: Option<sideswap::SideSwapState>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct PegStore {
    orders: Vec<StoredOrder>,
}

fn store_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(STORE_FILE)
}

fn load_store(data_dir: &Path) -> Result<PegStore, String> {
    let path = store_path(data_dir);
    if !path.exists() {
        return Ok(PegStore::default());
    }
    let raw = fs::read_to_string(&path).map_err(|e| format!("Cannot read {STORE_FILE}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| {
        format!(
            "{STORE_FILE} is corrupt: {e}. It was left untouched; move it away to start with \
             no peg orders."
        )
    })
}

fn save_store(data_dir: &Path, store: &PegStore) -> Result<(), String> {
    fs::create_dir_all(data_dir).map_err(|e| format!("Cannot create data dir: {e}"))?;
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| format!("Cannot serialize peg orders: {e}"))?;
    templar_core::registry::atomic_write(&store_path(data_dir), &json).map_err(|e| e.to_string())
}

/// Writes one order back into the store (by id). The signing steps call it
/// before and after a broadcast, so a signed transaction is on disk before
/// it can reach the network and a retry rebroadcasts the same bytes
/// instead of paying twice.
fn persist(data_dir: &Path, order: &StoredOrder) -> Result<(), String> {
    let mut store = load_store(data_dir)?;
    let index = find_index(&store, &order.order.order_id)?;
    store.orders[index] = order.clone();
    save_store(data_dir, &store)
}

fn find_index(store: &PegStore, order_id: &str) -> Result<usize, String> {
    store
        .orders
        .iter()
        .position(|o| o.order.order_id == order_id)
        .ok_or_else(|| format!("Unknown peg order: {order_id}"))
}

/// Payout txids other orders already account for: a payout is matched to
/// one order only.
fn payouts_taken(store: &PegStore, except_order: &str) -> Vec<String> {
    store
        .orders
        .iter()
        .filter(|o| o.order.order_id != except_order)
        .filter_map(|o| o.order.txid_payout.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!("templar_peg_{}_{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        AppState::new_for_test(dir)
    }

    /// An order exactly as the retired simulated provider wrote it.
    const LEGACY_STORE: &str = r#"{
      "orders": [
        {
          "order_id": "pg_0a1b2c3d", "wallet_id": "w1", "direction": "in",
          "status": "confirming",
          "deposit_address": "tb1qfakepegfakepegfakepegfakepegfakepegqqq",
          "deposit_expected_sats": 100000,
          "payout_address": "tlq1qqpayout", "payout_expected_sats": 99650,
          "created_at": 1700000000, "updated_at": 1700000050, "eta_minutes": 2,
          "txid_deposit": "aa", "txid_payout": null, "simulated": true,
          "status_history": [
            {"status": "awaiting_deposit", "at": 1700000000},
            {"status": "deposit_seen", "at": 1700000020},
            {"status": "confirming", "at": 1700000050}
          ]
        },
        {
          "order_id": "pg_00000002", "wallet_id": "w1", "direction": "out",
          "status": "completed", "deposit_address": "tlq1qqfake",
          "deposit_expected_sats": 50000, "payout_address": "tb1qpayout",
          "payout_expected_sats": 49650, "created_at": 1600000000,
          "updated_at": 1600000110, "eta_minutes": 2, "txid_deposit": "bb",
          "txid_payout": "cc", "simulated": true,
          "status_history": [{"status": "completed", "at": 1600000110}]
        }
      ]
    }"#;

    #[test]
    fn legacy_simulated_orders_load_list_and_are_closed() {
        let mut state = test_state("legacy");
        fs::write(state.data_dir.join(STORE_FILE), LEGACY_STORE).unwrap();
        let listed = list(&mut state, "w1").unwrap();
        assert_eq!(listed.len(), 2);
        // Newest first.
        assert_eq!(listed[0].order_id, "pg_0a1b2c3d");
        let open = &listed[0];
        assert!(open.simulated);
        assert_eq!(open.provider, "simulated");
        // The open one is closed once, as expired, and persisted.
        assert_eq!(open.status, EXPIRED);
        assert_eq!(open.status_history.len(), 4);
        assert!(open.last_error.as_deref().unwrap().contains("retired"));
        assert_eq!(listed[1].status, COMPLETED);
        assert_eq!(listed[1].status_history.len(), 1);
        let again = list(&mut state, "w1").unwrap();
        assert_eq!(again[0].status_history.len(), 4, "closed only once");
        // Never advance, never cancel, never fund or claim.
        let err = cancel(&mut state, "pg_0a1b2c3d").unwrap_err();
        assert!(
            err.contains("no longer be cancelled (status: expired)"),
            "{err}"
        );
        let err = fund(&mut state, "pg_0a1b2c3d", None).unwrap_err();
        assert!(
            err.starts_with("PEG_UNAVAILABLE:") && err.contains("simulated"),
            "{err}"
        );
        let err = claim(&mut state, "pg_00000002").unwrap_err();
        assert!(err.starts_with("PEG_UNAVAILABLE:"), "{err}");
        let s = status(&mut state, "pg_00000002").unwrap();
        assert_eq!(s.txid_payout.as_deref(), Some("cc"));
        // The legacy keys survive the rewrite.
        let raw = fs::read_to_string(state.data_dir.join(STORE_FILE)).unwrap();
        assert!(
            raw.contains("tb1qfakepeg") && !raw.contains("\"native\""),
            "{raw}"
        );
    }

    #[test]
    fn without_a_provider_nothing_new_starts() {
        // A fresh state is on Liquid testnet with no test server.
        let mut state = test_state("noprov");
        let err = quote(&state, "in", 100_000).unwrap_err();
        assert!(err.starts_with("PEG_UNAVAILABLE: Liquid testnet"), "{err}");
        let err = start(&mut state, "w", "in", 100_000, "x").unwrap_err();
        assert!(err.starts_with("PEG_UNAVAILABLE:"), "{err}");
        assert!(quote(&state, "sideways", 1)
            .unwrap_err()
            .contains("direction"));
        // Listing needs no provider.
        assert!(list(&mut state, "w").unwrap().is_empty());
        assert!(status(&mut state, "pg_missing")
            .unwrap_err()
            .contains("Unknown peg order"));
        let (p, why) = provider_info(&state);
        assert!(p.is_none() && why.unwrap().starts_with("PEG_UNAVAILABLE"));
    }

    #[test]
    fn status_history_records_each_status_once() {
        let mut o: PegOrderDto = serde_json::from_value(serde_json::json!({
            "order_id": "pg_1", "wallet_id": "w", "direction": "in",
            "status": "awaiting_deposit", "deposit_address": "", "deposit_expected_sats": 1,
            "payout_address": "", "payout_expected_sats": 1, "created_at": 1,
            "updated_at": 1, "eta_minutes": 1, "txid_deposit": null, "txid_payout": null,
            "simulated": false, "status_history": [], "provider": "native"
        }))
        .unwrap();
        assert!(set_status(&mut o, CONFIRMING, 5));
        assert!(!set_status(&mut o, CONFIRMING, 6));
        assert_eq!(o.updated_at, 5);
        assert_eq!(o.status_history.len(), 1);
        assert!(is_terminal(EXPIRED) && is_terminal(COMPLETED) && !is_terminal(CLAIMABLE));
    }

    #[test]
    fn corrupt_store_is_a_clear_error() {
        let mut state = test_state("corrupt");
        fs::write(state.data_dir.join(STORE_FILE), "{ not json").unwrap();
        let err = list(&mut state, "any").unwrap_err();
        assert!(err.contains("corrupt"));
    }
}
