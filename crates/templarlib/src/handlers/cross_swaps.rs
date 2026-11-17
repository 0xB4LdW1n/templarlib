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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    let mnemonic = mnemonic(state, &local.wallet_id)?;
    let own = swap_public_key(
        &derive_swap_secret_key(mnemonic, if maker { 0 } else { 1 }, local.key_index)
            .map_err(|e| e.to_string())?,
    )
    .to_string();
    let mut changed = false;
    let mut terms = match local.terms.clone() {
        Some(t) => t,
        None => {
            let t = AcceptedTerms::from_state(&row.state);
            let own_part = if maker {
                let key = derive_swap_secret_key(mnemonic, 0, local.key_index)
                    .map_err(|e| e.to_string())?;
                t.maker_pubkey == own
                    && t.payment_hash == sha256_hex(&deterministic_preimage(&key.secret_bytes()))
            } else {
                t.taker_pubkey.as_deref() == Some(own.as_str())
            };
            if !own_part {
                return Err(format!(
                    "The swap coordinator's record of swap {} does not carry this wallet's key; \
                     nothing was signed.",
                    row.id
                ));
            }
            changed = true;
            t
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
        save_local(state, local)?;
    }
    Ok(terms)
}

/// Writes one swap record back.
fn save_local(state: &AppState, local: &StoredAtomicSwap) -> Result<(), String> {
    let mut store = load_store(state)?;
    match store
        .swaps
        .iter_mut()
        .find(|s| s.wallet_id == local.wallet_id && s.offer_id == local.offer_id)
    {
        Some(slot) => *slot = local.clone(),
        None => store.swaps.push(local.clone()),
    }
    save_store(state, &store)
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AtomicStore {
    swaps: Vec<StoredAtomicSwap>,
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
    store.swaps.push(StoredAtomicSwap {
        offer_id: row.id,
        wallet_id: p.wallet_id.clone(),
        role: "maker".into(),
        key_index,
        coordinator: Some(api(state)),
        terms: Some(terms),
    });
    save_store(state, &store)?;
    Ok(enrich(row, &p.wallet_id, "maker", key_index))
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
    if store.swaps.iter().any(|s| s.offer_id == p.offer_id) {
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
    store.swaps.push(StoredAtomicSwap {
        offer_id: row.id,
        wallet_id: p.wallet_id.clone(),
        role: "taker".into(),
        key_index,
        coordinator: Some(api(state)),
        terms: Some(terms),
    });
    save_store(state, &store)?;
    Ok(enrich(row, &p.wallet_id, "taker", key_index))
}

pub fn list_mine(state: &AppState, wallet_id: &str) -> Result<Vec<MyAtomicSwap>, String> {
    let store = load_store(state)?;
    store
        .swaps
        .iter()
        .filter(|s| s.wallet_id == wallet_id)
        .map(|s| fetch(state, s.offer_id).map(|row| enrich(row, wallet_id, &s.role, s.key_index)))
        .collect()
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
    Ok(enrich(row, &p.wallet_id, &local.role, local.key_index))
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
    Ok(enrich(row, &p.wallet_id, &local.role, local.key_index))
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
    Ok(enrich(row, &p.wallet_id, &local.role, local.key_index))
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

fn owned(state: &AppState, wallet_id: &str, offer_id: u64) -> Result<StoredAtomicSwap, String> {
    load_store(state)?
        .swaps
        .into_iter()
        .find(|s| s.wallet_id == wallet_id && s.offer_id == offer_id)
        .ok_or_else(|| "This wallet is not a participant in the swap".into())
}

fn enrich(row: AtomicSwapRow, wallet_id: &str, role: &str, key_index: u32) -> MyAtomicSwap {
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
fn next_index(store: &AtomicStore, wallet_id: &str) -> u32 {
    store
        .swaps
        .iter()
        .filter(|s| s.wallet_id == wallet_id)
        .map(|s| s.key_index)
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
    #[test]
    fn deterministic_secret_is_stable_and_domain_separated() {
        let key = [7u8; 32];
        assert_eq!(deterministic_preimage(&key), deterministic_preimage(&key));
        assert_ne!(deterministic_preimage(&key), key);
        assert_eq!(sha256_hex(&deterministic_preimage(&key)).len(), 64);
    }
}
