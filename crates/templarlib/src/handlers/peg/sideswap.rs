//! The SideSwap provider on Liquid testnet
//! ([`templar_core::sideswap`]): a custodial swap by a third party, not a
//! peg. SideSwap gives a deposit address per order and pays the other
//! chain's coins to the receive address itself, so there is no claim step.
//!
//! Only the receive address and the order's parameters go to SideSwap. What
//! comes back is checked: the deposit address must be an address of the
//! expected testnet chain, every status must be for this order's addresses,
//! and a payout SideSwap calls done must be visible on the wallet's own
//! chain view, paying the receive address, before the order completes.

use lwk_wollet::elements::{self, bitcoin, encode};
use serde::{Deserialize, Serialize};
use templar_core::peg::{self as core_peg, BitcoinChainView};
use templar_core::sideswap::{PegTx, ServerStatus, SideSwapClient, TxState};
use templar_core::{CoinChain, PegError, PegProvider, WalletProfile};

use super::native::NewOrder;
use super::{
    now_secs, persist, set_status, PegOrderDto, PegQuoteDto, PegStatusEntryDto, StoredOrder,
    AWAITING_DEPOSIT, COMPLETED, CONFIRMING, DEPOSIT_SEEN, EXPIRED, FAILED, SETTLING,
};
use crate::state::AppState;

/// Nominal confirmations SideSwap waits for (each status reports the real
/// count of a deposit) and the block intervals the ETA assumes.
const NOMINAL_CONFIRMATIONS: u32 = 2;
const BITCOIN_BLOCK_MINUTES: u32 = 10;
const LIQUID_BLOCK_MINUTES: u32 = 1;
/// Fee rate of a peg-in deposit the wallet pays itself, unless given.
const DEFAULT_DEPOSIT_FEE_RATE: f32 = 1.0;

/// What the SideSwap provider keeps beside the DTO.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(super) struct SideSwapState {
    /// The endpoint the order was opened on.
    pub url: String,
    /// SideSwap's order id.
    pub order_id: String,
    pub peg_in: bool,
    /// A signed deposit, written before its broadcast.
    #[serde(default)]
    pub pending_deposit_tx: Option<String>,
    /// The deposit this wallet signed: SideSwap's reports are read for it
    /// only, never for another transaction it names.
    #[serde(default)]
    pub funded_txid: Option<String>,
    /// What the quote promised; a payout must bring at least this much.
    #[serde(default)]
    pub quoted_payout: Option<u64>,
    /// Transactions the receive address had when the order was opened:
    /// none of them is the payout.
    #[serde(default)]
    pub receive_known_txids: Vec<String>,
}

/// Rank of a status along the order's way; SideSwap's reports only move
/// an order forward.
fn rank(status: &str) -> u8 {
    match status {
        AWAITING_DEPOSIT => 0,
        DEPOSIT_SEEN => 1,
        CONFIRMING => 2,
        SETTLING => 3,
        _ => 4,
    }
}

/// Moves `order` to `next` only if that is further along.
fn advance(order: &mut PegOrderDto, next: &str, now: u64) {
    if rank(next) > rank(&order.status) {
        set_status(order, next, now);
    }
}

/// The deposit report to follow: the wallet's own deposit when it paid
/// one, else the one already followed, else (nothing followed yet) the
/// first. A followed deposit SideSwap no longer lists is waited for, never
/// swapped for another transaction.
fn pick_tx<'a>(
    list: &'a [PegTx],
    funded: Option<&str>,
    recorded: Option<&str>,
) -> Option<&'a PegTx> {
    match funded.or(recorded) {
        Some(followed) => list.iter().find(|t| t.tx_hash == followed),
        None => list.first(),
    }
}

/// A payout transaction SideSwap names may count only if it is new to the
/// receive address and no other order counted it.
fn payout_is_new(txid: &str, known: &[String], taken: &[String]) -> Result<(), String> {
    if known.iter().any(|k| k == txid) {
        return Err(format!(
            "SideSwap names payout {txid}, which the receive address had before this order."
        ));
    }
    if taken.iter().any(|t| t == txid) {
        return Err(format!(
            "SideSwap names payout {txid}, which another order already counted."
        ));
    }
    Ok(())
}

fn s(e: impl std::fmt::Display) -> String {
    e.to_string()
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

/// The quote for `amount_sats` under SideSwap's terms. Peg-in: SideSwap
/// keeps its percentage. Peg-out: its percentage and the Bitcoin fee of
/// its payout (`peg_out_bitcoin_tx_vsize` × the fastest fee rate it
/// quotes), as SideSwap's own client computes it.
pub(super) fn quote_from(
    terms: &ServerStatus,
    direction: &str,
    amount_sats: u64,
) -> Result<PegQuoteDto, String> {
    let pegin = direction == "in";
    let (min, percent) = if pegin {
        (terms.min_peg_in_amount, terms.server_fee_percent_peg_in)
    } else {
        (terms.min_peg_out_amount, terms.server_fee_percent_peg_out)
    };
    if amount_sats < min {
        return Err(format!("Amount is below the minimum of {min} sats"));
    }
    let max = core_peg::MAX_MONEY_SATS;
    if amount_sats > max {
        return Err(format!("Amount is above the maximum of {max} sats"));
    }
    let kept = (amount_sats as f64 * (1.0 - percent / 100.0)).round() as u64;
    let service_fee_sats = amount_sats.saturating_sub(kept);
    let network_fee_sats = if pegin {
        0
    } else {
        let rate = terms.fastest_fee_rate().unwrap_or(1.0);
        (terms.peg_out_bitcoin_tx_vsize as f64 * rate).round() as u64
    };
    let receive_sats = kept
        .checked_sub(network_fee_sats)
        .filter(|r| *r > 0)
        .ok_or_else(|| {
            format!("Amount is below the minimum of {min} sats once SideSwap's fees are paid")
        })?;
    Ok(PegQuoteDto {
        direction: direction.to_string(),
        amount_sats,
        rate: 1.0,
        service_fee_sats,
        network_fee_sats,
        receive_sats,
        min_sats: min,
        max_sats: max,
        eta_minutes: eta_minutes(direction, NOMINAL_CONFIRMATIONS, 0),
        simulated: false,
        provider: "sideswap".into(),
        confirmations_required: NOMINAL_CONFIRMATIONS,
        network_fee_included: true,
    })
}

pub(super) fn quote(url: &str, direction: &str, amount_sats: u64) -> Result<PegQuoteDto, String> {
    let terms = SideSwapClient::connect(url)
        .and_then(|mut c| c.server_status())
        .map_err(s)?;
    quote_from(&terms, direction, amount_sats)
}

/// The deposit address SideSwap gave must be an address of the chain the
/// deposit is paid on: Bitcoin testnet for a peg-in, Liquid testnet for a
/// peg-out.
fn check_deposit_address(state: &AppState, peg_in: bool, addr: &str) -> Result<(), String> {
    let ok = if peg_in {
        core_peg::bitcoin_script_for(addr, bitcoin::Network::Testnet).is_ok()
    } else {
        state.liquid_network.parse_address(addr).is_ok()
    };
    if !ok {
        return Err(PegError::Chain(
            "SideSwap answered with a deposit address of another chain".into(),
        )
        .to_string());
    }
    Ok(())
}

pub(super) fn start(
    state: &mut AppState,
    url: &str,
    n: NewOrder<'_>,
) -> Result<StoredOrder, String> {
    let peg_in = n.direction == "in";
    // The payout address is validated before anything leaves the wallet.
    if peg_in {
        state
            .liquid_network
            .parse_address(n.payout_address)
            .map_err(|e| format!("Payout address: {e}"))?;
    } else {
        core_peg::bitcoin_script_for(n.payout_address, bitcoin::Network::Testnet).map_err(s)?;
    }
    let mut client = SideSwapClient::connect(url).map_err(s)?;
    let terms = client.server_status().map_err(s)?;
    let q = quote_from(&terms, n.direction, n.amount_sats)?;
    let fee_rate = if peg_in {
        None
    } else {
        terms.fastest_fee_rate()
    };
    // What the receive address already has, before SideSwap knows it: no
    // later payout claim can point at one of these.
    let known: Vec<String> = if peg_in {
        let script = state
            .liquid_network
            .parse_address(n.payout_address)
            .map_err(s)?
            .script_pubkey();
        state
            .liquid_chain()?
            .script_txids(&script)
            .map_err(s)?
            .into_iter()
            .map(|t| t.to_string())
            .collect()
    } else {
        let spk =
            core_peg::bitcoin_script_for(n.payout_address, bitcoin::Network::Testnet).map_err(s)?;
        BitcoinChainView::connect(&state.bitcoin_backend())
            .and_then(|v| v.history(&spk))
            .map_err(s)?
            .into_iter()
            .map(|i| i.txid.to_string())
            .collect()
    };
    let order = client.peg(peg_in, n.payout_address, fee_rate).map_err(s)?;
    check_deposit_address(state, peg_in, &order.peg_addr)?;
    let now = now_secs();
    Ok(StoredOrder {
        order: PegOrderDto {
            order_id: n.order_id,
            wallet_id: n.wallet_id.to_string(),
            direction: n.direction.to_string(),
            status: AWAITING_DEPOSIT.to_string(),
            deposit_address: order.peg_addr,
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
            provider: "sideswap".into(),
            confirmations: 0,
            confirmations_required: q.confirmations_required,
            deposit_received_sats: None,
            txid_claim: None,
            valid_until_liquid_height: None,
            last_error: None,
            expires_at: (order.expires_at > 0).then_some(order.expires_at / 1000),
            deposits: Vec::new(),
        },
        native: None,
        sideswap: Some(SideSwapState {
            url: url.to_string(),
            order_id: order.order_id,
            peg_in,
            pending_deposit_tx: None,
            funded_txid: None,
            quoted_payout: Some(q.receive_sats),
            receive_known_txids: known,
        }),
    })
}

fn state_of(o: &StoredOrder) -> Result<&SideSwapState, String> {
    o.sideswap
        .as_ref()
        .ok_or_else(|| "The order has no SideSwap data".to_string())
}

/// The endpoint an order can be followed through: the active provider must
/// be SideSwap at the same URL.
fn url_for(state: &AppState, o: &StoredOrder) -> Result<String, String> {
    let ss = state_of(o)?;
    match super::provider(state) {
        Ok(PegProvider::SideSwap { url }) if url == ss.url => Ok(url),
        _ => Err(PegError::Unavailable(
            "this SideSwap order is followed on Liquid testnet with SideSwap as the peg \
             provider; switch there to follow it."
                .into(),
        )
        .to_string()),
    }
}

pub(super) fn refresh(state: &mut AppState, o: &mut StoredOrder, payouts_taken: &[String]) {
    let result = url_for(state, o).and_then(|url| refresh_with(state, &url, o, payouts_taken));
    o.order.last_error = result.err();
}

fn refresh_with(
    state: &AppState,
    url: &str,
    o: &mut StoredOrder,
    payouts_taken: &[String],
) -> Result<(), String> {
    let ss = state_of(o)?.clone();
    let status = SideSwapClient::connect(url)
        .and_then(|mut c| c.peg_status(ss.peg_in, &ss.order_id))
        .map_err(s)?;
    if status.addr != o.order.deposit_address || status.addr_recv != o.order.payout_address {
        return Err(PegError::Chain(
            "SideSwap answered with other addresses for this order; it is not followed".into(),
        )
        .to_string());
    }
    let now = now_secs();
    let funded = ss.funded_txid.as_deref();
    let Some(tx) = pick_tx(&status.list, funded, o.order.txid_deposit.as_deref()).cloned() else {
        let expired = o.order.expires_at.is_some_and(|at| now > at);
        if o.order.status == AWAITING_DEPOSIT && ss.pending_deposit_tx.is_none() && expired {
            set_status(&mut o.order, EXPIRED, now);
        }
        return Ok(());
    };
    if let Some(ss) = o.sideswap.as_mut() {
        ss.pending_deposit_tx = None;
    }
    let Some(payout) = apply_report(&mut o.order, &tx, funded.is_some(), now)? else {
        return Ok(());
    };
    match payout_verified(state, o, &payout, payouts_taken)? {
        Ok(()) => {
            o.order.txid_payout = Some(payout);
            o.order.eta_minutes = 0;
            set_status(&mut o.order, COMPLETED, now);
            Ok(())
        }
        Err(why) => {
            advance(&mut o.order, SETTLING, now);
            Err(why)
        }
    }
}

/// Applies SideSwap's report of the deposit the order follows. Returns
/// the payout txid to verify when SideSwap says it paid. Status only moves
/// forward; the deposit txid, once known, is never replaced; and SideSwap
/// alone cannot fail an order whose deposit this wallet paid.
fn apply_report(
    order: &mut PegOrderDto,
    tx: &PegTx,
    wallet_funded: bool,
    now: u64,
) -> Result<Option<String>, String> {
    if order.txid_deposit.is_none() {
        order.txid_deposit = Some(tx.tx_hash.clone());
    }
    order.deposit_received_sats = Some(tx.amount);
    if let Some(total) = tx.total_confs {
        order.confirmations_required = total;
    }
    order.confirmations = tx.detected_confs.unwrap_or(order.confirmations);
    if let Some(payout) = tx.payout {
        order.payout_expected_sats = payout;
    }
    let required = order.confirmations_required;
    order.eta_minutes = eta_minutes(&order.direction, required, order.confirmations);
    match tx.state {
        TxState::InsufficientAmount => {
            let why = format!(
                "SideSwap will not pay this deposit: it does not cover the fees ({}).",
                tx.status
            );
            if !wallet_funded {
                set_status(order, FAILED, now);
            }
            Err(why)
        }
        TxState::Detected => {
            let next = if order.confirmations == 0 {
                DEPOSIT_SEEN
            } else {
                CONFIRMING
            };
            advance(order, next, now);
            Ok(None)
        }
        TxState::Processing => {
            advance(order, SETTLING, now);
            Ok(None)
        }
        TxState::Done => Ok(tx.payout_txid.clone()),
    }
}

/// Whether payout `txid` counts, by the wallet's own chain view: new to
/// the receive address and nobody else's, in a block, paying the receive
/// address at least what the quote promised. The inner error says why not
/// (yet).
fn payout_verified(
    state: &AppState,
    o: &StoredOrder,
    txid: &str,
    payouts_taken: &[String],
) -> Result<Result<(), String>, String> {
    let ss = state_of(o)?;
    if let Err(why) = payout_is_new(txid, &ss.receive_known_txids, payouts_taken) {
        return Ok(Err(why));
    }
    let promised = ss.quoted_payout.unwrap_or(o.order.payout_expected_sats);
    if o.order.direction == "in" {
        // A Liquid payout is confidential: its amount is read from the
        // wallet that owns the receive address, once synced.
        let script = state
            .liquid_network
            .parse_address(&o.order.payout_address)
            .map_err(s)?
            .script_pubkey();
        let parsed: elements::Txid = txid.parse().map_err(|e| format!("Payout txid: {e}"))?;
        let confs = state
            .liquid_chain()?
            .tx_confirmations(&parsed, &script)
            .map_err(s)?;
        if confs.is_none_or(|c| c < 1) {
            return Ok(Err(format!(
                "SideSwap reports payout {txid}; it is not in a block paying the receive address \
                 yet."
            )));
        }
        let received = state
            .liquid
            .as_ref()
            .filter(|_| state.active_wallet_id.as_deref() == Some(o.order.wallet_id.as_str()))
            .and_then(|liq| {
                let wtx = liq.wollet.transaction(&parsed).ok()??;
                wtx.balance.get(&liq.policy_asset()).copied()
            });
        Ok(match received {
            Some(got) if got >= promised as i64 => Ok(()),
            Some(got) => Err(format!(
                "SideSwap's payout {txid} brought {got} sats, less than the {promised} quoted."
            )),
            None => Err(format!(
                "SideSwap's payout {txid} is in a block; open and sync this wallet to check its \
                 amount."
            )),
        })
    } else {
        let spk = core_peg::bitcoin_script_for(&o.order.payout_address, bitcoin::Network::Testnet)
            .map_err(s)?;
        let view = BitcoinChainView::connect(&state.bitcoin_backend()).map_err(s)?;
        let Some(item) = view
            .history(&spk)
            .map_err(s)?
            .into_iter()
            .find(|i| i.txid.to_string() == txid)
        else {
            return Ok(Err(format!(
                "SideSwap reports payout {txid}; the receive address has not received it."
            )));
        };
        if item.height.is_none() {
            return Ok(Err(format!(
                "SideSwap's payout {txid} is not in a block yet."
            )));
        }
        let paid: u64 = view
            .transaction(&item.txid)
            .map_err(s)?
            .output
            .iter()
            .filter(|out| out.script_pubkey == spk)
            .map(|out| out.value.to_sat())
            .sum();
        Ok(if paid < promised {
            Err(format!(
                "SideSwap's payout {txid} pays {paid} sats, less than the {promised} quoted."
            ))
        } else {
            Ok(())
        })
    }
}

/// Opens `wallet_id` and checks it signs with this app's own keys.
fn open_software_wallet(state: &mut AppState, wallet_id: &str) -> Result<(), String> {
    let entry = state.registry.find(wallet_id).ok_or("Wallet not found")?;
    if !matches!(entry.profile, WalletProfile::Software { .. }) {
        return Err(
            "Paying a SideSwap deposit from here needs a software wallet; pay the deposit \
             address from the send screen instead."
                .into(),
        );
    }
    if state.active_wallet_id.as_deref() != Some(wallet_id) {
        crate::handlers::wallet_ops::open_wallet(state, wallet_id)?;
    }
    Ok(())
}

pub(super) fn fund(
    state: &mut AppState,
    o: &mut StoredOrder,
    fee_rate: Option<f32>,
) -> Result<(), String> {
    let url = url_for(state, o)?;
    let fresh = refresh_with(state, &url, o, &[]);
    o.order.last_error = fresh.as_ref().err().cloned();
    persist(&state.data_dir, o)?;
    fresh?;
    match o.order.status.as_str() {
        AWAITING_DEPOSIT => {}
        EXPIRED => {
            return Err(
                PegError::Expired("SideSwap's order expired; start a new one.".into()).to_string(),
            )
        }
        other => {
            return Err(PegError::NotReady(format!(
                "this order's deposit was already made or it is closed (status: {other})."
            ))
            .to_string())
        }
    }
    open_software_wallet(state, &o.order.wallet_id)?;
    let pending = state_of(o)?.pending_deposit_tx.clone();
    if o.order.direction == "in" {
        let view = BitcoinChainView::connect(&state.bitcoin_backend()).map_err(s)?;
        if let Some(raw) = pending {
            let bytes = hex::decode(raw).map_err(|e| format!("Stored deposit: {e}"))?;
            view.broadcast_raw(&bytes).map_err(s)?;
        } else {
            let btc = state.bitcoin.as_ref().ok_or("Bitcoin wallet not open")?;
            let amount = o.order.deposit_expected_sats;
            let mut psbt = btc
                .create_tx_multi(
                    &[(o.order.deposit_address.clone(), amount, false)],
                    fee_rate.unwrap_or(DEFAULT_DEPOSIT_FEE_RATE),
                    None,
                    None,
                    &state.frozen_on(CoinChain::Bitcoin),
                )
                .map_err(|e| super::build_failure(e, &super::chain_names(state), "the deposit"))?;
            if !btc.sign(&mut psbt).map_err(s)? {
                return Err("The deposit could not be fully signed by this wallet.".into());
            }
            let tx = psbt.extract_tx();
            let raw = bdk::bitcoin::consensus::encode::serialize(&tx);
            o.order.txid_deposit = Some(tx.txid().to_string());
            if let Some(ss) = o.sideswap.as_mut() {
                ss.pending_deposit_tx = Some(hex::encode(&raw));
                ss.funded_txid = Some(tx.txid().to_string());
            }
            persist(&state.data_dir, o)?;
            btc.broadcast(tx).map_err(s)?;
        }
    } else {
        let chain = state.liquid_chain()?;
        let tx: elements::Transaction = if let Some(raw) = pending {
            let bytes = hex::decode(raw).map_err(|e| format!("Stored deposit: {e}"))?;
            encode::deserialize(&bytes).map_err(|e| format!("Stored deposit: {e}"))?
        } else {
            let liq = state.liquid.as_ref().ok_or("Liquid wallet not open")?;
            let amount = o.order.deposit_expected_sats;
            let target = state
                .liquid_network
                .parse_address(&o.order.deposit_address)
                .map_err(s)?
                .script_pubkey();
            let mut pset = liq
                .create_tx_multi(
                    &[(
                        o.order.deposit_address.clone(),
                        amount,
                        liq.policy_asset_hex(),
                    )],
                    None,
                    &state.frozen_on(CoinChain::Liquid),
                )
                .map_err(|e| {
                    super::build_failure(
                        e,
                        &super::chain_names(state),
                        &format!("the deposit of {amount} sat to SideSwap"),
                    )
                })?;
            if !pset
                .outputs()
                .iter()
                .any(|out| out.script_pubkey == target && out.amount == Some(amount))
            {
                return Err("The deposit does not pay SideSwap's address.".into());
            }
            liq.sign(&mut pset).map_err(s)?;
            let tx = liq.finalize(&mut pset).map_err(s)?;
            o.order.txid_deposit = Some(tx.txid().to_string());
            if let Some(ss) = o.sideswap.as_mut() {
                ss.pending_deposit_tx = Some(encode::serialize_hex(&tx));
                ss.funded_txid = Some(tx.txid().to_string());
            }
            persist(&state.data_dir, o)?;
            tx
        };
        chain.broadcast(&tx).map_err(s)?;
    }
    eprintln!(
        "[templarlib] SideSwap order {} deposit broadcast: {}",
        o.order.order_id,
        o.order.txid_deposit.as_deref().unwrap_or("?")
    );
    set_status(&mut o.order, DEPOSIT_SEEN, now_secs());
    persist(&state.data_dir, o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> ServerStatus {
        ServerStatus {
            min_peg_in_amount: 10_000,
            min_peg_out_amount: 25_000,
            server_fee_percent_peg_in: 0.1,
            server_fee_percent_peg_out: 0.1,
            peg_out_bitcoin_tx_vsize: 141,
            bitcoin_fee_rates: vec![(2, 3.0), (6, 1.0)],
        }
    }

    fn report(hash: &str, state: TxState, confs: Option<u32>) -> PegTx {
        PegTx {
            tx_hash: hash.into(),
            vout: 0,
            status: "x".into(),
            amount: 100_000,
            payout: Some(99_000),
            state,
            detected_confs: confs,
            total_confs: Some(2),
            payout_txid: (state == TxState::Done).then(|| "ff".repeat(32)),
        }
    }

    fn order(status: &str) -> PegOrderDto {
        serde_json::from_value(serde_json::json!({
            "order_id": "pg_1", "wallet_id": "w", "direction": "out", "status": status,
            "deposit_address": "x", "deposit_expected_sats": 100000, "payout_address": "y",
            "payout_expected_sats": 99000, "created_at": 1, "updated_at": 1, "eta_minutes": 1,
            "txid_deposit": null, "txid_payout": null, "simulated": false,
            "status_history": [], "provider": "sideswap"
        }))
        .unwrap()
    }

    #[test]
    fn sideswap_cannot_swap_the_deposit_or_turn_the_order_back() {
        let ours = "aa".repeat(32);
        let theirs = "bb".repeat(32);
        let list = vec![
            report(&theirs, TxState::Done, None),
            report(&ours, TxState::Detected, Some(1)),
        ];
        // The wallet's own deposit is the one followed; when SideSwap does
        // not list it, nothing is.
        assert_eq!(pick_tx(&list, Some(&ours), None).unwrap().tx_hash, ours);
        assert!(pick_tx(&list[..1], Some(&ours), None).is_none());
        assert!(pick_tx(&list[..1], None, Some(&ours)).is_none());
        assert_eq!(pick_tx(&list, None, None).unwrap().tx_hash, theirs);

        let mut o = order(CONFIRMING);
        o.txid_deposit = Some(ours.clone());
        // A report for another transaction never replaces the deposit.
        apply_report(
            &mut o,
            &report(&theirs, TxState::Detected, Some(0)),
            true,
            5,
        )
        .unwrap();
        assert_eq!(o.txid_deposit.as_deref(), Some(ours.as_str()));
        // Nor does a report move the order back.
        assert_eq!(o.status, CONFIRMING);
        apply_report(&mut o, &report(&ours, TxState::Processing, None), true, 6).unwrap();
        assert_eq!(o.status, SETTLING);
        apply_report(&mut o, &report(&ours, TxState::Detected, Some(1)), true, 7).unwrap();
        assert_eq!(o.status, SETTLING);
        // SideSwap alone cannot fail a deposit the wallet paid…
        let err = apply_report(
            &mut o,
            &report(&ours, TxState::InsufficientAmount, None),
            true,
            8,
        )
        .unwrap_err();
        assert!(err.contains("does not cover the fees"), "{err}");
        assert_eq!(o.status, SETTLING);
        // …but it can say so of one paid from elsewhere.
        let mut other = order(DEPOSIT_SEEN);
        let _ = apply_report(
            &mut other,
            &report(&theirs, TxState::InsufficientAmount, None),
            false,
            9,
        );
        assert_eq!(other.status, FAILED);
        // "Done" only names the payout to verify; it completes nothing.
        let payout = apply_report(&mut o, &report(&ours, TxState::Done, None), true, 10).unwrap();
        assert_eq!(payout, Some("ff".repeat(32)));
        assert_eq!(o.status, SETTLING);
    }

    #[test]
    fn a_payout_must_be_new_and_nobody_elses() {
        let p = "cc".repeat(32);
        assert!(payout_is_new(&p, &[], &[]).is_ok());
        let err = payout_is_new(&p, std::slice::from_ref(&p), &[]).unwrap_err();
        assert!(err.contains("had before this order"), "{err}");
        let err = payout_is_new(&p, &[], std::slice::from_ref(&p)).unwrap_err();
        assert!(err.contains("another order"), "{err}");
    }

    #[test]
    fn sideswap_quotes_follow_its_terms() {
        let q = quote_from(&terms(), "in", 100_000).unwrap();
        assert_eq!(q.provider, "sideswap");
        assert_eq!(q.service_fee_sats, 100);
        assert_eq!(q.network_fee_sats, 0);
        assert_eq!(q.receive_sats, 99_900);
        assert_eq!(q.min_sats, 10_000);
        assert!(q.network_fee_included);

        let q = quote_from(&terms(), "out", 100_000).unwrap();
        assert_eq!(q.service_fee_sats, 100);
        assert_eq!(q.network_fee_sats, 423, "141 vB at 3 sat/vB");
        assert_eq!(q.receive_sats, 100_000 - 100 - 423);
        assert_eq!(q.min_sats, 25_000);

        let err = quote_from(&terms(), "out", 24_999).unwrap_err();
        assert!(err.contains("below the minimum of 25000"), "{err}");
        let mut pricey = terms();
        pricey.bitcoin_fee_rates = vec![(2, 1_000.0)];
        let err = quote_from(&pricey, "out", 100_000).unwrap_err();
        assert!(err.contains("once SideSwap's fees are paid"), "{err}");
    }
}
