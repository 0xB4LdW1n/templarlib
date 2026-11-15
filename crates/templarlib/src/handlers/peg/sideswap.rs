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
}

fn s(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn eta_minutes(direction: &str, required: u32, seen: u32) -> u32 {
    let left = required.saturating_sub(seen);
    if direction == "in" {
        left * BITCOIN_BLOCK_MINUTES + LIQUID_BLOCK_MINUTES
    } else {
        left * LIQUID_BLOCK_MINUTES + BITCOIN_BLOCK_MINUTES
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
        },
        native: None,
        sideswap: Some(SideSwapState {
            url: url.to_string(),
            order_id: order.order_id,
            peg_in,
            pending_deposit_tx: None,
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

pub(super) fn refresh(state: &mut AppState, o: &mut StoredOrder) {
    let result = url_for(state, o).and_then(|url| refresh_with(state, &url, o));
    o.order.last_error = result.err();
}

fn refresh_with(state: &AppState, url: &str, o: &mut StoredOrder) -> Result<(), String> {
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
    let recorded = o.order.txid_deposit.clone();
    let tx = recorded
        .as_deref()
        .and_then(|t| status.list.iter().find(|x| x.tx_hash == t))
        .or_else(|| status.list.first())
        .cloned();
    let now = now_secs();
    let Some(tx) = tx else {
        let expired = o.order.expires_at.is_some_and(|at| now > at);
        if o.order.status == AWAITING_DEPOSIT && ss.pending_deposit_tx.is_none() && expired {
            set_status(&mut o.order, EXPIRED, now);
        }
        return Ok(());
    };
    apply_tx(state, o, &tx)
}

/// Moves the order along SideSwap's report of its deposit.
fn apply_tx(state: &AppState, o: &mut StoredOrder, tx: &PegTx) -> Result<(), String> {
    let now = now_secs();
    o.order.txid_deposit = Some(tx.tx_hash.clone());
    o.order.deposit_received_sats = Some(tx.amount);
    if let Some(total) = tx.total_confs {
        o.order.confirmations_required = total;
    }
    o.order.confirmations = tx.detected_confs.unwrap_or(o.order.confirmations);
    if let Some(payout) = tx.payout {
        o.order.payout_expected_sats = payout;
    }
    if let Some(ss) = o.sideswap.as_mut() {
        ss.pending_deposit_tx = None;
    }
    let required = o.order.confirmations_required;
    o.order.eta_minutes = eta_minutes(&o.order.direction, required, o.order.confirmations);
    match tx.state {
        TxState::InsufficientAmount => {
            set_status(&mut o.order, FAILED, now);
            Err(format!(
                "SideSwap will not pay this deposit: it does not cover the fees ({}).",
                tx.status
            ))
        }
        TxState::Detected => {
            let next = if o.order.confirmations == 0 {
                DEPOSIT_SEEN
            } else {
                CONFIRMING
            };
            set_status(&mut o.order, next, now);
            Ok(())
        }
        TxState::Processing => {
            set_status(&mut o.order, SETTLING, now);
            Ok(())
        }
        TxState::Done => {
            let txid = tx.payout_txid.clone().unwrap_or_default();
            o.order.txid_payout = Some(txid.clone());
            o.order.eta_minutes = 0;
            if payout_confirmed(state, o, &txid)? {
                set_status(&mut o.order, COMPLETED, now);
                Ok(())
            } else {
                set_status(&mut o.order, SETTLING, now);
                Err(format!(
                    "SideSwap reports payout {txid}; it is not confirmed to the receive address \
                     on chain yet."
                ))
            }
        }
    }
}

/// Whether the payout `txid` is in a block and pays the receive address,
/// by the wallet's own chain view (Liquid for a peg-in, Bitcoin for a
/// peg-out).
fn payout_confirmed(state: &AppState, o: &StoredOrder, txid: &str) -> Result<bool, String> {
    if o.order.direction == "in" {
        let script = state
            .liquid_network
            .parse_address(&o.order.payout_address)
            .map_err(s)?
            .script_pubkey();
        let txid: elements::Txid = txid.parse().map_err(|e| format!("Payout txid: {e}"))?;
        let confs = state
            .liquid_chain()?
            .tx_confirmations(&txid, &script)
            .map_err(s)?;
        Ok(confs.is_some_and(|c| c >= 1))
    } else {
        let spk = core_peg::bitcoin_script_for(&o.order.payout_address, bitcoin::Network::Testnet)
            .map_err(s)?;
        let view = BitcoinChainView::connect(&state.bitcoin_backend().electrum_url).map_err(s)?;
        let Some(item) = view
            .history(&spk)
            .map_err(s)?
            .into_iter()
            .find(|i| i.txid.to_string() == txid)
        else {
            return Ok(false);
        };
        let pays = view
            .transaction(&item.txid)
            .map_err(s)?
            .output
            .iter()
            .any(|out| out.script_pubkey == spk);
        Ok(pays && item.height.is_some())
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
    let fresh = refresh_with(state, &url, o);
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
        let view = BitcoinChainView::connect(&state.bitcoin_backend().electrum_url).map_err(s)?;
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
                .map_err(s)?;
            if !btc.sign(&mut psbt).map_err(s)? {
                return Err("The deposit could not be fully signed by this wallet.".into());
            }
            let tx = psbt.extract_tx();
            let raw = bdk::bitcoin::consensus::encode::serialize(&tx);
            o.order.txid_deposit = Some(tx.txid().to_string());
            if let Some(ss) = o.sideswap.as_mut() {
                ss.pending_deposit_tx = Some(hex::encode(&raw));
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
                .map_err(s)?;
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
