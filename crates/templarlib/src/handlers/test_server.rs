//! Joining a Templar test server: `set_test_server` fetches and validates
//! `<url>/api/config` and applies it, `get_test_server` reports it (and,
//! asked to, whether the server still says the same), `clear_test_server`
//! leaves it. Every answer also says which servers the engine talks to now
//! and where each one came from.

use templar_core::endpoints::redact_userinfo;
use templar_core::test_server::{
    fetch_profile, request_faucet, FaucetAsset, FAUCET_BITCOIN_REGTEST,
};
use templar_core::{FaucetError, LiquidNetwork, Resolved, Source};

use crate::state::{AppState, TestServerApplied};
use crate::types::{
    ActiveEndpointsDto, BitcoinEndpointDto, FaucetInfoDto, FaucetPaymentDto, LiquidEndpointDto,
    OrderbookEndpointsDto, SourcedUrlDto, TestServerAppliedDto, TestServerCheckDto, TestServerDto,
};

/// The stored profile; with `check`, the server is asked again (bounded).
pub fn get(state: &AppState, check: bool) -> TestServerDto {
    let check = match (&state.test_server, check) {
        (Some(stored), true) => Some(match fetch_profile(&stored.base_url) {
            Ok(fresh) => TestServerCheckDto {
                reachable: true,
                error: None,
                server_instance_id: Some(fresh.regtest.instance_id.clone()),
                stale: stored.differs_from(&fresh),
            },
            Err(e) => TestServerCheckDto {
                reachable: false,
                error: Some(e.to_string()),
                server_instance_id: None,
                stale: false,
            },
        }),
        _ => None,
    };
    dto(state, check, None)
}

/// Fetches, validates, stores and applies the server at `url`. Nothing is
/// applied when any check fails.
pub fn set(state: &mut AppState, url: &str) -> Result<TestServerDto, String> {
    let profile = fetch_profile(url).map_err(|e| e.to_string())?;
    let check = TestServerCheckDto {
        reachable: true,
        error: None,
        server_instance_id: Some(profile.regtest.instance_id.clone()),
        stale: false,
    };
    let applied = state.apply_test_server(Some(profile))?;
    Ok(dto(state, Some(check), Some(applied)))
}

/// Leaves the joined test server (a no-op apart from closing the open
/// wallet when none is joined).
pub fn clear(state: &mut AppState) -> Result<TestServerDto, String> {
    let applied = state.apply_test_server(None)?;
    Ok(dto(state, None, Some(applied)))
}

fn dto(
    state: &AppState,
    check: Option<TestServerCheckDto>,
    applied: Option<TestServerApplied>,
) -> TestServerDto {
    TestServerDto {
        configured: state.test_server.is_some(),
        profile: state.test_server.clone(),
        check,
        applied: applied.map(|a| TestServerAppliedDto {
            liquid_network: state.liquid_network.name().to_string(),
            network_switched: a.network_switched,
            wallet_closed: a.wallet_closed,
            regtest_cache_reset: a.regtest_cache_reset,
        }),
        active: active(state),
        faucet: state.test_server.as_ref().map(|p| FaucetInfoDto {
            url: redact_userinfo(&p.regtest.faucet_url),
            assets_source: if p.regtest.faucet.is_some() {
                Source::Profile
            } else {
                Source::Default
            }
            .as_str()
            .to_string(),
            assets: p.regtest.faucet_assets(),
            available: state.endpoints().faucet(&state.liquid_network).is_some(),
        }),
    }
}

/// The joined lab's faucet on the active network, or why there is none
/// (`FAUCET_UNAVAILABLE: …`). Contacts nothing: `test_server_faucet` asks
/// it before opening the wallet.
pub fn faucet_terms(state: &AppState) -> Result<(String, Vec<FaucetAsset>), String> {
    let unavailable = |why: String| FaucetError::Unavailable(why).to_string();
    if state.test_server.is_none() {
        return Err(unavailable(
            "no test server is joined; join one (Settings → Test server) to use its faucet.".into(),
        ));
    }
    let (url, assets) = state
        .endpoints()
        .faucet(&state.liquid_network)
        .ok_or_else(|| {
            unavailable(format!(
                "the wallet is on {}, not on the test server's regtest; the lab's faucet pays \
                 its regtest only.",
                state.liquid_network.name()
            ))
        })?;
    if assets.is_empty() {
        return Err(unavailable("the test server's faucet pays nothing.".into()));
    }
    Ok((url, assets))
}

/// Asks the joined lab's faucet to pay the open wallet some `asset`, at a
/// fresh receive address of the wallet on the asset's chain. Only the
/// address, the network and the asset are sent; nothing is signed.
pub fn faucet(
    state: &AppState,
    (url, assets): (String, Vec<FaucetAsset>),
    asset: &str,
) -> Result<FaucetPaymentDto, String> {
    let unavailable = |why: String| FaucetError::Unavailable(why).to_string();
    let wanted = asset.trim();
    let entry = assets
        .iter()
        .find(|a| {
            a.asset.eq_ignore_ascii_case(wanted)
                || a.ticker.eq_ignore_ascii_case(wanted)
                || a.asset_id
                    .as_deref()
                    .is_some_and(|id| id.eq_ignore_ascii_case(wanted))
        })
        .ok_or_else(|| {
            let pays: Vec<&str> = assets.iter().map(|a| a.ticker.as_str()).collect();
            unavailable(format!(
                "the lab's faucet does not pay {:?}; it pays {}.",
                templar_core::http::printable(wanted, 64),
                pays.join(", ")
            ))
        })?;
    let address = if entry.network == FAUCET_BITCOIN_REGTEST {
        if state.bitcoin_backend().network != bdk::bitcoin::Network::Regtest {
            return Err(unavailable(
                "the wallet's Bitcoin side is not the lab's Bitcoin regtest.".into(),
            ));
        }
        let btc = state
            .bitcoin
            .as_ref()
            .ok_or_else(|| unavailable("this wallet has no Bitcoin side.".into()))?;
        btc.get_fresh_address()
            .map_err(|e| e.to_string())?
            .address
            .to_string()
    } else {
        let liq = state
            .liquid
            .as_ref()
            .ok_or_else(|| unavailable("this wallet has no Liquid side.".into()))?;
        liq.get_new_address().map_err(|e| e.to_string())?
    };
    let paid =
        request_faucet(&url, &entry.network, &address, &entry.asset).map_err(|e| e.to_string())?;
    eprintln!(
        "[templarlib] faucet paid {} of {} on {}: {}",
        paid.amount_sat, entry.asset, entry.network, paid.txid
    );
    Ok(FaucetPaymentDto {
        txid: paid.txid,
        asset: entry.asset.clone(),
        network: entry.network.clone(),
        amount_sat: paid.amount_sat,
        address,
        ticker: entry.ticker.clone(),
        precision: entry.precision,
        asset_id: entry.asset_id.clone(),
    })
}

fn sourced(r: Resolved<String>) -> SourcedUrlDto {
    SourcedUrlDto {
        url: redact_userinfo(&r.value),
        source: r.source.as_str().to_string(),
    }
}

/// Every server the engine talks to with the current settings.
pub fn active(state: &AppState) -> ActiveEndpointsDto {
    let e = state.endpoints();
    let network = &state.liquid_network;
    let params_source = if state.liquid_network_env_locked && !network.is_regtest() {
        Source::Env
    } else if network.is_regtest() {
        match e.regtest_network(Some(network)).source {
            Source::Setting if *network == LiquidNetwork::regtest_default() => Source::Default,
            s => s,
        }
    } else {
        Source::Default
    };
    let (backend, backend_description, backend_source) = match state.liquid_backend() {
        Ok(r) => (
            r.value.kind().to_string(),
            r.value.describe(),
            r.source.as_str().to_string(),
        ),
        // A bad TEMPLAR_LIQUID_BACKEND: sync reports it; show it here too.
        Err(err) => ("invalid".to_string(), err, Source::Env.as_str().to_string()),
    };
    let genesis_hash = match network {
        LiquidNetwork::LiquidRegtest { genesis_hash, .. } => genesis_hash.clone(),
        LiquidNetwork::LiquidTestnet => None,
    };
    let btc = e.bitcoin_backend(network);
    ActiveEndpointsDto {
        liquid_network: network.name().to_string(),
        env_locked: state.liquid_network_env_locked,
        orderbook: OrderbookEndpointsDto {
            origin: sourced(e.orderbook_url()),
            book: sourced(e.book_url()),
            markets: sourced(e.markets_url()),
            publish: sourced(e.publish_url()),
            atomic_swaps: sourced(e.atomic_swaps_url()),
            assets: sourced(e.assets_url()),
        },
        liquid: LiquidEndpointDto {
            network: network.name().to_string(),
            policy_asset: network.policy_asset_hex(),
            genesis_hash,
            params_source: params_source.as_str().to_string(),
            backend,
            backend_description,
            backend_source,
        },
        bitcoin: BitcoinEndpointDto {
            network: btc.value.network_name().to_string(),
            electrum_url: redact_userinfo(&btc.value.electrum_url),
            source: btc.source.as_str().to_string(),
        },
        protocol: e.protocol_url(network).map(sourced),
    }
}
