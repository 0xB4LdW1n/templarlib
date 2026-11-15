//! Joining a Templar test server: `set_test_server` fetches and validates
//! `<url>/api/config` and applies it, `get_test_server` reports it (and,
//! asked to, whether the server still says the same), `clear_test_server`
//! leaves it. Every answer also says which servers the engine talks to now
//! and where each one came from.

use templar_core::endpoints::redact_userinfo;
use templar_core::test_server::fetch_profile;
use templar_core::{LiquidNetwork, Resolved, Source};

use crate::state::{AppState, TestServerApplied};
use crate::types::{
    ActiveEndpointsDto, BitcoinEndpointDto, LiquidEndpointDto, OrderbookEndpointsDto,
    SourcedUrlDto, TestServerAppliedDto, TestServerCheckDto, TestServerDto,
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
    }
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
    }
}
