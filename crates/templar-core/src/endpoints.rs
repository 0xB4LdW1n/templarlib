//! The one place that decides which servers the wallet talks to: the order
//! book, the Liquid chain backend, the Bitcoin network and its Electrum
//! server, and the parameters of a Liquid regtest.
//!
//! Every value is resolved with the same precedence:
//!
//! 1. **env** — an environment variable (kept for developers and old setups);
//! 2. **profile** — a Templar test server's `/api/config`
//!    ([`crate::test_server`]), which only ever applies to the regtest side
//!    and to the order book;
//! 3. **setting** — the Liquid regtest policy asset the user set by hand
//!    (only for [`Endpoints::regtest_network`]);
//! 4. **default** — the built-in value (the public testnet servers, the
//!    local order book on `127.0.0.1:3210`, a local `elementsd`).
//!
//! Each answer carries its [`Source`], so a host can show where a value came
//! from. Nothing here contacts the network.

use serde::Serialize;

use crate::bitcoin::wallet::{electrum_env_override, BitcoinBackend};
use crate::error::TemplarError;
use crate::liquid::chain::LiquidBackend;
use crate::liquid::network::{env_non_empty, LiquidNetwork, ENV_REGTEST_POLICY_ASSET};
use crate::test_server::TestServerProfile;

/// Origin of the local order book (`templar-orderbook` on its default port).
pub const LOCAL_ORDERBOOK_URL: &str = "http://127.0.0.1:3210";
/// Overrides the book feed URL (`GET …/api/book`).
pub const ENV_SWAP_BOOK_URL: &str = "TEMPLAR_SWAP_BOOK_URL";
/// Overrides the unified markets feed URL (`GET …/api/markets`).
pub const ENV_SWAP_MARKETS_URL: &str = "TEMPLAR_SWAP_MARKETS_URL";
/// Overrides the publish URL. Kept for old setups that publish through the
/// order book's admin route (`…/api/admin/offers`).
pub const ENV_SWAP_ADMIN_URL: &str = "TEMPLAR_SWAP_ADMIN_URL";

/// Where a resolved value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Env,
    Profile,
    Setting,
    Default,
}

impl Source {
    /// Wire name: `env` | `profile` | `setting` | `default`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Source::Env => "env",
            Source::Profile => "profile",
            Source::Setting => "setting",
            Source::Default => "default",
        }
    }
}

/// A value and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved<T> {
    pub value: T,
    pub source: Source,
}

impl<T> Resolved<T> {
    fn new(value: T, source: Source) -> Self {
        Self { value, source }
    }
}

/// The resolver: the environment, plus the stored test-server profile when
/// there is one.
#[derive(Debug, Clone, Copy, Default)]
pub struct Endpoints<'a> {
    profile: Option<&'a TestServerProfile>,
}

impl<'a> Endpoints<'a> {
    /// The resolver over `profile` (none = environment and defaults only).
    pub fn new(profile: Option<&'a TestServerProfile>) -> Self {
        Self { profile }
    }

    /// The test-server profile in use, if any.
    pub fn profile(&self) -> Option<&'a TestServerProfile> {
        self.profile
    }

    /// Origin of the order book (no environment variable names it; the
    /// per-route variables below override single routes).
    pub fn orderbook_url(&self) -> Resolved<String> {
        match self.profile {
            Some(p) => Resolved::new(p.orderbook_url.clone(), Source::Profile),
            None => Resolved::new(LOCAL_ORDERBOOK_URL.to_string(), Source::Default),
        }
    }

    /// A route on the order book's origin, unless `env` overrides it.
    fn route(&self, env: Option<&str>, path: &str) -> Resolved<String> {
        if let Some(url) = env.and_then(env_non_empty) {
            return Resolved::new(url, Source::Env);
        }
        let origin = self.orderbook_url();
        Resolved::new(format!("{}{path}", origin.value), origin.source)
    }

    /// The wallet-compatible book feed, `GET …/api/book`.
    pub fn book_url(&self) -> Resolved<String> {
        self.route(Some(ENV_SWAP_BOOK_URL), "/api/book")
    }

    /// The unified markets feed, `GET …/api/markets`.
    pub fn markets_url(&self) -> Resolved<String> {
        self.route(Some(ENV_SWAP_MARKETS_URL), "/api/markets")
    }

    /// Where a signed proposal is published: the public
    /// `POST …/api/offers`, or the admin route `TEMPLAR_SWAP_ADMIN_URL`
    /// names.
    pub fn publish_url(&self) -> Resolved<String> {
        self.route(Some(ENV_SWAP_ADMIN_URL), "/api/offers")
    }

    /// The HTLC v1 coordinator, `…/api/atomic-swaps`.
    pub fn atomic_swaps_url(&self) -> Resolved<String> {
        self.route(None, "/api/atomic-swaps")
    }

    /// The Liquid regtest to run on: the environment's policy asset
    /// (`TEMPLAR_LIQUID_REGTEST_POLICY_ASSET`), else the test server's
    /// policy asset and genesis, else `setting` (a regtest the user chose by
    /// hand), else the stock `liquidregtest`. An unparsable environment value
    /// is logged and skipped, as [`LiquidNetwork::from_env`] does.
    pub fn regtest_network(&self, setting: Option<&LiquidNetwork>) -> Resolved<LiquidNetwork> {
        if let Some(asset) = env_non_empty(ENV_REGTEST_POLICY_ASSET) {
            match LiquidNetwork::regtest(&asset) {
                Ok(n) => return Resolved::new(n, Source::Env),
                Err(e) => eprintln!("[liquid] {ENV_REGTEST_POLICY_ASSET}: {e}; ignored"),
            }
        }
        if let Some(p) = self.profile {
            return Resolved::new(p.regtest.liquid_network(), Source::Profile);
        }
        match setting {
            Some(n) if n.is_regtest() => Resolved::new(n.clone(), Source::Setting),
            _ => Resolved::new(LiquidNetwork::regtest_default(), Source::Default),
        }
    }

    /// The chain backend of `network` (see [`LiquidBackend::resolve`]).
    pub fn liquid_backend(
        &self,
        network: &LiquidNetwork,
    ) -> Result<Resolved<LiquidBackend>, TemplarError> {
        let regtest = self.profile.map(|p| &p.regtest);
        LiquidBackend::resolve(network, regtest).map(|(b, s)| Resolved::new(b, s))
    }

    /// The Bitcoin side that goes with the Liquid network `liquid`: Bitcoin
    /// regtest through the lab's Electrum when `liquid` is regtest and the
    /// test server's `bitcoin_network` is `regtest`; Bitcoin testnet
    /// otherwise, exactly as before. `TEMPLAR_ELECTRUM_URL` overrides the
    /// Electrum server of whichever network that is.
    pub fn bitcoin_backend(&self, liquid: &LiquidNetwork) -> Resolved<BitcoinBackend> {
        let env = electrum_env_override();
        let lab = self
            .profile
            .filter(|p| liquid.is_regtest() && p.regtest.bitcoin_is_regtest());
        match (lab, env) {
            (Some(_), Some(url)) => Resolved::new(BitcoinBackend::regtest(&url), Source::Env),
            (Some(p), None) => Resolved::new(
                BitcoinBackend::regtest(&p.regtest.bitcoin_electrum_url),
                Source::Profile,
            ),
            (None, Some(_)) => Resolved::new(BitcoinBackend::testnet_default(), Source::Env),
            (None, None) => Resolved::new(BitcoinBackend::testnet_default(), Source::Default),
        }
    }
}

/// `scheme://user:pass@host…` → `scheme://***@host…`: for describing a URL
/// that may carry credentials (an RPC URL from the environment).
pub fn redact_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{scheme}://***@{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::{parse_config, tests_example};
    use bdk::bitcoin::Network;

    fn profile() -> TestServerProfile {
        parse_config("http://127.0.0.1:8096", tests_example(), 0).unwrap()
    }

    // The gate runs without the TEMPLAR_* variables; setting them here would
    // race the parallel test runner, so only the levels below env are tested.

    #[test]
    fn the_order_book_follows_the_profile() {
        let none = Endpoints::default();
        assert_eq!(
            none.book_url(),
            Resolved::new(
                "http://127.0.0.1:3210/api/book".to_string(),
                Source::Default
            )
        );
        assert_eq!(none.publish_url().value, "http://127.0.0.1:3210/api/offers");
        let mut p = profile();
        p.orderbook_url = "https://book.lab.example.org".into();
        let e = Endpoints::new(Some(&p));
        for (r, path) in [
            (e.book_url(), "/api/book"),
            (e.markets_url(), "/api/markets"),
            (e.publish_url(), "/api/offers"),
            (e.atomic_swaps_url(), "/api/atomic-swaps"),
        ] {
            assert_eq!(r.source, Source::Profile);
            assert_eq!(r.value, format!("https://book.lab.example.org{path}"));
        }
    }

    #[test]
    fn regtest_parameters_come_from_the_profile_before_the_setting() {
        let p = profile();
        let custom = LiquidNetwork::regtest(&"cc".repeat(32)).unwrap();
        let with = Endpoints::new(Some(&p)).regtest_network(Some(&custom));
        assert_eq!(with.source, Source::Profile);
        assert_eq!(with.value, p.regtest.liquid_network());
        let without = Endpoints::default().regtest_network(Some(&custom));
        assert_eq!(without, Resolved::new(custom, Source::Setting));
        let none = Endpoints::default().regtest_network(Some(&LiquidNetwork::testnet()));
        assert_eq!(
            none,
            Resolved::new(LiquidNetwork::regtest_default(), Source::Default)
        );
    }

    #[test]
    fn bitcoin_runs_on_regtest_only_beside_the_labs_liquid_regtest() {
        let p = profile();
        let e = Endpoints::new(Some(&p));
        let lab = e.bitcoin_backend(&p.regtest.liquid_network());
        assert_eq!(lab.source, Source::Profile);
        assert_eq!(lab.value.network, Network::Regtest);
        assert_eq!(lab.value.electrum_url, "ssl://lab.example.org:50012");
        // Liquid testnet keeps Bitcoin testnet, profile or not.
        let t = e.bitcoin_backend(&LiquidNetwork::testnet());
        assert_eq!(
            t,
            Resolved::new(BitcoinBackend::testnet_default(), Source::Default)
        );
        // A plain regtest without a lab: Bitcoin stays testnet, as before.
        let r = Endpoints::default().bitcoin_backend(&LiquidNetwork::regtest_default());
        assert_eq!(r.value.network, Network::Testnet);
    }

    #[test]
    fn regtest_data_lives_apart_from_testnet_data() {
        let dir = std::path::Path::new("/data");
        assert_eq!(BitcoinBackend::testnet_default().data_root(dir), dir);
        assert_eq!(
            BitcoinBackend::regtest("tcp://h:1").data_root(dir),
            dir.join("bitcoin-regtest")
        );
    }

    #[test]
    fn credentials_in_urls_are_masked() {
        assert_eq!(
            redact_userinfo("http://user:secret@127.0.0.1:18884/wallet"),
            "http://***@127.0.0.1:18884/wallet"
        );
        assert_eq!(redact_userinfo("http://h:1/a@b"), "http://h:1/a@b");
        assert_eq!(redact_userinfo("h:1"), "h:1");
    }
}
