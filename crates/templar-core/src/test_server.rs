//! A Templar test server ("testlab") profile: what `GET <url>/api/config`
//! (contract version 1, `templar-testlab/docs/api-config.md`) tells a wallet,
//! validated and reduced to the values the wallet applies.
//!
//! The profile decides which servers the wallet talks to, so this module is a
//! trust boundary. A config is refused as a whole (never applied in part)
//! unless:
//!
//! - the base URL is `http`/`https` without credentials, query or fragment,
//!   and the answer came from it directly (no redirects), within the size
//!   and time bounds below;
//! - `version` is one this wallet reads ([`SUPPORTED_CONFIG_VERSION`]);
//! - every id is 64 hex, every Electrum URL is `tcp://host:port` or
//!   `ssl://host:port`, every HTTP URL is `http(s)` without credentials;
//! - nothing names a mainnet: no mainnet network key, no Liquid mainnet
//!   policy asset or genesis, `bitcoin_network` exactly `"regtest"`.
//!
//! Only the `liquid-regtest` block and `orderbook_url` are ever applied
//! (see [`crate::endpoints`]). The `liquid-testnet` block is kept for display
//! — it never changes how Liquid testnet reaches its chain.
//!
//! Parsing ([`parse_config`]) is pure; only [`fetch_profile`] touches the
//! network.

use std::io::Read;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{TemplarError, TestServerError};
use crate::liquid::chain::LiquidBackend;
use crate::liquid::liquidex::{LBTC_MAINNET_ASSET_ID, LBTC_TESTNET_ASSET_ID};
use crate::liquid::network::LiquidNetwork;

/// The `/api/config` contract version this wallet reads.
pub const SUPPORTED_CONFIG_VERSION: u32 = 1;
/// Largest `/api/config` answer read. Version 1 is well under 2 KiB.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// TCP connect bound for the config fetch.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Whole-request bound for the config fetch: the engine mutex is held for
/// the duration of the call, so a stalled server must not hold it longer.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest display name kept.
const MAX_NAME_CHARS: usize = 64;

/// Genesis block hash of Liquid mainnet (display hex).
const LIQUID_MAINNET_GENESIS: &str =
    "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003";
/// Genesis block hash of Liquid testnet (display hex).
const LIQUID_TESTNET_GENESIS: &str =
    "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1";

/// Network keys that name a mainnet; their presence refuses the config.
const MAINNET_KEYS: &[&str] = &[
    "liquid",
    "liquidv1",
    "liquid-mainnet",
    "mainnet",
    "bitcoin",
    "bitcoin-mainnet",
];

/// A validated test-server profile, as persisted in the app config and
/// returned to hosts. Every URL is normalised (no trailing slash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestServerProfile {
    /// The URL the user set, normalised: `http(s)://host[:port][/path]`.
    pub base_url: String,
    /// Display name of the lab.
    pub name: String,
    /// The contract version of the answer.
    pub version: u32,
    /// Unix seconds of the fetch this profile came from.
    pub fetched_at: u64,
    /// Origin of the LiquiDEX order book (both books).
    pub orderbook_url: String,
    /// The lab's own chains — the only network block that is applied.
    pub regtest: RegtestProfile,
    /// The public Liquid testnet block: display only.
    #[serde(default)]
    pub testnet: Option<TestnetProfile>,
}

/// `networks["liquid-regtest"]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegtestProfile {
    /// Changes on every chain reset (hash of Liquid block 1).
    pub instance_id: String,
    /// L-BTC asset id of the lab's chain.
    pub policy_asset: String,
    /// Elements genesis block hash (display order).
    pub genesis_hash: String,
    /// `tcp://host:port` or `ssl://host:port`.
    pub liquid_electrum_url: String,
    /// Always `"regtest"`.
    pub bitcoin_network: String,
    /// `tcp://host:port` or `ssl://host:port`.
    pub bitcoin_electrum_url: String,
    /// Esplora REST base URL: raw transactions and merkle proofs for
    /// peg-in claims (checked against the Bitcoin Electrum server).
    pub bitcoin_esplora_url: String,
    /// The lab faucet (`POST`).
    pub faucet_url: String,
    /// The lab's peg terms ([`crate::Endpoints::peg_provider`]).
    pub peg: PegProfile,
}

/// A `peg` block. Only `provider` is always present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegProfile {
    /// `"native"` (the lab's own Elements peg) or `"sideswap"`.
    pub provider: String,
    #[serde(default)]
    pub pegin_confirmations: Option<u32>,
    #[serde(default)]
    pub pegout_confirmations: Option<u32>,
    #[serde(default)]
    pub pegout_max_sat: Option<u64>,
}

/// `networks["liquid-testnet"]`: links for display, never chain settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestnetProfile {
    #[serde(default)]
    pub faucet_url: Option<String>,
    #[serde(default)]
    pub peg: Option<PegProfile>,
}

impl RegtestProfile {
    /// The Liquid regtest this lab runs: its policy asset and genesis.
    pub fn liquid_network(&self) -> LiquidNetwork {
        LiquidNetwork::regtest_with_genesis(&self.policy_asset, &self.genesis_hash)
            .expect("validated when the profile was parsed")
    }

    /// The lab's Liquid Electrum server as a chain backend. TLS certificates
    /// are validated against the host.
    pub fn liquid_backend(&self) -> LiquidBackend {
        let (host_port, tls) =
            split_electrum_url(&self.liquid_electrum_url).expect("validated when parsed");
        LiquidBackend::Electrum {
            url: host_port,
            tls,
            validate_domain: true,
        }
    }

    /// Whether the lab's Bitcoin side is Bitcoin regtest.
    pub fn bitcoin_is_regtest(&self) -> bool {
        self.bitcoin_network == "regtest"
    }
}

impl TestServerProfile {
    /// Whether `other` (a fresh fetch) says anything different from this
    /// stored profile, ignoring the fetch time.
    pub fn differs_from(&self, other: &TestServerProfile) -> bool {
        let mut a = self.clone();
        a.fetched_at = other.fetched_at;
        a != *other
    }
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

/// Normalises an `http`/`https` URL: no credentials, query or fragment, a
/// host; trailing slashes dropped. `what` names the field in errors.
fn normalize_http_url(raw: &str, what: &str) -> Result<String, String> {
    let raw = raw.trim();
    let url = reqwest::Url::parse(raw).map_err(|e| format!("{what} {}: {e}", quoted(raw)))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "{what} must be an http:// or https:// URL, not {}",
            quoted(url.scheme())
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{what} must not carry a user name or password"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(format!("{what} has no host"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!("{what} must not carry a query or fragment"));
    }
    let origin = url.origin().ascii_serialization();
    let path = url.path().trim_end_matches('/');
    Ok(format!("{origin}{path}"))
}

/// Normalises the test server URL the user typed.
pub fn normalize_base_url(raw: &str) -> Result<String, TemplarError> {
    normalize_http_url(raw, "the test server URL")
        .map_err(|e| TestServerError::InvalidUrl(e).into())
}

/// Splits `tcp://host:port` / `ssl://host:port` into `host:port` and the
/// TLS flag.
fn split_electrum_url(raw: &str) -> Result<(String, bool), String> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| format!("{} is not tcp://host:port or ssl://host:port", quoted(raw)))?;
    let tls = match scheme {
        "tcp" => false,
        "ssl" => true,
        other => {
            return Err(format!(
                "Electrum scheme {} is not tcp or ssl",
                quoted(other)
            ))
        }
    };
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| format!("{} has no port", quoted(raw)))?;
    let host_ok = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '[' | ']' | ':'));
    if !host_ok {
        return Err(format!("{} has no valid host", quoted(raw)));
    }
    match port.parse::<u16>() {
        Ok(p) if p > 0 => Ok((format!("{host}:{p}"), tls)),
        _ => Err(format!("{} has no valid port", quoted(raw))),
    }
}

/// A short, printable rendering of a server-supplied value for an error.
fn quoted(raw: &str) -> String {
    let clean: String = raw.chars().filter(|c| !c.is_control()).take(80).collect();
    format!("{clean:?}")
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn invalid(msg: impl Into<String>) -> TemplarError {
    TestServerError::Invalid(msg.into()).into()
}

fn obj<'a>(v: &'a Value, path: &str) -> Result<&'a Map<String, Value>, TemplarError> {
    v.as_object()
        .ok_or_else(|| invalid(format!("{path} is not an object")))
}

fn string<'a>(o: &'a Map<String, Value>, path: &str, key: &str) -> Result<&'a str, TemplarError> {
    match o.get(key) {
        Some(Value::String(s)) => Ok(s.trim()),
        Some(_) => Err(invalid(format!("{path}.{key} is not a string"))),
        None => Err(invalid(format!("{path}.{key} is missing"))),
    }
}

fn hex64(o: &Map<String, Value>, path: &str, key: &str) -> Result<String, TemplarError> {
    let s = string(o, path, key)?;
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(format!("{path}.{key} is not 64 hex characters")));
    }
    Ok(s.to_ascii_lowercase())
}

fn http_url(o: &Map<String, Value>, path: &str, key: &str) -> Result<String, TemplarError> {
    normalize_http_url(string(o, path, key)?, &format!("{path}.{key}")).map_err(invalid)
}

fn electrum_url(o: &Map<String, Value>, path: &str, key: &str) -> Result<String, TemplarError> {
    let raw = string(o, path, key)?;
    let (host_port, tls) =
        split_electrum_url(raw).map_err(|e| invalid(format!("{path}.{key}: {e}")))?;
    Ok(format!("{}://{host_port}", if tls { "ssl" } else { "tcp" }))
}

fn opt_u32(o: &Map<String, Value>, path: &str, key: &str) -> Result<Option<u32>, TemplarError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| invalid(format!("{path}.{key} is not a small whole number"))),
    }
}

fn opt_u64(o: &Map<String, Value>, path: &str, key: &str) -> Result<Option<u64>, TemplarError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| invalid(format!("{path}.{key} is not a whole number"))),
    }
}

fn peg(v: &Value, path: &str) -> Result<PegProfile, TemplarError> {
    let o = obj(v, path)?;
    let provider = string(o, path, "provider")?;
    if provider.is_empty()
        || provider.len() > 32
        || !provider
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(invalid(format!("{path}.provider is not a provider name")));
    }
    Ok(PegProfile {
        provider: provider.to_string(),
        pegin_confirmations: opt_u32(o, path, "pegin_confirmations")?,
        pegout_confirmations: opt_u32(o, path, "pegout_confirmations")?,
        pegout_max_sat: opt_u64(o, path, "pegout_max_sat")?,
    })
}

fn regtest_block(v: &Value) -> Result<RegtestProfile, TemplarError> {
    const P: &str = "networks.liquid-regtest";
    let o = obj(v, P)?;
    let policy_asset = hex64(o, P, "policy_asset")?;
    if policy_asset == LBTC_MAINNET_ASSET_ID {
        return Err(
            TestServerError::Mainnet("its policy asset is Liquid mainnet L-BTC".into()).into(),
        );
    }
    if policy_asset == LBTC_TESTNET_ASSET_ID {
        return Err(invalid(format!(
            "{P}.policy_asset is Liquid testnet's L-BTC, not a regtest asset"
        )));
    }
    let genesis_hash = hex64(o, P, "genesis_hash")?;
    if genesis_hash == LIQUID_MAINNET_GENESIS {
        return Err(TestServerError::Mainnet("its genesis is Liquid mainnet's".into()).into());
    }
    if genesis_hash == LIQUID_TESTNET_GENESIS {
        return Err(invalid(format!(
            "{P}.genesis_hash is Liquid testnet's genesis, not a regtest's"
        )));
    }
    let bitcoin_network = string(o, P, "bitcoin_network")?.to_ascii_lowercase();
    match bitcoin_network.as_str() {
        "regtest" => {}
        "bitcoin" | "main" | "mainnet" => {
            return Err(
                TestServerError::Mainnet("bitcoin_network is Bitcoin mainnet".into()).into(),
            )
        }
        other => {
            return Err(invalid(format!(
                "{P}.bitcoin_network {} is not supported (only \"regtest\")",
                quoted(other)
            )))
        }
    }
    Ok(RegtestProfile {
        instance_id: hex64(o, P, "instance_id")?,
        policy_asset,
        genesis_hash,
        liquid_electrum_url: electrum_url(o, P, "liquid_electrum_url")?,
        bitcoin_network,
        bitcoin_electrum_url: electrum_url(o, P, "bitcoin_electrum_url")?,
        bitcoin_esplora_url: http_url(o, P, "bitcoin_esplora_url")?,
        faucet_url: http_url(o, P, "faucet_url")?,
        peg: peg(
            o.get("peg")
                .ok_or_else(|| invalid(format!("{P}.peg is missing")))?,
            &format!("{P}.peg"),
        )?,
    })
}

fn testnet_block(v: &Value) -> Result<TestnetProfile, TemplarError> {
    const P: &str = "networks.liquid-testnet";
    let o = obj(v, P)?;
    let faucet_url = match o.get("faucet_url") {
        None | Some(Value::Null) => None,
        Some(_) => Some(http_url(o, P, "faucet_url")?),
    };
    let peg = match o.get("peg") {
        None | Some(Value::Null) => None,
        Some(p) => Some(peg(p, &format!("{P}.peg"))?),
    };
    Ok(TestnetProfile { faucet_url, peg })
}

/// Validates a `/api/config` answer of the server at `base_url` (already
/// normalised) into a profile stamped `fetched_at`. Pure: no network.
pub fn parse_config(
    base_url: &str,
    body: &str,
    fetched_at: u64,
) -> Result<TestServerProfile, TemplarError> {
    let root: Value =
        serde_json::from_str(body).map_err(|e| invalid(format!("the answer is not JSON ({e})")))?;
    let o = obj(&root, "the answer")?;

    let version = o
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("version is missing or not a number"))?;
    if version != u64::from(SUPPORTED_CONFIG_VERSION) {
        return Err(TestServerError::UnsupportedVersion {
            found: version,
            supported: SUPPORTED_CONFIG_VERSION,
        }
        .into());
    }

    let name = string(o, "config", "name")?;
    if name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(invalid(format!(
            "name must be at most {MAX_NAME_CHARS} printable characters"
        )));
    }
    let orderbook_url = http_url(o, "config", "orderbook_url")?;

    let networks = obj(
        o.get("networks")
            .ok_or_else(|| invalid("networks is missing"))?,
        "networks",
    )?;
    if let Some(key) = networks
        .keys()
        .find(|k| MAINNET_KEYS.contains(&k.to_ascii_lowercase().as_str()))
    {
        return Err(TestServerError::Mainnet(format!("network {}", quoted(key))).into());
    }
    let regtest = regtest_block(
        networks
            .get("liquid-regtest")
            .ok_or_else(|| invalid("networks.liquid-regtest is missing"))?,
    )?;
    let testnet = networks
        .get("liquid-testnet")
        .map(testnet_block)
        .transpose()?;

    Ok(TestServerProfile {
        base_url: base_url.to_string(),
        name: name.to_string(),
        version: SUPPORTED_CONFIG_VERSION,
        fetched_at,
        orderbook_url,
        regtest,
        testnet,
    })
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

/// Fetches and validates `<base_url>/api/config`. `base_url` is what the user
/// typed; it is normalised first. Redirects are refused: the profile must
/// come from the server the user named. Bounded in time and size.
pub fn fetch_profile(base_url: &str) -> Result<TestServerProfile, TemplarError> {
    let base = normalize_base_url(base_url)?;
    let body = fetch_config_body(&base)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    parse_config(&base, &body, now)
}

fn fetch_config_body(base: &str) -> Result<String, TemplarError> {
    let unreachable = |e: &dyn std::fmt::Display| -> TemplarError {
        TestServerError::Unreachable(format!("{base}: {e}")).into()
    };
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| unreachable(&e))?;
    let resp = client
        .get(format!("{base}/api/config"))
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .map_err(|e| unreachable(&e))?;
    let status = resp.status();
    if status.is_redirection() {
        return Err(TestServerError::InvalidUrl(format!(
            "{base} redirects (HTTP {}); set the URL it points to instead",
            status.as_u16()
        ))
        .into());
    }
    if !status.is_success() {
        return Err(TestServerError::Http(status.as_u16()).into());
    }
    if resp.content_length().is_some_and(|n| n > MAX_CONFIG_BYTES) {
        return Err(TestServerError::TooLarge(MAX_CONFIG_BYTES).into());
    }
    let mut body = Vec::new();
    resp.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| unreachable(&e))?;
    if body.len() as u64 > MAX_CONFIG_BYTES {
        return Err(TestServerError::TooLarge(MAX_CONFIG_BYTES).into());
    }
    String::from_utf8(body).map_err(|_| invalid("the answer is not UTF-8"))
}

/// The documented example config, for other modules' tests.
#[cfg(test)]
pub(crate) fn tests_example() -> &'static str {
    tests::EXAMPLE
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented version-1 example (api-config.md §2), local flavour.
    pub(crate) const EXAMPLE: &str = r#"{
      "version": 1,
      "name": "Templar testlab",
      "orderbook_url": "http://127.0.0.1:3210/",
      "networks": {
        "liquid-regtest": {
          "instance_id": "cf8f3167af838434a6e5673964da75989328aac58a14a6ce3bba759450a08483",
          "policy_asset": "B0B2BEF620AC742B2399A0085BC84E4860AE2C65B5375E3B94399DEBEC69AA6B",
          "genesis_hash": "d51392db10c135e2e5f7bcfeab36e859ca4e69d6f76439ec0ebcb0a8da7be248",
          "liquid_electrum_url": "tcp://127.0.0.1:19061",
          "bitcoin_network": "regtest",
          "bitcoin_electrum_url": "ssl://lab.example.org:50012",
          "bitcoin_esplora_url": "https://lab.example.org/bitcoin-esplora/",
          "faucet_url": "http://127.0.0.1:8096/api/faucet",
          "peg": {"provider": "native", "pegin_confirmations": 2,
                  "pegout_confirmations": 2, "pegout_max_sat": 100000000},
          "a_future_field": true
        },
        "liquid-testnet": {"faucet_url": "https://liquidtestnet.com", "peg": {"provider": "sideswap"}},
        "some-future-network": {}
      }
    }"#;

    fn with(mutate: impl FnOnce(&mut Value)) -> String {
        let mut v: Value = serde_json::from_str(EXAMPLE).unwrap();
        mutate(&mut v);
        v.to_string()
    }

    fn reg(v: &mut Value) -> &mut Value {
        &mut v["networks"]["liquid-regtest"]
    }

    fn parse(body: &str) -> Result<TestServerProfile, String> {
        parse_config("http://127.0.0.1:8096", body, 7).map_err(|e| e.to_string())
    }

    #[test]
    fn the_documented_example_parses_and_normalises() {
        let p = parse(EXAMPLE).unwrap();
        assert_eq!(p.base_url, "http://127.0.0.1:8096");
        assert_eq!(p.version, 1);
        assert_eq!(p.fetched_at, 7);
        assert_eq!(p.orderbook_url, "http://127.0.0.1:3210");
        let r = &p.regtest;
        // Ids are lowercased; URLs lose their trailing slash.
        assert_eq!(
            r.policy_asset,
            "b0b2bef620ac742b2399a0085bc84e4860ae2c65b5375e3b94399debec69aa6b"
        );
        assert_eq!(
            r.bitcoin_esplora_url,
            "https://lab.example.org/bitcoin-esplora"
        );
        assert_eq!(r.peg.pegout_max_sat, Some(100_000_000));
        assert_eq!(
            r.liquid_backend(),
            LiquidBackend::Electrum {
                url: "127.0.0.1:19061".into(),
                tls: false,
                validate_domain: true
            }
        );
        let net = r.liquid_network();
        assert!(net.is_regtest());
        assert_eq!(net.policy_asset_hex(), r.policy_asset);
        assert_eq!(net.elements().genesis_hash().to_string(), r.genesis_hash);
        let t = p.testnet.as_ref().unwrap();
        assert_eq!(t.peg.as_ref().unwrap().provider, "sideswap");
        // The persisted form round-trips.
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<TestServerProfile>(&json).unwrap(), p);
    }

    #[test]
    fn base_urls_are_http_only_and_normalised() {
        assert_eq!(
            normalize_base_url(" http://127.0.0.1:8096/ ").unwrap(),
            "http://127.0.0.1:8096"
        );
        assert_eq!(
            normalize_base_url("https://lab.example.org/lab/").unwrap(),
            "https://lab.example.org/lab"
        );
        for bad in [
            "ftp://lab.example.org",
            "file:///etc/passwd",
            "lab.example.org",
            "http://user:pw@lab.example.org",
            "http://lab.example.org/?x=1",
            "http://lab.example.org/#frag",
            "",
        ] {
            let err = normalize_base_url(bad).unwrap_err().to_string();
            assert!(err.starts_with("Invalid test server URL"), "{bad}: {err}");
            assert!(
                !err.contains("pw@"),
                "credentials must not be echoed: {err}"
            );
        }
    }

    #[test]
    fn an_unsupported_version_asks_for_a_newer_wallet() {
        let err = parse(&with(|v| v["version"] = 2.into())).unwrap_err();
        assert!(err.contains("needs a newer wallet"), "{err}");
        let err = parse(&with(|v| v["version"] = "1".into())).unwrap_err();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn anything_naming_mainnet_is_refused() {
        let err = parse(&with(|v| v["networks"]["liquid"] = json_obj())).unwrap_err();
        assert!(err.contains("mainnet"), "{err}");
        let err = parse(&with(|v| v["networks"]["Bitcoin"] = json_obj())).unwrap_err();
        assert!(err.contains("mainnet"), "{err}");
        let err = parse(&with(|v| {
            reg(v)["policy_asset"] = LBTC_MAINNET_ASSET_ID.into();
        }))
        .unwrap_err();
        assert!(err.contains("mainnet"), "{err}");
        let err = parse(&with(|v| {
            reg(v)["genesis_hash"] = LIQUID_MAINNET_GENESIS.into();
        }))
        .unwrap_err();
        assert!(err.contains("mainnet"), "{err}");
        let err = parse(&with(|v| reg(v)["bitcoin_network"] = "bitcoin".into())).unwrap_err();
        assert!(err.contains("mainnet"), "{err}");
        let err = parse(&with(|v| reg(v)["bitcoin_network"] = "testnet".into())).unwrap_err();
        assert!(err.contains("only \"regtest\""), "{err}");
        // Testnet's own ids are not a regtest either.
        let err = parse(&with(|v| {
            reg(v)["policy_asset"] = LBTC_TESTNET_ASSET_ID.into();
        }))
        .unwrap_err();
        assert!(err.contains("testnet"), "{err}");
    }

    fn json_obj() -> Value {
        Value::Object(Map::new())
    }

    #[test]
    fn malformed_fields_are_named_in_the_error() {
        type Mutation = Box<dyn FnOnce(&mut Value)>;
        let cases: Vec<(Mutation, &str)> = vec![
            (
                Box::new(|v| reg(v)["instance_id"] = "abc".into()),
                "instance_id",
            ),
            (
                Box::new(|v| reg(v)["policy_asset"] = 5.into()),
                "policy_asset",
            ),
            (
                Box::new(|v| reg(v)["liquid_electrum_url"] = "http://h:1".into()),
                "liquid_electrum_url",
            ),
            (
                Box::new(|v| reg(v)["bitcoin_electrum_url"] = "tcp://h".into()),
                "bitcoin_electrum_url",
            ),
            (
                Box::new(|v| reg(v)["liquid_electrum_url"] = "tcp://h:0".into()),
                "liquid_electrum_url",
            ),
            (
                Box::new(|v| reg(v)["faucet_url"] = "javascript:alert(1)".into()),
                "faucet_url",
            ),
            (
                Box::new(|v| v["orderbook_url"] = "http://u:p@h:1".into()),
                "orderbook_url",
            ),
            (Box::new(|v| reg(v)["peg"] = "native".into()), "peg"),
            (
                Box::new(|v| reg(v)["peg"]["pegin_confirmations"] = (-1).into()),
                "pegin_confirmations",
            ),
            (
                Box::new(|v| {
                    v["networks"]
                        .as_object_mut()
                        .unwrap()
                        .remove("liquid-regtest");
                }),
                "liquid-regtest",
            ),
            (Box::new(|v| v["name"] = "x".repeat(65).into()), "name"),
        ];
        for (mutate, field) in cases {
            let err = parse(&with(mutate)).unwrap_err();
            assert!(
                err.starts_with("The test server's config is invalid"),
                "{err}"
            );
            assert!(err.contains(field), "{field}: {err}");
        }
        assert!(parse("not json").unwrap_err().contains("not JSON"));
        assert!(parse("[]").unwrap_err().contains("not an object"));
    }

    #[test]
    fn a_fresh_fetch_is_compared_without_its_timestamp() {
        let a = parse(EXAMPLE).unwrap();
        let mut b = a.clone();
        b.fetched_at = 99;
        assert!(!a.differs_from(&b));
        b.regtest.instance_id = "00".repeat(32);
        assert!(a.differs_from(&b));
    }

    #[test]
    fn electrum_urls_split_into_host_port_and_tls() {
        assert_eq!(
            split_electrum_url("ssl://lab.example.org:50022").unwrap(),
            ("lab.example.org:50022".to_string(), true)
        );
        assert_eq!(
            split_electrum_url("tcp://[::1]:19061").unwrap(),
            ("[::1]:19061".to_string(), false)
        );
        assert!(split_electrum_url("tcp://h:99999").is_err());
        assert!(split_electrum_url("tcp://a b:1").is_err());
        assert!(split_electrum_url("tcp://h/x:1").is_err());
    }
}
