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
//! and to switch on the testnet peg provider it names (SideSwap) — it never
//! changes how Liquid testnet reaches its chain, and never names a server.
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
    /// The lab's Templar Protocol (lending) site, `http(s)://…` without
    /// credentials; optional in version 1 (absent: none).
    #[serde(default)]
    pub protocol_url: Option<String>,
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
    /// What the faucet pays, as the lab lists it (optional in version 1;
    /// `None` on older labs: see [`RegtestProfile::faucet_assets`]).
    #[serde(default)]
    pub faucet: Option<Vec<FaucetAsset>>,
}

/// One asset the lab's faucet pays (`networks["liquid-regtest"].faucet[]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaucetAsset {
    /// What the faucet request names: `btc`, `lbtc`, or the lab's ticker or
    /// id of one of its assets.
    pub asset: String,
    /// `bitcoin-regtest` | `liquid-regtest`.
    pub network: String,
    pub ticker: String,
    pub name: String,
    /// Decimal places of the asset (0–8).
    pub precision: u8,
    /// The Liquid asset id (64 hex); null for Bitcoin.
    #[serde(default)]
    pub asset_id: Option<String>,
    /// What one request pays when it names no amount, in base units.
    #[serde(default)]
    pub default_sat: Option<u64>,
    /// The most one request may ask for, in base units.
    #[serde(default)]
    pub max_sat: Option<u64>,
}

/// Network name of a faucet asset on the lab's Bitcoin regtest.
pub const FAUCET_BITCOIN_REGTEST: &str = "bitcoin-regtest";
/// Network name of a faucet asset on the lab's Liquid regtest.
pub const FAUCET_LIQUID_REGTEST: &str = "liquid-regtest";
/// Most faucet assets a config may list.
pub const MAX_FAUCET_ASSETS: usize = 32;
/// Most base units a faucet entry may name (21 million BTC).
const MAX_FAUCET_SAT: u64 = 2_100_000_000_000_000;

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
    /// Smallest peg-out the lab pays; smaller outputs are never paid (the
    /// L-BTC is burned). Optional in version 1: absent means
    /// [`DEFAULT_PEGOUT_MIN_SAT`].
    #[serde(default)]
    pub pegout_min_sat: Option<u64>,
}

/// `networks["liquid-testnet"]`: links for display and the testnet peg
/// provider's name, never chain settings or servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestnetProfile {
    #[serde(default)]
    pub faucet_url: Option<String>,
    #[serde(default)]
    pub peg: Option<PegProfile>,
}

impl RegtestProfile {
    /// The Liquid regtest this lab runs: its policy asset and genesis.
    /// Fallible: a profile is validated when fetched and again when loaded
    /// ([`TestServerProfile::revalidate`]), but this never panics on one
    /// that slipped through.
    pub fn liquid_network(&self) -> Result<LiquidNetwork, TemplarError> {
        LiquidNetwork::regtest_with_genesis(&self.policy_asset, &self.genesis_hash)
    }

    /// The lab's Liquid Electrum server as a chain backend. TLS certificates
    /// are validated against the host.
    pub fn liquid_backend(&self) -> Result<LiquidBackend, TemplarError> {
        let (host_port, tls) = split_electrum_url(&self.liquid_electrum_url)
            .map_err(|e| invalid(format!("liquid_electrum_url: {e}")))?;
        Ok(LiquidBackend::Electrum {
            url: host_port,
            tls,
            validate_domain: true,
        })
    }

    /// Whether the lab's Bitcoin side is Bitcoin regtest.
    pub fn bitcoin_is_regtest(&self) -> bool {
        self.bitcoin_network == "regtest"
    }

    /// What the faucet pays: the lab's own list, else (a lab older than
    /// the list) regtest BTC and the chain's L-BTC.
    pub fn faucet_assets(&self) -> Vec<FaucetAsset> {
        match &self.faucet {
            Some(list) => list.clone(),
            None => vec![
                FaucetAsset {
                    asset: "btc".into(),
                    network: FAUCET_BITCOIN_REGTEST.into(),
                    ticker: "BTC".into(),
                    name: "Bitcoin (regtest)".into(),
                    precision: 8,
                    asset_id: None,
                    default_sat: None,
                    max_sat: None,
                },
                FaucetAsset {
                    asset: "lbtc".into(),
                    network: FAUCET_LIQUID_REGTEST.into(),
                    ticker: "LBTC".into(),
                    name: "Liquid Bitcoin".into(),
                    precision: 8,
                    asset_id: Some(self.policy_asset.clone()),
                    default_sat: None,
                    max_sat: None,
                },
            ],
        }
    }
}

impl TestServerProfile {
    /// Checks a stored profile (read back from the app config, which anyone
    /// with access to the file can edit) with exactly the rules a fetched
    /// `/api/config` meets: it is turned back into that document and parsed
    /// again, and must come out unchanged. A profile that fails is not
    /// applied.
    pub fn revalidate(&self) -> Result<(), TemplarError> {
        let base = normalize_base_url(&self.base_url)?;
        let mut networks = Map::new();
        networks.insert(
            "liquid-regtest".into(),
            serde_json::to_value(&self.regtest).map_err(|e| invalid(e.to_string()))?,
        );
        if let Some(t) = &self.testnet {
            networks.insert(
                "liquid-testnet".into(),
                serde_json::to_value(t).map_err(|e| invalid(e.to_string()))?,
            );
        }
        let doc = serde_json::json!({
            "version": self.version,
            "name": self.name,
            "orderbook_url": self.orderbook_url,
            "protocol_url": self.protocol_url,
            "networks": networks,
        });
        let parsed = parse_config(&base, &doc.to_string(), self.fetched_at)?;
        if parsed != *self {
            return Err(invalid(
                "the stored profile is not in the form the wallet writes".to_string(),
            ));
        }
        Ok(())
    }

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

/// The lab's smallest paid peg-out when its config does not say
/// (`api-config.md`: "when absent, assume 100000").
pub const DEFAULT_PEGOUT_MIN_SAT: u64 = 100_000;

/// Most confirmations a peg may ask for: Liquid mainnet's peg-in depth is
/// 102; anything far beyond a few hundred is a broken or hostile config.
pub const MAX_PEG_CONFIRMATIONS: u32 = 1_000;

fn opt_confirmations(
    o: &Map<String, Value>,
    path: &str,
    key: &str,
) -> Result<Option<u32>, TemplarError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n <= MAX_PEG_CONFIRMATIONS)
            .map(Some)
            .ok_or_else(|| {
                invalid(format!(
                    "{path}.{key} is not a whole number up to {MAX_PEG_CONFIRMATIONS}"
                ))
            }),
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
        pegin_confirmations: opt_confirmations(o, path, "pegin_confirmations")?,
        pegout_confirmations: opt_confirmations(o, path, "pegout_confirmations")?,
        pegout_max_sat: opt_u64(o, path, "pegout_max_sat")?,
        pegout_min_sat: opt_u64(o, path, "pegout_min_sat")?,
    })
}

/// A short display text of the config: at most `max` characters, none of
/// them a control character, not empty.
fn display_text(
    o: &Map<String, Value>,
    path: &str,
    key: &str,
    max: usize,
) -> Result<String, TemplarError> {
    let s = string(o, path, key)?;
    if s.is_empty() || s.chars().count() > max || s.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{path}.{key} must be 1 to {max} printable characters"
        )));
    }
    Ok(s.to_string())
}

/// A ticker or asset name of the faucet list: 1–64 of `A-Z a-z 0-9 . _ -`.
fn token(o: &Map<String, Value>, path: &str, key: &str) -> Result<String, TemplarError> {
    let s = string(o, path, key)?;
    if s.is_empty()
        || s.len() > 64
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(invalid(format!(
            "{path}.{key} must be 1 to 64 of A-Z, a-z, 0-9, '.', '_', '-'"
        )));
    }
    Ok(s.to_string())
}

fn faucet_entry(
    v: &Value,
    path: &str,
    policy_asset: &str,
) -> Result<Option<FaucetAsset>, TemplarError> {
    let o = obj(v, path)?;
    let network = string(o, path, "network")?.to_ascii_lowercase();
    if MAINNET_KEYS.contains(&network.as_str()) {
        return Err(
            TestServerError::Mainnet(format!("{path}.network {}", quoted(&network))).into(),
        );
    }
    if network != FAUCET_BITCOIN_REGTEST && network != FAUCET_LIQUID_REGTEST {
        // A network this wallet does not know: ignored, like unknown keys.
        return Ok(None);
    }
    let asset = token(o, path, "asset")?;
    let ticker = token(o, path, "ticker")?;
    if ticker.len() > 24 {
        return Err(invalid(format!(
            "{path}.ticker is longer than 24 characters"
        )));
    }
    let name = display_text(o, path, "name", MAX_NAME_CHARS)?;
    let precision = o
        .get("precision")
        .and_then(Value::as_u64)
        .filter(|p| *p <= 8)
        .ok_or_else(|| {
            invalid(format!(
                "{path}.precision is not a whole number from 0 to 8"
            ))
        })? as u8;
    let asset_id = match o.get("asset_id") {
        None | Some(Value::Null) => None,
        Some(_) => Some(hex64(o, path, "asset_id")?),
    };
    let amount = |key: &str| -> Result<Option<u64>, TemplarError> {
        match opt_u64(o, path, key)? {
            Some(n) if n == 0 || n > MAX_FAUCET_SAT => Err(invalid(format!(
                "{path}.{key} is not an amount from 1 to {MAX_FAUCET_SAT}"
            ))),
            other => Ok(other),
        }
    };
    let default_sat = amount("default_sat")?;
    let max_sat = amount("max_sat")?;
    if let (Some(d), Some(m)) = (default_sat, max_sat) {
        if d > m {
            return Err(invalid(format!("{path}.default_sat is above its max_sat")));
        }
    }
    let lbtc = asset.eq_ignore_ascii_case("lbtc");
    if network == FAUCET_BITCOIN_REGTEST {
        if !asset.eq_ignore_ascii_case("btc") || asset_id.is_some() || precision != 8 {
            return Err(invalid(format!(
                "{path} on bitcoin-regtest must be asset \"btc\" with 8 decimals and no asset_id"
            )));
        }
    } else if lbtc {
        if asset_id.as_deref().is_some_and(|id| id != policy_asset) || precision != 8 {
            return Err(invalid(format!(
                "{path} names \"lbtc\" but not the chain's policy asset with 8 decimals"
            )));
        }
    } else if asset.eq_ignore_ascii_case("btc") || asset_id.as_deref() == Some(policy_asset) {
        return Err(invalid(format!(
            "{path} gives another name to BTC or to the chain's L-BTC"
        )));
    }
    Ok(Some(FaucetAsset {
        asset,
        network,
        ticker,
        name,
        precision,
        asset_id: if lbtc {
            Some(policy_asset.to_string())
        } else {
            asset_id
        },
        default_sat,
        max_sat,
    }))
}

fn faucet_list(v: &Value, policy_asset: &str) -> Result<Vec<FaucetAsset>, TemplarError> {
    const P: &str = "networks.liquid-regtest.faucet";
    let items = v
        .as_array()
        .ok_or_else(|| invalid(format!("{P} is not a list")))?;
    if items.len() > MAX_FAUCET_ASSETS {
        return Err(invalid(format!(
            "{P} lists more than {MAX_FAUCET_ASSETS} assets"
        )));
    }
    let mut out: Vec<FaucetAsset> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let Some(entry) = faucet_entry(item, &format!("{P}[{i}]"), policy_asset)? else {
            continue;
        };
        if out
            .iter()
            .any(|e| e.network == entry.network && e.asset.eq_ignore_ascii_case(&entry.asset))
        {
            return Err(invalid(format!(
                "{P}[{i}] repeats asset {}",
                quoted(&entry.asset)
            )));
        }
        out.push(entry);
    }
    Ok(out)
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
        faucet: match o.get("faucet") {
            None | Some(Value::Null) => None,
            Some(list) => Some(faucet_list(list, &policy_asset)?),
        },
        policy_asset,
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
    let protocol_url = match o.get("protocol_url") {
        None | Some(Value::Null) => None,
        Some(_) => Some(http_url(o, "config", "protocol_url")?),
    };

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
        protocol_url,
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

// ---------------------------------------------------------------------------
// Faucet
// ---------------------------------------------------------------------------

/// Whole-request bound of a faucet request: the lab answers once the
/// payment is in its mempool.
const FAUCET_TIMEOUT: Duration = Duration::from_secs(20);
/// Largest faucet answer read.
const MAX_FAUCET_ANSWER_BYTES: u64 = 64 * 1024;

/// What the faucet paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaucetPayment {
    pub txid: String,
    /// Base units paid.
    pub amount_sat: u64,
}

/// Asks the lab's faucet at `faucet_url` to pay `address` on `network`
/// (`bitcoin-regtest` | `liquid-regtest`) some `asset` (the faucet's name
/// for it). Only those three values are sent; the amount is the faucet's
/// default. Bounded in time and size; no redirect is followed.
pub fn request_faucet(
    faucet_url: &str,
    network: &str,
    address: &str,
    asset: &str,
) -> Result<FaucetPayment, crate::error::FaucetError> {
    use crate::error::FaucetError;
    let client = crate::http::client(FAUCET_TIMEOUT).map_err(FaucetError::Unreachable)?;
    let request = client
        .post(faucet_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&serde_json::json!({
            "network": network,
            "address": address,
            "asset": asset,
        }));
    let answer = crate::http::send(request, MAX_FAUCET_ANSWER_BYTES)
        .map_err(|e| FaucetError::Unreachable(format!("the lab's faucet: {e}")))?;
    let status = answer.status.as_u16();
    let reason = crate::http::excerpt(&answer.body)
        .trim_end_matches('.')
        .to_string();
    match status {
        200..=299 => {}
        429 => {
            let when = match answer.retry_after {
                Some(s) => format!("Try again in {s} seconds."),
                None => "Try again later.".to_string(),
            };
            return Err(FaucetError::RateLimited {
                message: format!("the lab's faucet is at a limit: {reason}. {when}"),
                retry_after: answer.retry_after,
            });
        }
        404 | 405 | 421 | 501 => {
            return Err(FaucetError::Unavailable(format!(
                "the lab has no faucet at its published address (HTTP {status})."
            )))
        }
        400..=499 => {
            return Err(FaucetError::Refused(format!(
                "the lab's faucet refused the request (HTTP {status}): {reason}"
            )))
        }
        _ => {
            return Err(FaucetError::Unavailable(format!(
                "the lab's faucet cannot pay right now (HTTP {status}): {reason}"
            )))
        }
    }
    let unreadable =
        || FaucetError::Unavailable("the lab's faucet answered something unreadable.".to_string());
    let v: Value = serde_json::from_str(&answer.body).map_err(|_| unreadable())?;
    if v.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(FaucetError::Refused(format!(
            "the lab's faucet did not pay: {reason}"
        )));
    }
    let txid = v
        .get("txid")
        .and_then(Value::as_str)
        .filter(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(unreadable)?
        .to_ascii_lowercase();
    let amount_sat = v
        .get("amount_sat")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0 && *n <= MAX_FAUCET_SAT)
        .ok_or_else(unreadable)?;
    Ok(FaucetPayment { txid, amount_sat })
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
        assert_eq!(r.peg.pegout_min_sat, None, "absent in the example");
        let p = parse(&with(|v| reg(v)["peg"]["pegout_min_sat"] = 25_000.into())).unwrap();
        assert_eq!(p.regtest.peg.pegout_min_sat, Some(25_000));
        p.revalidate().unwrap();
        let err = parse(&with(|v| reg(v)["peg"]["pegout_min_sat"] = "1".into())).unwrap_err();
        assert!(err.contains("pegout_min_sat"), "{err}");
        assert_eq!(
            r.liquid_backend().unwrap(),
            LiquidBackend::Electrum {
                url: "127.0.0.1:19061".into(),
                tls: false,
                validate_domain: true
            }
        );
        let net = r.liquid_network().unwrap();
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
    fn a_stored_profile_is_checked_again_with_the_fetch_rules() {
        let good = parse(EXAMPLE).unwrap();
        good.revalidate().unwrap();
        let mut no_testnet = good.clone();
        no_testnet.testnet = None;
        no_testnet.revalidate().unwrap();
        type Tamper = Box<dyn FnOnce(&mut TestServerProfile)>;
        let cases: Vec<(Tamper, &str)> = vec![
            (
                Box::new(|p| p.regtest.policy_asset = "zz".repeat(32)),
                "policy_asset",
            ),
            (
                Box::new(|p| p.regtest.policy_asset = LBTC_MAINNET_ASSET_ID.into()),
                "mainnet",
            ),
            (
                Box::new(|p| p.regtest.genesis_hash = LIQUID_MAINNET_GENESIS.into()),
                "mainnet",
            ),
            (
                Box::new(|p| p.regtest.bitcoin_network = "bitcoin".into()),
                "mainnet",
            ),
            (
                Box::new(|p| p.regtest.liquid_electrum_url = "http://h:1".into()),
                "liquid_electrum_url",
            ),
            (
                Box::new(|p| p.regtest.peg.pegin_confirmations = Some(u32::MAX)),
                "pegin_confirmations",
            ),
            (
                Box::new(|p| p.base_url = "ftp://h".into()),
                "test server URL",
            ),
            (
                Box::new(|p| p.regtest.instance_id = "AB".repeat(32)),
                "form the wallet writes",
            ),
        ];
        for (tamper, want) in cases {
            let mut p = good.clone();
            tamper(&mut p);
            let err = p.revalidate().unwrap_err().to_string();
            assert!(err.contains(want), "{want}: {err}");
        }
        // The accessors fail instead of panicking on such a profile.
        let mut p = good.clone();
        p.regtest.policy_asset = "not hex".into();
        assert!(p.regtest.liquid_network().is_err());
        p.regtest.liquid_electrum_url = "garbage".into();
        assert!(p.regtest.liquid_backend().is_err());
    }

    /// The `faucet` list and `protocol_url` as the brief documents them.
    fn with_faucet() -> Value {
        let policy = "b0b2bef620ac742b2399a0085bc84e4860ae2c65b5375e3b94399debec69aa6b";
        let mut v: Value = serde_json::from_str(EXAMPLE).unwrap();
        v["protocol_url"] = "http://127.0.0.1:4000/".into();
        reg(&mut v)["faucet"] = serde_json::json!([
            {"asset":"btc","network":"bitcoin-regtest","ticker":"BTC","name":"Bitcoin (regtest)",
             "precision":8,"default_sat":1000000,"max_sat":10000000},
            {"asset":"lbtc","network":"liquid-regtest","ticker":"LBTC","name":"Liquid Bitcoin",
             "precision":8,"asset_id":policy,"default_sat":1000000,"max_sat":10000000},
            {"asset":"USDt","network":"liquid-regtest","ticker":"USDt","name":"Tether USD (test)",
             "precision":8,"asset_id":"cc".repeat(32),"default_sat":10000000000u64,
             "max_sat":100000000000u64},
            {"asset":"x","network":"some-future-chain","ticker":"X","name":"ignored","precision":2}
        ]);
        v
    }

    #[test]
    fn the_faucet_list_and_protocol_url_are_read_and_checked() {
        let p = parse(&with_faucet().to_string()).unwrap();
        assert_eq!(p.protocol_url.as_deref(), Some("http://127.0.0.1:4000"));
        let list = p.regtest.faucet.clone().unwrap();
        assert_eq!(list.len(), 3, "the unknown network is ignored");
        assert_eq!(list[0].network, FAUCET_BITCOIN_REGTEST);
        assert_eq!(
            list[1].asset_id.as_deref(),
            Some(p.regtest.policy_asset.as_str())
        );
        assert_eq!(list[2].ticker, "USDt");
        assert_eq!(list[2].max_sat, Some(100_000_000_000));
        assert_eq!(p.regtest.faucet_assets(), list);
        p.revalidate().unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<TestServerProfile>(&json).unwrap(), p);

        // Older labs: no list, no protocol site; the faucet pays BTC and L-BTC.
        let old = parse(EXAMPLE).unwrap();
        assert!(old.protocol_url.is_none() && old.regtest.faucet.is_none());
        let defaults = old.regtest.faucet_assets();
        let names: Vec<&str> = defaults.iter().map(|a| a.asset.as_str()).collect();
        assert_eq!(names, ["btc", "lbtc"]);
        assert_eq!(
            defaults[1].asset_id.as_deref(),
            Some(old.regtest.policy_asset.as_str())
        );
        // A profile stored before these fields existed still loads.
        let mut stored = serde_json::to_value(&old).unwrap();
        stored.as_object_mut().unwrap().remove("protocol_url");
        stored["regtest"].as_object_mut().unwrap().remove("faucet");
        let back: TestServerProfile = serde_json::from_value(stored).unwrap();
        assert_eq!(back, old);
        back.revalidate().unwrap();
    }

    #[test]
    fn a_hostile_faucet_list_or_protocol_url_refuses_the_config() {
        type Mutation = Box<dyn FnOnce(&mut Value)>;
        let f = |i: usize| -> Box<dyn Fn(&mut Value) -> &mut Value> {
            Box::new(move |v: &mut Value| &mut v["networks"]["liquid-regtest"]["faucet"][i])
        };
        let cases: Vec<(Mutation, &str)> = vec![
            (
                Box::new(|v| {
                    let one = reg(v)["faucet"][2].clone();
                    reg(v)["faucet"] = Value::Array(vec![one; MAX_FAUCET_ASSETS + 1]);
                }),
                "more than",
            ),
            (Box::new(|v| reg(v)["faucet"] = "btc".into()), "not a list"),
            (
                Box::new({
                    let f = f(2);
                    move |v| f(v)["asset_id"] = "zz".repeat(32).into()
                }),
                "asset_id",
            ),
            (
                Box::new({
                    let f = f(2);
                    move |v| f(v)["precision"] = 9.into()
                }),
                "precision",
            ),
            (
                Box::new({
                    let f = f(2);
                    move |v| f(v)["name"] = "Tether\u{1b}[2J".into()
                }),
                "name",
            ),
            (
                Box::new({
                    let f = f(2);
                    move |v| f(v)["ticker"] = "US Dt".into()
                }),
                "ticker",
            ),
            (
                // Another asset named with the chain's own L-BTC id.
                Box::new(|v| {
                    let policy = reg(v)["policy_asset"].clone();
                    reg(v)["faucet"][2]["asset_id"] = policy;
                }),
                "L-BTC",
            ),
            (
                Box::new({
                    let f = f(1);
                    move |v| f(v)["asset_id"] = "dd".repeat(32).into()
                }),
                "policy asset",
            ),
            (
                Box::new({
                    let f = f(0);
                    move |v| f(v)["asset_id"] = "dd".repeat(32).into()
                }),
                "bitcoin-regtest",
            ),
            (
                Box::new({
                    let f = f(2);
                    move |v| f(v)["default_sat"] = (u64::MAX).into()
                }),
                "default_sat",
            ),
            (
                Box::new({
                    let f = f(2);
                    move |v| f(v)["max_sat"] = 5.into()
                }),
                "above its max_sat",
            ),
            (
                Box::new(|v| {
                    let dup = reg(v)["faucet"][2].clone();
                    reg(v)["faucet"].as_array_mut().unwrap().push(dup);
                }),
                "repeats",
            ),
            (
                Box::new(|v| v["protocol_url"] = "http://u:p@h:1".into()),
                "protocol_url",
            ),
            (
                Box::new(|v| v["protocol_url"] = "ftp://h".into()),
                "protocol_url",
            ),
        ];
        for (mutate, want) in cases {
            let mut v = with_faucet();
            mutate(&mut v);
            let err = parse(&v.to_string()).unwrap_err();
            assert!(err.contains(want), "{want}: {err}");
            assert!(!err.contains('\u{1b}'), "{err}");
        }
        let mut v = with_faucet();
        reg(&mut v)["faucet"][3]["network"] = "liquid".into();
        assert!(parse(&v.to_string()).unwrap_err().contains("mainnet"));
        // A stored profile tampered with is refused like a fetched one.
        let mut p = parse(&with_faucet().to_string()).unwrap();
        p.regtest.faucet.as_mut().unwrap()[2].precision = 12;
        assert!(p
            .revalidate()
            .unwrap_err()
            .to_string()
            .contains("precision"));
        let mut p = parse(&with_faucet().to_string()).unwrap();
        p.protocol_url = Some("javascript:alert(1)".into());
        assert!(p.revalidate().is_err());
    }

    #[test]
    fn peg_confirmations_are_capped() {
        let err = parse(&with(|v| {
            reg(v)["peg"]["pegin_confirmations"] = 4_294_967_295u64.into()
        }))
        .unwrap_err();
        assert!(err.contains("pegin_confirmations"), "{err}");
        let err = parse(&with(|v| {
            reg(v)["peg"]["pegout_confirmations"] = (MAX_PEG_CONFIRMATIONS + 1).into()
        }))
        .unwrap_err();
        assert!(err.contains("pegout_confirmations"), "{err}");
        let p = parse(&with(|v| {
            reg(v)["peg"]["pegin_confirmations"] = MAX_PEG_CONFIRMATIONS.into()
        }))
        .unwrap();
        assert_eq!(
            p.regtest.peg.pegin_confirmations,
            Some(MAX_PEG_CONFIRMATIONS)
        );
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
