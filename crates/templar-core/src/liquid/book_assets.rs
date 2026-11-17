//! The active order book's public asset registry (`GET` / `POST
//! …/api/assets`, templar-protocol `docs/guides/orderbook.md` §5.4): the
//! ticker, name and precision the book shows for each Liquid asset of one
//! network, so a wallet that did not issue an asset can still name it.
//!
//! The registry is display metadata from a server this wallet does not
//! control, so it is read as untrusted input: a bounded list, 64-hex ids,
//! printable bounded names, precision 0–8, and never a word about the
//! network's policy asset (no entry for it, no other asset called after it).
//! Amounts stay in base units everywhere; only how they are shown changes.
//!
//! Parsing is pure; only [`fetch_assets`] and [`register_asset`] touch the
//! network, through [`crate::http`].

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Most entries a registry answer may hold (the book lists at most 2 000).
pub const MAX_BOOK_ASSETS: usize = 2_000;
/// Longest ticker kept (LWK's contract rule: 3–24 of `A-Z a-z 0-9 . -`; an
/// admin row may be shorter).
pub const MAX_TICKER_CHARS: usize = 24;
/// Longest name kept (LWK's contract rule: 1–255 ASCII characters).
pub const MAX_NAME_CHARS: usize = 255;
/// Largest registry answer read.
const MAX_ASSETS_BYTES: u64 = 1024 * 1024;
/// Largest answer to a registration.
const MAX_REGISTER_ANSWER_BYTES: u64 = 64 * 1024;
/// Whole-request bound of a registry read: it runs inside `sync_wallet`
/// and `list_markets`, best-effort, while the engine is held.
const FETCH_TIMEOUT: Duration = Duration::from_secs(6);
/// Whole-request bound of a registration (the book fetches the issuance
/// from its chain backend before it answers).
const REGISTER_TIMEOUT: Duration = Duration::from_secs(20);

/// Tickers that name Bitcoin or the policy asset: an entry calling another
/// asset by one of them is dropped (compared upper-case, dashes removed).
const RESERVED_TICKERS: &[&str] = &["BTC", "LBTC", "TBTC", "TLBTC", "RLBTC"];

/// One registry entry, checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookAsset {
    /// 64 hex, lower-case.
    pub asset_id: String,
    pub ticker: String,
    pub name: String,
    /// Decimal places, 0–8.
    pub precision: u8,
    /// Where the book has it from: `admin` | `contract` (`policy` rows are
    /// dropped), or `other` for a value this wallet does not know.
    pub source: String,
}

/// A registry that cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookAssetsError {
    /// The book has no registry (HTTP 404 / 405): an older book.
    NotAvailable,
    /// No usable answer: unreachable, an error status, garbage.
    Failed(String),
}

impl std::fmt::Display for BookAssetsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BookAssetsError::NotAvailable => write!(f, "this order book has no asset registry"),
            BookAssetsError::Failed(e) => write!(f, "{e}"),
        }
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// A ticker this wallet shows: 1–24 of `A-Z a-z 0-9 . -`, not a name of
/// Bitcoin or the policy asset.
fn ticker_ok(t: &str) -> bool {
    let reserved = {
        let norm: String = t
            .chars()
            .filter(|c| *c != '-')
            .collect::<String>()
            .to_ascii_uppercase();
        RESERVED_TICKERS.contains(&norm.as_str())
    };
    !t.is_empty()
        && t.len() <= MAX_TICKER_CHARS
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !reserved
}

fn name_ok(n: &str) -> bool {
    !n.trim().is_empty() && n.chars().count() <= MAX_NAME_CHARS && !n.chars().any(char::is_control)
}

/// One entry of an answer, or `None` when it cannot be shown safely.
fn entry(v: &Value, policy_asset: &str) -> Option<BookAsset> {
    let o = v.as_object()?;
    let asset_id = o.get("asset_id")?.as_str()?.trim().to_ascii_lowercase();
    if !is_hex64(&asset_id) || asset_id == policy_asset {
        return None;
    }
    let ticker = o.get("ticker")?.as_str()?.trim().to_string();
    let name = o.get("name")?.as_str()?.trim().to_string();
    let precision = u8::try_from(o.get("precision")?.as_u64()?).ok()?;
    if !ticker_ok(&ticker) || !name_ok(&name) || precision > 8 {
        return None;
    }
    let source = match o.get("source").and_then(Value::as_str) {
        Some(s @ ("admin" | "contract")) => s.to_string(),
        Some("policy") => return None,
        _ => "other".to_string(),
    };
    Some(BookAsset {
        asset_id,
        ticker,
        name,
        precision,
        source,
    })
}

/// Reads a `GET /api/assets?network=…` answer for `network`, whose policy
/// asset is `policy_asset` (hex). The answer as a whole must be an object
/// naming that network with at most [`MAX_BOOK_ASSETS`] entries; an entry
/// that cannot be shown safely is dropped (a malformed id, a ticker or name
/// out of bounds or with control characters, precision above 8, the policy
/// asset itself, another asset called BTC or LBTC), and of two entries for
/// one asset the first is kept.
pub fn parse_assets(
    body: &str,
    network: &str,
    policy_asset: &str,
) -> Result<Vec<BookAsset>, BookAssetsError> {
    let fail = |why: &str| BookAssetsError::Failed(format!("the asset registry {why}"));
    let root: Value =
        serde_json::from_str(body).map_err(|_| fail("answered something unreadable"))?;
    if root.get("network").and_then(Value::as_str) != Some(network) {
        return Err(fail(&format!("did not answer for {network}")));
    }
    let items = root
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("answered without a list"))?;
    if items.len() > MAX_BOOK_ASSETS {
        return Err(fail(&format!("lists more than {MAX_BOOK_ASSETS} assets")));
    }
    let policy = policy_asset.to_ascii_lowercase();
    let mut out: Vec<BookAsset> = Vec::new();
    for item in items {
        if let Some(e) = entry(item, &policy) {
            if !out.iter().any(|seen| seen.asset_id == e.asset_id) {
                out.push(e);
            }
        }
    }
    Ok(out)
}

/// Fetches the registry of `network` from `assets_url` (the book's
/// `…/api/assets`). Bounded in time and size; no redirect is followed.
pub fn fetch_assets(
    assets_url: &str,
    network: &str,
    policy_asset: &str,
) -> Result<Vec<BookAsset>, BookAssetsError> {
    let client = crate::http::client(FETCH_TIMEOUT).map_err(BookAssetsError::Failed)?;
    let separator = if assets_url.contains('?') { '&' } else { '?' };
    let url = format!("{assets_url}{separator}network={network}");
    let answer =
        crate::http::send(client.get(url), MAX_ASSETS_BYTES).map_err(BookAssetsError::Failed)?;
    match answer.status.as_u16() {
        200..=299 => parse_assets(&answer.body, network, policy_asset),
        404 | 405 => Err(BookAssetsError::NotAvailable),
        status => Err(BookAssetsError::Failed(format!(
            "the asset registry answered HTTP {status}: {}",
            crate::http::excerpt(&answer.body)
        ))),
    }
}

/// Announces a new issuance to the book's registry (`POST …/api/assets`):
/// the contract exactly as LWK serialises it (the object whose hash the
/// asset id commits to), the issuance transaction and its input. Returns
/// the row the book stored, or a readable reason it did not.
pub fn register_asset(
    assets_url: &str,
    network: &str,
    asset_id: &str,
    contract: &Value,
    issuance_txid: &str,
    issuance_vin: u32,
) -> Result<BookAsset, BookAssetsError> {
    let client = crate::http::client(REGISTER_TIMEOUT).map_err(BookAssetsError::Failed)?;
    let request = client.post(assets_url).json(&serde_json::json!({
        "network": network,
        "asset_id": asset_id,
        "contract": contract,
        "issuance_txid": issuance_txid,
        "issuance_vin": issuance_vin,
    }));
    let answer = crate::http::send(request, MAX_REGISTER_ANSWER_BYTES)
        .map_err(|e| BookAssetsError::Failed(format!("the order book: {e}")))?;
    let status = answer.status.as_u16();
    let message = crate::http::excerpt(&answer.body);
    let retry = answer
        .retry_after
        .map(|s| format!(" Try again in {s} seconds."))
        .unwrap_or_default();
    let why = match status {
        200 | 201 => {
            let row: Value = serde_json::from_str(&answer.body).map_err(|_| {
                BookAssetsError::Failed("the order book's answer could not be read".into())
            })?;
            let mut row = row;
            // The stored row of the asset just registered.
            row["source"] = row
                .get("source")
                .cloned()
                .unwrap_or_else(|| "contract".into());
            return entry(&row, "")
                .filter(|e| e.asset_id.eq_ignore_ascii_case(asset_id))
                .ok_or_else(|| {
                    BookAssetsError::Failed(
                        "the order book stored a row this wallet cannot show".into(),
                    )
                });
        }
        404 | 405 => return Err(BookAssetsError::NotAvailable),
        400 => format!("the order book refused the asset: {message}"),
        403 => format!("the order book does not register assets on {network}: {message}"),
        409 => format!("the order book has this ticker or asset already: {message}"),
        413 | 415 => format!("the order book could not read the request (HTTP {status})"),
        429 => format!("too many registrations from here.{retry}"),
        503 if answer.retry_after.is_some() => {
            format!("the order book cannot check the issuance right now.{retry} ({message})")
        }
        503 => format!("the order book's registry is full: {message}"),
        _ => format!("the order book answered HTTP {status}: {message}"),
    };
    Err(BookAssetsError::Failed(why))
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "b0b2bef620ac742b2399a0085bc84e4860ae2c65b5375e3b94399debec69aa6b";

    fn answer(assets: Value) -> String {
        serde_json::json!({"network": "liquid-regtest", "assets": assets}).to_string()
    }

    #[test]
    fn a_registry_answer_is_read_and_its_hostile_entries_dropped() {
        let tmpl = "80d249a8".repeat(8);
        let body = answer(serde_json::json!([
            {"asset_id": POLICY, "ticker": "LBTC", "name": "Liquid Bitcoin",
             "precision": 8, "source": "policy"},
            {"asset_id": tmpl.to_uppercase(), "ticker": "TMPL", "name": "Templar Token",
             "precision": 2, "source": "contract"},
            {"asset_id": tmpl, "ticker": "DUP", "name": "Second row", "precision": 0,
             "source": "admin"},
            {"asset_id": "cc".repeat(32), "ticker": "USDt", "name": "Tether USD (test)",
             "precision": 8, "source": "admin"},
            {"asset_id": "zz".repeat(32), "ticker": "BAD", "name": "bad hex", "precision": 2},
            {"asset_id": "dd".repeat(32), "ticker": "NINE", "name": "Too precise", "precision": 9},
            {"asset_id": "ee".repeat(32), "ticker": "CTRL", "name": "a\u{1b}[2Jb", "precision": 2},
            {"asset_id": "ff".repeat(32), "ticker": "l-btc", "name": "Fake", "precision": 8},
            {"asset_id": "aa".repeat(32), "ticker": "T".repeat(25), "name": "Long", "precision": 2},
            {"asset_id": "ab".repeat(32), "ticker": "NAME", "name": "n".repeat(256), "precision": 2},
            {"asset_id": "ac".repeat(32), "ticker": "NEW", "name": "Unknown source", "precision": 3,
             "source": "something"},
            "not an object"
        ]));
        let list = parse_assets(&body, "liquid-regtest", POLICY).unwrap();
        let tickers: Vec<&str> = list.iter().map(|a| a.ticker.as_str()).collect();
        assert_eq!(tickers, ["TMPL", "USDt", "NEW"]);
        assert_eq!(list[0].asset_id, "80d249a8".repeat(8), "lower-cased");
        assert_eq!(list[0].precision, 2);
        assert_eq!(list[0].source, "contract");
        assert_eq!(list[2].source, "other");
    }

    #[test]
    fn a_registry_answer_is_refused_as_a_whole_when_it_is_not_one() {
        let too_many: Vec<Value> = (0..=MAX_BOOK_ASSETS)
            .map(|i| {
                serde_json::json!({"asset_id": format!("{i:064x}"), "ticker": "TKN",
                                   "name": "x", "precision": 0})
            })
            .collect();
        for (body, want) in [
            (answer(Value::Array(too_many)), "more than"),
            (
                serde_json::json!({"network": "liquid-testnet", "assets": []}).to_string(),
                "did not answer for",
            ),
            ("[]".to_string(), "did not answer"),
            ("garbage".to_string(), "unreadable"),
            (
                serde_json::json!({"network": "liquid-regtest"}).to_string(),
                "without a list",
            ),
        ] {
            let err = parse_assets(&body, "liquid-regtest", POLICY)
                .unwrap_err()
                .to_string();
            assert!(err.contains(want), "{want}: {err}");
        }
        assert!(
            parse_assets(&answer(serde_json::json!([])), "liquid-regtest", POLICY)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn reserved_tickers_cover_bitcoin_and_the_policy_asset() {
        for t in ["BTC", "btc", "LBTC", "L-BTC", "tL-BTC", "rl-btc", "TBTC"] {
            assert!(!ticker_ok(t), "{t}");
        }
        for t in ["TMPL", "USDt", "L-USDT", "BTCX", "A.B-C"] {
            assert!(ticker_ok(t), "{t}");
        }
    }
}
