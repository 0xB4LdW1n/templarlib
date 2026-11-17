//! How the engine names a Liquid asset: the wallet's own knowledge first
//! (the policy asset, assets it issued, the built-in table), then the
//! active order book's public registry (`templar_core::liquid::book_assets`),
//! else the short asset id with 8 decimals.
//!
//! The registry is fetched only in network paths — `list_markets` and
//! `sync_wallet` — bounded and best-effort: a 404, a timeout or garbage
//! never fails the calling method. What it last answered is kept on disk
//! per order-book origin and network (`<data_dir>/book_assets.json`, plain
//! JSON, no secrets) and loaded when the book or the network changes, so
//! offline calls (opening a wallet, its summary) keep the names without
//! asking anyone.
//!
//! A registry entry never renames or re-scales the policy asset, and never
//! overrides what the wallet knows; a name taken from it is marked
//! `metadata_source: "book"` so a host can show the short asset id beside
//! it. Amounts in base units stay the source of truth everywhere.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use templar_core::liquid::book_assets::{fetch_assets, parse_assets, BookAsset, BookAssetsError};

use crate::state::AppState;

/// The on-disk cache of the registries this engine has read.
pub const CACHE_FILE: &str = "book_assets.json";
/// Most books (origin + network) kept in the cache; the oldest goes first.
const MAX_CACHED_BOOKS: usize = 16;
/// Least time between two reads of one registry (a sync and a market list
/// in quick succession ask once).
const REFRESH_EVERY: Duration = Duration::from_secs(20);

/// `metadata_source` of a name the wallet knows itself.
pub const FROM_WALLET: &str = "wallet";
/// `metadata_source` of a name from the active order book's registry.
pub const FROM_BOOK: &str = "book";
/// `metadata_source` of a name a feed row carried (the markets or book
/// feed), when neither the wallet nor the registry knows the asset.
pub const FROM_FEED: &str = "feed";
/// `metadata_source` of an asset nobody named: the ticker is the short
/// asset id and amounts use 8 decimals.
pub const FROM_NONE: &str = "none";

/// The active registry, in memory.
#[derive(Debug, Default)]
pub struct BookAssetCache {
    /// `<order book origin> <network>` the entries belong to.
    key: Option<String>,
    assets: HashMap<String, BookAsset>,
    /// When this engine last asked which registry.
    last_attempt: Option<(String, Instant)>,
}

impl BookAssetCache {
    fn get(&self, asset_id: &str) -> Option<&BookAsset> {
        self.assets.get(&asset_id.to_ascii_lowercase())
    }
}

/// How one asset is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetDisplay {
    pub ticker: String,
    pub name: String,
    pub precision: u8,
    /// [`FROM_WALLET`] | [`FROM_BOOK`] | [`FROM_NONE`].
    pub source: &'static str,
    /// The book's own provenance of a [`FROM_BOOK`] name (`admin` |
    /// `contract` | `other`).
    pub book_source: Option<String>,
}

impl AssetDisplay {
    /// `amount` base units with this asset's decimals, e.g. `100.00`.
    pub fn format(&self, amount: u64) -> String {
        format_units(amount, self.precision)
    }
}

/// `amount` base units with `precision` decimals (0–8).
pub fn format_units(amount: u64, precision: u8) -> String {
    let precision = precision.min(8);
    if precision == 0 {
        return amount.to_string();
    }
    let divisor = 10u64.pow(u32::from(precision));
    format!(
        "{}.{:0>width$}",
        amount / divisor,
        amount % divisor,
        width = usize::from(precision)
    )
}

/// How `asset_id` is shown on the active network.
pub fn display(state: &AppState, asset_id: &str) -> AssetDisplay {
    let wallet = |ticker: String, name: String, precision: u8| AssetDisplay {
        ticker,
        name,
        precision,
        source: FROM_WALLET,
        book_source: None,
    };
    if state.is_policy_asset(asset_id) {
        let name = state
            .asset_registry
            .get(&state.policy_asset_hex())
            .map(|a| a.name.clone())
            .unwrap_or_else(|| "Liquid Bitcoin".to_string());
        return wallet("LBTC".to_string(), name, 8);
    }
    let short: String = asset_id.chars().take(8).collect();
    if let Some(meta) = state.asset_registry.get_local_metadata(asset_id) {
        return wallet(
            meta.ticker.clone().unwrap_or_else(|| short.clone()),
            meta.name.clone(),
            meta.precision,
        );
    }
    if let Some(info) = state.asset_registry.get(asset_id) {
        return wallet(info.ticker.clone(), info.name.clone(), info.precision);
    }
    if let Some(entry) = state.book_assets.get(asset_id) {
        return AssetDisplay {
            ticker: entry.ticker.clone(),
            name: entry.name.clone(),
            precision: entry.precision,
            source: FROM_BOOK,
            book_source: Some(entry.source.clone()),
        };
    }
    AssetDisplay {
        ticker: short.clone(),
        name: format!("Unknown ({short})"),
        precision: 8,
        source: FROM_NONE,
        book_source: None,
    }
}

/// The registry key of the active book and network.
fn current_key(state: &AppState) -> String {
    format!(
        "{} {}",
        state.endpoints().orderbook_url().value,
        state.liquid_network.name()
    )
}

#[derive(Serialize, Deserialize, Default)]
struct CacheFile {
    books: BTreeMap<String, CachedBook>,
}

#[derive(Serialize, Deserialize)]
struct CachedBook {
    fetched_at: u64,
    assets: Vec<BookAsset>,
}

fn cache_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(CACHE_FILE)
}

fn load_file(data_dir: &Path) -> CacheFile {
    std::fs::read_to_string(cache_path(data_dir))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_file(data_dir: &Path, file: &CacheFile) {
    let written = serde_json::to_string_pretty(file)
        .map_err(|e| e.to_string())
        .and_then(|raw| {
            templar_core::registry::atomic_write(&cache_path(data_dir), &raw)
                .map_err(|e| e.to_string())
        });
    if let Err(e) = written {
        eprintln!("[templarlib] could not save {CACHE_FILE}: {e}");
    }
}

/// Loads the active book's names from disk (no network). Called whenever
/// the order book or the network may have changed. The file is checked
/// with the rules of a fresh answer: anyone with access to it can edit it.
pub fn reload(state: &mut AppState) {
    let key = current_key(state);
    let network = state.liquid_network.name().to_string();
    let policy = state.policy_asset_hex();
    let assets = load_file(&state.data_dir)
        .books
        .remove(&key)
        .and_then(|book| {
            let as_answer = serde_json::json!({ "network": network, "assets": book.assets });
            parse_assets(&as_answer.to_string(), &network, &policy).ok()
        })
        .unwrap_or_default();
    state.book_assets.assets = assets
        .into_iter()
        .map(|a| (a.asset_id.clone(), a))
        .collect();
    state.book_assets.key = Some(key);
}

/// Stores the names of the active book in memory and on disk.
fn store(state: &mut AppState, key: String, assets: Vec<BookAsset>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut file = load_file(&state.data_dir);
    file.books.insert(
        key.clone(),
        CachedBook {
            fetched_at: now,
            assets: assets.clone(),
        },
    );
    while file.books.len() > MAX_CACHED_BOOKS {
        let oldest = file
            .books
            .iter()
            .min_by_key(|(_, b)| b.fetched_at)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => file.books.remove(&k),
            None => break,
        };
    }
    save_file(&state.data_dir, &file);
    state.book_assets.assets = assets
        .into_iter()
        .map(|a| (a.asset_id.clone(), a))
        .collect();
    state.book_assets.key = Some(key);
}

/// Reads the active book's registry again for `sync_wallet`, best-effort:
/// a book without one, an unreachable book or a garbage answer keeps what
/// is cached and is only logged. Asks at most once per [`REFRESH_EVERY`]
/// per book (a sync loop does not hammer the book).
pub fn refresh(state: &mut AppState) {
    read_registry(state, true);
}

/// [`refresh`] without the interval, for `list_markets`: the rows it is
/// about to name may carry an asset registered seconds ago (a token just
/// issued and offered), and a cached list from the last sync would leave
/// it to the feed's own text.
pub fn refresh_now(state: &mut AppState) {
    read_registry(state, false);
}

fn read_registry(state: &mut AppState, throttled: bool) {
    let key = current_key(state);
    if state.book_assets.key.as_deref() != Some(key.as_str()) {
        reload(state);
    }
    if let Some((last, at)) = &state.book_assets.last_attempt {
        if throttled && *last == key && at.elapsed() < REFRESH_EVERY {
            return;
        }
    }
    state.book_assets.last_attempt = Some((key.clone(), Instant::now()));
    let url = state.endpoints().assets_url().value;
    let network = state.liquid_network.name().to_string();
    match fetch_assets(&url, &network, &state.policy_asset_hex()) {
        Ok(assets) => store(state, key, assets),
        Err(BookAssetsError::NotAvailable) => {
            eprintln!("[templarlib] the order book has no asset registry for {network}")
        }
        Err(BookAssetsError::Failed(e)) => {
            eprintln!("[templarlib] asset registry for {network} not read: {e}")
        }
    }
}

/// Adds one entry the book just stored (after this wallet announced it).
pub fn remember(state: &mut AppState, asset: BookAsset) {
    let key = current_key(state);
    if state.book_assets.key.as_deref() != Some(key.as_str()) {
        reload(state);
    }
    if state.is_policy_asset(&asset.asset_id) {
        return;
    }
    let mut assets: Vec<BookAsset> = state
        .book_assets
        .assets
        .values()
        .filter(|a| a.asset_id != asset.asset_id)
        .cloned()
        .collect();
    assets.push(asset);
    assets.sort_by(|a, b| a.asset_id.cmp(&b.asset_id));
    store(state, key, assets);
}

/// Forgets every cached registry of `network` (a reset regtest takes its
/// assets with it). Returns whether anything was dropped.
pub(crate) fn drop_network(data_dir: &Path, network: &str) -> bool {
    if !cache_path(data_dir).exists() {
        return false;
    }
    let mut file = load_file(data_dir);
    let before = file.books.len();
    let suffix = format!(" {network}");
    file.books.retain(|k, _| !k.ends_with(&suffix));
    let dropped = file.books.len() != before;
    if dropped {
        save_file(data_dir, &file);
    }
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http::{MockHttp, Reply};

    fn test_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "templar_names_{}_{}_{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        AppState::new_for_test(dir)
    }

    #[test]
    fn units_are_formatted_with_the_assets_decimals() {
        assert_eq!(format_units(10_000, 2), "100.00");
        assert_eq!(format_units(10_000, 8), "0.00010000");
        assert_eq!(format_units(7, 0), "7");
        assert_eq!(format_units(u64::MAX, 8), "184467440737.09551615");
        assert_eq!(format_units(5, 200), "0.00000005", "capped at 8");
    }

    #[test]
    fn the_wallet_knows_first_the_registry_second() {
        let mut state = test_state("order");
        let tmpl = "80d249a8".repeat(8);
        let mine = "aa".repeat(32);
        state.book_assets.assets = [
            (
                tmpl.clone(),
                BookAsset {
                    asset_id: tmpl.clone(),
                    ticker: "TMPL".into(),
                    name: "Templar Token".into(),
                    precision: 2,
                    source: "contract".into(),
                },
            ),
            (
                mine.clone(),
                BookAsset {
                    asset_id: mine.clone(),
                    ticker: "FAKE".into(),
                    name: "Renamed by the book".into(),
                    precision: 0,
                    source: "admin".into(),
                },
            ),
        ]
        .into();
        state
            .asset_registry
            .add_local_metadata(templar_core::AssetMetadata {
                asset_id: mine.clone(),
                name: "My Token".into(),
                ticker: Some("MINE".into()),
                precision: 3,
                domain: None,
                is_reissuance_token: false,
                parent_asset_id: None,
            });
        let d = display(&state, &tmpl);
        assert_eq!(
            (d.ticker.as_str(), d.precision, d.source),
            ("TMPL", 2, FROM_BOOK)
        );
        assert_eq!(d.book_source.as_deref(), Some("contract"));
        assert_eq!(d.format(10_000), "100.00");
        let d = display(&state, &tmpl.to_uppercase());
        assert_eq!(d.source, FROM_BOOK, "ids compare case-insensitively");
        let d = display(&state, &mine);
        assert_eq!(
            (d.ticker.as_str(), d.precision, d.source),
            ("MINE", 3, FROM_WALLET)
        );
        let d = display(&state, &state.policy_asset_hex());
        assert_eq!(
            (d.ticker.as_str(), d.precision, d.source),
            ("LBTC", 8, FROM_WALLET)
        );
        let d = display(&state, &"bb".repeat(32));
        assert_eq!(
            (d.ticker.as_str(), d.precision, d.source),
            ("bbbbbbbb", 8, FROM_NONE)
        );
    }

    #[test]
    fn a_registry_is_cached_per_book_and_survives_a_restart_offline() {
        let tmpl = "80d249a8".repeat(8);
        let mut state = test_state("cache");
        let policy = state.policy_asset_hex();
        let answer = serde_json::json!({"network": "liquid-testnet", "assets": [
            {"asset_id": policy, "ticker": "TLBTC", "name": "Renamed policy", "precision": 2,
             "source": "policy"},
            {"asset_id": tmpl, "ticker": "TMPL", "name": "Templar Token", "precision": 2,
             "source": "contract"}
        ]})
        .to_string();
        let book = MockHttp::start(move |r| {
            if r.target == "/api/assets?network=liquid-testnet" {
                Reply::json(200, answer.clone())
            } else {
                Reply::json(404, "{}")
            }
        });
        // An engine whose order book is the stub (as a lab profile would).
        let mut profile = templar_core::test_server::parse_config(
            "http://127.0.0.1:8096",
            &crate::contract_tests::lab_config_text(&"77".repeat(32)),
            0,
        )
        .unwrap();
        profile.orderbook_url = book.url.clone();
        state.test_server = Some(profile.clone());
        refresh(&mut state);
        assert_eq!(display(&state, &tmpl).ticker, "TMPL");
        assert_eq!(display(&state, &policy).precision, 8, "never re-scaled");
        // Within the refresh interval a sync asks nothing again; a market
        // listing always asks.
        refresh(&mut state);
        assert_eq!(book.requests().len(), 1);
        refresh_now(&mut state);
        assert_eq!(book.requests().len(), 2);
        let raw = std::fs::read_to_string(state.data_dir.join(CACHE_FILE)).unwrap();
        assert!(
            raw.contains("TMPL") && !raw.contains("Renamed policy"),
            "{raw}"
        );

        // Another engine on the same data directory, offline: the names are
        // there without a request.
        let dir = state.data_dir.clone();
        drop(state);
        let mut again = AppState::new_for_test(dir);
        again.test_server = Some(profile);
        reload(&mut again);
        assert_eq!(display(&again, &tmpl).ticker, "TMPL");
        assert_eq!(book.requests().len(), 2, "nothing asked by the reload");
        // A tampered cache is checked like an answer.
        let mut file = load_file(&again.data_dir);
        for b in file.books.values_mut() {
            b.assets[0].precision = 12;
        }
        save_file(&again.data_dir, &file);
        reload(&mut again);
        assert_eq!(display(&again, &tmpl).source, FROM_NONE);
        // A reset regtest drops only regtest books.
        assert!(!drop_network(&again.data_dir, "liquid-regtest"));
        assert!(drop_network(&again.data_dir, "liquid-testnet"));
    }

    #[test]
    fn a_book_without_a_registry_or_out_of_reach_changes_nothing() {
        let mut state = test_state("absent");
        let book = MockHttp::start(|_| Reply::json(404, "not found"));
        let mut profile = templar_core::test_server::parse_config(
            "http://127.0.0.1:8096",
            &crate::contract_tests::lab_config_text(&"78".repeat(32)),
            0,
        )
        .unwrap();
        profile.orderbook_url = book.url.clone();
        state.test_server = Some(profile.clone());
        refresh(&mut state);
        assert!(state.book_assets.assets.is_empty());
        assert!(!state.data_dir.join(CACHE_FILE).exists());
        profile.orderbook_url = crate::test_http::closed_port_url();
        state.test_server = Some(profile);
        refresh(&mut state);
        assert!(state.book_assets.assets.is_empty());
    }
}
