//! Hermetic contract tests for the shared JSON application surface.
//!
//! These drive `dispatch::dispatch()` — the same router the C `wallet_call`
//! entry point uses — against a throwaway data directory per test, fully
//! offline (nothing here calls `sync_wallet` or touches an Electrum server).
//!
//! The key assertions mirror the exact JSON keys the Dart decode sites read
//! (templar-wallet's `apps/gui/lib/bridge/ffi_wallet_bridge.dart` and the model
//! `fromJson` factories), so a shape drift on either side of the boundary
//! fails here before it ships — a decode-shape bug already shipped once
//! (commit 0b75bd9).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::dispatch::dispatch;
use crate::state::AppState;

/// Standard BIP39 test vector. Master fingerprint: 73c5da0a.
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon about";

static DIR_SEQ: AtomicU32 = AtomicU32::new(0);

/// Per-test state bound to a unique temp data dir. `AppState` takes an
/// exclusive per-data-dir file lock, so unique dirs keep the parallel test
/// runner from colliding; the dir is removed (best-effort) on drop.
struct TestEnv {
    state: AppState,
    dir: PathBuf,
    /// Leave the data directory on disk when dropped (a live test asked to
    /// keep its funded wallets for the next run).
    keep: bool,
}

/// The passphrase of every test vault.
const TEST_VAULT_PASSPHRASE: &str = "contract-test-passphrase";

impl TestEnv {
    fn new() -> Self {
        let mut env = Self::new_without_vault();
        env.install_test_vault();
        env
    }

    /// An engine on a data directory that outlives the test: reopened (its
    /// test vault unlocked) when it exists, set up like [`TestEnv::new`]
    /// otherwise. Never removed.
    fn kept(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).expect("create kept data dir");
        let reopen = templar_core::registry::vault_is_initialized(&dir);
        let state = AppState::new_for_test(dir.clone());
        let mut env = Self {
            state,
            dir,
            keep: true,
        };
        if reopen {
            env.ok(
                "unlock_vault",
                json!({ "passphrase": TEST_VAULT_PASSPHRASE }),
            );
        } else {
            env.install_test_vault();
        }
        env
    }

    fn install_test_vault(&mut self) {
        // Production never stores a seed without a vault (A2), so neither does
        // the harness: `create_wallet` is refused on an unencrypted install.
        // Built directly with cheap KDF parameters — going through
        // `vault::setup` would spend 64 MiB and half a second of Argon2 per
        // test for no extra coverage.
        if self.state.startup_error.is_none() {
            let (vault, header) = templar_core::Vault::create_with_params(
                TEST_VAULT_PASSPHRASE,
                templar_core::KdfParams::FAST_FOR_TESTS,
            )
            .expect("test vault");
            templar_core::registry::save_vault_header(&self.dir, &header)
                .expect("test vault header");
            self.state
                .registry
                .save_with_vault(&self.dir, Some(&vault))
                .expect("seal test registry");
            self.state.vault = Some(vault);
        }
    }

    /// A fresh install with no vault at all — what the app sees before the
    /// user has ever set an app password.
    fn new_without_vault() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let dir = std::env::temp_dir().join(format!(
            "templar-ffi-contract-{}-{}-{}",
            std::process::id(),
            DIR_SEQ.fetch_add(1, Ordering::Relaxed),
            nanos,
        ));
        std::fs::create_dir_all(&dir).expect("create test data dir");
        let state = AppState::new_for_test(dir.clone());
        Self {
            state,
            dir,
            keep: false,
        }
    }

    /// Raw dispatch — returns the full `{"ok": ...}` / `{"err": ...}` envelope.
    fn call(&mut self, method: &str, params: Value) -> Value {
        dispatch(&mut self.state, method, &params)
    }

    /// Dispatch that must succeed; returns the `ok` payload.
    fn ok(&mut self, method: &str, params: Value) -> Value {
        let resp = self.call(method, params);
        assert!(
            resp.get("err").is_none(),
            "{method} unexpectedly failed: {resp}"
        );
        resp.get("ok")
            .cloned()
            .unwrap_or_else(|| panic!("{method} response has neither ok nor err: {resp}"))
    }

    /// Dispatch that must fail; returns the `err` message.
    fn err(&mut self, method: &str, params: Value) -> String {
        let resp = self.call(method, params);
        assert!(
            resp.get("ok").is_none(),
            "{method} unexpectedly succeeded: {resp}"
        );
        resp["err"]
            .as_str()
            .unwrap_or_else(|| panic!("{method} err is not a string: {resp}"))
            .to_string()
    }

    /// Creates a Bitcoin-only software wallet from the test mnemonic and
    /// returns its id.
    fn create_test_wallet(&mut self) -> String {
        let created = self.ok(
            "create_wallet",
            json!({ "name": "Contract Test", "mnemonic": MNEMONIC, "liquid": false }),
        );
        created["id"]
            .as_str()
            .expect("create_wallet ok payload must carry a string id")
            .to_string()
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Every listed key must be present on the object (value may be null — the
/// Dart mappers handle null, but a *missing* key means the shapes diverged).
fn assert_keys(context: &str, obj: &Value, keys: &[&str]) {
    let map = obj
        .as_object()
        .unwrap_or_else(|| panic!("{context}: expected a JSON object, got {obj}"));
    for key in keys {
        assert!(
            map.contains_key(*key),
            "{context}: missing key {key:?} in {obj}"
        );
    }
}

#[test]
fn swap_publish_rejects_invalid_proposal_before_network_access() {
    let mut env = TestEnv::new_without_vault();
    let error = env.err(
        "swap_publish",
        json!({ "proposal_json": "not-json", "note": "local test" }),
    );
    assert!(!error.is_empty());
}

// ── Registry ─────────────────────────────────────────────────────────────────

#[test]
fn generate_mnemonic_word_counts() {
    let mut env = TestEnv::new();
    for count in [12usize, 24] {
        let words = env.ok("generate_mnemonic", json!({ "word_count": count }));
        let words = words.as_array().expect("generate_mnemonic returns a list");
        assert_eq!(words.len(), count, "wrong word count");
        assert!(
            words
                .iter()
                .all(|w| w.as_str().is_some_and(|s| !s.is_empty())),
            "every word must be a non-empty string: {words:?}"
        );
    }
}

#[test]
fn create_wallet_then_list_wallets_roundtrip() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    assert!(!id.is_empty());

    let listed = env.ok("list_wallets", json!({}));
    let listed = listed.as_array().expect("list_wallets returns a list");
    assert_eq!(listed.len(), 1, "exactly the created wallet: {listed:?}");

    let w = &listed[0];
    // Exact keys WalletSummary.fromJson reads (wallet_summary.dart).
    assert_keys(
        "list_wallets[0]",
        w,
        &[
            "id",
            "name",
            "wallet_type",
            "network",
            "balance_sats",
            "tx_count",
            "last_sync_at",
            "is_watch_only",
            "type_label",
            "liquid_enabled",
            "master_fingerprint",
            "xpub",
            "required_sigs",
            "total_signers",
        ],
    );
    assert_eq!(w["id"], json!(id));
    assert_eq!(w["name"], json!("Contract Test"));
    assert_eq!(w["wallet_type"], json!("singlesig"));
    assert_eq!(w["network"], json!("testnet"));
    assert_eq!(w["is_watch_only"], json!(false));
    assert_eq!(w["liquid_enabled"], json!(false));
    assert_eq!(w["master_fingerprint"], json!("73c5da0a"));
    assert!(
        w["xpub"].as_str().unwrap_or("").starts_with("tpub"),
        "testnet account xpub expected: {}",
        w["xpub"]
    );
}

#[test]
fn create_wallet_rejects_invalid_mnemonic() {
    let mut env = TestEnv::new();
    let err = env.err(
        "create_wallet",
        json!({ "name": "Broken", "mnemonic": "not a valid seed phrase at all", "liquid": false }),
    );
    assert!(!err.is_empty());
    // A rejected create must not leave an orphan registry entry (N2).
    let listed = env.ok("list_wallets", json!({}));
    assert_eq!(listed.as_array().map(Vec::len), Some(0));
}

// ── Wallet lifecycle + addresses (offline) ───────────────────────────────────

#[test]
fn open_wallet_and_generate_receive_address_offline() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();

    let opened = env.ok("open_wallet", json!({ "wallet_id": id }));
    assert!(opened.is_null(), "open_wallet returns null, got {opened}");

    let first = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    );
    // Exact keys _addressInfoFromJson reads (ffi_wallet_bridge.dart).
    assert_keys(
        "generate_receive_address",
        &first,
        &[
            "address",
            "index",
            "asset",
            "label",
            "received_sats",
            "derivation_path",
        ],
    );
    let first_addr = first["address"].as_str().unwrap_or("");
    assert!(
        first_addr.starts_with("tb1"),
        "testnet bech32 address expected: {first_addr:?}"
    );
    assert_eq!(first["asset"], json!("BTC"));
    let first_index = first["index"].as_u64().expect("index is a number");

    // `fresh` must advance the derivation index even though the current
    // address was never used (commit f88de7b behavior).
    let fresh = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC", "fresh": true }),
    );
    let fresh_addr = fresh["address"].as_str().unwrap_or("");
    assert!(fresh_addr.starts_with("tb1"));
    assert_ne!(fresh_addr, first_addr, "fresh must hand out a new address");
    assert!(
        fresh["index"].as_u64().expect("index is a number") > first_index,
        "fresh must advance the index: first={first}, fresh={fresh}"
    );
}

#[test]
fn liquid_receive_address_advances_on_fresh_like_bitcoin() {
    let mut env = TestEnv::new();
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Liquid addresses", "mnemonic": MNEMONIC, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();
    let get = |env: &mut TestEnv, fresh: bool| {
        env.ok(
            "generate_receive_address",
            json!({ "wallet_id": id, "asset": "LBTC", "fresh": fresh }),
        )
    };

    let first = get(&mut env, false);
    assert_keys(
        "generate_receive_address",
        &first,
        &[
            "address",
            "index",
            "asset",
            "label",
            "received_sats",
            "derivation_path",
            "unconfidential_address",
        ],
    );
    let addr = first["address"].as_str().unwrap().to_string();
    let plain = first["unconfidential_address"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(addr.starts_with("tlq1"), "confidential address: {addr}");
    assert!(plain.starts_with("tex1"), "unconfidential address: {plain}");
    assert_eq!(first["index"], json!(0));

    // Revisiting reuses the unused address instead of burning an index.
    assert_eq!(get(&mut env, false)["address"], json!(addr));

    // "New address" hands out the next one although this one never received.
    let fresh = get(&mut env, true);
    assert_eq!(fresh["index"], json!(1), "{fresh}");
    assert_ne!(fresh["address"], json!(addr));
    assert_ne!(fresh["unconfidential_address"], json!(plain));
    assert_eq!(get(&mut env, false)["address"], fresh["address"]);

    // The index survives closing and reopening the wallet.
    env.state.liquid = None;
    env.state.active_wallet_id = None;
    assert_eq!(get(&mut env, false)["address"], fresh["address"]);
    assert_eq!(get(&mut env, true)["index"], json!(2));

    // A Bitcoin address has no unconfidential form: the key stays absent.
    let btc = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    );
    assert!(btc.get("unconfidential_address").is_none(), "{btc}");
}

#[test]
fn open_wallet_unknown_id_errs() {
    let mut env = TestEnv::new();
    let err = env.err("open_wallet", json!({ "wallet_id": "no-such-wallet" }));
    assert!(
        err.contains("not found") || err.contains("Wallet"),
        "unexpected message: {err}"
    );
}

// ── Wallet info ──────────────────────────────────────────────────────────────

#[test]
fn get_wallet_info_exposes_public_identity_for_software_wallet() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    let info = env.ok("get_wallet_info", json!({ "wallet_id": id }));

    // Exact keys _walletInfoFromJson reads (ffi_wallet_bridge.dart).
    assert_keys(
        "get_wallet_info",
        &info,
        &[
            "id",
            "name",
            "network",
            "master_fingerprint",
            "derivation_path",
            "script_type",
            "xpub",
            "receive_descriptor",
            "change_descriptor",
            "multipath_descriptor",
            "liquid_descriptor",
            "master_blinding_key",
            "has_seed",
            "has_passphrase",
            "last_backup_at",
            "cosigner_keys",
        ],
    );
    assert_eq!(info["id"], json!(id));
    assert_eq!(info["master_fingerprint"], json!("73c5da0a"));
    assert!(info["xpub"].as_str().unwrap_or("").starts_with("tpub"));
    assert_eq!(info["has_seed"], json!(true));

    let recv = info["receive_descriptor"].as_str().unwrap_or("");
    assert!(recv.contains("wpkh("), "descriptor expected: {recv:?}");
    // N1 guarantee: never expose a signing descriptor across the API.
    for field in ["receive_descriptor", "change_descriptor"] {
        let desc = info[field].as_str().unwrap_or("");
        assert!(
            !desc.contains("tprv") && !desc.contains("xprv"),
            "{field} leaks a private key: {desc}"
        );
    }
}

// ── Dashboard ────────────────────────────────────────────────────────────────

#[test]
fn get_wallet_summary_matches_dart_decode_shape() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    let dash = env.ok("get_wallet_summary", json!({ "wallet_id": id }));

    // Exact keys _dashboardFromJson reads (ffi_wallet_bridge.dart).
    assert_keys(
        "get_wallet_summary",
        &dash,
        &[
            "wallet_id",
            "wallet_name",
            "total_balance_display",
            "sync_state",
            "assets",
            "recent_activity",
        ],
    );
    assert_eq!(dash["wallet_id"], json!(id));
    assert_eq!(dash["wallet_name"], json!("Contract Test"));
    assert!(!dash["sync_state"].as_str().unwrap_or("").is_empty());
    assert!(dash["recent_activity"].is_array());

    let assets = dash["assets"].as_array().expect("assets is a list");
    assert!(!assets.is_empty(), "BTC asset always present");
    // Exact keys _assetBalanceFromJson reads.
    assert_keys(
        "assets[0]",
        &assets[0],
        &[
            "asset_id",
            "ticker",
            "name",
            "amount",
            "display_amount",
            "fiat_estimate",
            "status",
            "utxo_count",
            "is_native",
        ],
    );
    assert_eq!(assets[0]["ticker"], json!("BTC"));
    assert_eq!(assets[0]["amount"], json!(0), "fresh wallet holds nothing");
    // Additive: how the amount is scaled and who named the asset.
    for a in assets {
        assert_keys(
            "assets[]",
            a,
            &["precision", "metadata_source", "book_source"],
        );
        assert_eq!(a["metadata_source"], json!("wallet"));
    }
}

// ── Version handshake ────────────────────────────────────────────────────────

#[test]
fn version_reports_the_crate_version() {
    let mut env = TestEnv::new();
    let v = env.ok("version", json!({}));
    assert_eq!(v, json!(env!("CARGO_PKG_VERSION")));
}

#[test]
fn version_survives_a_startup_error() {
    // The About screen must distinguish "engine loaded but init failed" from
    // "dylib unreachable" — version answers even under a fatal init condition.
    let mut env = TestEnv::new();
    env.state.startup_error = Some("test-injected corruption".to_string());
    let v = env.ok("version", json!({}));
    assert_eq!(v, json!(env!("CARGO_PKG_VERSION")));
}

// ── Error paths ──────────────────────────────────────────────────────────────

#[test]
fn unknown_method_is_an_error() {
    let mut env = TestEnv::new();
    let err = env.err("definitely_not_a_method", json!({}));
    assert!(err.contains("Unknown method"), "unexpected message: {err}");
}

#[test]
fn inspect_psbt_rejects_garbage() {
    let mut env = TestEnv::new();
    env.err("inspect_psbt", json!({ "psbt_base64": "not a psbt" }));
}

#[test]
fn startup_error_fails_every_method_with_its_message() {
    let mut env = TestEnv::new();
    let msg = "Wallet storage could not be read: test-injected corruption.";
    env.state.startup_error = Some(msg.to_string());

    for (method, params) in [
        ("list_wallets", json!({})),
        ("generate_mnemonic", json!({ "word_count": 12 })),
        (
            "create_wallet",
            json!({ "name": "X", "mnemonic": MNEMONIC }),
        ),
        ("get_wallet_summary", json!({ "wallet_id": "any" })),
    ] {
        let err = env.err(method, params);
        assert_eq!(err, msg, "{method} must propagate the startup error");
    }
}

/// Backup verification is the safety net behind every "write these words
/// down" screen, so the four outcomes it can report are pinned here: the right
/// phrase passes, a different valid phrase fails, a transposed word fails, and
/// the wire shape stays what the Dart side decodes.
#[test]
fn verify_backup_accepts_only_this_wallets_phrase() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();

    let good = env.ok(
        "verify_backup",
        json!({ "wallet_id": &id, "mnemonic": MNEMONIC }),
    );
    assert_eq!(
        good["matched"],
        json!(true),
        "own phrase must verify: {good}"
    );
    assert_eq!(good["reason"], json!("ok"));
    assert_eq!(good["fingerprint_match"], json!(true));
    for key in [
        "matched",
        "reason",
        "derived_fingerprint",
        "expected_fingerprint",
        "fingerprint_match",
    ] {
        assert!(good.get(key).is_some(), "verify_backup must carry {key}");
    }

    // A valid phrase for some *other* wallet: checksum passes, keys do not.
    let other = "legal winner thank year wave sausage worth useful legal winner                  thank yellow";
    let wrong = env.ok(
        "verify_backup",
        json!({ "wallet_id": &id, "mnemonic": other }),
    );
    assert_eq!(wrong["matched"], json!(false), "foreign phrase must fail");
    assert_eq!(wrong["reason"], json!("mismatch"));
    assert_ne!(
        wrong["derived_fingerprint"], wrong["expected_fingerprint"],
        "a failure must report which wallet the paper actually is"
    );

    // The failure a quiz cannot catch: right words, wrong order.
    let transposed = "abandon abandon abandon abandon abandon abandon abandon                       abandon abandon abandon about abandon";
    let swapped = env.ok(
        "verify_backup",
        json!({ "wallet_id": &id, "mnemonic": transposed }),
    );
    assert_eq!(swapped["matched"], json!(false), "word order must matter");

    // Formatting noise from a notes app is not a backup failure.
    let messy = format!(
        "  1. {}  ",
        MNEMONIC.split_whitespace().collect::<Vec<_>>().join("\n")
    );
    let tidy = env.ok(
        "verify_backup",
        json!({ "wallet_id": &id, "mnemonic": messy }),
    );
    assert_eq!(
        tidy["matched"],
        json!(true),
        "line breaks must not fail: {tidy}"
    );
}

/// The reveal gate proves the app password without handing out a session, and
/// throttles guessing on top of Argon2id's own cost.
#[test]
fn verify_vault_passphrase_checks_without_unlocking() {
    let mut env = TestEnv::new();
    // The harness builds its vault directly, so `state.vault` is already set;
    // drop it to model the real "vault exists, gate is closed" case.
    env.state.vault = None;

    let err = env.err(
        "verify_vault_passphrase",
        json!({ "passphrase": "not the passphrase" }),
    );
    assert!(
        err.contains("Wrong app password"),
        "unexpected error: {err}"
    );
    assert!(
        env.state.vault.is_none(),
        "a failed check must not touch the session"
    );

    env.ok(
        "verify_vault_passphrase",
        json!({ "passphrase": "contract-test-passphrase" }),
    );
    assert!(
        env.state.vault.is_none(),
        "verifying proves the password, it must not unlock the vault"
    );
    assert_eq!(env.state.verify_failures, 0, "success resets the counter");
}

/// The Touch ID confirmation gate proves the keystore's copy of the vault key
/// the way the reveal gate proves the passphrase: without opening a session.
#[test]
fn verify_vault_key_checks_without_unlocking() {
    let mut env = TestEnv::new();
    let key_hex = env.ok("export_vault_key", json!({}))["key_hex"]
        .as_str()
        .expect("key_hex")
        .to_string();
    env.ok("lock_vault", json!({}));
    assert!(env.state.vault.is_none());

    // The right key proves itself and grants nothing.
    let resp = env.call("verify_vault_key", json!({ "key_hex": key_hex }));
    assert_eq!(resp, json!({ "ok": null }), "{resp}");
    assert!(
        env.state.vault.is_none(),
        "verifying proves the key, it must not unlock the vault"
    );
    assert_eq!(env.ok("vault_status", json!({}))["state"], json!("locked"));

    // A key from another vault reads as a mismatch, so the UI can switch the
    // feature off rather than retry forever.
    let wrong = "ff".repeat(32);
    let err = env.err("verify_vault_key", json!({ "key_hex": wrong }));
    assert!(err.contains("does not match"), "unexpected error: {err}");
    assert!(env.state.vault.is_none());

    // Garbage is garbage, not a mismatch.
    let err = env.err("verify_vault_key", json!({ "key_hex": "zz" }));
    assert!(err.contains("hex"), "unexpected error: {err}");
    assert!(!err.contains("does not match"), "unexpected error: {err}");
}

/// A2's blind spot: the create-time refusal does nothing about phrases already
/// written by an older build, so the status call has to report them.
#[test]
fn vault_status_reports_plaintext_seeds_needing_migration() {
    let mut env = TestEnv::new();
    let status = env.ok("vault_status", json!({}));
    for key in [
        "initialized",
        "unlocked",
        "needs_migration",
        "plaintext_seed_wallets",
        "state",
    ] {
        assert!(status.get(key).is_some(), "vault_status must carry {key}");
    }
    // This env has a vault, so nothing is in the clear.
    assert_eq!(status["needs_migration"], json!(false));
    assert_eq!(status["plaintext_seed_wallets"], json!(0));
}

/// The key behind the biometric unlock exists only inside an unlocked vault:
/// nothing to export before setup, nothing while locked.
#[test]
fn export_vault_key_needs_a_set_up_and_unlocked_vault() {
    let mut fresh = TestEnv::new_without_vault();
    let err = fresh.err("export_vault_key", json!({}));
    assert!(err.contains("No vault"), "unexpected error: {err}");

    let mut env = TestEnv::new();
    env.ok("lock_vault", json!({}));
    let err = env.err("export_vault_key", json!({}));
    assert!(err.contains("locked"), "unexpected error: {err}");
    assert!(
        env.state.vault.is_none(),
        "a refused export must not unlock"
    );
}

/// Biometric unlock end to end: the key exported from an unlocked session
/// opens the vault again after a lock, with the same post-unlock state as a
/// passphrase unlock — wallets listed, status unlocked, same `null` payload.
#[test]
fn stored_key_unlocks_the_vault_without_the_passphrase() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();

    let exported = env.ok("export_vault_key", json!({}));
    let key_hex = exported["key_hex"]
        .as_str()
        .expect("export_vault_key ok payload must carry a string key_hex")
        .to_string();
    assert_eq!(key_hex.len(), 64, "32 bytes of hex: {key_hex}");
    assert!(
        key_hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "lowercase hex: {key_hex}"
    );
    // The same session hands out the same key every time.
    assert_eq!(
        env.ok("export_vault_key", json!({}))["key_hex"],
        json!(key_hex)
    );

    env.ok("lock_vault", json!({}));
    assert!(env.state.vault.is_none());
    assert_eq!(env.ok("vault_status", json!({}))["unlocked"], json!(false));
    env.err("list_wallets", json!({}));

    // Same envelope as `unlock_vault`: `{"ok": null}`.
    let resp = env.call("unlock_vault_with_key", json!({ "key_hex": key_hex }));
    assert_eq!(resp, json!({ "ok": null }), "{resp}");
    assert!(env.state.vault.is_some());
    let status = env.ok("vault_status", json!({}));
    assert_eq!(status["unlocked"], json!(true), "{status}");
    assert_eq!(status["state"], json!("unlocked"), "{status}");
    let wallets = env.ok("list_wallets", json!({}));
    assert_eq!(
        wallets[0]["id"],
        json!(id),
        "the sealed registry is back: {wallets}"
    );

    // The keystore may round-trip the case; both must open.
    env.ok("lock_vault", json!({}));
    env.ok(
        "unlock_vault_with_key",
        json!({ "key_hex": key_hex.to_uppercase() }),
    );

    // The exported key *is* the passphrase-derived one: a passphrase unlock
    // exports the same bytes, so the keystore copy stays valid across both.
    env.ok("lock_vault", json!({}));
    env.ok(
        "unlock_vault",
        json!({ "passphrase": "contract-test-passphrase" }),
    );
    assert_eq!(
        env.ok("export_vault_key", json!({}))["key_hex"],
        json!(key_hex)
    );
}

/// A well-formed key from some other vault (or a vault re-created since the
/// key was stored) is refused with a "does not match" error, and the session
/// stays locked so the UI falls back to the passphrase screen.
#[test]
fn wrong_stored_key_is_rejected_and_leaves_the_vault_locked() {
    let mut env = TestEnv::new();
    env.ok("lock_vault", json!({}));

    let wrong = "ff".repeat(32);
    let err = env.err("unlock_vault_with_key", json!({ "key_hex": wrong }));
    assert!(err.contains("does not match"), "unexpected error: {err}");
    assert!(env.state.vault.is_none(), "a rejected key must not unlock");
    let status = env.ok("vault_status", json!({}));
    assert_eq!(status["unlocked"], json!(false), "{status}");
    assert_eq!(status["state"], json!("locked"), "{status}");
    env.err("list_wallets", json!({}));
}

/// Garbage from the keystore is reported as garbage — never as a mismatched
/// key, and never as a successful unlock.
#[test]
fn malformed_stored_key_is_rejected() {
    let mut env = TestEnv::new();
    env.ok("lock_vault", json!({}));

    let missing = env.err("unlock_vault_with_key", json!({}));
    assert!(missing.contains("key_hex"), "unexpected error: {missing}");

    for bad in [
        String::new(),
        "abc".into(),
        "00".repeat(31),
        "00".repeat(33),
        "zz".repeat(32),
        "0".repeat(63) + "g",
    ] {
        let err = env.err("unlock_vault_with_key", json!({ "key_hex": bad }));
        assert!(err.contains("hex"), "{bad:?}: unexpected error: {err}");
        assert!(
            !err.contains("does not match"),
            "{bad:?}: malformed input is not a mismatch: {err}"
        );
        assert!(env.state.vault.is_none(), "{bad:?} must not unlock");
    }
    assert_eq!(env.ok("vault_status", json!({}))["state"], json!("locked"));
}

/// A2 — no vault, no seed on disk. The wizard makes the password step
/// mandatory, but Restore-wallet and the direct `/create-wallet` route do not
/// go through the wizard, so the refusal lives here.
#[test]
fn creating_a_seed_wallet_without_a_vault_is_refused() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "templar-ffi-novault-{}-{}-{}",
        std::process::id(),
        DIR_SEQ.fetch_add(1, Ordering::Relaxed),
        nanos,
    ));
    std::fs::create_dir_all(&dir).expect("create test data dir");
    let mut state = AppState::new_for_test(dir.clone());

    let resp = dispatch(
        &mut state,
        "create_wallet",
        &json!({ "name": "Plaintext", "mnemonic": MNEMONIC, "liquid": false }),
    );
    let err = resp["err"].as_str().expect("must be refused, not created");
    assert!(
        err.contains("app password"),
        "the error must tell the user what to do: {err}"
    );
    assert!(
        !dir.join("registry.json").exists(),
        "nothing may be persisted in plaintext"
    );

    // With encryption set up, the same call succeeds and the seed only ever
    // reaches disk sealed.
    crate::handlers::vault::setup(&mut state, "contract-test-passphrase").unwrap();
    let resp = dispatch(
        &mut state,
        "create_wallet",
        &json!({ "name": "Sealed", "mnemonic": MNEMONIC, "liquid": false }),
    );
    assert!(
        resp.get("ok").is_some(),
        "with a vault it must succeed: {resp}"
    );
    assert!(!dir.join("registry.json").exists());
    let sealed = std::fs::read_to_string(dir.join("registry.enc")).unwrap();
    assert!(!sealed.contains("abandon"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn second_instance_on_same_data_dir_gets_startup_error() {
    let mut env = TestEnv::new();
    assert!(env.state.startup_error.is_none());

    // A second state on the same dir must fail to take the instance lock…
    let mut second = AppState::new_for_test(env.dir.clone());
    let msg = second
        .startup_error
        .clone()
        .expect("second instance must record a startup error");
    assert!(
        msg.contains("Another Templar Wallet instance"),
        "unexpected message: {msg}"
    );
    // …and every call through it must surface that error.
    let resp = dispatch(&mut second, "list_wallets", &json!({}));
    assert_eq!(resp["err"], json!(msg));

    // The first instance keeps working.
    env.ok("list_wallets", json!({}));
}

// ── Hardware wallet surface ───────────────────────────────────────────────────

/// `hwi_status` feeds `HwiStatus.fromJson` in
/// `lib/bridge/wallet_bridge.dart`, which decides between "show the install
/// card", "offer the udev fix", and "let the user scan". Every key it reads
/// must be present with the right JSON type, whether or not HWI is installed
/// on the machine running the tests.
#[cfg(feature = "hardware")]
#[test]
fn hwi_status_matches_dart_decode_shape() {
    let mut env = TestEnv::new();
    let v = env.ok("hwi_status", json!({}));
    assert_eq!(v["hardware_supported"], json!(true), "{v}");

    // resolved_bin: string or null — null is the install-card cue.
    assert!(v.get("resolved_bin").is_some(), "missing resolved_bin: {v}");
    assert!(
        v["resolved_bin"].is_string() || v["resolved_bin"].is_null(),
        "resolved_bin must be string|null: {v}"
    );
    assert!(v.get("version").is_some(), "missing version: {v}");
    assert!(
        v["version"].is_string() || v["version"].is_null(),
        "version must be string|null: {v}"
    );
    assert!(v["platform"].is_string(), "platform must be a string: {v}");
    // udev_rules_installed: bool on Linux, null elsewhere — Dart reads it as
    // `bool?` and treats null as "not applicable", never as "missing".
    assert!(
        v["udev_rules_installed"].is_boolean() || v["udev_rules_installed"].is_null(),
        "udev_rules_installed must be bool|null: {v}"
    );
    if cfg!(target_os = "linux") {
        assert!(
            v["udev_rules_installed"].is_boolean(),
            "linux must report: {v}"
        );
    } else {
        assert!(
            v["udev_rules_installed"].is_null(),
            "non-linux must be null: {v}"
        );
    }
    // True since Jade support landed. It is a build capability flag, not a
    // per-device one — the UI still has to check that *this* device is a Jade,
    // because no other hardware wallet can sign Liquid.
    assert_eq!(v["liquid_hw_signing"], json!(true), "{v}");

    // The UI decides whether to show the "some devices don't work here" card
    // from these two, rather than from the platform tag. A missing field would
    // make Dart fall back to its defaults and quietly claim full support.
    let families = v["native_families"]
        .as_array()
        .unwrap_or_else(|| panic!("native_families must be an array: {v}"));
    let families: Vec<&str> = families.iter().filter_map(|f| f.as_str()).collect();
    assert!(
        families.contains(&"Ledger") && families.contains(&"Blockstream Jade"),
        "both native drivers must be advertised: {families:?}"
    );
    assert!(
        v["hwi_usable"].is_boolean(),
        "hwi_usable must be a bool: {v}"
    );
    // The HWI subprocess cannot run inside the macOS App Sandbox — measured,
    // see bitcoin/device/mod.rs. Everywhere else it is the fallback for the
    // families without a native driver.
    assert_eq!(v["hwi_usable"], json!(!cfg!(target_os = "macos")), "{v}");
}

/// A Liquid asset must never reach the hardware or air-gap signing paths:
/// both build a Bitcoin PSBT, so "send LBTC" would silently become "send
/// BTC". The rejection carries the stable tag the Dart classifier keys on.
#[cfg(feature = "hardware")]
#[test]
fn hardware_send_paths_reject_liquid_assets() {
    let lbtc = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
    for method in [
        "send_transaction_hw",
        "sign_transaction_hw",
        "build_unsigned_psbt",
    ] {
        let mut env = TestEnv::new();
        let err = env.err(
            method,
            json!({
                "wallet_id": "does-not-matter",
                "asset_id": lbtc,
                "fee_rate": 3.0,
                "outputs": [{"address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "amount_sats": 1000}],
            }),
        );
        assert!(
            err.starts_with("LIQUID_HW_UNSUPPORTED: ") || err.contains("not found"),
            "{method} must reject the asset (or fail earlier on the wallet \
             lookup), got: {err}"
        );
    }
}

/// The multisig co-signing entry point exists and validates its input before
/// touching a device. Without it, a hardware key enrolled in a multisig could
/// contribute an xpub and then never be asked to sign.
#[cfg(feature = "hardware")]
#[test]
fn sign_psbt_hw_is_routed_and_validates_input() {
    let mut env = TestEnv::new();
    let err = env.err(
        "sign_psbt_hw",
        json!({"fingerprint": "f0b68896", "psbt_base64": "   "}),
    );
    assert!(err.contains("No PSBT"), "got: {err}");

    // Unknown method would say so — proving the arm is wired.
    let resp = env.call("sign_psbt_hw", json!({"fingerprint": "f0b68896"}));
    let err = resp["err"].as_str().unwrap_or_default();
    assert!(
        !err.contains("Unknown method"),
        "sign_psbt_hw is not routed: {err}"
    );
}

/// `enumerate_native_devices` backs the "your device is connected, this build
/// just cannot talk to it yet" message, so it must answer with a list — never
/// an error — on a machine with nothing plugged in. An error there would put
/// a scary banner in front of every user who has no device attached.
#[cfg(feature = "hardware")]
#[test]
fn native_device_enumeration_is_always_a_list() {
    let mut env = TestEnv::new();
    let v = env.ok("enumerate_native_devices", json!({}));
    let list = v.as_array().unwrap_or_else(|| panic!("not an array: {v}"));
    // Every entry must carry the keys `NativeDevice.fromJson` reads.
    for d in list {
        for key in [
            "family",
            "model",
            "transport",
            "path",
            "vendor_id",
            "product_id",
            // Whether the device can be driven, not just seen. Absent, Dart
            // defaults it to false and marks a working Ledger unusable.
            "drivable",
        ] {
            assert!(d.get(key).is_some(), "missing {key}: {d}");
        }
        assert!(d["vendor_id"].is_number(), "vendor_id must be numeric: {d}");
        assert!(d["drivable"].is_boolean(), "drivable must be a bool: {d}");
        assert!(
            d["transport"] == json!("hid") || d["transport"] == json!("serial"),
            "unexpected transport: {d}"
        );
    }
}

/// A Liquid wallet may only ever be paired with a Jade. Every other USB signer
/// is Bitcoin-only in firmware, so pairing one would create a wallet that can
/// receive funds no signature can ever move. The wizard blocks it; this checks
/// the backend blocks it too, since the wizard is not the only caller.
#[cfg(feature = "hardware")]
#[test]
fn liquid_pairing_is_refused_for_non_jade_devices() {
    // Pairing opens whatever is attached to ask for its fingerprint, and a
    // locked Jade holds that call for its full 90 s PIN window. With hardware
    // on the desk this is a manual test (docs/HARDWARE_TESTING.md), not a
    // routing check.
    if templar_core::enumerate_native()
        .unwrap_or_default()
        .iter()
        .any(|d| d.drivable)
    {
        eprintln!("skipped: a drivable device is attached");
        return;
    }
    let mut env = TestEnv::new();
    // No device attached, so this cannot reach the device layer — but the
    // request must not be accepted on its way there either.
    let err = env.err(
        "import_hw_wallet",
        json!({"name": "LedgerLiquid", "fingerprint": "f0b68896", "liquid": true}),
    );
    assert!(
        !err.is_empty() && !err.contains("Unknown method"),
        "import_hw_wallet is not routed: {err}"
    );
}

/// The Jade-only Liquid import must validate its input before reaching for a
/// device — a blank name should not make the user unlock their Jade first.
#[cfg(feature = "hardware")]
#[test]
fn jade_liquid_import_validates_before_touching_the_device() {
    let mut env = TestEnv::new();
    let err = env.err("import_jade_liquid_wallet", json!({"name": "   "}));
    assert!(err.contains("name is required"), "got: {err}");
}

/// Listing Jade serial ports must be safe and side-effect free with nothing
/// attached: the wizard calls it to decide between "plug in your Jade" and
/// "found it", and it must never open the port.
#[cfg(feature = "hardware")]
#[test]
fn jade_port_listing_is_always_a_list() {
    let mut env = TestEnv::new();
    let v = env.ok("jade_ports", json!({}));
    assert!(v.is_array(), "not an array: {v}");
}

// ── Liquid multisig ──────────────────────────────────────────────────────────

/// Second BIP39 test vector, so a multisig can be built from two distinct
/// seeds without touching a device.
const MNEMONIC_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

/// Third BIP39 test vector — a key that belongs to nobody in the wallet, for
/// the cases that need a *wrong* key rather than a repeated one.
const MNEMONIC_C: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// Collect one cosigner's pair of keys: BIP48 for Bitcoin, BIP87 for Liquid.
/// Two accounts on one seed — neither is derivable from the other, which is
/// the whole reason the wizard asks for both.
fn cosigner_keys(env: &mut TestEnv, mnemonic: &str) -> (String, String) {
    let btc = env.ok("derive_cosigner_xpub", json!({"mnemonic": mnemonic}));
    let liquid = env.ok("derive_liquid_cosigner_xpub", json!({"mnemonic": mnemonic}));
    (
        btc.as_str().expect("btc xpub is a string").to_string(),
        liquid
            .as_str()
            .expect("liquid xpub is a string")
            .to_string(),
    )
}

/// The two key exports are distinct accounts and carry the paths their chains
/// expect. A silent fallback to one shared key would put the same public keys
/// on both chains — spendable, but it links the wallets forever.
#[test]
fn bitcoin_and_liquid_cosigner_keys_are_separate_accounts() {
    let mut env = TestEnv::new();
    let (btc, liquid) = cosigner_keys(&mut env, MNEMONIC);
    assert!(
        btc.contains("/48'/1'/0'/2']") || btc.contains("/48h/1h/0h/2h]"),
        "btc: {btc}"
    );
    assert!(
        liquid.contains("/87'/1'/0']") || liquid.contains("/87h/1h/0h]"),
        "liquid: {liquid}"
    );
    assert_ne!(btc, liquid);
}

/// The wallet the wizard produces: one entry, both chains, Liquid advertised
/// to the UI through the same flag every other wallet type uses.
#[test]
fn liquid_multisig_wallet_is_created_with_both_chains() {
    let mut env = TestEnv::new();
    let (btc_a, liq_a) = cosigner_keys(&mut env, MNEMONIC);
    let (btc_b, liq_b) = cosigner_keys(&mut env, MNEMONIC_B);

    let summary = env.ok(
        "create_multisig_wallet",
        json!({
            "name": "Treasury",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a, btc_b],
            "local_mnemonics": [MNEMONIC, MNEMONIC_B],
            "liquid_xpubs": [liq_a, liq_b],
            "liquid_capable_keys": 2,
        }),
    );
    assert_eq!(summary["wallet_type"], "multisig");
    assert_eq!(summary["liquid_enabled"], true);
    assert_eq!(summary["is_watch_only"], false);

    // The picker reads the same flags from the registry, not from this reply.
    let wallets = env.ok("list_wallets", json!({}));
    let row = &wallets.as_array().expect("array")[0];
    assert_eq!(row["liquid_enabled"], true);
    assert_eq!(row["bitcoin_enabled"], true);
    assert_eq!(row["required_sigs"], 2);
    assert_eq!(row["total_signers"], 2);
}

/// Omitting the Liquid keys leaves a Bitcoin-only multisig — the pre-existing
/// behaviour, and what the wizard sends when the user picks "Bitcoin only".
#[test]
fn multisig_without_liquid_keys_stays_bitcoin_only() {
    let mut env = TestEnv::new();
    let (btc_a, _) = cosigner_keys(&mut env, MNEMONIC);
    let (btc_b, _) = cosigner_keys(&mut env, MNEMONIC_B);
    let summary = env.ok(
        "create_multisig_wallet",
        json!({
            "name": "BtcOnly",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a, btc_b],
            "local_mnemonics": [MNEMONIC],
        }),
    );
    assert_eq!(summary["liquid_enabled"], false);
}

/// The fund trap: fewer Liquid-capable keys than the threshold means funds
/// could arrive and never leave. Refused at creation, before any address is
/// handed out.
#[test]
fn liquid_multisig_is_refused_when_too_few_keys_can_sign_liquid() {
    let mut env = TestEnv::new();
    let (btc_a, liq_a) = cosigner_keys(&mut env, MNEMONIC);
    let (btc_b, liq_b) = cosigner_keys(&mut env, MNEMONIC_B);
    let err = env.err(
        "create_multisig_wallet",
        json!({
            "name": "Trap",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a, btc_b],
            "local_mnemonics": [MNEMONIC],
            "liquid_xpubs": [liq_a, liq_b],
            // e.g. the second key lives on a Ledger: Bitcoin-only in firmware.
            "liquid_capable_keys": 1,
        }),
    );
    assert!(err.contains("could never be spent"), "got: {err}");
    // Nothing may be left behind by a refused creation.
    assert!(env
        .ok("list_wallets", json!({}))
        .as_array()
        .unwrap()
        .is_empty());
}

/// One BIP87 key per cosigner, or none at all. A short list means the wizard
/// dropped a key, and building a smaller Liquid quorum than the Bitcoin one
/// would silently weaken the wallet.
#[test]
fn liquid_multisig_requires_one_liquid_key_per_cosigner() {
    let mut env = TestEnv::new();
    let (btc_a, liq_a) = cosigner_keys(&mut env, MNEMONIC);
    let (btc_b, _) = cosigner_keys(&mut env, MNEMONIC_B);
    let err = env.err(
        "create_multisig_wallet",
        json!({
            "name": "Short",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a, btc_b],
            "local_mnemonics": [MNEMONIC],
            "liquid_xpubs": [liq_a],
            "liquid_capable_keys": 2,
        }),
    );
    assert!(err.contains("one BIP87 key per cosigner"), "got: {err}");
}

/// A local seed whose Liquid key is missing from the descriptor would leave
/// the app unable to sign on Liquid while looking like a co-signer. Caught at
/// creation, where the fix is obvious (keys pasted out of order).
#[test]
fn liquid_multisig_rejects_a_local_key_absent_from_the_liquid_list() {
    let mut env = TestEnv::new();
    let (btc_a, liq_a) = cosigner_keys(&mut env, MNEMONIC);
    let (btc_b, _liq_b) = cosigner_keys(&mut env, MNEMONIC_B);
    let (_btc_c, liq_c) = cosigner_keys(&mut env, MNEMONIC_C);
    let err = env.err(
        "create_multisig_wallet",
        json!({
            "name": "Mismatch",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a, btc_b],
            // B signs locally, but the Liquid list carries a stranger's key
            // where B's belongs — keys pasted out of order, or the wrong
            // export copied in.
            "local_mnemonics": [MNEMONIC_B],
            "liquid_xpubs": [liq_a, liq_c],
            "liquid_capable_keys": 2,
        }),
    );
    assert!(err.contains("no matching BIP87 key"), "got: {err}");
}

/// The same key twice is not a 2-of-2: the threshold it enforces is really 1.
/// Cheap to do by accident when keys are collected one card at a time.
#[test]
fn multisig_rejects_the_same_cosigner_key_twice() {
    let mut env = TestEnv::new();
    let (btc_a, _) = cosigner_keys(&mut env, MNEMONIC);
    let err = env.err(
        "create_multisig_wallet",
        json!({
            "name": "Doubled",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a.clone(), btc_a],
            "local_mnemonics": [MNEMONIC],
        }),
    );
    assert!(err.contains("same key as key 1"), "got: {err}");
}

/// The bug this whole guard exists for: a cosigner key scanned from an
/// air-gapped device arrives as a whole `wpkh(...)` descriptor, and the
/// multisig builder used to nest it inside `sortedmulti` and persist the
/// result. Creation reported success; every later open died on
/// "Miniscript error: expected )" and the wallet could not be removed from
/// the sidebar. It must now be reduced to its key and open normally.
#[test]
fn scanned_descriptor_key_is_reduced_and_the_wallet_opens() {
    let mut env = TestEnv::new();
    let (btc_a, _) = cosigner_keys(&mut env, MNEMONIC);
    let (btc_b, _) = cosigner_keys(&mut env, MNEMONIC_B);
    // What decode_ur_parts hands back for a Jade "Export Xpub" QR.
    let scanned = format!("wpkh({}/<0;1>/*)", btc_b);

    let summary = env.ok(
        "create_multisig_wallet",
        json!({
            "name": "Scanned",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a, scanned],
            "local_mnemonics": [MNEMONIC],
        }),
    );
    let id = summary["id"].as_str().expect("wallet id").to_string();

    env.ok("open_wallet", json!({ "wallet_id": id }));
    let addr = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    );
    assert!(
        addr["address"].as_str().unwrap_or("").starts_with("tb1"),
        "wallet must open and derive: {addr}"
    );
}

/// A key that cannot be used must be refused while the wizard is still on
/// screen, never written to the registry. The wallet list is the one place
/// with no repair path.
#[test]
fn unusable_cosigner_key_never_reaches_the_registry() {
    let mut env = TestEnv::new();
    let (btc_a, _) = cosigner_keys(&mut env, MNEMONIC);
    let before = env.ok("list_wallets", json!({}));
    let err = env.err(
        "create_multisig_wallet",
        json!({
            "name": "Garbage",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a, "not-a-key-at-all"],
            "local_mnemonics": [MNEMONIC],
        }),
    );
    assert!(err.starts_with("Key 2:"), "must name the key: {err}");
    let after = env.ok("list_wallets", json!({}));
    assert_eq!(
        before.as_array().map(|a| a.len()),
        after.as_array().map(|a| a.len()),
        "a refused wallet must leave nothing behind"
    );
}

/// The rescue path for a wallet already broken this way, reproduced exactly:
/// a registry entry whose descriptors nest a scanned key's `wpkh(...)` inside
/// `sortedmulti`. It cannot be opened, so nothing in the app can act on it —
/// and re-collecting the keys means going back to every device. Repair must
/// rebuild it from the keys it already stores and give back the *same* wallet.
#[test]
fn a_wallet_broken_by_a_scanned_key_can_be_repaired_in_place() {
    use templar_core::WalletProfile;

    let mut env = TestEnv::new();
    let (btc_a, _) = cosigner_keys(&mut env, MNEMONIC);
    let (btc_b, _) = cosigner_keys(&mut env, MNEMONIC_B);

    // A watch-only coordinator: every key came from somewhere else, which is
    // how an air-gapped multisig is collected in the first place.
    let summary = env.ok(
        "create_multisig_wallet",
        json!({
            "name": "Rescue",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a.clone(), btc_b.clone()],
            "local_mnemonics": [],
        }),
    );
    let id = summary["id"].as_str().expect("wallet id").to_string();

    env.ok("open_wallet", json!({ "wallet_id": id }));
    let before = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    )["address"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(!before.is_empty());

    // Put the entry back into the state the old code produced.
    let scanned = format!("wpkh({btc_b}/<0;1>/*)");
    {
        let entry = env.state.registry.find_mut(&id).expect("entry");
        let WalletProfile::Multisig {
            cosigner_xpubs,
            receive_descriptor,
            change_descriptor,
            ..
        } = &mut entry.profile
        else {
            panic!("multisig expected")
        };
        *cosigner_xpubs = vec![btc_a.clone(), scanned.clone()];
        *receive_descriptor = format!("wsh(sortedmulti(2,{btc_a}/0/*,{scanned}/0/*))");
        *change_descriptor = format!("wsh(sortedmulti(2,{btc_a}/1/*,{scanned}/1/*))");
    }
    env.state.save_registry().expect("save broken registry");
    env.state.bitcoin = None;
    env.state.active_wallet_id = None;

    let err = env.err("open_wallet", json!({ "wallet_id": id }));
    assert!(err.contains("descriptor"), "must fail to open: {err}");

    env.ok("repair_multisig_wallet", json!({ "wallet_id": id }));
    env.ok("open_wallet", json!({ "wallet_id": id }));
    let after = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    )["address"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(after, before, "repair must give back the same wallet");
}

/// Repair is not a button to press on any wallet that will not open: when the
/// descriptors are fine, it says so instead of rewriting them.
#[test]
fn repair_refuses_a_wallet_with_nothing_wrong() {
    let mut env = TestEnv::new();
    let (btc_a, _) = cosigner_keys(&mut env, MNEMONIC);
    let (btc_b, _) = cosigner_keys(&mut env, MNEMONIC_B);
    let summary = env.ok(
        "create_multisig_wallet",
        json!({
            "name": "Healthy",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a, btc_b],
            "local_mnemonics": [MNEMONIC],
        }),
    );
    let id = summary["id"].as_str().expect("wallet id");
    let err = env.err("repair_multisig_wallet", json!({ "wallet_id": id }));
    assert!(err.contains("nothing to repair"), "got: {err}");
}

/// The wizard's live check: same rules as creation, reported per field.
#[test]
fn cosigner_key_validation_reports_path_and_fingerprint() {
    let mut env = TestEnv::new();
    let (btc_a, liq_a) = cosigner_keys(&mut env, MNEMONIC);

    let info = env.ok("validate_cosigner_key", json!({ "key": btc_a }));
    assert_eq!(info["path"].as_str(), Some("48'/1'/0'/2'"));
    assert_eq!(info["fingerprint"].as_str().map(|s| s.len()), Some(8));
    assert!(info["warning"].is_null(), "clean key must not warn: {info}");

    let info = env.ok(
        "validate_cosigner_key",
        json!({ "key": liq_a, "liquid": true }),
    );
    assert_eq!(info["path"].as_str(), Some("87h/1h/0h"));

    // A key whose origin lies about where it was derived: the BIP48 key
    // relabelled as a single-sig account. Every coordinator would agree on
    // the wallet and the device would never sign for it, so it is refused.
    // (A real single-sig account key at its true path still only warns —
    // `multisig::tests::singlesig_account_key_warns_but_is_allowed`.)
    let relabelled = btc_a.replace("48'/1'/0'/2'", "84'/1'/0'");
    let err = env.err("validate_cosigner_key", json!({ "key": relabelled }));
    assert!(err.contains("levels deep"), "got: {err}");

    // And a mainnet key, which a tpub re-encode would otherwise hide.
    let mainnet = btc_a.replace("48'/1'/0'/2'", "48'/0'/0'/2'");
    let err = env.err("validate_cosigner_key", json!({ "key": mainnet }));
    assert!(err.contains("mainnet path"), "got: {err}");
}

/// The end-to-end offline proof: a Liquid multisig wallet opens on both chains
/// and hands out addresses on each. This is what catches a CT descriptor that
/// the registry accepted but LWK cannot actually open — the failure that would
/// otherwise surface only after the wizard claimed success.
#[test]
fn liquid_multisig_opens_and_derives_on_both_chains() {
    let mut env = TestEnv::new();
    let (btc_a, liq_a) = cosigner_keys(&mut env, MNEMONIC);
    let (btc_b, liq_b) = cosigner_keys(&mut env, MNEMONIC_B);

    let summary = env.ok(
        "create_multisig_wallet",
        json!({
            "name": "BothChains",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": [btc_a, btc_b],
            "local_mnemonics": [MNEMONIC],
            "liquid_xpubs": [liq_a, liq_b],
            "liquid_capable_keys": 2,
        }),
    );
    let id = summary["id"].as_str().expect("wallet id").to_string();

    env.ok("open_wallet", json!({ "wallet_id": id }));

    let btc = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    );
    let btc_addr = btc["address"].as_str().unwrap_or("");
    assert!(
        btc_addr.starts_with("tb1"),
        "P2WSH testnet address expected: {btc_addr:?}"
    );

    let liquid = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "LBTC" }),
    );
    let liquid_addr = liquid["address"].as_str().unwrap_or("");
    assert!(
        !liquid_addr.is_empty() && liquid_addr != btc_addr,
        "confidential Liquid address expected: {liquid_addr:?}"
    );

    // The descriptor every co-signer arrives at on their own: a SLIP77
    // blinding key derived from the keys (ELIP151, written as the raw bytes a
    // Jade registers — never the `elip151` keyword the device cannot take)
    // over a sortedmulti, so the key order does not matter either.
    let info = env.ok("get_wallet_info", json!({ "wallet_id": id }));
    let desc = info["liquid_descriptor"].as_str().unwrap_or("");
    assert!(desc.starts_with("ct(slip77("), "got: {desc}");
    assert!(desc.contains("elwsh(sortedmulti(2,"), "got: {desc}");
    assert!(!desc.contains("elip151"), "got: {desc}");
    // The Bitcoin side keeps its own account, and never leaks a private key.
    assert_eq!(info["derivation_path"], json!("m/48'/1'/0'/2'"));
    assert!(!info["receive_descriptor"]
        .as_str()
        .unwrap_or("")
        .contains("tprv"));
}

/// The wizard's default name is "My Multisig Wallet", so two multisigs with
/// the same name and threshold are the normal case. Their BDK databases used
/// to be keyed by that name: the second wallet opened the first one's
/// directory and BDK refused it — "Descriptor checksum mismatch" at every
/// open, an entry with nothing to repair.
#[test]
fn two_multisigs_with_the_same_name_open_independently() {
    let mut env = TestEnv::new();
    let (a, _) = cosigner_keys(&mut env, MNEMONIC);
    let (b, _) = cosigner_keys(&mut env, MNEMONIC_B);
    let (c, _) = cosigner_keys(&mut env, MNEMONIC_C);
    fn create(env: &mut TestEnv, keys: [&str; 2]) -> String {
        let summary = env.ok(
            "create_multisig_wallet",
            json!({
                "name": "My Multisig Wallet",
                "required_sigs": 2,
                "total_signers": 2,
                "cosigner_xpubs": keys,
                "local_mnemonics": [MNEMONIC],
            }),
        );
        summary["id"].as_str().expect("wallet id").to_string()
    }
    fn address(env: &mut TestEnv, id: &str) -> String {
        env.ok("open_wallet", json!({ "wallet_id": id }));
        let out = env.ok(
            "generate_receive_address",
            json!({ "wallet_id": id, "asset": "BTC" }),
        );
        out["address"].as_str().unwrap_or("").to_string()
    }
    let first = create(&mut env, [&a, &b]);
    let second = create(&mut env, [&a, &c]);

    let first_addr = address(&mut env, &first);
    let second_addr = address(&mut env, &second);
    assert!(first_addr.starts_with("tb1"), "{first_addr:?}");
    assert_ne!(first_addr, second_addr, "two wallets, two address sets");

    // Deleting one must not take the other's database with it.
    env.ok("delete_wallet", json!({ "wallet_id": first }));
    assert_eq!(address(&mut env, &second), second_addr);
}

/// Two apps build one 2-of-2 from the same two BIP87 keys, in opposite order,
/// and it is the same wallet — same descriptor, same address. That is what
/// makes the co-signing round trip possible at all: with a random blinding
/// key (the old scheme) each copy was a different Liquid wallet.
#[test]
fn liquid_multisig_rebuilt_from_the_same_keys_is_the_same_wallet() {
    let mut a = TestEnv::new();
    let mut b = TestEnv::new();
    let (btc_a, liq_a) = cosigner_keys(&mut a, MNEMONIC);
    let (btc_b, liq_b) = cosigner_keys(&mut a, MNEMONIC_B);
    let wa = shared_liquid_multisig(&mut a, [&btc_a, &btc_b], [&liq_a, &liq_b], MNEMONIC);
    let wb = shared_liquid_multisig(&mut b, [&btc_b, &btc_a], [&liq_b, &liq_a], MNEMONIC_B);
    a.ok("open_wallet", json!({ "wallet_id": wa }));
    b.ok("open_wallet", json!({ "wallet_id": wb }));

    let ia = a.ok("get_wallet_info", json!({ "wallet_id": wa }));
    let ib = b.ok("get_wallet_info", json!({ "wallet_id": wb }));
    // Byte-identical on Liquid, blinding key included. (The Bitcoin
    // descriptor's text keeps the typed key order — BDK's sortedmulti sorts
    // inside the script — so it is compared by the addresses below.)
    assert_eq!(ia["liquid_descriptor"], ib["liquid_descriptor"]);
    for asset in ["BTC", "LBTC"] {
        let addr = |env: &mut TestEnv, id: &str| {
            env.ok(
                "generate_receive_address",
                json!({ "wallet_id": id, "asset": asset }),
            )["address"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(addr(&mut a, &wa), addr(&mut b, &wb), "{asset}");
    }
}

/// One co-signer's copy of a shared 2-of-2: the multisig built from both
/// keys on both chains, holding `local` as its own seed.
fn shared_liquid_multisig(
    env: &mut TestEnv,
    btc: [&str; 2],
    liq: [&str; 2],
    local: &str,
) -> String {
    let summary = env.ok(
        "create_multisig_wallet",
        json!({
            "name": "Shared",
            "required_sigs": 2,
            "total_signers": 2,
            "cosigner_xpubs": btc,
            "local_mnemonics": [local],
            "liquid_xpubs": liq,
            "liquid_capable_keys": 2,
        }),
    );
    summary["id"].as_str().expect("wallet id").to_string()
}

/// The whole Liquid multisig round trip, on the Templar Protocol's local
/// regtest node: A funds the shared wallet and starts a spend, B co-signs it from
/// its own copy of the wallet, A finalizes and broadcasts. Every step is the
/// same engine call the app makes.
#[test]
#[ignore = "needs the protocol's regtest elementsd at 127.0.0.1:18884"]
fn liquid_multisig_round_trip_on_regtest() {
    use crate::state::ChainSyncOutcome;
    let rpc = templar_core::ElementsRpcBackend::new("http://127.0.0.1:18884", "templar", "templar")
        .expect("rpc client");
    let mut a = TestEnv::new();
    let mut b = TestEnv::new();
    a.ok("set_liquid_network", json!({ "network": "regtest" }));
    b.ok("set_liquid_network", json!({ "network": "regtest" }));
    let policy = a.ok("get_liquid_network", json!({}))["policy_asset"]
        .as_str()
        .unwrap()
        .to_string();

    let (btc_a, liq_a) = cosigner_keys(&mut a, MNEMONIC);
    let (btc_b, liq_b) = cosigner_keys(&mut a, MNEMONIC_B);
    let wa = shared_liquid_multisig(&mut a, [&btc_a, &btc_b], [&liq_a, &liq_b], MNEMONIC);
    let wb = shared_liquid_multisig(&mut b, [&btc_b, &btc_a], [&liq_b, &liq_a], MNEMONIC_B);
    a.ok("open_wallet", json!({ "wallet_id": wa }));
    b.ok("open_wallet", json!({ "wallet_id": wb }));

    // Fund A's copy; B's copy must see the coin too.
    let addr = a.ok(
        "generate_receive_address",
        json!({ "wallet_id": wa, "asset": "LBTC" }),
    )["address"]
        .as_str()
        .unwrap()
        .to_string();
    rpc.wallet_call_json("ops", "sendtoaddress", &[json!(addr), json!(0.001)])
        .expect("fund the shared wallet");
    let miner = rpc
        .wallet_call_json("ops", "getnewaddress", &[])
        .expect("miner address");
    rpc.call_json("generatetoaddress", &[json!(1), miner])
        .expect("mine a block");
    for env in [&mut a, &mut b] {
        let outcome = crate::handlers::wallet_ops::sync_liquid(&mut env.state);
        assert!(matches!(outcome, ChainSyncOutcome::Ok), "{outcome:?}");
    }

    // A starts the spend: its one key signs, the PSET comes back short.
    let dest = rpc
        .wallet_call_json("ops", "getnewaddress", &[])
        .expect("destination")
        .as_str()
        .unwrap()
        .to_string();
    let sent = a.ok(
        "send_transaction",
        json!({
            "wallet_id": wa,
            "outputs": [{ "address": dest, "amount_sats": 50_000 }],
            "asset_id": policy,
            "fee_rate": 0.1,
        }),
    );
    assert_eq!(sent["sigs_have"], json!(1), "{sent}");
    assert_eq!(sent["sigs_needed"], json!(2), "{sent}");
    assert_eq!(sent["chain"], json!("liquid"), "{sent}");
    let partial = sent["partial_pset"].as_str().unwrap().to_string();

    // B reads it as its own wallet's transaction — amounts in the clear —
    // and adds the second signature.
    let seen = b.ok(
        "inspect_pset",
        json!({ "wallet_id": wb, "pset_base64": partial }),
    );
    assert_eq!(seen["sigs_have"], json!(1), "{seen}");
    assert_eq!(seen["sigs_needed"], json!(2), "{seen}");
    assert_eq!(seen["can_finalize"], json!(false), "{seen}");
    assert_eq!(seen["inputs"][0]["is_ours"], json!(true), "{seen}");
    assert_eq!(seen["inputs"][0]["threshold"], json!(2), "{seen}");
    let paid: Vec<i64> = seen["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["amount_sats"].as_i64())
        .collect();
    assert!(paid.contains(&50_000), "B must read the amount: {seen}");
    let signed = b.ok(
        "sign_pset",
        json!({ "wallet_id": wb, "pset_base64": partial }),
    );
    let signed = signed.as_str().unwrap().to_string();
    let after = b.ok(
        "inspect_pset",
        json!({ "wallet_id": wb, "pset_base64": signed }),
    );
    assert_eq!(after["sigs_have"], json!(2), "{after}");
    assert_eq!(after["can_finalize"], json!(true), "{after}");

    // A gets it back and broadcasts.
    let txid = a.ok(
        "broadcast_pset",
        json!({ "wallet_id": wa, "pset_base64": signed }),
    );
    assert_eq!(txid.as_str().map(str::len), Some(64), "{txid}");
}

/// The PSET co-signing ops are routed and validate their input before doing
/// anything expensive. Without this, a renamed method would fail at the worst
/// possible moment — with a half-signed transaction in hand.
#[test]
fn pset_cosign_methods_are_routed_and_reject_garbage() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    for method in [
        "inspect_pset",
        "sign_pset",
        "sign_pset_hw",
        "broadcast_pset",
    ] {
        let err = env.err(
            method,
            json!({ "wallet_id": id, "pset_base64": "not-a-pset" }),
        );
        assert!(
            !err.contains("Unknown method"),
            "{method} is not routed: {err}"
        );
    }
    let err = env.err(
        "combine_psets",
        json!({ "wallet_id": id, "psets": ["only-one"] }),
    );
    assert!(err.contains("at least two"), "got: {err}");
}

/// A coordinator folds a co-signer's copy into the one it hands out. Two
/// copies of one transaction combine; a different transaction is refused
/// with the reason; a single copy is not a combine.
#[test]
fn combine_psbts_merges_signed_copies_and_refuses_strangers() {
    let mut env = TestEnv::new();
    let err = env.err("combine_psbts", json!({ "psbts": ["only-one"] }));
    assert!(err.contains("at least two"), "got: {err}");

    let err = env.err(
        "combine_psbts",
        json!({ "psbts": ["not-a-psbt", "not-a-psbt-either"] }),
    );
    assert!(!err.contains("Unknown method"), "not routed: {err}");

    // Two different unsigned transactions: refused, naming the copy.
    // (Any two structurally valid PSBTs with different unsigned txs.)
    let a = "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AQAAAAAAAAAAFgAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let b = "cHNidP8BAFICAAAAAQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AQAAAAAAAAAAFgAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    // A copy combined with itself is itself.
    let same = env.ok("combine_psbts", json!({ "psbts": [a, a] }));
    assert_eq!(same, json!(a));
    let err = env.err("combine_psbts", json!({ "psbts": [a, b] }));
    assert!(
        err.contains("not a signed copy of this transaction"),
        "got: {err}"
    );
}

// ── Frozen coins ─────────────────────────────────────────────────────────────

/// The prevout of the zero-input PSBT used by the combine test below.
const ZERO_OUTPOINT: &str = "0000000000000000000000000000000000000000000000000000000000000000:0";
const ZERO_INPUT_PSBT: &str = "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AQAAAAAAAAAAFgAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn frozen_coins_persist_on_the_sealed_registry_entry() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    let freeze = |frozen: bool| json!({ "wallet_id": id, "chain": "BTC", "outpoints": [ZERO_OUTPOINT], "frozen": frozen });

    assert!(env.ok("set_utxos_frozen", freeze(true)).is_null());
    // Read back from disk, through the vault: the list is part of the
    // sealed registry, not a side file.
    let reloaded = env.state.load_registry().expect("reload registry");
    let entry = reloaded.find(&id).expect("entry");
    assert!(
        entry.frozen.bitcoin.contains(ZERO_OUTPOINT),
        "{:?}",
        entry.frozen
    );
    assert!(entry.frozen.liquid.is_empty(), "chains are kept apart");

    env.ok("set_utxos_frozen", freeze(false));
    let reloaded = env.state.load_registry().expect("reload registry");
    assert!(reloaded.find(&id).expect("entry").frozen.is_empty());
}

#[test]
fn set_utxos_frozen_rejects_what_it_cannot_store() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    let err = env.err(
        "set_utxos_frozen",
        json!({ "wallet_id": id, "chain": "Doge", "outpoints": [ZERO_OUTPOINT], "frozen": true }),
    );
    assert!(err.contains("Unknown chain"), "got: {err}");
    let err = env.err(
        "set_utxos_frozen",
        json!({ "wallet_id": id, "chain": "Liquid", "outpoints": ["nope"], "frozen": true }),
    );
    assert!(err.contains("Invalid outpoint"), "got: {err}");
    let err = env.err(
        "set_utxos_frozen",
        json!({ "wallet_id": "nope", "chain": "BTC", "outpoints": [ZERO_OUTPOINT], "frozen": true }),
    );
    assert!(err.contains("Wallet not found"), "got: {err}");
}

#[test]
fn a_frozen_coin_is_refused_by_coin_control_and_by_the_signer() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    env.ok("open_wallet", json!({ "wallet_id": id }));
    env.ok(
        "set_utxos_frozen",
        json!({ "wallet_id": id, "chain": "BTC", "outpoints": [ZERO_OUTPOINT], "frozen": true }),
    );

    // Picked by hand: refused before BDK is even asked.
    let err = env.err(
        "preview_transaction",
        json!({
            "wallet_id": id,
            "address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "amount_sats": 10_000,
            "asset_id": "BTC",
            "fee_rate": 2.0,
            "utxos": [ZERO_OUTPOINT],
        }),
    );
    assert!(err.contains("is frozen"), "got: {err}");

    // Built elsewhere and handed over for a signature: refused too.
    let err = env.err(
        "sign_psbt",
        json!({ "wallet_id": id, "psbt_base64": ZERO_INPUT_PSBT }),
    );
    assert!(err.contains("is frozen"), "got: {err}");
}

// ── Liquid network selection (testnet / regtest) ─────────────────────────────

#[test]
fn liquid_network_defaults_to_testnet_and_matches_dart_decode_shape() {
    let mut env = TestEnv::new();
    let info = env.ok("get_liquid_network", json!({}));
    // Exact keys LiquidNetworkInfo.fromJson reads (ffi_wallet_bridge.dart).
    assert_keys(
        "get_liquid_network",
        &info,
        &[
            "network",
            "short_name",
            "policy_asset",
            "backend",
            "backend_description",
            "env_locked",
            "regtest_default_policy_asset",
        ],
    );
    assert_eq!(info["network"], json!("liquid-testnet"));
    assert_eq!(info["short_name"], json!("testnet"));
    assert_eq!(
        info["policy_asset"],
        json!(templar_core::TESTNET_POLICY_ASSET)
    );
    assert_eq!(info["env_locked"], json!(false));
    assert_eq!(
        info["regtest_default_policy_asset"],
        json!(templar_core::REGTEST_DEFAULT_POLICY_ASSET)
    );
    // The description never leaks RPC credentials.
    let desc = info["backend_description"].as_str().unwrap_or("");
    assert!(!desc.contains("templar:templar"), "{desc}");
}

#[test]
fn switching_to_regtest_closes_the_wallet_and_reopens_it_there() {
    let mut env = TestEnv::new();
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Regtest Test", "mnemonic": MNEMONIC, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();

    // Testnet first: the wallet reports it and hands out tlq1 addresses.
    let info = env.ok("get_wallet_info", json!({ "wallet_id": id }));
    assert_eq!(info["liquid_network"], json!("liquid-testnet"));
    let addr = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "LBTC" }),
    );
    let testnet_addr = addr["address"].as_str().unwrap_or("").to_string();
    assert!(testnet_addr.starts_with("tlq1"), "got {testnet_addr}");
    assert_eq!(env.state.active_wallet_id.as_deref(), Some(id.as_str()));

    // Switch. The open wallet is closed: its Liquid side was built on the
    // other network.
    let switched = env.ok("set_liquid_network", json!({ "network": "regtest" }));
    assert_eq!(switched["network"], json!("liquid-regtest"));
    assert_eq!(
        switched["policy_asset"],
        json!(templar_core::REGTEST_DEFAULT_POLICY_ASSET)
    );
    assert_eq!(switched["backend"], json!("elements_rpc"));
    assert!(
        env.state.active_wallet_id.is_none(),
        "switch must close the wallet"
    );

    // The setting is persisted — under the test dir, never in ~/.config.
    let cfg = std::fs::read_to_string(env.dir.join("templar_wallet.json")).unwrap();
    assert!(cfg.contains("liquid-regtest"), "{cfg}");

    // Reopened lazily on the next call, on regtest: el1 addresses, the
    // regtest policy asset as LBTC on the dashboard.
    let info = env.ok("get_wallet_info", json!({ "wallet_id": id }));
    assert_eq!(info["liquid_network"], json!("liquid-regtest"));
    let addr = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "LBTC" }),
    );
    let regtest_addr = addr["address"].as_str().unwrap_or("").to_string();
    assert!(regtest_addr.starts_with("el1"), "got {regtest_addr}");
    assert_ne!(regtest_addr, testnet_addr);

    let dash = env.ok("get_wallet_summary", json!({ "wallet_id": id }));
    assert_eq!(dash["liquid_network"], json!("liquid-regtest"));
    let lbtc = dash["assets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["ticker"] == json!("LBTC"))
        .expect("an LBTC row");
    assert_eq!(
        lbtc["asset_id"],
        json!(templar_core::REGTEST_DEFAULT_POLICY_ASSET)
    );

    // And back: testnet again, config entry gone (absent = testnet).
    env.ok("set_liquid_network", json!({ "network": "testnet" }));
    let info = env.ok("get_wallet_info", json!({ "wallet_id": id }));
    assert_eq!(info["liquid_network"], json!("liquid-testnet"));
    let cfg = std::fs::read_to_string(env.dir.join("templar_wallet.json")).unwrap();
    assert!(!cfg.contains("liquid_network"), "{cfg}");
}

#[test]
fn set_liquid_network_rejects_bad_values() {
    let mut env = TestEnv::new();
    let err = env.err("set_liquid_network", json!({ "network": "mainnet" }));
    assert!(err.contains("unknown Liquid network"), "{err}");
    let err = env.err(
        "set_liquid_network",
        json!({ "network": "regtest", "policy_asset": "not-hex" }),
    );
    assert!(err.contains("policy asset"), "{err}");
    // Nothing changed.
    let info = env.ok("get_liquid_network", json!({}));
    assert_eq!(info["network"], json!("liquid-testnet"));

    // A custom regtest policy asset is honoured.
    let custom = "aa".repeat(32);
    let switched = env.ok(
        "set_liquid_network",
        json!({ "network": "liquid-regtest", "policy_asset": custom }),
    );
    assert_eq!(switched["policy_asset"], json!(custom));
}

#[test]
fn regtest_refuses_public_services_but_keeps_local_swaps_available() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    env.ok("set_liquid_network", json!({ "network": "regtest" }));

    // A plain regtest (no test server) has no peg provider; stored orders
    // still list.
    let err = env.err(
        "peg_quote",
        json!({ "direction": "in", "amount_sats": 100_000 }),
    );
    assert!(
        err.starts_with("PEG_UNAVAILABLE: a plain Liquid regtest"),
        "{err}"
    );
    let listed = env.ok("peg_list", json!({ "wallet_id": id }));
    assert_eq!(listed, json!([]));
    // The public registry is never asked on regtest; the order book's
    // registry needs the issuance in this wallet's history (offline check
    // first: nothing is sent for an asset this wallet did not issue).
    let v = env.ok(
        "reregister_asset",
        json!({
            "wallet_id": id, "asset_id": "aa".repeat(32), "name": "Xyz",
            "ticker": "XYZ", "precision": 8
        }),
    );
    assert_keys(
        "reregister_asset",
        &v,
        &["registered", "book_registered", "book_error"],
    );
    assert_eq!(v["registered"], json!(false));
    assert_eq!(v["book_registered"], json!(false));
    assert!(
        v["book_error"]
            .as_str()
            .unwrap()
            .contains("not in this wallet's history"),
        "{v}"
    );
}

/// The whole regtest path the app takes, against the Templar Protocol's local node:
/// open a wallet on regtest, get funded by the node's `ops` wallet, sync
/// through `elementsd` RPC, see the balance, send, see it move.
///
/// Needs the protocol's regtest node running (see the Templar Protocol
/// repository); run with `cargo test -p templarlib -- --ignored regtest_node`.
#[test]
#[ignore = "needs the Templar Protocol's regtest elementsd on 127.0.0.1:18884"]
fn regtest_node_sync_and_send_end_to_end() {
    let rpc = templar_core::ElementsRpcBackend::new(
        templar_core::DEFAULT_ELEMENTS_RPC_URL,
        templar_core::DEFAULT_ELEMENTS_RPC_USER,
        templar_core::DEFAULT_ELEMENTS_RPC_PASS,
    )
    .expect("rpc client");
    let ops = |method: &str, args: &[Value]| {
        rpc.wallet_call_json("ops", method, args)
            .unwrap_or_else(|e| panic!("ops {method}: {e}"))
    };
    let mine = || {
        let addr = ops("getnewaddress", &[]);
        ops("generatetoaddress", &[json!(1), addr]);
    };
    let lbtc_of = |dash: &Value| -> i64 {
        dash["assets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["ticker"] == json!("LBTC"))
            .expect("LBTC row")["amount"]
            .as_i64()
            .unwrap()
    };

    let mut env = TestEnv::new();
    env.ok("set_liquid_network", json!({ "network": "regtest" }));
    // A fresh seed so the balance starts at zero.
    let words = env.ok("generate_mnemonic", json!({ "word_count": 12 }));
    let mnemonic = words
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Regtest E2E", "mnemonic": mnemonic, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();

    let addr = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "LBTC" }),
    );
    let addr = addr["address"].as_str().unwrap().to_string();
    assert!(
        addr.starts_with("el1"),
        "regtest address expected, got {addr}"
    );

    // Fund from the node's own wallet and confirm.
    ops("sendtoaddress", &[json!(addr), json!("0.5")]);
    mine();

    let outcome = env.ok("sync_wallet", json!({ "wallet_id": id }));
    assert_eq!(outcome["liquid"], json!("ok"), "sync: {outcome}");
    let dash = env.ok("get_wallet_summary", json!({ "wallet_id": id }));
    assert_eq!(dash["liquid_network"], json!("liquid-regtest"));
    assert_eq!(lbtc_of(&dash), 50_000_000, "{dash}");

    // Spend: 10 000 sats to a fresh address of our own.
    let dest = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "LBTC", "fresh": true }),
    );
    let dest = dest["address"].as_str().unwrap().to_string();
    let sent = env.ok(
        "send_transaction",
        json!({
            "wallet_id": id,
            "asset_id": templar_core::REGTEST_DEFAULT_POLICY_ASSET,
            "fee_rate": 0.1,
            "outputs": [{ "address": dest, "amount_sats": 10_000 }],
        }),
    );
    let txid = sent.as_str().expect("txid string");
    assert_eq!(txid.len(), 64, "txid: {txid}");

    mine();
    let outcome = env.ok("sync_wallet", json!({ "wallet_id": id }));
    assert_eq!(outcome["liquid"], json!("ok"), "sync: {outcome}");
    let dash = env.ok("get_wallet_summary", json!({ "wallet_id": id }));
    let after = lbtc_of(&dash);
    // Self-send: only the fee leaves the wallet.
    assert!(
        after < 50_000_000 && after > 49_990_000,
        "balance after send: {after}"
    );
    let activity = dash["recent_activity"].as_array().unwrap();
    assert!(
        activity.iter().any(|a| a["txid"] == json!(txid)),
        "sent tx must show in recent activity: {activity:?}"
    );
}

// ── Test server (Templar testlab profile) ──────────────────────────

const LAB_POLICY: &str = "b0b2bef620ac742b2399a0085bc84e4860ae2c65b5375e3b94399debec69aa6b";
const LAB_GENESIS: &str = "d51392db10c135e2e5f7bcfeab36e859ca4e69d6f76439ec0ebcb0a8da7be248";

/// [`lab_config`] as text, for other modules' tests.
pub(crate) fn lab_config_text(instance: &str) -> String {
    lab_config(instance).to_string()
}

/// A version-1 `/api/config` like a local testlab's.
fn lab_config(instance: &str) -> Value {
    json!({
        "version": 1,
        "name": "Contract lab",
        "orderbook_url": "http://127.0.0.1:3210",
        "networks": {
            "liquid-regtest": {
                "instance_id": instance,
                "policy_asset": LAB_POLICY,
                "genesis_hash": LAB_GENESIS,
                "liquid_electrum_url": "tcp://127.0.0.1:19061",
                "bitcoin_network": "regtest",
                "bitcoin_electrum_url": "tcp://127.0.0.1:19060",
                "bitcoin_esplora_url": "http://127.0.0.1:19070",
                "faucet_url": "http://127.0.0.1:8096/api/faucet",
                "peg": {"provider": "native", "pegin_confirmations": 2,
                        "pegout_confirmations": 2, "pegout_max_sat": 100000000}
            },
            "liquid-testnet": {"faucet_url": "https://liquidtestnet.com",
                               "peg": {"provider": "sideswap"}}
        }
    })
}

/// A loopback HTTP server answering every request with `(status, body)`
/// from the shared slot — offline, no external host. Returns its base URL.
fn serve(answer: std::sync::Arc<std::sync::Mutex<(u16, String)>>) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let mut req = Vec::new();
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let (status, body) = answer.lock().unwrap().clone();
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    url
}

fn lab_server(instance: &str) -> (String, std::sync::Arc<std::sync::Mutex<(u16, String)>>) {
    let slot = std::sync::Arc::new(std::sync::Mutex::new((
        200,
        lab_config(instance).to_string(),
    )));
    (serve(slot.clone()), slot)
}

fn assert_test_server_shape(context: &str, v: &Value) {
    assert_keys(
        context,
        v,
        &["configured", "profile", "check", "applied", "active"],
    );
    let active = &v["active"];
    assert_keys(
        context,
        active,
        &[
            "liquid_network",
            "env_locked",
            "orderbook",
            "liquid",
            "bitcoin",
        ],
    );
    for route in ["origin", "book", "markets", "publish", "atomic_swaps"] {
        assert_keys(context, &active["orderbook"][route], &["url", "source"]);
    }
    assert_keys(
        context,
        &active["liquid"],
        &[
            "network",
            "policy_asset",
            "genesis_hash",
            "params_source",
            "backend",
            "backend_description",
            "backend_source",
        ],
    );
    assert_keys(
        context,
        &active["bitcoin"],
        &["network", "electrum_url", "source"],
    );
}

#[test]
fn get_test_server_without_a_lab_reports_the_defaults() {
    let mut env = TestEnv::new();
    let v = env.ok("get_test_server", json!({}));
    assert_test_server_shape("get_test_server", &v);
    assert_eq!(v["configured"], json!(false));
    assert!(v["profile"].is_null() && v["check"].is_null() && v["applied"].is_null());
    let a = &v["active"];
    assert_eq!(a["liquid_network"], json!("liquid-testnet"));
    assert_eq!(
        a["orderbook"]["publish"]["url"],
        json!("http://127.0.0.1:3210/api/offers")
    );
    assert_eq!(a["orderbook"]["book"]["source"], json!("default"));
    assert_eq!(a["bitcoin"]["network"], json!("bitcoin-testnet"));
    assert_eq!(a["liquid"]["backend"], json!("electrum"));
    // `check` without a lab asks nothing.
    let v = env.ok("get_test_server", json!({ "check": true }));
    assert!(v["check"].is_null());
    let net = env.ok("get_liquid_network", json!({}));
    assert!(net["test_server"].is_null());
    assert_eq!(net["backend_source"], json!("default"));
}

#[test]
fn joining_a_lab_applies_its_regtest_and_order_book_only() {
    let mut env = TestEnv::new();
    let (url, slot) = lab_server(&"11".repeat(32));

    let v = env.ok("set_test_server", json!({ "url": format!("{url}/") }));
    assert_test_server_shape("set_test_server", &v);
    assert_eq!(v["configured"], json!(true));
    let p = &v["profile"];
    assert_keys(
        "profile",
        p,
        &[
            "base_url",
            "name",
            "version",
            "fetched_at",
            "orderbook_url",
            "regtest",
            "testnet",
        ],
    );
    assert_eq!(p["base_url"], json!(url));
    assert_keys(
        "profile.regtest",
        &p["regtest"],
        &[
            "instance_id",
            "policy_asset",
            "genesis_hash",
            "liquid_electrum_url",
            "bitcoin_network",
            "bitcoin_electrum_url",
            "bitcoin_esplora_url",
            "faucet_url",
            "peg",
        ],
    );
    assert_eq!(v["check"]["reachable"], json!(true));
    assert_eq!(v["applied"]["network_switched"], json!(true));
    assert_eq!(v["applied"]["liquid_network"], json!("liquid-regtest"));

    let a = &v["active"];
    assert_eq!(a["liquid"]["policy_asset"], json!(LAB_POLICY));
    assert_eq!(a["liquid"]["genesis_hash"], json!(LAB_GENESIS));
    assert_eq!(a["liquid"]["params_source"], json!("profile"));
    assert_eq!(
        a["liquid"]["backend_description"],
        json!("electrum tcp://127.0.0.1:19061")
    );
    assert_eq!(a["liquid"]["backend_source"], json!("profile"));
    assert_eq!(a["bitcoin"]["network"], json!("bitcoin-regtest"));
    assert_eq!(a["bitcoin"]["electrum_url"], json!("tcp://127.0.0.1:19060"));
    assert_eq!(a["orderbook"]["markets"]["source"], json!("profile"));
    let net = env.ok("get_liquid_network", json!({}));
    assert_eq!(net["network"], json!("liquid-regtest"));
    assert_eq!(net["test_server"], json!(url));
    assert_eq!(net["backend_source"], json!("profile"));

    // Persisted for the next launch.
    let cfg = std::fs::read_to_string(env.dir.join("templar_wallet.json")).unwrap();
    assert!(
        cfg.contains("test_server") && cfg.contains(LAB_POLICY),
        "{cfg}"
    );

    // A wallet opened now runs Bitcoin regtest (offline: just an address).
    let id = env.create_test_wallet();
    let addr = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    );
    let addr = addr["address"].as_str().unwrap();
    assert!(addr.starts_with("bcrt1"), "{addr}");
    // ...with its database apart from testnet's.
    assert!(env.dir.join("bitcoin-regtest").is_dir());

    // With a lab joined, regtest means the lab's regtest.
    let err = env.err(
        "set_liquid_network",
        json!({ "network": "regtest", "policy_asset": "aa".repeat(32) }),
    );
    assert!(err.contains("Clear the test server"), "{err}");
    // Testnet stays reachable, and stays exactly testnet.
    let t = env.ok("set_liquid_network", json!({ "network": "testnet" }));
    assert_eq!(t["backend"], json!("electrum"));
    assert_eq!(t["backend_source"], json!("default"));
    let v = env.ok("get_test_server", json!({}));
    assert_eq!(v["active"]["bitcoin"]["network"], json!("bitcoin-testnet"));
    assert_eq!(v["active"]["orderbook"]["book"]["source"], json!("profile"));
    env.ok("set_liquid_network", json!({ "network": "regtest" }));

    // The lab resets its chains: `check` sees it, `set` applies it and
    // drops the regtest caches (never testnet data).
    std::fs::create_dir_all(env.dir.join("liquid-regtest/enc_cache")).unwrap();
    std::fs::create_dir_all(env.dir.join("liquid-testnet/enc_cache")).unwrap();
    slot.lock().unwrap().1 = lab_config(&"22".repeat(32)).to_string();
    let v = env.ok("get_test_server", json!({ "check": true }));
    assert_eq!(v["check"]["stale"], json!(true));
    assert_eq!(v["check"]["server_instance_id"], json!("22".repeat(32)));
    let v = env.ok("set_test_server", json!({ "url": url }));
    assert_eq!(v["applied"]["regtest_cache_reset"], json!(true));
    assert_eq!(v["applied"]["network_switched"], json!(false));
    assert!(!env.dir.join("liquid-regtest").exists());
    assert!(!env.dir.join("bitcoin-regtest").exists());
    assert!(env.dir.join("liquid-testnet").exists());
    let v = env.ok("get_test_server", json!({ "check": true }));
    assert_eq!(v["check"]["stale"], json!(false));

    // An unreachable lab: the stored profile stays in use.
    *slot.lock().unwrap() = (503, "{}".to_string());
    let v = env.ok("get_test_server", json!({ "check": true }));
    assert_eq!(v["check"]["reachable"], json!(false));
    assert!(v["check"]["error"].as_str().unwrap().contains("HTTP 503"));
    assert_eq!(v["configured"], json!(true));

    // Leaving the lab returns to testnet and drops its regtest caches.
    let v = env.ok("clear_test_server", json!({}));
    assert_test_server_shape("clear_test_server", &v);
    assert_eq!(v["configured"], json!(false));
    assert_eq!(v["applied"]["liquid_network"], json!("liquid-testnet"));
    let cfg = std::fs::read_to_string(env.dir.join("templar_wallet.json")).unwrap();
    assert!(!cfg.contains("test_server"), "{cfg}");
}

/// On a lab's regtest every method that names a network says regtest, and
/// nothing testnet-only is offered or contacted.
#[test]
fn on_a_labs_regtest_every_network_name_is_regtest() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    let wallets = env.ok("list_wallets", json!({}));
    assert_eq!(wallets[0]["network"], json!("testnet"));
    let info = env.ok("get_wallet_info", json!({ "wallet_id": id }));
    assert_eq!(info["network"], json!("Testnet"));

    let (lab, _) = lab_server(&"66".repeat(32));
    env.ok("set_test_server", json!({ "url": lab }));
    let wallets = env.ok("list_wallets", json!({}));
    assert_eq!(wallets[0]["network"], json!("regtest"));
    let info = env.ok("get_wallet_info", json!({ "wallet_id": id }));
    assert_eq!(info["network"], json!("Regtest"));
    assert_eq!(info["liquid_network"], json!("liquid-regtest"));
    let dash = env.ok("get_wallet_summary", json!({ "wallet_id": id }));
    assert_eq!(dash["bitcoin_network"], json!("bitcoin-regtest"));
    assert_eq!(dash["liquid_network"], json!("liquid-regtest"));
    let lbtc = dash["assets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["ticker"] == json!("LBTC"))
        .expect("an LBTC row");
    assert_eq!(lbtc["asset_id"], json!(LAB_POLICY));
    // Testnet-only services: empty or refused, nothing contacted.
    assert_eq!(
        env.ok("atomic_swap_list", json!({ "wallet_id": id })),
        json!([])
    );
    let err = env.err(
        "atomic_swap_create",
        json!({ "wallet_id": id, "direction": "btc-to-liquid", "btc_amount_sats": 1,
                "liquid_asset_id": LAB_POLICY, "liquid_ticker": "LBTC",
                "liquid_name": "x", "liquid_amount_sats": 1 }),
    );
    assert!(err.contains("require Liquid testnet"), "{err}");
    let net = env.ok("get_liquid_network", json!({}));
    assert_eq!(net["peg_provider"], json!("native"));
    // Back on testnet, testnet again.
    env.ok("set_liquid_network", json!({ "network": "testnet" }));
    let dash = env.ok("get_wallet_summary", json!({ "wallet_id": id }));
    assert_eq!(dash["bitcoin_network"], json!("bitcoin-testnet"));
    let wallets = env.ok("list_wallets", json!({}));
    assert_eq!(wallets[0]["network"], json!("testnet"));
}

/// A wallet created and opened on testnet BEFORE the engine joins a lab
/// (the order a manual tester takes) must come back, in the same engine,
/// entirely on the lab's chains: Bitcoin regtest with its own database
/// under `bitcoin-regtest/`, the lab's Electrum server, regtest addresses,
/// and Liquid on the lab's regtest. Nothing of the testnet side may be
/// reused.
#[test]
fn a_wallet_created_before_joining_a_lab_reopens_on_the_labs_chains() {
    let mut env = TestEnv::new();
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Before the lab", "mnemonic": MNEMONIC, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();
    let testnet_btc = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    )["address"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(testnet_btc.starts_with("tb1"), "{testnet_btc}");
    let testnet_db: Vec<_> = std::fs::read_dir(&env.dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("bdk_sw_"))
        .collect();
    assert_eq!(testnet_db.len(), 1, "{testnet_db:?}");
    {
        let b = env.state.bitcoin.as_ref().unwrap();
        assert_eq!(b.network(), bdk::bitcoin::Network::Testnet);
    }

    let (lab, _slot) = lab_server(&"66".repeat(32));
    let joined = env.ok("set_test_server", json!({ "url": lab }));
    assert_eq!(joined["applied"]["wallet_closed"], json!(true));
    assert!(
        env.state.bitcoin.is_none(),
        "the testnet manager must be gone"
    );

    let regtest_btc = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    )["address"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(regtest_btc.starts_with("bcrt1"), "{regtest_btc}");
    let b = env.state.bitcoin.as_ref().unwrap();
    assert_eq!(b.network(), bdk::bitcoin::Network::Regtest);
    assert_eq!(
        b.backend(),
        &templar_core::BitcoinBackend::regtest("tcp://127.0.0.1:19060")
    );
    // The wallet's own descriptor, re-encoded for regtest.
    use std::str::FromStr;
    let addr = bdk::bitcoin::Address::from_str(&regtest_btc)
        .unwrap()
        .require_network(bdk::bitcoin::Network::Regtest)
        .unwrap();
    assert!(b.is_mine(&addr.script_pubkey()));
    // Its own database under bitcoin-regtest/, the testnet one untouched.
    let regtest_db = env.dir.join("bitcoin-regtest").join(&testnet_db[0]);
    assert!(regtest_db.is_dir(), "{regtest_db:?}");
    assert!(env.dir.join(&testnet_db[0]).is_dir());
    let liq = env.state.liquid.as_ref().unwrap();
    assert!(liq.network().unwrap().is_regtest());
    let lbtc = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "LBTC" }),
    )["address"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(lbtc.starts_with("el1"), "{lbtc}");
}

#[test]
fn set_test_server_refuses_bad_servers_and_applies_nothing() {
    let mut env = TestEnv::new();
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({ "url": "ftp://127.0.0.1:1" }),
            "Invalid test server URL",
        ),
        (
            json!({ "url": "http://u:secret@127.0.0.1:1" }),
            "Invalid test server URL",
        ),
    ];
    for (params, want) in cases {
        let err = env.err("set_test_server", params);
        assert!(err.contains(want), "{err}");
        assert!(!err.contains("secret"), "{err}");
    }
    let mut bad = lab_config(&"11".repeat(32));
    bad["version"] = json!(2);
    let (url, slot) = lab_server(&"11".repeat(32));
    slot.lock().unwrap().1 = bad.to_string();
    let err = env.err("set_test_server", json!({ "url": url }));
    assert!(err.contains("needs a newer wallet"), "{err}");

    let mut mainnet = lab_config(&"11".repeat(32));
    mainnet["networks"]["liquid-regtest"]["policy_asset"] =
        json!(templar_core::LBTC_MAINNET_ASSET_ID);
    slot.lock().unwrap().1 = mainnet.to_string();
    let err = env.err("set_test_server", json!({ "url": url }));
    assert!(err.contains("mainnet"), "{err}");

    *slot.lock().unwrap() = (200, "x".repeat(70 * 1024));
    let err = env.err("set_test_server", json!({ "url": url }));
    assert!(err.contains("larger than"), "{err}");

    // Nothing listens on a port just freed.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let err = env.err("set_test_server", json!({ "url": closed }));
    assert!(err.contains("Cannot reach the test server"), "{err}");

    let v = env.ok("get_test_server", json!({}));
    assert_eq!(v["configured"], json!(false));
    assert_eq!(v["active"]["liquid_network"], json!("liquid-testnet"));
    assert!(!env.dir.join("templar_wallet.json").exists());
}

// ── Peg-in / peg-out ───────────────────────────────────────────────

/// Every key of a peg order hosts read: the original ones and the
/// additive native-peg ones.
const PEG_ORDER_KEYS: &[&str] = &[
    "order_id",
    "wallet_id",
    "direction",
    "status",
    "deposit_address",
    "deposit_expected_sats",
    "payout_address",
    "payout_expected_sats",
    "created_at",
    "updated_at",
    "eta_minutes",
    "txid_deposit",
    "txid_payout",
    "simulated",
    "status_history",
    "provider",
    "confirmations",
    "confirmations_required",
    "deposit_received_sats",
    "txid_claim",
    "valid_until_liquid_height",
    "last_error",
    "expires_at",
    "deposits",
];

const PEG_QUOTE_KEYS: &[&str] = &[
    "direction",
    "amount_sats",
    "rate",
    "service_fee_sats",
    "network_fee_sats",
    "receive_sats",
    "min_sats",
    "max_sats",
    "eta_minutes",
    "simulated",
    "provider",
    "confirmations_required",
    "network_fee_included",
];

// ── Asset names from the order book's registry ──────────────────────

/// An order book stub on Liquid testnet: an empty book, one market row of
/// an unregistered token wanting the policy asset (both mis-named by the
/// feed), and a registry naming the token (and trying to rename LBTC).
fn registry_book(
    registry: std::sync::Arc<std::sync::Mutex<(u16, String)>>,
) -> crate::test_http::MockHttp {
    use crate::test_http::{MockHttp, Reply};
    let lbtc = templar_core::TESTNET_POLICY_ASSET;
    let market = json!([{
        "id": "liquidex:1", "source_id": 1, "status": "open", "settlement": "liquidex",
        "demo": false, "available": true,
        "maker_gives": {"chain": "liquid", "network": "liquid-testnet",
            "asset_id": "80d249a8".repeat(8), "ticker": "80D249A8",
            "name": "80D249A8 \u{1b}[2J Unregistered asset", "precision": 8,
            "amount_sats": 10_000, "display_amount": "0.00010000"},
        "maker_wants": {"chain": "liquid", "network": "liquid-testnet", "asset_id": lbtc,
            "ticker": "FAKE", "name": "Not LBTC", "precision": 2,
            "amount_sats": 50_000, "display_amount": "500.00"},
        "price_display": "", "note": "", "created_at": 1, "proposal_json": "{}"
    }])
    .to_string();
    MockHttp::start(move |r| {
        if r.target.starts_with("/api/markets") {
            Reply::json(200, market.clone())
        } else if r.target.starts_with("/api/assets") {
            let (status, body) = registry.lock().unwrap().clone();
            Reply::json(status, body)
        } else {
            Reply::json(404, "{}")
        }
    })
}

fn registry_answer() -> String {
    json!({"network": "liquid-testnet", "assets": [
        {"asset_id": templar_core::TESTNET_POLICY_ASSET, "ticker": "LBTC",
         "name": "Liquid Bitcoin", "precision": 8, "source": "policy"},
        {"asset_id": "80d249a8".repeat(8), "ticker": "TMPL", "name": "Templar Token",
         "precision": 2, "source": "contract"},
        {"asset_id": "002452cb8f56a0a5628240edfb3d1e966c9b1959adcfb95b5726e5e9688611bf",
         "ticker": "DBEER", "name": "Dex Beer", "precision": 2, "source": "admin"},
        {"asset_id": "aa".repeat(32), "ticker": "L-BTC", "name": "Impostor",
         "precision": 8, "source": "admin"}
    ]})
    .to_string()
}

#[test]
fn the_order_books_registry_names_what_the_wallet_does_not_know() {
    let registry = std::sync::Arc::new(std::sync::Mutex::new((200u16, registry_answer())));
    let book = registry_book(registry.clone());
    let (mut env, id) = swap_env(&book.url, MNEMONIC);

    // list_markets reads the registry first (best-effort) and names the
    // token from it; the policy asset stays the wallet's own.
    let rows = env.ok("list_markets", json!({}));
    let gives = &rows[0]["maker_gives"];
    assert_keys(
        "maker_gives",
        gives,
        &[
            "ticker",
            "name",
            "precision",
            "display_amount",
            "metadata_source",
            "book_source",
        ],
    );
    assert_eq!(gives["ticker"], json!("TMPL"));
    assert_eq!(gives["precision"], json!(2));
    assert_eq!(gives["display_amount"], json!("100.00"));
    assert_eq!(gives["amount_sats"], json!(10_000), "base units unchanged");
    assert_eq!(gives["metadata_source"], json!("book"));
    assert_eq!(gives["book_source"], json!("contract"));
    let wants = &rows[0]["maker_wants"];
    assert_eq!(wants["ticker"], json!("LBTC"));
    assert_eq!(wants["precision"], json!(8));
    assert_eq!(wants["display_amount"], json!("0.00050000"));
    assert_eq!(wants["metadata_source"], json!("wallet"));
    assert!(book
        .requests()
        .iter()
        .any(|r| r.target == "/api/assets?network=liquid-testnet"));
    assert!(env.dir.join("book_assets.json").is_file());

    // swap_verify (offline) names a registered asset the same way.
    let v = env.ok(
        "swap_verify",
        json!({ "proposal_json": crate::handlers::swaps::tests::PROPOSAL_ID_9 }),
    );
    let offers = &v["maker_offers"];
    assert_keys(
        "maker_offers",
        offers,
        &[
            "asset_id",
            "ticker",
            "amount_sats",
            "display_amount",
            "name",
            "precision",
            "metadata_source",
            "book_source",
        ],
    );
    assert_eq!(offers["ticker"], json!("DBEER"));
    assert_eq!(offers["display_amount"], json!("10.00"));
    assert_eq!(offers["metadata_source"], json!("book"));
    assert_eq!(offers["book_source"], json!("admin"));

    // list_my_offers names its legs now, from the registry when the wallet
    // does not know the asset (a closed offer: no chain is asked).
    let stored = json!({"offers": [{
        "wallet_id": id, "network": "liquid-testnet", "offer_id": "of_00000001",
        "kind": "swap", "status": "closed", "created_at": 1,
        "offers": {"asset_id": "80d249a8".repeat(8), "ticker": "80d249a8",
                   "amount_sats": 10_000, "display_amount": "0.00010000"},
        "wants": {"asset_id": templar_core::TESTNET_POLICY_ASSET, "ticker": "LBTC",
                  "amount_sats": 500, "display_amount": "0.00000500"},
        "proposal_json": "{}", "utxo": format!("{}:0", "cc".repeat(32))
    }]});
    std::fs::write(env.dir.join("swap_offers.json"), stored.to_string()).unwrap();
    let mine = env.ok("list_my_offers", json!({ "wallet_id": id }));
    assert_eq!(mine[0]["offers"]["ticker"], json!("TMPL"));
    assert_eq!(mine[0]["offers"]["precision"], json!(2));
    assert_eq!(mine[0]["offers"]["display_amount"], json!("100.00"));
    assert_eq!(mine[0]["wants"]["metadata_source"], json!("wallet"));

    // The book loses its registry: the list still works (it asked again)
    // and keeps the names cached.
    *registry.lock().unwrap() = (404, "not found".into());
    let asked = book.requests().len();
    let rows = env.ok("list_markets", json!({}));
    assert_eq!(
        book.requests().len(),
        asked + 2,
        "the registry, then the feed"
    );
    assert_eq!(rows[0]["maker_gives"]["ticker"], json!("TMPL"));
    assert_eq!(rows[0]["maker_gives"]["metadata_source"], json!("book"));
}

/// The live failure, offline: a token registered after the last read of
/// the registry (the buyer synced before the issuer issued) must be named
/// from the registry by the very next `list_markets`, not left to the
/// feed's text. Precedence: the wallet, then the registry, then the feed.
#[test]
fn list_markets_names_an_asset_registered_seconds_ago_from_the_registry() {
    let empty = json!({"network": "liquid-testnet", "assets": []}).to_string();
    let registry = std::sync::Arc::new(std::sync::Mutex::new((200u16, empty)));
    let book = registry_book(registry.clone());
    let (mut env, _) = swap_env(&book.url, MNEMONIC);
    let rows = env.ok("list_markets", json!({}));
    assert_eq!(rows[0]["maker_gives"]["metadata_source"], json!("feed"));
    assert_eq!(rows[0]["maker_gives"]["ticker"], json!("80D249A8"));
    // Registered now; listed again at once.
    *registry.lock().unwrap() = (200, registry_answer());
    let rows = env.ok("list_markets", json!({}));
    let gives = &rows[0]["maker_gives"];
    assert_eq!(gives["metadata_source"], json!("book"), "{gives}");
    assert_eq!(gives["ticker"], json!("TMPL"));
    assert_eq!(gives["display_amount"], json!("100.00"));
}

#[test]
fn without_a_registry_the_feed_names_stay_sanitised_and_marked() {
    let registry = std::sync::Arc::new(std::sync::Mutex::new((
        200u16,
        "{\"network\": \"liquid-testnet\", \"assets\": \"garbage\"}".to_string(),
    )));
    let book = registry_book(registry);
    let (mut env, _) = swap_env(&book.url, MNEMONIC);
    let rows = env.ok("list_markets", json!({}));
    let gives = &rows[0]["maker_gives"];
    assert_eq!(gives["ticker"], json!("80D249A8"));
    assert_eq!(gives["metadata_source"], json!("feed"));
    assert!(!gives["name"].as_str().unwrap().contains('\u{1b}'));
    assert!(gives["book_source"].is_null());
    // The policy asset is never the feed's.
    assert_eq!(rows[0]["maker_wants"]["ticker"], json!("LBTC"));
}

#[test]
fn issue_asset_needs_a_domain_on_testnet_only() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    // No `domain` at all: refused on testnet before anything is built.
    let err = env.err(
        "issue_asset",
        json!({ "wallet_id": id, "name": "Templar Token", "ticker": "TMPL",
                "precision": 2, "amount_sats": 10_000, "reissuance_tokens": 0 }),
    );
    assert!(err.contains("domain is required"), "{err}");
}

// ── Test coins from a lab's faucet ──────────────────────────────────

type FaucetSlot = std::sync::Arc<std::sync::Mutex<(u16, Option<String>, String)>>;

/// A lab whose faucet is a loopback stub answering from `slot`
/// (`status`, `Retry-After`, body). Returns the engine side, the stub and
/// the lab's config server.
fn faucet_lab(mutate: impl FnOnce(&mut Value)) -> (crate::test_http::MockHttp, FaucetSlot, String) {
    use crate::test_http::{MockHttp, Reply};
    let slot: FaucetSlot = std::sync::Arc::new(std::sync::Mutex::new((
        200,
        None,
        json!({"ok": true, "txid": "ab".repeat(32), "amount_sat": 1_000_000, "asset": "lbtc"})
            .to_string(),
    )));
    let answer = slot.clone();
    let faucet = MockHttp::start(move |_| {
        let (status, retry, body) = answer.lock().unwrap().clone();
        let reply = Reply::json(status, body);
        match retry {
            Some(r) => reply.with_header("Retry-After", &r),
            None => reply,
        }
    });
    let mut cfg = lab_config(&"33".repeat(32));
    cfg["networks"]["liquid-regtest"]["faucet_url"] = json!(format!("{}/api/faucet", faucet.url));
    mutate(&mut cfg);
    let lab = serve(std::sync::Arc::new(std::sync::Mutex::new((
        200,
        cfg.to_string(),
    ))));
    (faucet, slot, lab)
}

#[test]
fn the_test_server_object_shows_the_faucet_and_the_protocol_site() {
    let mut env = TestEnv::new();
    let v = env.ok("get_test_server", json!({}));
    assert!(v["faucet"].is_null(), "no lab, no faucet");
    assert!(v["active"]["protocol"].is_null());
    assert_eq!(
        v["active"]["orderbook"]["assets"]["url"],
        json!("http://127.0.0.1:3210/api/assets")
    );

    // An older lab: no list, no protocol site.
    let (lab, _) = lab_server(&"11".repeat(32));
    let v = env.ok("set_test_server", json!({ "url": lab }));
    assert_keys(
        "faucet",
        &v["faucet"],
        &["url", "assets_source", "assets", "available"],
    );
    assert_eq!(v["faucet"]["assets_source"], json!("default"));
    assert_eq!(v["faucet"]["available"], json!(true));
    let assets = v["faucet"]["assets"].as_array().unwrap();
    assert_eq!(assets.len(), 2);
    assert_keys(
        "faucet asset",
        &assets[1],
        &[
            "asset",
            "network",
            "ticker",
            "name",
            "precision",
            "asset_id",
            "default_sat",
            "max_sat",
        ],
    );
    assert_eq!(assets[0]["asset"], json!("btc"));
    assert_eq!(assets[1]["asset_id"], json!(LAB_POLICY));
    assert!(v["active"]["protocol"].is_null());

    // A lab that lists its faucet and its protocol site.
    let (_, _, lab) = faucet_lab(|cfg| {
        cfg["protocol_url"] = json!("http://127.0.0.1:4100/");
        cfg["networks"]["liquid-regtest"]["faucet"] = json!([
            {"asset":"USDt","network":"liquid-regtest","ticker":"USDt",
             "name":"Tether USD (test)","precision":8,"asset_id":"cc".repeat(32),
             "default_sat":10000000000u64,"max_sat":100000000000u64}
        ]);
    });
    let v = env.ok("set_test_server", json!({ "url": lab }));
    assert_eq!(v["faucet"]["assets_source"], json!("profile"));
    assert_eq!(v["faucet"]["assets"][0]["ticker"], json!("USDt"));
    assert_eq!(v["profile"]["protocol_url"], json!("http://127.0.0.1:4100"));
    assert_eq!(
        v["active"]["protocol"],
        json!({"url": "http://127.0.0.1:4100", "source": "profile"})
    );
    // On Liquid testnet the lab's protocol site and faucet are not offered.
    env.ok("set_liquid_network", json!({ "network": "testnet" }));
    let v = env.ok("get_test_server", json!({}));
    assert!(v["active"]["protocol"].is_null());
    assert_eq!(v["faucet"]["available"], json!(false));
}

#[test]
fn test_server_faucet_pays_this_wallet_on_the_labs_regtest_only() {
    let mut env = TestEnv::new();
    // No lab: refused before any wallet is opened.
    let err = env.err(
        "test_server_faucet",
        json!({ "wallet_id": "nope", "asset": "lbtc" }),
    );
    assert!(err.starts_with("FAUCET_UNAVAILABLE: "), "{err}");

    let (faucet, slot, lab) = faucet_lab(|_| {});
    env.ok("set_test_server", json!({ "url": lab }));
    let id = env.create_test_wallet();

    // L-BTC: a Liquid regtest address of this wallet; network, address and
    // asset are all that is sent.
    let paid = env.ok(
        "test_server_faucet",
        json!({ "wallet_id": id, "asset": "LBTC" }),
    );
    assert_keys(
        "test_server_faucet",
        &paid,
        &[
            "txid",
            "asset",
            "network",
            "amount_sat",
            "address",
            "ticker",
            "precision",
            "asset_id",
        ],
    );
    assert_eq!(paid["txid"], json!("ab".repeat(32)));
    assert_eq!(paid["asset"], json!("lbtc"));
    assert_eq!(paid["network"], json!("liquid-regtest"));
    assert_eq!(paid["amount_sat"], json!(1_000_000));
    assert_eq!(paid["asset_id"], json!(LAB_POLICY));
    let address = paid["address"].as_str().unwrap();
    assert!(address.starts_with("el1"), "{address}");
    let sent: Value = serde_json::from_str(&faucet.requests()[0].body).unwrap();
    assert_eq!(
        sent,
        json!({"network": "liquid-regtest", "address": address, "asset": "lbtc"})
    );
    assert_eq!(faucet.requests()[0].method, "POST");
    assert_eq!(faucet.requests()[0].target, "/api/faucet");

    // BTC: a Bitcoin regtest address.
    let paid = env.ok(
        "test_server_faucet",
        json!({ "wallet_id": id, "asset": "btc" }),
    );
    assert_eq!(paid["network"], json!("bitcoin-regtest"));
    assert!(paid["address"].as_str().unwrap().starts_with("bcrt1"));
    assert!(paid["asset_id"].is_null());

    // Refusals, each with its tag.
    let mut ask = |status: u16, retry: Option<&str>, body: &str| -> String {
        *slot.lock().unwrap() = (status, retry.map(str::to_string), body.to_string());
        env.err(
            "test_server_faucet",
            json!({ "wallet_id": id, "asset": "lbtc" }),
        )
    };
    let err = ask(
        429,
        Some("120"),
        r#"{"ok":false,"error":"3 payments per address per hour."}"#,
    );
    assert!(err.starts_with("FAUCET_RATE_LIMITED: "), "{err}");
    assert!(
        err.contains("per address") && err.contains("120 seconds"),
        "{err}"
    );
    let err = ask(429, None, r#"{"ok":false,"error":"budget"}"#);
    assert!(err.contains("Try again later"), "{err}");
    let hostile = format!(
        r#"{{"ok":false,"error":"bad address\u001b[2J{}"}}"#,
        "x".repeat(5000)
    );
    let err = ask(400, None, &hostile);
    assert!(err.starts_with("FAUCET_REFUSED: "), "{err}");
    assert!(err.contains("bad address"), "{err}");
    assert!(!err.contains('\u{1b}') && err.len() < 600, "{err}");
    let err = ask(502, None, r#"{"ok":false,"error":"node refused"}"#);
    assert!(err.starts_with("FAUCET_UNAVAILABLE: "), "{err}");
    let err = ask(404, None, "not found");
    assert!(err.starts_with("FAUCET_UNAVAILABLE: "), "{err}");
    let err = ask(200, None, r#"{"ok":true,"txid":"nope"}"#);
    assert!(err.starts_with("FAUCET_UNAVAILABLE: "), "{err}");
    let err = ask(200, None, r#"{"ok":false,"error":"empty"}"#);
    assert!(err.starts_with("FAUCET_REFUSED: "), "{err}");

    // An asset the faucet does not pay: refused without asking it.
    let before = faucet.requests().len();
    let err = env.err(
        "test_server_faucet",
        json!({ "wallet_id": id, "asset": "DOGE" }),
    );
    assert!(err.starts_with("FAUCET_UNAVAILABLE: "), "{err}");
    assert!(err.contains("BTC, LBTC"), "{err}");
    // Never on testnet.
    env.ok("set_liquid_network", json!({ "network": "testnet" }));
    let err = env.err(
        "test_server_faucet",
        json!({ "wallet_id": id, "asset": "lbtc" }),
    );
    assert!(err.starts_with("FAUCET_UNAVAILABLE: "), "{err}");
    assert!(err.contains("liquid-testnet"), "{err}");
    assert_eq!(faucet.requests().len(), before, "nothing asked");

    // An unreachable faucet.
    let mut env = TestEnv::new();
    let mut cfg = lab_config(&"44".repeat(32));
    cfg["networks"]["liquid-regtest"]["faucet_url"] = json!(format!(
        "{}/api/faucet",
        crate::test_http::closed_port_url()
    ));
    let lab = serve(std::sync::Arc::new(std::sync::Mutex::new((
        200,
        cfg.to_string(),
    ))));
    env.ok("set_test_server", json!({ "url": lab }));
    let id = env.create_test_wallet();
    let err = env.err(
        "test_server_faucet",
        json!({ "wallet_id": id, "asset": "btc" }),
    );
    assert!(err.starts_with("FAUCET_UNREACHABLE: "), "{err}");
}

#[test]
fn test_server_faucet_asks_for_a_listed_lab_asset_by_its_faucet_name() {
    let (faucet, _, lab) = faucet_lab(|cfg| {
        cfg["networks"]["liquid-regtest"]["faucet"] = json!([
            {"asset":"lbtc","network":"liquid-regtest","ticker":"LBTC","name":"Liquid Bitcoin",
             "precision":8},
            {"asset":"USDt","network":"liquid-regtest","ticker":"USDt",
             "name":"Tether USD (test)","precision":8,"asset_id":"cc".repeat(32)}
        ]);
    });
    let mut env = TestEnv::new();
    env.ok("set_test_server", json!({ "url": lab }));
    let id = env.create_test_wallet();
    let paid = env.ok(
        "test_server_faucet",
        json!({ "wallet_id": id, "asset": "cc".repeat(32) }),
    );
    assert_eq!(paid["asset"], json!("USDt"));
    assert_eq!(paid["ticker"], json!("USDt"));
    let sent: Value = serde_json::from_str(&faucet.requests()[0].body).unwrap();
    assert_eq!(sent["asset"], json!("USDt"));
    // This lab's faucet pays no BTC.
    let err = env.err(
        "test_server_faucet",
        json!({ "wallet_id": id, "asset": "btc" }),
    );
    assert!(err.starts_with("FAUCET_UNAVAILABLE: "), "{err}");
}

#[test]
fn peg_without_a_provider_says_why_and_still_lists() {
    let mut env = TestEnv::new();
    let net = env.ok("get_liquid_network", json!({}));
    assert_keys(
        "get_liquid_network",
        &net,
        &["peg_provider", "peg_unavailable_reason"],
    );
    assert!(net["peg_provider"].is_null());
    let why = net["peg_unavailable_reason"].as_str().unwrap();
    assert!(why.starts_with("PEG_UNAVAILABLE: Liquid testnet"), "{why}");

    let err = env.err(
        "peg_quote",
        json!({ "direction": "out", "amount_sats": 100_000 }),
    );
    assert!(err.starts_with("PEG_UNAVAILABLE:"), "{err}");
    let id = env.create_test_wallet();
    let err = env.err(
        "peg_start",
        json!({ "wallet_id": id, "direction": "in", "amount_sats": 100_000,
                "payout_address": "x" }),
    );
    assert!(err.starts_with("PEG_UNAVAILABLE:"), "{err}");
    assert_eq!(env.ok("peg_list", json!({ "wallet_id": id })), json!([]));
    for method in ["peg_fund", "peg_claim", "peg_status", "peg_cancel"] {
        let err = env.err(method, json!({ "order_id": "pg_nope" }));
        assert!(err.contains("Unknown peg order"), "{method}: {err}");
    }
}

/// A lab config whose chain servers are a port nothing listens on: the
/// test stays offline and a chain read fails fast.
fn offline_lab_server() -> String {
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut cfg = lab_config(&"33".repeat(32));
    let reg = &mut cfg["networks"]["liquid-regtest"];
    reg["liquid_electrum_url"] = json!(format!("tcp://127.0.0.1:{closed}"));
    reg["bitcoin_electrum_url"] = json!(format!("tcp://127.0.0.1:{closed}"));
    reg["bitcoin_esplora_url"] = json!(format!("http://127.0.0.1:{closed}"));
    let slot = std::sync::Arc::new(std::sync::Mutex::new((200, cfg.to_string())));
    serve(slot)
}

#[test]
fn native_peg_orders_have_the_contract_shape() {
    let mut env = TestEnv::new();
    let lab = offline_lab_server();
    env.ok("set_test_server", json!({ "url": lab }));
    let net = env.ok("get_liquid_network", json!({}));
    assert_eq!(net["peg_provider"], json!("native"));
    assert!(net["peg_unavailable_reason"].is_null());

    // Quotes: real terms, no service fee, the lab's limits.
    let q = env.ok(
        "peg_quote",
        json!({ "direction": "in", "amount_sats": 100_000 }),
    );
    assert_keys("peg_quote", &q, PEG_QUOTE_KEYS);
    assert_eq!(q["provider"], json!("native"));
    assert_eq!(q["simulated"], json!(false));
    assert_eq!(q["service_fee_sats"], json!(0));
    assert_eq!(q["confirmations_required"], json!(2));
    assert_eq!(q["network_fee_included"], json!(true));
    let q = env.ok(
        "peg_quote",
        json!({ "direction": "out", "amount_sats": 100_000 }),
    );
    assert_eq!(q["receive_sats"], json!(100_000));
    assert_eq!(q["max_sats"], json!(100_000_000));
    assert_eq!(q["min_sats"], json!(100_000), "the lab's pegout_min_sat");
    let ts = env.ok("get_test_server", json!({}));
    assert_keys(
        "profile.regtest.peg",
        &ts["profile"]["regtest"]["peg"],
        &[
            "provider",
            "pegin_confirmations",
            "pegout_confirmations",
            "pegout_max_sat",
            "pegout_min_sat",
        ],
    );
    let err = env.err(
        "peg_quote",
        json!({ "direction": "out", "amount_sats": 100_000_001 }),
    );
    assert!(err.contains("above the maximum of 100000000"), "{err}");
    let err = env.err(
        "peg_quote",
        json!({ "direction": "in", "amount_sats": 9_999 }),
    );
    assert!(err.contains("below the minimum"), "{err}");

    let created = env.ok(
        "create_wallet",
        json!({ "name": "Peg", "mnemonic": MNEMONIC, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();
    let btc = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    )["address"]
        .as_str()
        .unwrap()
        .to_string();
    let lbtc = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "LBTC" }),
    )["address"]
        .as_str()
        .unwrap()
        .to_string();

    // A peg-in pays out on Liquid; its address comes from the chain, which
    // is unreachable here: nothing is stored.
    let start = |dir: &str, payout: &str, amount: u64| {
        json!({ "wallet_id": id, "direction": dir, "amount_sats": amount,
                "payout_address": payout })
    };
    let err = env.err("peg_start", start("in", &btc, 100_000));
    assert!(err.contains("Payout address"), "{err}");
    env.err("peg_start", start("in", &lbtc, 100_000));
    // A peg-out pays out on the lab's Bitcoin regtest.
    let err = env.err(
        "peg_start",
        start("out", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 150_000),
    );
    assert!(err.contains("another network"), "{err}");
    let err = env.err("peg_start", start("out", &btc, 200_000_000));
    assert!(err.contains("above the maximum"), "{err}");
    assert_eq!(env.ok("peg_list", json!({ "wallet_id": id })), json!([]));

    // Below the lab's pegout_min_sat (absent here: 100 000) the output
    // would be burned: refused.
    let err = env.err("peg_start", start("out", &btc, 50_000));
    assert!(err.contains("below the minimum of 100000"), "{err}");
    let order = env.ok("peg_start", start("out", &btc, 150_000));
    assert_keys("peg_start", &order, PEG_ORDER_KEYS);
    assert_eq!(order["provider"], json!("native"));
    assert_eq!(order["simulated"], json!(false));
    assert_eq!(order["status"], json!("awaiting_deposit"));
    assert_eq!(order["deposit_address"], json!(""));
    assert_eq!(order["deposit_expected_sats"], json!(150_000));
    assert_eq!(order["payout_expected_sats"], json!(150_000));
    assert_eq!(order["confirmations"], json!(0));
    assert_eq!(order["confirmations_required"], json!(2));
    for null in [
        "txid_deposit",
        "txid_payout",
        "txid_claim",
        "deposit_received_sats",
        "valid_until_liquid_height",
        "last_error",
    ] {
        assert!(order[null].is_null(), "{null}: {order}");
    }
    assert_keys(
        "status_history",
        &order["status_history"][0],
        &["status", "at"],
    );
    let oid = order["order_id"].as_str().unwrap().to_string();

    // Following an unfunded peg-out reads no chain.
    let s = env.ok("peg_status", json!({ "order_id": oid }));
    assert_keys("peg_status", &s, PEG_ORDER_KEYS);
    assert!(s["last_error"].is_null(), "{s}");
    let listed = env.ok("peg_list", json!({ "wallet_id": id }));
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_keys("peg_list", &listed[0], PEG_ORDER_KEYS);

    let err = env.err("peg_claim", json!({ "order_id": oid }));
    assert!(err.starts_with("PEG_NOT_READY: only a peg-in"), "{err}");
    let cancelled = env.ok("peg_cancel", json!({ "order_id": oid }));
    assert_eq!(cancelled["status"], json!("cancelled"));
    let err = env.err("peg_fund", json!({ "order_id": oid }));
    assert!(err.starts_with("PEG_NOT_READY:"), "{err}");

    // Back on testnet the stored order still reads; nothing can be paid.
    env.ok("clear_test_server", json!({}));
    let s = env.ok("peg_status", json!({ "order_id": oid }));
    assert_eq!(s["status"], json!("cancelled"));
    let err = env.err("peg_fund", json!({ "order_id": oid }));
    assert!(err.starts_with("PEG_UNAVAILABLE:"), "{err}");
}

#[test]
fn sideswap_serves_testnet_only_when_the_lab_names_it() {
    let mut env = TestEnv::new();
    let lab = offline_lab_server();
    env.ok("set_test_server", json!({ "url": lab }));
    // The lab's regtest has the native peg; its testnet block names
    // SideSwap, which serves Liquid testnet (no chain is contacted here).
    env.ok("set_liquid_network", json!({ "network": "testnet" }));
    let net = env.ok("get_liquid_network", json!({}));
    assert_eq!(net["peg_provider"], json!("sideswap"));
    assert!(net["peg_unavailable_reason"].is_null());
    env.ok("clear_test_server", json!({}));
    let net = env.ok("get_liquid_network", json!({}));
    assert!(net["peg_provider"].is_null());
}

/// SideSwap's real testnet endpoint (`TEMPLAR_SIDESWAP_URL` overrides it):
/// its terms, then one order per direction opened, followed and cancelled
/// locally. No funds move — SideSwap's deposit addresses are never paid.
/// See docs/guides/LIVE_TESTS.md.
#[test]
#[ignore = "needs SideSwap's public testnet API (network)"]
fn live_sideswap_testnet_quote_and_orders() {
    let mut env = TestEnv::new();
    // A lab profile whose testnet block names SideSwap, served locally.
    let (lab, _slot) = lab_server(&"44".repeat(32));
    env.ok("set_test_server", json!({ "url": lab }));
    env.ok("set_liquid_network", json!({ "network": "testnet" }));
    let words = env.ok("generate_mnemonic", json!({ "word_count": 12 }));
    let mnemonic = words
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Live SideSwap", "mnemonic": mnemonic, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();
    let address = |env: &mut TestEnv, asset: &str| {
        env.ok(
            "generate_receive_address",
            json!({ "wallet_id": id, "asset": asset, "fresh": true }),
        )["address"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let lbtc = address(&mut env, "LBTC");
    let btc = address(&mut env, "BTC");
    assert!(lbtc.starts_with("tlq1"), "{lbtc}");
    assert!(btc.starts_with("tb1"), "{btc}");

    for (dir, amount) in [("in", 100_000u64), ("out", 100_000u64)] {
        let q = env.ok(
            "peg_quote",
            json!({ "direction": dir, "amount_sats": amount }),
        );
        eprintln!("[live] SideSwap {dir} quote: {q}");
        assert_keys("peg_quote", &q, PEG_QUOTE_KEYS);
        assert_eq!(q["provider"], json!("sideswap"));
    }
    let err = env.err(
        "peg_quote",
        json!({ "direction": "out", "amount_sats": 1_000 }),
    );
    assert!(err.contains("below the minimum"), "{err}");

    for (dir, payout) in [("in", lbtc.clone()), ("out", btc.clone())] {
        let started = env.call(
            "peg_start",
            json!({ "wallet_id": id, "direction": dir, "amount_sats": 100_000,
                    "payout_address": payout }),
        );
        // SideSwap may refuse an order (on 2026-11-15 its testnet answered
        // peg-out with "disabled on testnet" and peg-in with an internal
        // error): the refusal must arrive as an error and store nothing.
        let Some(order) = started.get("ok").cloned() else {
            let err = started["err"].as_str().unwrap_or_default().to_string();
            eprintln!("[live] SideSwap refused the {dir} order: {err}");
            assert!(err.contains("SideSwap: the server refused"), "{err}");
            let listed = env.ok("peg_list", json!({ "wallet_id": id }));
            assert!(
                !listed
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|o| o["direction"] == json!(dir) && o["status"] != json!("cancelled")),
                "a refused order must not be stored: {listed}"
            );
            continue;
        };
        assert_keys("peg_start", &order, PEG_ORDER_KEYS);
        eprintln!(
            "[live] SideSwap {dir} order {}: deposit address {}, expires_at {}",
            order["order_id"], order["deposit_address"], order["expires_at"]
        );
        assert_eq!(order["provider"], json!("sideswap"));
        let oid = order["order_id"].as_str().unwrap().to_string();
        let s = env.ok("peg_status", json!({ "order_id": oid }));
        eprintln!(
            "[live] SideSwap {dir} status: {}, error {}",
            s["status"], s["last_error"]
        );
        assert_eq!(s["status"], json!("awaiting_deposit"));
        assert!(s["last_error"].is_null(), "{s}");
        let err = env.err("peg_claim", json!({ "order_id": oid }));
        assert!(err.starts_with("PEG_UNAVAILABLE:"), "{err}");
        let c = env.ok("peg_cancel", json!({ "order_id": oid }));
        assert_eq!(c["status"], json!("cancelled"));
    }
}

// ── Cross-chain swaps against a lying coordinator ──────────────────

/// A loopback HTLC coordinator (`/api/atomic-swaps`) keeping one swap row
/// the test can rewrite between calls. Returns its origin.
fn mock_coordinator(row: std::sync::Arc<std::sync::Mutex<Value>>) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut req = Vec::new();
            let mut buf = [0u8; 8192];
            let (head, body) = loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break (String::new(), Vec::new()),
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
                if let Some(at) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&req[..at]).to_string();
                    let len = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    while req.len() < at + 4 + len {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => req.extend_from_slice(&buf[..n]),
                        }
                    }
                    break (head, req[at + 4..].to_vec());
                }
            };
            let method = head.split_whitespace().next().unwrap_or("").to_string();
            let sent: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let answer = {
                let mut row = row.lock().unwrap();
                match method.as_str() {
                    "POST" => {
                        *row = json!({
                            "id": 7, "network": sent["network"], "status": "open",
                            "state": sent["state"], "created_at": 1, "updated_at": 1
                        });
                    }
                    "PUT" => {
                        row["status"] = sent["status"].clone();
                        row["state"] = sent["state"].clone();
                    }
                    _ => {}
                }
                row.to_string()
            };
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{answer}",
                answer.len()
            );
        }
    });
    url
}

/// An engine on Liquid testnet whose order book (and so HTLC coordinator)
/// is `coordinator`, with one software wallet from `mnemonic`.
fn swap_env(coordinator: &str, mnemonic: &str) -> (TestEnv, String) {
    let mut env = TestEnv::new();
    let mut cfg = lab_config(&"55".repeat(32));
    cfg["orderbook_url"] = json!(coordinator);
    let lab = serve(std::sync::Arc::new(std::sync::Mutex::new((
        200,
        cfg.to_string(),
    ))));
    env.ok("set_test_server", json!({ "url": lab }));
    env.ok("set_liquid_network", json!({ "network": "testnet" }));
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Swap", "mnemonic": mnemonic, "liquid": true }),
    );
    (env, created["id"].as_str().unwrap().to_string())
}

#[test]
fn a_lying_htlc_coordinator_cannot_redirect_a_swap_payment() {
    use templar_core::{
        bitcoin_contract, derive_swap_secret_key, liquid_contract, swap_public_key, HtlcTerms,
    };
    let row = std::sync::Arc::new(std::sync::Mutex::new(Value::Null));
    let coordinator = mock_coordinator(row.clone());
    let (mut maker, maker_id) = swap_env(&coordinator, MNEMONIC);
    let created = maker.ok(
        "atomic_swap_create",
        json!({
            "wallet_id": maker_id, "direction": "btc-to-liquid", "btc_amount_sats": 50_000,
            "liquid_asset_id": templar_core::TESTNET_POLICY_ASSET, "liquid_ticker": "LBTC",
            "liquid_name": "Liquid Bitcoin", "liquid_amount_sats": 50_000
        }),
    );
    assert_eq!(created["offer_id"], json!(7));

    // A taker joins (simulated): its key and timeout, the honest contracts.
    let taker_key = derive_swap_secret_key(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        1,
        0,
    )
    .unwrap();
    let taker_pub = swap_public_key(&taker_key).to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (honest, attacker) = {
        let mut r = row.lock().unwrap();
        let st = &mut r["state"];
        st["taker_claim_pubkey"] = json!(taker_pub);
        st["taker_timeout"] = json!(now + 24 * 3600);
        let maker_terms = HtlcTerms {
            payment_hash: st["payment_hash"].as_str().unwrap().into(),
            claim_pubkey: taker_pub.clone(),
            refund_pubkey: st["maker_refund_pubkey"].as_str().unwrap().into(),
            timeout: st["maker_timeout"].as_u64().unwrap(),
        };
        let honest = bitcoin_contract(maker_terms.clone()).unwrap();
        // The coordinator's own key as the refund key: its address, not the
        // maker's contract.
        let attacker = bitcoin_contract(HtlcTerms {
            refund_pubkey: taker_pub.clone(),
            ..maker_terms
        })
        .unwrap();
        let taker_contract = liquid_contract(HtlcTerms {
            payment_hash: st["payment_hash"].as_str().unwrap().into(),
            claim_pubkey: st["maker_refund_pubkey"].as_str().unwrap().into(),
            refund_pubkey: taker_pub.clone(),
            timeout: now + 24 * 3600,
        })
        .unwrap();
        st["maker_contract_address"] = json!(attacker.address);
        st["maker_contract_script"] = json!(attacker.script_hex);
        st["taker_contract_address"] = json!(taker_contract.address);
        st["taker_contract_script"] = json!(taker_contract.script_hex);
        r["status"] = json!("reserved");
        (honest, attacker)
    };
    assert_ne!(honest.address, attacker.address);
    let fund = json!({ "wallet_id": maker_id, "offer_id": 7 });
    // The maker would pay the coordinator's address: refused before any
    // coin is selected (an unfunded wallet would otherwise fail on funds).
    let err = maker.err("atomic_swap_fund", fund.clone());
    assert!(
        err.contains("no longer matches") && err.contains("maker contract"),
        "{err}"
    );
    // Honest contracts, but the amount changed after creation: refused.
    {
        let mut r = row.lock().unwrap();
        r["state"]["maker_contract_address"] = json!(honest.address);
        r["state"]["maker_contract_script"] = json!(honest.script_hex);
        r["state"]["offered_amount_sats"] = json!(5_000_000);
    }
    let err = maker.err("atomic_swap_fund", fund.clone());
    assert!(err.contains("offered amount"), "{err}");
    // A taker timeout that leaves the maker no time to claim: refused.
    {
        let mut r = row.lock().unwrap();
        r["state"]["offered_amount_sats"] = json!(50_000);
        let maker_timeout = r["state"]["maker_timeout"].as_u64().unwrap();
        r["state"]["taker_timeout"] = json!(maker_timeout);
    }
    let err = maker.err("atomic_swap_fund", fund.clone());
    assert!(err.contains("no safe time"), "{err}");

    // The taker's side: it joins an open offer and keeps what it accepted.
    {
        let mut r = row.lock().unwrap();
        r["status"] = json!("open");
        for k in [
            "taker_claim_pubkey",
            "taker_timeout",
            "maker_contract_address",
            "maker_contract_script",
            "taker_contract_address",
            "taker_contract_script",
        ] {
            r["state"][k] = Value::Null;
        }
    }
    let (mut taker, taker_id) = swap_env(
        &coordinator,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    );
    let joined = taker.ok(
        "atomic_swap_join",
        json!({ "wallet_id": taker_id, "offer_id": 7 }),
    );
    assert_eq!(joined["row"]["status"], json!("reserved"));
    // The maker's key changes after the taker accepted: the taker's
    // funding is refused.
    {
        let mut r = row.lock().unwrap();
        r["status"] = json!("maker_funded");
        r["state"]["maker_refund_pubkey"] = json!(taker_pub);
        r["state"]["maker_funding_txid"] = json!("11".repeat(32));
        r["state"]["maker_funding_vout"] = json!(0);
    }
    let err = taker.err(
        "atomic_swap_fund",
        json!({ "wallet_id": taker_id, "offer_id": 7 }),
    );
    assert!(err.contains("maker key"), "{err}");
}

/// The record found on the owner's machine (an older engine, an order book
/// whose database is gone), for the wallet `id`.
fn legacy_swap_store(id: &str) -> String {
    json!({"swaps": [{"key_index": 0, "offer_id": 1, "role": "maker", "wallet_id": id}]})
        .to_string()
}

#[test]
fn atomic_swap_list_is_empty_on_a_labs_regtest_and_touches_nothing() {
    let mut env = TestEnv::new();
    let (lab, _) = lab_server(&"11".repeat(32));
    env.ok("set_test_server", json!({ "url": lab }));
    let id = env.create_test_wallet();
    let path = env.dir.join("atomic_swaps.json");
    std::fs::write(&path, legacy_swap_store(&id)).unwrap();
    // The lab's book answers on 127.0.0.1:3210 only if something runs
    // there; nothing may be asked anyway.
    let listed = env.ok("atomic_swap_list", json!({ "wallet_id": id }));
    assert_eq!(listed, json!([]));
    // Even for a wallet that does not exist: nothing is opened.
    let listed = env.ok("atomic_swap_list", json!({ "wallet_id": "nope" }));
    assert_eq!(listed, json!([]));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        legacy_swap_store(&id)
    );
}

#[test]
fn atomic_swap_list_survives_a_record_the_book_does_not_know() {
    use crate::test_http::{MockHttp, Reply};
    let book = MockHttp::start(|_| Reply::json(404, r#"{"error":"Unknown atomic swap: 1"}"#));
    let (mut env, id) = swap_env(&book.url, MNEMONIC);
    let path = env.dir.join("atomic_swaps.json");
    std::fs::write(&path, legacy_swap_store(&id)).unwrap();
    // The owner's bug: `Order book HTTP 404: Unknown atomic swap: 1` for the
    // whole list. Now the legacy record (no terms: nothing to act on) is
    // left out and kept.
    let listed = env.ok("atomic_swap_list", json!({ "wallet_id": id }));
    assert_eq!(listed, json!([]));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        legacy_swap_store(&id)
    );
    assert_eq!(book.requests()[0].target, "/api/atomic-swaps/1");

    // A record that kept its terms is listed, with why it is not live.
    let coordinator = format!("{}/api/atomic-swaps", book.url);
    let with_terms = json!({"swaps": [{
        "key_index": 1, "offer_id": 2, "role": "taker", "wallet_id": id,
        "coordinator": coordinator,
        "terms": {
            "offered_chain": "bitcoin", "offered_asset_id": "btc-testnet",
            "offered_amount_sats": 50000, "wanted_chain": "liquid",
            "wanted_asset_id": templar_core::TESTNET_POLICY_ASSET,
            "wanted_amount_sats": 49000, "payment_hash": "ab".repeat(32),
            "maker_pubkey": "02".to_string() + &"11".repeat(32),
            "maker_timeout": 4_000_000_000u64,
            "taker_pubkey": "03".to_string() + &"22".repeat(32),
            "taker_timeout": 3_900_000_000u64
        }
    }]});
    std::fs::write(&path, with_terms.to_string()).unwrap();
    let listed = env.ok("atomic_swap_list", json!({ "wallet_id": id }));
    let row = &listed[0];
    assert_keys(
        "atomic_swap_list row",
        row,
        &[
            "offer_id",
            "wallet_id",
            "role",
            "key_index",
            "row",
            "next_action",
            "can_fund",
            "can_claim",
            "can_refund",
            "availability",
            "availability_note",
            "coordinator",
        ],
    );
    assert_eq!(row["availability"], json!("not_on_this_book"));
    assert_eq!(row["row"]["status"], json!("unavailable"));
    assert_eq!(row["next_action"], json!("wait"));
    assert_eq!(row["row"]["state"]["offered_amount_sats"], json!(50000));
    assert_eq!(row["row"]["state"]["wanted_ticker"], json!("LBTC"));
    assert_eq!(row["coordinator"], json!(coordinator));
}

// ── Live: LiquiDEX on a Templar testlab ────────────────────────────

/// One side of a live test: an engine on its own data directory (joined to
/// the lab, or on Liquid testnet), with one software wallet open.
struct LabWallet {
    env: TestEnv,
    id: String,
}

impl LabWallet {
    fn join(lab: &str, name: &str) -> Self {
        let mut env = TestEnv::new();
        let joined = env.ok("set_test_server", json!({ "url": lab }));
        assert_eq!(joined["active"]["liquid_network"], json!("liquid-regtest"));
        Self::create(env, name)
    }

    /// A fresh software wallet (Bitcoin and Liquid) named `name` in `env`.
    fn create(mut env: TestEnv, name: &str) -> Self {
        let words = env.ok("generate_mnemonic", json!({ "word_count": 12 }));
        let mnemonic = words
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        let created = env.ok(
            "create_wallet",
            json!({ "name": name, "mnemonic": mnemonic, "liquid": true }),
        );
        let id = created["id"].as_str().unwrap().to_string();
        Self { env, id }
    }

    fn ok(&mut self, method: &str, mut params: Value) -> Value {
        if params.get("wallet_id").is_none() && params.is_object() {
            params["wallet_id"] = json!(self.id);
        }
        self.env.ok(method, params)
    }

    fn err(&mut self, method: &str, mut params: Value) -> String {
        if params.get("wallet_id").is_none() && params.is_object() {
            params["wallet_id"] = json!(self.id);
        }
        self.env.err(method, params)
    }

    fn address(&mut self, asset: &str) -> String {
        let a = self.ok(
            "generate_receive_address",
            json!({ "asset": asset, "fresh": true }),
        );
        a["address"].as_str().unwrap().to_string()
    }

    /// Syncs both chains; both must succeed.
    fn sync(&mut self) {
        let outcome = self.ok("sync_wallet", json!({}));
        assert_eq!(outcome["liquid"], json!("ok"), "sync: {outcome}");
        assert_eq!(outcome["btc"], json!("ok"), "sync: {outcome}");
    }

    /// Balance of `asset_id` (base units) after a sync; 0 when absent.
    fn balance(&mut self, asset_id: &str) -> i64 {
        self.sync();
        let dash = self.ok("get_wallet_summary", json!({}));
        dash["assets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["asset_id"] == json!(asset_id))
            .map(|a| a["amount"].as_i64().unwrap())
            .unwrap_or(0)
    }

    /// Syncs until `pred` holds on the balance of `asset_id` (Electrum
    /// indexes a new block a moment after it is mined).
    fn wait_balance(&mut self, asset_id: &str, what: &str, pred: impl Fn(i64) -> bool) -> i64 {
        for _ in 0..30 {
            let b = self.balance(asset_id);
            if pred(b) {
                return b;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        panic!("{what}: balance of {asset_id} never satisfied the check");
    }
}

fn lab_http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap()
}

fn lab_post(url: &str, body: Value) -> Value {
    let resp = lab_http().post(url).json(&body).send().unwrap();
    let status = resp.status();
    let v: Value = resp.json().unwrap_or(Value::Null);
    assert!(status.is_success(), "POST {url} → {status}: {v}");
    v
}

fn lab_get(url: &str) -> Value {
    lab_http().get(url).send().unwrap().json().unwrap()
}

/// LiquiDEX end to end on a running Templar testlab (and its order book),
/// through nothing but the test-server profile: two fresh software
/// wallets join the lab, get coins from its public faucet, A makes and
/// publishes an offer, B finds it in `list_markets`, verifies it deep,
/// previews and takes it, both balances move, the book's watcher closes it;
/// then A makes a second offer and cancels it, and neither offer can be
/// taken again. See docs/guides/LIVE_TESTS.md.
#[test]
#[ignore = "needs a running Templar testlab with its order book (TEMPLAR_LIVE_TESTLAB_URL)"]
fn live_testlab_liquidex_make_publish_take_cancel() {
    let lab = std::env::var("TEMPLAR_LIVE_TESTLAB_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8096".to_string());
    let lab = lab.trim_end_matches('/').to_string();
    let config = lab_get(&format!("{lab}/api/config"));
    let regtest = &config["networks"]["liquid-regtest"];
    let lbtc = regtest["policy_asset"].as_str().unwrap().to_string();
    let book = config["orderbook_url"].as_str().unwrap().to_string();
    // The asset A offers: TEMPLAR_LIVE_TESTLAB_ASSET, else a lab asset its
    // faucet lists (the lab keeps paying those), else the lab's newest (a
    // smoke-test token may be spent out).
    let asset = std::env::var("TEMPLAR_LIVE_TESTLAB_ASSET").unwrap_or_else(|_| {
        let listed = regtest["faucet"].as_array().and_then(|list| {
            list.iter()
                .find(|a| {
                    a["network"] == json!("liquid-regtest")
                        && a["asset"] != json!("lbtc")
                        && a["asset_id"].is_string()
                })
                .map(|a| a["asset_id"].as_str().unwrap().to_string())
        });
        listed.unwrap_or_else(|| {
            let assets = lab_get(&format!("{lab}/api/assets"));
            assets["assets"]
                .as_array()
                .unwrap()
                .last()
                .expect("the lab has issued an asset")["asset_id"]
                .as_str()
                .unwrap()
                .to_string()
        })
    });
    let mine = |n: u32| {
        lab_post(
            &format!("{lab}/admin/api/mine"),
            json!({ "chain": "liquid", "blocks": n }),
        );
    };
    let mine_bitcoin = |n: u32| {
        lab_post(
            &format!("{lab}/admin/api/mine"),
            json!({ "chain": "bitcoin", "blocks": n }),
        );
    };
    // Funding goes through the lab's admin API (open on loopback without a
    // password): the public faucet's limits (per client, per address, per
    // request, a shared budget) are for testers, and it no longer mines a
    // block per payment. Blocks are mined explicitly below.
    let admin_pay = |network: &str, address: &str, asset: &str, amount: &str| {
        let r = lab_post(
            &format!("{lab}/admin/api/send"),
            json!({ "network": network, "address": address, "asset": asset, "amount": amount }),
        );
        eprintln!(
            "[live] admin send {amount} {asset} → {address}: {}",
            r["txid"]
        );
    };

    let mut a = LabWallet::join(&lab, "Live maker");
    let mut b = LabWallet::join(&lab, "Live taker");
    let v = a.env.ok("get_test_server", json!({ "check": true }));
    assert_eq!(v["check"]["stale"], json!(false), "{v}");
    assert_eq!(v["active"]["liquid"]["policy_asset"], json!(lbtc));
    assert_eq!(
        v["active"]["orderbook"]["publish"]["url"],
        json!(format!("{book}/api/offers"))
    );

    let a_lbtc_addr = a.address("LBTC");
    let a_asset_addr = a.address("LBTC");
    let b_lbtc_addr = b.address("LBTC");
    let b_btc_addr = b.address("BTC");
    assert!(a_lbtc_addr.starts_with("el1"), "{a_lbtc_addr}");
    assert!(b_btc_addr.starts_with("bcrt1"), "{b_btc_addr}");
    admin_pay("liquid-regtest", &a_lbtc_addr, "lbtc", "0.1");
    admin_pay("liquid-regtest", &a_asset_addr, &asset, "1000");
    admin_pay("liquid-regtest", &b_lbtc_addr, "lbtc", "0.5");
    // Admin API, not the public faucet: its per-client limit is shared by
    // everyone on this host (`live_testlab_wallet_funds_itself_from_the_faucet`
    // covers the faucet).
    admin_pay("bitcoin-regtest", &b_btc_addr, "btc", "0.01");
    mine(1);
    mine_bitcoin(1);
    a.wait_balance(&lbtc, "A funded", |x| x == 10_000_000);
    let a_asset_start = a.wait_balance(&asset, "A asset", |x| x > 0);
    b.wait_balance(&lbtc, "B funded", |x| x == 50_000_000);
    // Bitcoin regtest through the lab's Electrum.
    b.sync();
    let dash = b.ok("get_wallet_summary", json!({}));
    eprintln!("[live] B summary assets: {}", dash["assets"]);

    // ── Make: an exact 500.00-unit coin, offered for 0.05 L-BTC ─────────
    const OFFER: i64 = 50_000;
    const PRICE: i64 = 5_000_000;
    let prep = a.ok(
        "swap_make_prepare",
        json!({ "asset_id": asset, "amount_sats": OFFER }),
    );
    eprintln!("[live] make_prepare txid {prep}");
    mine(1);
    let utxo = {
        let mut found = None;
        for _ in 0..30 {
            a.sync();
            let utxos = a.ok("list_utxos", json!({ "chain": "liquid" }));
            found = utxos.as_array().unwrap().iter().find_map(|u| {
                (u["asset_id"] == json!(asset)
                    && u["amount"] == json!(OFFER)
                    && u["outpoint"]
                        .as_str()
                        .unwrap()
                        .starts_with(prep.as_str().unwrap()))
                .then(|| u["outpoint"].as_str().unwrap().to_string())
            });
            if found.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        found.expect("the prepared coin")
    };
    let offer = a.ok(
        "swap_make",
        json!({ "utxo": utxo, "want_asset_id": lbtc, "want_amount_sats": PRICE }),
    );
    let proposal = offer["proposal_json"].as_str().unwrap().to_string();
    let book_id = a.env.ok(
        "swap_publish",
        json!({ "proposal_json": proposal, "note": "live test" }),
    );
    eprintln!("[live] published as book offer {book_id}");
    // The same proposal again is a duplicate.
    let dup = a
        .env
        .err("swap_publish", json!({ "proposal_json": proposal }));
    assert!(dup.starts_with("BOOK_DUPLICATE:"), "{dup}");

    // ── Take ───────────────────────────────────────────────────────────
    let markets = b.env.ok("list_markets", json!({}));
    let row = markets
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["proposal_json"] == json!(proposal))
        .unwrap_or_else(|| panic!("offer not in list_markets: {markets}"))
        .clone();
    assert_eq!(row["verified"], json!(true), "{row}");
    assert_eq!(row["takeable"], json!(true), "{row}");
    let analysis = b.env.ok(
        "swap_verify",
        json!({ "proposal_json": proposal, "deep": true }),
    );
    assert_eq!(analysis["valid"], json!(true), "{analysis}");
    assert_eq!(analysis["takeable"], json!(true), "{analysis}");
    assert_eq!(analysis["network"], json!("regtest"), "{analysis}");
    let preview = b.ok("swap_take_preview", json!({ "proposal_json": proposal }));
    eprintln!("[live] take preview: {preview}");
    assert_eq!(preview["you_receive"]["amount_sats"], json!(OFFER));
    assert_eq!(preview["you_pay"]["amount_sats"], json!(PRICE));
    let fee = preview["fee_sats"].as_i64().unwrap();
    let take_txid = b.ok("swap_take", json!({ "proposal_json": proposal }));
    eprintln!("[live] take txid {take_txid}");
    mine(1);

    b.wait_balance(&asset, "B received the asset", |x| x == OFFER);
    let b_lbtc = b.wait_balance(&lbtc, "B paid", |x| x < 50_000_000);
    assert!(
        b_lbtc <= 50_000_000 - PRICE - fee + 10 && b_lbtc >= 50_000_000 - PRICE - fee - 10,
        "B L-BTC {b_lbtc}, fee {fee}"
    );
    a.wait_balance(&asset, "A gave the asset", |x| x == a_asset_start - OFFER);
    let a_lbtc = a.wait_balance(&lbtc, "A was paid", |x| x > 10_000_000);
    assert!(a_lbtc > 10_000_000 + PRICE - 5_000, "A L-BTC {a_lbtc}");
    eprintln!(
        "[live] after the take: A L-BTC {a_lbtc}, asset {}; B L-BTC {b_lbtc}, asset {OFFER}; \
         taker fee {fee}",
        a_asset_start - OFFER
    );

    // A taken offer cannot be taken again.
    let again = b.err("swap_take", json!({ "proposal_json": proposal }));
    eprintln!("[live] retake refused: {again}");
    assert!(again.contains("already spent"), "{again}");
    let mine_offers = a.ok("list_my_offers", json!({}));
    let first = mine_offers
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["proposal_json"] == json!(proposal))
        .unwrap();
    assert_eq!(first["status"], json!("closed"), "{first}");

    // ── Cancel: a second offer on the other half of the asset ──────────
    let utxos = a.ok("list_utxos", json!({ "chain": "liquid" }));
    let rest = utxos
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["asset_id"] == json!(asset))
        .expect("A keeps some of the asset")["outpoint"]
        .as_str()
        .unwrap()
        .to_string();
    let second = a.ok(
        "swap_make",
        json!({ "utxo": rest, "want_asset_id": lbtc, "want_amount_sats": PRICE }),
    );
    let second_json = second["proposal_json"].as_str().unwrap().to_string();
    let second_id = a
        .env
        .ok("swap_publish", json!({ "proposal_json": second_json }));
    eprintln!("[live] second offer published as {second_id}");
    let cancel_txid = a.ok("swap_cancel", json!({ "offer_id": second["offer_id"] }));
    eprintln!("[live] cancel txid {cancel_txid}");
    mine(1);
    a.wait_balance(&asset, "A still holds the cancelled coin", |x| {
        x == a_asset_start - OFFER
    });
    let refused = b.err("swap_take", json!({ "proposal_json": second_json }));
    eprintln!("[live] cancelled offer refused: {refused}");
    assert!(refused.contains("already spent"), "{refused}");
    let mine_offers = a.ok("list_my_offers", json!({}));
    let cancelled = mine_offers
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["offer_id"] == second["offer_id"])
        .unwrap();
    assert_eq!(cancelled["status"], json!("cancelled"));

    // ── The book's watcher closes both offers (it runs every minute) ───
    let status_of = |id: &Value| -> String {
        let rows = lab_get(&format!("{book}/api/markets?network=liquid-regtest&all"));
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| {
                r["source_id"] == *id
                    && r["settlement"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("liquidex"))
            })
            .map(|r| r["status"].as_str().unwrap_or("").to_string())
            .unwrap_or_default()
    };
    let mut closed = (String::new(), String::new());
    for _ in 0..40 {
        closed = (status_of(&book_id), status_of(&second_id));
        if ![&closed.0, &closed.1]
            .iter()
            .any(|s| s.is_empty() || s.as_str() == "open")
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    eprintln!("[live] book statuses after the watcher: {closed:?}");
    // `filled` or `cancelled` (on regtest the book cannot see who spent a
    // coin, so a taken offer reads `cancelled` too).
    for (what, status) in [("taken", &closed.0), ("cancelled", &closed.1)] {
        assert!(
            status == "filled" || status == "cancelled",
            "{what} offer is {status:?} in the book"
        );
    }
    let rows = b.env.ok("list_markets", json!({}));
    assert!(
        !rows
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["proposal_json"] == json!(proposal)
                || r["proposal_json"] == json!(second_json)),
        "closed offers must leave the open book"
    );
}

/// The running lab's base URL (`TEMPLAR_LIVE_TESTLAB_URL`, default the
/// local one) and its `/api/config`.
fn live_lab() -> (String, Value) {
    let lab = std::env::var("TEMPLAR_LIVE_TESTLAB_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8096".to_string());
    let lab = lab.trim_end_matches('/').to_string();
    let config = lab_get(&format!("{lab}/api/config"));
    (lab, config)
}

fn live_mine(lab: &str, chain: &str) {
    lab_post(
        &format!("{lab}/admin/api/mine"),
        json!({ "chain": chain, "blocks": 1 }),
    );
}

/// A fresh wallet funds itself from the lab's public faucet with
/// `test_server_faucet`: regtest BTC and L-BTC, each at a fresh address of
/// its own, each the amount the faucet reports. Needs a lab whose
/// `/api/config` lists its faucet (`networks["liquid-regtest"].faucet`);
/// skips, saying so, on an older lab. See docs/guides/LIVE_TESTS.md.
#[test]
#[ignore = "needs a running Templar testlab whose /api/config lists its faucet (TEMPLAR_LIVE_TESTLAB_URL)"]
fn live_testlab_wallet_funds_itself_from_the_faucet() {
    let (lab, config) = live_lab();
    let regtest = &config["networks"]["liquid-regtest"];
    if !regtest["faucet"].is_array() {
        eprintln!(
            "[live] SKIPPED: {lab}/api/config has no `faucet` list (an older lab); \
             test_server_faucet was not exercised"
        );
        return;
    }
    let lbtc = regtest["policy_asset"].as_str().unwrap().to_string();
    let mut w = LabWallet::join(&lab, "Live faucet");
    let ts = w.env.ok("get_test_server", json!({}));
    eprintln!("[live] faucet: {}", ts["faucet"]);
    assert_eq!(ts["faucet"]["assets_source"], json!("profile"), "{ts}");
    assert_eq!(ts["faucet"]["available"], json!(true), "{ts}");

    // The lab's per-client limit (10 requests an hour) is shared by every
    // tester on this host: a refusal for it is the engine's tag, checked,
    // and the payment itself cannot be tested now.
    let first = w.env.call(
        "test_server_faucet",
        json!({ "wallet_id": w.id, "asset": "lbtc" }),
    );
    if let Some(err) = first["err"].as_str() {
        assert!(err.starts_with("FAUCET_RATE_LIMITED: "), "{err}");
        eprintln!(
            "[live] SKIPPED: the lab's faucet refused this client for its limit ({err}); \
             the tag was checked, the payment was not exercised"
        );
        return;
    }
    let lbtc_paid = first["ok"].clone();
    eprintln!("[live] faucet L-BTC: {lbtc_paid}");
    assert_eq!(lbtc_paid["network"], json!("liquid-regtest"));
    assert!(lbtc_paid["address"].as_str().unwrap().starts_with("el1"));
    let btc_paid = w.ok("test_server_faucet", json!({ "asset": "btc" }));
    eprintln!("[live] faucet BTC: {btc_paid}");
    assert_eq!(btc_paid["network"], json!("bitcoin-regtest"));
    assert!(btc_paid["address"].as_str().unwrap().starts_with("bcrt1"));
    live_mine(&lab, "liquid");
    live_mine(&lab, "bitcoin");

    let want_lbtc = lbtc_paid["amount_sat"].as_i64().unwrap();
    w.wait_balance(&lbtc, "the faucet's L-BTC", |x| x == want_lbtc);
    let want_btc = btc_paid["amount_sat"].as_i64().unwrap();
    w.wait_balance("BTC", "the faucet's BTC", |x| x == want_btc);
    // Never on testnet.
    w.env
        .ok("set_liquid_network", json!({ "network": "testnet" }));
    let err = w.err("test_server_faucet", json!({ "asset": "lbtc" }));
    assert!(err.starts_with("FAUCET_UNAVAILABLE:"), "{err}");
}

/// A token issued on the lab is named for everyone, not only its issuer:
/// A issues it with no domain (regtest), the engine announces it to the
/// order book's registry (`book_registered`), A offers 100.00 of it; a
/// second wallet sees the ticker and precision in `list_markets`, in the
/// take preview and, after taking it, in its own summary, all marked
/// `metadata_source: "book"`. Needs an order book with `/api/assets`;
/// skips, saying so, without one. See docs/guides/LIVE_TESTS.md.
#[test]
#[ignore = "needs a running Templar testlab whose order book has /api/assets (TEMPLAR_LIVE_TESTLAB_URL)"]
fn live_testlab_registered_token_is_named_for_another_wallet() {
    let (lab, config) = live_lab();
    let lbtc = config["networks"]["liquid-regtest"]["policy_asset"]
        .as_str()
        .unwrap()
        .to_string();
    let book = config["orderbook_url"].as_str().unwrap().to_string();
    let registry = lab_http()
        .get(format!("{book}/api/assets?network=liquid-regtest"))
        .send()
        .map(|r| r.status().as_u16())
        .unwrap_or(0);
    if registry != 200 {
        eprintln!(
            "[live] SKIPPED: {book}/api/assets answered {registry} (an order book without \
             the registry); the announcement and the names were not exercised"
        );
        return;
    }
    let admin_pay = |address: &str, amount: &str| {
        let r = lab_post(
            &format!("{lab}/admin/api/send"),
            json!({ "network": "liquid-regtest", "address": address, "asset": "lbtc",
                    "amount": amount }),
        );
        eprintln!(
            "[live] admin send {amount} L-BTC → {address}: {}",
            r["txid"]
        );
    };
    let mut a = LabWallet::join(&lab, "Live registry issuer");
    let mut b = LabWallet::join(&lab, "Live registry buyer");
    let a_addr = a.address("LBTC");
    let b_addr = b.address("LBTC");
    admin_pay(&a_addr, "0.01");
    admin_pay(&b_addr, "0.2");
    live_mine(&lab, "liquid");
    a.wait_balance(&lbtc, "A funded", |x| x == 1_000_000);
    b.wait_balance(&lbtc, "B funded", |x| x == 20_000_000);

    // A ticker of its own: tickers are unique per network on a book.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let ticker = format!("RT{:06X}", nanos & 0xff_ffff);
    let issued = a.ok(
        "issue_asset",
        json!({ "name": "Registry Token", "ticker": ticker, "precision": 2,
                "amount_sats": 1_000_000, "reissuance_tokens": 0 }),
    );
    eprintln!("[live] issue_asset: {issued}");
    assert_eq!(issued["domain"], json!("regtest.templar.test"), "{issued}");
    assert_eq!(issued["proof_url"], json!(""), "{issued}");
    assert_eq!(issued["book_registered"], json!(true), "{issued}");
    let token = issued["asset_id"].as_str().unwrap().to_string();
    live_mine(&lab, "liquid");
    a.wait_balance(&token, "A issued", |x| x == 1_000_000);
    // Announcing again is idempotent.
    let again = a.ok(
        "reregister_asset",
        json!({ "asset_id": token, "name": "Registry Token", "ticker": ticker,
                "precision": 2 }),
    );
    eprintln!("[live] reregister_asset: {again}");
    assert_eq!(again["book_registered"], json!(true), "{again}");
    assert_eq!(
        again["registered"],
        json!(false),
        "no public registry on regtest"
    );

    // A offers 100.00 of it for 0.01 L-BTC.
    const OFFER: i64 = 10_000;
    let prep = a.ok(
        "swap_make_prepare",
        json!({ "asset_id": token, "amount_sats": OFFER }),
    );
    live_mine(&lab, "liquid");
    let utxo = {
        let mut found = None;
        for _ in 0..30 {
            a.sync();
            let utxos = a.ok("list_utxos", json!({ "chain": "liquid" }));
            found = utxos.as_array().unwrap().iter().find_map(|u| {
                (u["asset_id"] == json!(token)
                    && u["amount"] == json!(OFFER)
                    && u["outpoint"]
                        .as_str()
                        .unwrap()
                        .starts_with(prep.as_str().unwrap()))
                .then(|| u["outpoint"].as_str().unwrap().to_string())
            });
            if found.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        found.expect("the prepared coin")
    };
    let offer = a.ok(
        "swap_make",
        json!({ "utxo": utxo, "want_asset_id": lbtc, "want_amount_sats": 1_000_000 }),
    );
    let proposal = offer["proposal_json"].as_str().unwrap().to_string();
    a.env
        .ok("swap_publish", json!({ "proposal_json": proposal }));

    // B: the market row, the preview and its own summary name the token.
    let markets = b.env.ok("list_markets", json!({}));
    let row = markets
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["proposal_json"] == json!(proposal))
        .unwrap_or_else(|| panic!("offer not in list_markets: {markets}"))
        .clone();
    eprintln!("[live] B's market row: {}", row["maker_gives"]);
    assert_eq!(row["maker_gives"]["ticker"], json!(ticker));
    assert_eq!(row["maker_gives"]["precision"], json!(2));
    assert_eq!(row["maker_gives"]["display_amount"], json!("100.00"));
    assert_eq!(row["maker_gives"]["metadata_source"], json!("book"));
    let preview = b.ok("swap_take_preview", json!({ "proposal_json": proposal }));
    assert_eq!(preview["you_receive"]["ticker"], json!(ticker), "{preview}");
    assert_eq!(preview["you_receive"]["display_amount"], json!("100.00"));
    let take = b.ok("swap_take", json!({ "proposal_json": proposal }));
    eprintln!("[live] take txid {take}");
    live_mine(&lab, "liquid");
    b.wait_balance(&token, "B received the token", |x| x == OFFER);
    let dash = b.ok("get_wallet_summary", json!({}));
    let held = dash["assets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["asset_id"] == json!(token))
        .cloned()
        .expect("B's token row");
    eprintln!("[live] B's summary row: {held}");
    assert_eq!(held["ticker"], json!(ticker));
    assert_eq!(held["name"], json!("Registry Token"));
    assert_eq!(held["precision"], json!(2));
    assert_eq!(held["display_amount"], json!("100.00"));
    assert_eq!(held["metadata_source"], json!("book"));
}

/// A wallet issues its own token on a running Templar testlab and sells
/// part of it on LiquiDEX for L-BTC; then reissues and burns some. The
/// owner's manual test in the app, through the engine: two fresh software
/// wallets join the lab, A gets L-BTC for fees and B L-BTC to pay (admin
/// API); A issues "Templar Token" (`TMPL`, precision 2) with one
/// reissuance token, prepares an exact 100.00 TMPL coin, offers it for
/// 0.05 L-BTC and publishes it; B finds it in `list_markets`, verifies it
/// deep, previews and takes it; both balances move by exactly the offer and
/// the price; the book closes the offer; A reissues and burns. See
/// docs/guides/LIVE_TESTS.md.
#[test]
#[ignore = "needs a running Templar testlab with its order book (TEMPLAR_LIVE_TESTLAB_URL)"]
fn live_testlab_issue_token_and_sell_for_lbtc() {
    let lab = std::env::var("TEMPLAR_LIVE_TESTLAB_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8096".to_string());
    let lab = lab.trim_end_matches('/').to_string();
    let config = lab_get(&format!("{lab}/api/config"));
    let lbtc = config["networks"]["liquid-regtest"]["policy_asset"]
        .as_str()
        .unwrap()
        .to_string();
    let book = config["orderbook_url"].as_str().unwrap().to_string();
    let mine = || {
        lab_post(
            &format!("{lab}/admin/api/mine"),
            json!({ "chain": "liquid", "blocks": 1 }),
        );
    };
    let admin_pay = |address: &str, amount: &str| {
        let r = lab_post(
            &format!("{lab}/admin/api/send"),
            json!({ "network": "liquid-regtest", "address": address, "asset": "lbtc",
                    "amount": amount }),
        );
        eprintln!(
            "[live] admin send {amount} L-BTC → {address}: {}",
            r["txid"]
        );
    };
    // The summary row of `asset_id` (null when absent), after a sync.
    let summary_row = |w: &mut LabWallet, asset_id: &str| -> Value {
        w.sync();
        let dash = w.ok("get_wallet_summary", json!({}));
        dash["assets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["asset_id"] == json!(asset_id))
            .cloned()
            .unwrap_or(Value::Null)
    };

    let mut a = LabWallet::join(&lab, "Live issuer");
    let mut b = LabWallet::join(&lab, "Live buyer");
    let a_addr = a.address("LBTC");
    let b_addr = b.address("LBTC");
    admin_pay(&a_addr, "0.01");
    admin_pay(&b_addr, "0.5");
    mine();
    a.wait_balance(&lbtc, "A funded", |x| x == 1_000_000);
    b.wait_balance(&lbtc, "B funded", |x| x == 50_000_000);

    // ── Issue: 10 000.00 TMPL and one reissuance token ─────────────────
    const SUPPLY: i64 = 1_000_000;
    let issued = a.ok(
        "issue_asset",
        json!({
            "name": "Templar Token",
            "ticker": "TMPL",
            "precision": 2,
            "domain": "templar.red",
            "amount_sats": SUPPLY,
            "reissuance_tokens": 1,
        }),
    );
    eprintln!("[live] issue_asset: {issued}");
    assert_keys(
        "issue_asset",
        &issued,
        &[
            "asset_id",
            "token_id",
            "txid",
            "registry_registered",
            "proof_url",
            "proof_content",
        ],
    );
    // No public registry on regtest: not attempted. The order book's
    // registry is asked (best-effort): `book_registered`, or `book_error`
    // on a book without one.
    assert_eq!(issued["registry_registered"], json!(false), "{issued}");
    assert!(issued["book_registered"].is_boolean(), "{issued}");
    assert_eq!(issued["proof_url"], json!(""), "no domain proof on regtest");
    let tmpl = issued["asset_id"].as_str().unwrap().to_string();
    let token = issued["token_id"]
        .as_str()
        .expect("a reissuance token")
        .to_string();
    mine();
    a.wait_balance(&tmpl, "A issued", |x| x == SUPPLY);
    a.wait_balance(&token, "A holds the reissuance token", |x| x == 1);
    let a_row = summary_row(&mut a, &tmpl);
    eprintln!("[live] A's TMPL row: {a_row}");
    assert_eq!(a_row["ticker"], json!("TMPL"), "{a_row}");
    assert_eq!(a_row["name"], json!("Templar Token"), "{a_row}");
    assert_eq!(a_row["display_amount"], json!("10000.00"), "{a_row}");
    eprintln!("[live] A's token row: {}", summary_row(&mut a, &token));
    let a_lbtc_issued = a.balance(&lbtc);
    eprintln!(
        "[live] A L-BTC after the issuance: {a_lbtc_issued} (fee {})",
        1_000_000 - a_lbtc_issued
    );

    // ── Make: an exact 100.00 TMPL coin, offered for 0.05 L-BTC ─────────
    const OFFER: i64 = 10_000;
    const PRICE: i64 = 5_000_000;
    let prep = a.ok(
        "swap_make_prepare",
        json!({ "asset_id": tmpl, "amount_sats": OFFER }),
    );
    eprintln!("[live] make_prepare txid {prep}");
    mine();
    let utxo = {
        let mut found = None;
        for _ in 0..30 {
            a.sync();
            let utxos = a.ok("list_utxos", json!({ "chain": "liquid" }));
            found = utxos.as_array().unwrap().iter().find_map(|u| {
                (u["asset_id"] == json!(tmpl)
                    && u["amount"] == json!(OFFER)
                    && u["outpoint"]
                        .as_str()
                        .unwrap()
                        .starts_with(prep.as_str().unwrap()))
                .then(|| u["outpoint"].as_str().unwrap().to_string())
            });
            if found.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        found.expect("the prepared coin")
    };
    let a_tmpl_before = a.balance(&tmpl);
    let a_lbtc_before = a.balance(&lbtc);
    assert_eq!(a_tmpl_before, SUPPLY, "a preparation keeps the supply");
    eprintln!(
        "[live] A before the take: L-BTC {a_lbtc_before} (preparation fee {}), TMPL {a_tmpl_before}",
        a_lbtc_issued - a_lbtc_before
    );
    let offer = a.ok(
        "swap_make",
        json!({ "utxo": utxo, "want_asset_id": lbtc, "want_amount_sats": PRICE }),
    );
    let proposal = offer["proposal_json"].as_str().unwrap().to_string();
    let book_id = a.env.ok(
        "swap_publish",
        json!({ "proposal_json": proposal, "note": "Templar Token live test" }),
    );
    eprintln!("[live] published as book offer {book_id}");

    // ── How the offer is named: B's market feed and the book ───────────
    let markets = b.env.ok("list_markets", json!({}));
    let row = markets
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["proposal_json"] == json!(proposal))
        .unwrap_or_else(|| panic!("offer not in list_markets: {markets}"))
        .clone();
    eprintln!(
        "[live] B's list_markets row: gives {} wants {} price {} verified {} takeable {}",
        row["maker_gives"],
        row["maker_wants"],
        row["price_display"],
        row["verified"],
        row["takeable"]
    );
    assert_eq!(row["verified"], json!(true), "{row}");
    assert_eq!(row["takeable"], json!(true), "{row}");
    assert_eq!(row["maker_gives"]["asset_id"], json!(tmpl), "{row}");
    assert_eq!(row["maker_gives"]["amount_sats"], json!(OFFER), "{row}");
    assert_eq!(row["maker_wants"]["amount_sats"], json!(PRICE), "{row}");
    let book_rows = lab_get(&format!("{book}/api/book?network=liquid-regtest"));
    let entry = &book_rows[book_id.to_string().trim_matches('"')];
    eprintln!(
        "[live] /api/book entry {book_id}: input {} output {}",
        entry["input"], entry["output"]
    );
    assert_eq!(entry["input"][0]["asset"], json!(tmpl), "{entry}");

    // ── Take ───────────────────────────────────────────────────────────
    let analysis = b.env.ok(
        "swap_verify",
        json!({ "proposal_json": proposal, "deep": true }),
    );
    assert_eq!(analysis["valid"], json!(true), "{analysis}");
    assert_eq!(analysis["takeable"], json!(true), "{analysis}");
    assert_eq!(analysis["network"], json!("regtest"), "{analysis}");
    let preview = b.ok("swap_take_preview", json!({ "proposal_json": proposal }));
    eprintln!("[live] take preview: {preview}");
    assert_eq!(preview["you_receive"]["asset_id"], json!(tmpl));
    assert_eq!(preview["you_receive"]["amount_sats"], json!(OFFER));
    assert_eq!(preview["you_pay"]["amount_sats"], json!(PRICE));
    let fee = preview["fee_sats"].as_i64().unwrap();
    let take_txid = b.ok("swap_take", json!({ "proposal_json": proposal }));
    eprintln!("[live] take txid {take_txid}");
    mine();

    b.wait_balance(&tmpl, "B received TMPL", |x| x == OFFER);
    let b_lbtc = b.wait_balance(&lbtc, "B paid", |x| x < 50_000_000);
    eprintln!(
        "[live] B paid {} (price {PRICE} + preview fee {fee})",
        50_000_000 - b_lbtc
    );
    assert!(
        (50_000_000 - PRICE - fee - b_lbtc).abs() <= 10,
        "B L-BTC {b_lbtc}, fee {fee}"
    );
    a.wait_balance(&tmpl, "A gave TMPL", |x| x == a_tmpl_before - OFFER);
    let a_lbtc = a.wait_balance(&lbtc, "A was paid", |x| x > a_lbtc_before);
    assert_eq!(a_lbtc, a_lbtc_before + PRICE, "A is paid exactly the price");
    let b_row = summary_row(&mut b, &tmpl);
    eprintln!("[live] B's TMPL row: {b_row}");
    eprintln!(
        "[live] after the take: A L-BTC {a_lbtc}, TMPL {}; B L-BTC {b_lbtc}, TMPL {OFFER}",
        a_tmpl_before - OFFER
    );

    // ── Reissue 5 000.00 TMPL, then burn 10.00 ─────────────────────────
    const REISSUE: i64 = 500_000;
    const BURN: i64 = 1_000;
    let reissued = a.ok(
        "reissue_asset",
        json!({ "asset_id": tmpl, "amount_sats": REISSUE }),
    );
    eprintln!("[live] reissue_asset: {reissued}");
    assert_eq!(reissued["asset_id"], json!(tmpl), "{reissued}");
    mine();
    let after_reissue = SUPPLY - OFFER + REISSUE;
    a.wait_balance(&tmpl, "A reissued", |x| x == after_reissue);
    a.wait_balance(&token, "A keeps the reissuance token", |x| x == 1);
    let a_lbtc_reissued = a.balance(&lbtc);
    eprintln!(
        "[live] after the reissuance: TMPL {after_reissue}, L-BTC {a_lbtc_reissued} (fee {})",
        a_lbtc - a_lbtc_reissued
    );

    let burn_txid = a.ok(
        "burn_asset",
        json!({ "asset_id": tmpl, "amount_sats": BURN }),
    );
    eprintln!("[live] burn txid {burn_txid}");
    mine();
    a.wait_balance(&tmpl, "A burned", |x| x == after_reissue - BURN);
    let a_lbtc_burned = a.balance(&lbtc);
    eprintln!(
        "[live] after the burn: TMPL {}, L-BTC {a_lbtc_burned} (fee {})",
        after_reissue - BURN,
        a_lbtc_reissued - a_lbtc_burned
    );

    // ── The book's watcher closes the taken offer (every minute) ───────
    let mut status = String::new();
    for _ in 0..40 {
        let rows = lab_get(&format!("{book}/api/markets?network=liquid-regtest&all"));
        status = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                r["source_id"] == book_id
                    && r["settlement"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("liquidex"))
            })
            .map(|r| r["status"].as_str().unwrap_or("").to_string())
            .unwrap_or_default();
        if !status.is_empty() && status != "open" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    eprintln!("[live] book status after the watcher: {status:?}");
    // On regtest the book cannot see who spent a coin: `cancelled` too.
    assert!(
        status == "filled" || status == "cancelled",
        "taken offer is {status:?} in the book"
    );
}

// ── Live: LiquiDEX on public Liquid testnet ────────────────────────

/// The public Liquid testnet faucet (liquidtestnet.com, OpenAPI at
/// `/openapi.json`): `action=lbtc` pays 100 000 sats of L-BTC,
/// `action=test` 5 000 base units of its TEST asset; 3 requests a minute.
const TESTNET_FAUCET: &str = "https://liquidtestnet.com/api/faucet";
/// The faucet's TEST asset, registered in Blockstream's asset registry.
const TESTNET_FAUCET_ASSET: &str =
    "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";
const TESTNET_EXPLORER_TX: &str = "https://blockstream.info/liquidtestnet/tx/";
/// Liquid testnet makes a block about every minute: poll every 15 s.
const TESTNET_POLL: std::time::Duration = std::time::Duration::from_secs(15);
/// How long one wait for a confirmation may take (a slow block, a busy
/// public Electrum).
const TESTNET_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// One faucet request, never retried: the faucet's coins and its rate
/// limit are shared by everyone. Only throwaway addresses go to it.
fn testnet_faucet(address: &str, action: &str) -> String {
    let url = format!("{TESTNET_FAUCET}?address={address}&action={action}");
    let resp = lab_http()
        .get(&url)
        .send()
        .unwrap_or_else(|e| panic!("the testnet faucet cannot be reached: {e}"));
    let status = resp.status();
    let v: Value = resp.json().unwrap_or(Value::Null);
    let txid = v["txid"].as_str().unwrap_or_default().to_string();
    assert!(
        status.is_success() && txid.len() == 64,
        "the testnet faucet refused {action} (HTTP {status}): {v}; not retried"
    );
    eprintln!("[live] faucet {action} → {address}: {TESTNET_EXPLORER_TX}{txid}");
    txid
}

/// One faucet payment of `action` to a fresh address of `w`, waited for
/// until it is confirmed in `w`.
fn testnet_fund(w: &mut LabWallet, who: &str, action: &str, asset_id: &str) {
    let to = w.address("LBTC");
    let txid = testnet_faucet(&to, action);
    w.wait_coins(
        &format!("{who}: faucet {action} confirmed"),
        TESTNET_CONFIRM_TIMEOUT,
        |c| confirmed(coin_from(c, &txid, asset_id)),
    );
}

/// Sum of `asset_id` over `coins` with at least `min_conf` confirmations.
fn coin_sum(coins: &[Value], asset_id: &str, min_conf: u64) -> i64 {
    coins
        .iter()
        .filter(|c| c["asset_id"] == json!(asset_id))
        .filter(|c| c["confirmations"].as_u64().unwrap_or(0) >= min_conf)
        .map(|c| c["amount"].as_i64().unwrap())
        .sum()
}

/// The coin of `asset_id` that transaction `txid` paid this wallet, if any.
fn coin_from<'a>(coins: &'a [Value], txid: &str, asset_id: &str) -> Option<&'a Value> {
    coins.iter().find(|c| {
        c["asset_id"] == json!(asset_id)
            && c["outpoint"]
                .as_str()
                .is_some_and(|o| o.starts_with(&format!("{txid}:")))
    })
}

fn confirmed(coin: Option<&Value>) -> bool {
    coin.is_some_and(|c| c["confirmations"].as_u64().unwrap_or(0) >= 1)
}

impl LabWallet {
    /// A wallet on Liquid testnet: in a throwaway data directory, or, with
    /// `keep`, in `keep` (reopened when a previous run left it there, so a
    /// rerun spends what the faucet already paid).
    fn on_testnet(name: &str, keep: Option<PathBuf>) -> Self {
        let Some(dir) = keep else {
            return Self::create(TestEnv::new(), name);
        };
        let mut env = TestEnv::kept(dir);
        let wallets = env.ok("list_wallets", json!({}));
        let existing = wallets
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["name"] == json!(name))
            .and_then(|w| w["id"].as_str())
            .map(str::to_string);
        match existing {
            Some(id) => {
                eprintln!(
                    "[live] {name}: reusing the wallet kept in {}",
                    env.dir.display()
                );
                Self { env, id }
            }
            None => Self::create(env, name),
        }
    }

    /// The Liquid coins after a sync, or `None` when the Liquid sync failed
    /// (a public Electrum server has bad moments; the caller polls again).
    /// The Bitcoin side is synced too and ignored.
    fn liquid_coins(&mut self) -> Option<Vec<Value>> {
        let outcome = self.ok("sync_wallet", json!({}));
        if outcome["liquid"] != json!("ok") {
            eprintln!("[live] Liquid sync: {}", outcome["liquid"]);
            return None;
        }
        let coins = self.ok("list_utxos", json!({ "chain": "liquid" }));
        Some(coins.as_array().unwrap().clone())
    }

    /// Syncs every [`TESTNET_POLL`] until `pred` holds on the Liquid coins;
    /// panics after `timeout` or six failed syncs in a row. Prints how long
    /// it took.
    fn wait_coins(
        &mut self,
        what: &str,
        timeout: std::time::Duration,
        pred: impl Fn(&[Value]) -> bool,
    ) -> Vec<Value> {
        let start = std::time::Instant::now();
        let mut failures = 0;
        loop {
            match self.liquid_coins() {
                Some(coins) if pred(&coins) => {
                    eprintln!("[live] {what}: after {} s", start.elapsed().as_secs());
                    return coins;
                }
                Some(_) => failures = 0,
                None => {
                    failures += 1;
                    assert!(
                        failures < 6,
                        "{what}: the Liquid sync failed 6 times in a row"
                    );
                }
            }
            assert!(
                start.elapsed() < timeout,
                "{what}: not seen after {} s",
                start.elapsed().as_secs()
            );
            std::thread::sleep(TESTNET_POLL);
        }
    }
}

/// LiquiDEX end to end on public Liquid testnet with the local order book's
/// testnet book (`http://127.0.0.1:3210`, the engine's default with no test
/// server joined): two fresh software wallets, funded by the public faucet
/// (A: its TEST asset and L-BTC for fees; B: L-BTC); A prepares an exact
/// coin, makes and publishes an offer of TEST for L-BTC; B finds it in
/// `list_markets`, verifies it deep, previews and takes it; both wallets
/// see the trade (the maker sees the L-BTC it was paid); a second take is
/// refused; a second offer is published and cancelled and can no longer
/// be taken; the book's watcher marks the first `filled` and the second
/// `cancelled`. See docs/guides/LIVE_TESTS.md.
#[test]
#[ignore = "needs public Liquid testnet (faucet, Blockstream Electrum) and the local order book on 127.0.0.1:3210"]
fn live_testnet_liquidex_make_publish_take_cancel() {
    // The asset A offers, in base units, and the L-BTC it asks for.
    const OFFER: i64 = 2_000;
    const PRICE: i64 = 20_000;
    // What each side needs before the trade: A some L-BTC for the
    // preparation and cancel fees, B the price and its fee.
    const A_LBTC_MIN: i64 = 2_000;
    const B_LBTC_MIN: i64 = PRICE + 2_000;
    let keep = std::env::var("TEMPLAR_LIVE_TESTNET_DIR")
        .ok()
        .filter(|d| !d.is_empty())
        .map(PathBuf::from);
    let asset = TESTNET_FAUCET_ASSET;
    let tx_link = |txid: &str| format!("{TESTNET_EXPLORER_TX}{txid}");
    let run = std::time::Instant::now();

    let mut a = LabWallet::on_testnet("Live testnet maker", keep.as_ref().map(|d| d.join("maker")));
    let mut b = LabWallet::on_testnet("Live testnet taker", keep.as_ref().map(|d| d.join("taker")));
    // No test server, Liquid testnet: the defaults (local order book,
    // Blockstream's public Electrum).
    let v = a.env.ok("get_test_server", json!({}));
    assert_eq!(v["configured"], json!(false), "{v}");
    let active = &v["active"];
    assert_eq!(active["liquid_network"], json!("liquid-testnet"), "{v}");
    let lbtc = active["liquid"]["policy_asset"]
        .as_str()
        .unwrap()
        .to_string();
    let markets_url = active["orderbook"]["markets"]["url"]
        .as_str()
        .unwrap()
        .to_string();
    eprintln!(
        "[live] order book: publish {}, markets {markets_url}; Liquid backend {}",
        active["orderbook"]["publish"]["url"], active["liquid"]["backend_description"]
    );
    assert!(
        markets_url.starts_with("http://127.0.0.1:3210/"),
        "expected the local order book: {markets_url}"
    );

    // ── Fund: only what is missing (a kept wallet may hold enough) ──────
    // One faucet request at a time, each confirmed before the next: the
    // faucet spends its own unconfirmed change no sooner than the next
    // block, and a second request in the same block fails with
    // `InsufficientFunds`.
    let a_coins = a.wait_coins("A first sync", TESTNET_CONFIRM_TIMEOUT, |_| true);
    let b_coins = b.wait_coins("B first sync", TESTNET_CONFIRM_TIMEOUT, |_| true);
    if coin_sum(&a_coins, asset, 0) <= OFFER {
        testnet_fund(&mut a, "A", "test", asset);
    }
    if coin_sum(&a_coins, &lbtc, 0) < A_LBTC_MIN {
        testnet_fund(&mut a, "A", "lbtc", &lbtc);
    }
    if coin_sum(&b_coins, &lbtc, 0) < B_LBTC_MIN {
        testnet_fund(&mut b, "B", "lbtc", &lbtc);
    }
    // A kept wallet's coins may still be waiting for their block.
    let a_coins = a.wait_coins("A's funds confirmed", TESTNET_CONFIRM_TIMEOUT, |c| {
        coin_sum(c, asset, 1) > OFFER && coin_sum(c, &lbtc, 1) >= A_LBTC_MIN
    });
    let b_coins = b.wait_coins("B's funds confirmed", TESTNET_CONFIRM_TIMEOUT, |c| {
        coin_sum(c, &lbtc, 1) >= B_LBTC_MIN
    });
    let a_asset_start = coin_sum(&a_coins, asset, 0);
    let a_lbtc_start = coin_sum(&a_coins, &lbtc, 0);
    let b_lbtc_start = coin_sum(&b_coins, &lbtc, 0);
    let b_asset_start = coin_sum(&b_coins, asset, 0);
    eprintln!(
        "[live] funded: A {a_asset_start} TEST + {a_lbtc_start} L-BTC sats, \
         B {b_lbtc_start} L-BTC sats + {b_asset_start} TEST"
    );
    assert!(a_asset_start > OFFER, "A holds {a_asset_start} TEST");
    assert!(
        b_lbtc_start >= B_LBTC_MIN,
        "B holds {b_lbtc_start} L-BTC sats"
    );

    // ── Make: an exact coin of OFFER, offered for PRICE L-BTC ──────────
    let prep = a.ok(
        "swap_make_prepare",
        json!({ "asset_id": asset, "amount_sats": OFFER }),
    );
    let prep = prep.as_str().unwrap().to_string();
    eprintln!("[live] make_prepare: {}", tx_link(&prep));
    let coins = a.wait_coins("A's exact coin confirmed", TESTNET_CONFIRM_TIMEOUT, |c| {
        c.iter().any(|u| {
            u["asset_id"] == json!(asset)
                && u["amount"] == json!(OFFER)
                && u["outpoint"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{prep}:"))
                && u["confirmations"].as_u64().unwrap_or(0) >= 1
        })
    });
    let utxo = coins
        .iter()
        .find(|u| {
            u["asset_id"] == json!(asset)
                && u["amount"] == json!(OFFER)
                && u["outpoint"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{prep}:"))
        })
        .unwrap()["outpoint"]
        .as_str()
        .unwrap()
        .to_string();
    let a_lbtc_before = coin_sum(&coins, &lbtc, 0);
    eprintln!(
        "[live] preparation fee: {} sats",
        a_lbtc_start - a_lbtc_before
    );
    let offer = a.ok(
        "swap_make",
        json!({ "utxo": utxo, "want_asset_id": lbtc, "want_amount_sats": PRICE }),
    );
    let proposal = offer["proposal_json"].as_str().unwrap().to_string();
    let wire: Value = serde_json::from_str(&proposal).unwrap();
    assert!(
        wire["outputs"][0]["blinding_nonce"].is_string(),
        "the proposal carries the maker's blinding nonce: {}",
        wire["outputs"][0]
    );
    let published = std::time::Instant::now();
    let book_id = a.env.ok(
        "swap_publish",
        json!({ "proposal_json": proposal, "note": "templarlib live testnet test" }),
    );
    eprintln!(
        "[live] published as testnet book offer {book_id} (deep-verified by the book in {} ms)",
        published.elapsed().as_millis()
    );
    let dup = a
        .env
        .err("swap_publish", json!({ "proposal_json": proposal }));
    assert!(dup.starts_with("BOOK_DUPLICATE:"), "{dup}");

    // ── Take ───────────────────────────────────────────────────────────
    let markets = b.env.ok("list_markets", json!({}));
    let row = markets
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["proposal_json"] == json!(proposal))
        .unwrap_or_else(|| panic!("offer not in list_markets: {markets}"))
        .clone();
    eprintln!(
        "[live] B's market row: {} {} for {} {}, verified {}, takeable {}",
        row["maker_gives"]["display_amount"],
        row["maker_gives"]["ticker"],
        row["maker_wants"]["display_amount"],
        row["maker_wants"]["ticker"],
        row["verified"],
        row["takeable"]
    );
    assert_eq!(row["verified"], json!(true), "{row}");
    assert_eq!(row["takeable"], json!(true), "{row}");
    assert_eq!(row["maker_gives"]["asset_id"], json!(asset), "{row}");
    assert_eq!(row["maker_gives"]["amount_sats"], json!(OFFER), "{row}");
    assert_eq!(row["maker_wants"]["asset_id"], json!(lbtc), "{row}");
    assert_eq!(row["maker_wants"]["amount_sats"], json!(PRICE), "{row}");
    let analysis = b.env.ok(
        "swap_verify",
        json!({ "proposal_json": proposal, "deep": true }),
    );
    assert_eq!(analysis["valid"], json!(true), "{analysis}");
    assert_eq!(analysis["takeable"], json!(true), "{analysis}");
    assert_eq!(analysis["network"], json!("testnet"), "{analysis}");
    let preview = b.ok("swap_take_preview", json!({ "proposal_json": proposal }));
    eprintln!("[live] take preview: {preview}");
    assert_eq!(preview["you_receive"]["amount_sats"], json!(OFFER));
    assert_eq!(preview["you_pay"]["amount_sats"], json!(PRICE));
    let fee = preview["fee_sats"].as_i64().unwrap();
    let take_txid = b.ok("swap_take", json!({ "proposal_json": proposal }));
    let take_txid = take_txid.as_str().unwrap().to_string();
    eprintln!("[live] take: {}", tx_link(&take_txid));

    let b_coins = b.wait_coins("B's take confirmed", TESTNET_CONFIRM_TIMEOUT, |c| {
        confirmed(coin_from(c, &take_txid, asset))
    });
    let b_asset = coin_sum(&b_coins, asset, 0);
    let b_lbtc = coin_sum(&b_coins, &lbtc, 0);
    assert_eq!(b_asset, b_asset_start + OFFER, "B's TEST");
    assert!(
        (b_lbtc - (b_lbtc_start - PRICE - fee)).abs() <= 10,
        "B L-BTC {b_lbtc}, started {b_lbtc_start}, price {PRICE}, fee {fee}"
    );
    // The maker sees the L-BTC it was paid: the take's output to A is
    // blinded with the proposal's nonce, which A's wallet unblinds.
    let a_coins = a.wait_coins("A sees the payment", TESTNET_CONFIRM_TIMEOUT, |c| {
        confirmed(coin_from(c, &take_txid, &lbtc))
    });
    let paid = coin_from(&a_coins, &take_txid, &lbtc).unwrap();
    assert_eq!(paid["amount"], json!(PRICE), "{paid}");
    let a_asset = coin_sum(&a_coins, asset, 0);
    let a_lbtc = coin_sum(&a_coins, &lbtc, 0);
    assert_eq!(a_asset, a_asset_start - OFFER, "A's TEST");
    assert_eq!(a_lbtc, a_lbtc_before + PRICE, "A's L-BTC");
    let summary = a.ok("get_wallet_summary", json!({}));
    let a_dash_lbtc = summary["assets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["asset_id"] == json!(lbtc))
        .map(|x| x["amount"].as_i64().unwrap())
        .unwrap_or(0);
    assert_eq!(a_dash_lbtc, a_lbtc, "A's dashboard L-BTC");
    eprintln!(
        "[live] after the take: A {a_asset} TEST + {a_lbtc} L-BTC sats (paid {PRICE} at {}); \
         B {b_asset} TEST + {b_lbtc} L-BTC sats (taker fee {fee})",
        paid["outpoint"]
    );

    // A taken offer cannot be taken again.
    let again = b.err("swap_take", json!({ "proposal_json": proposal }));
    eprintln!("[live] second take refused: {again}");
    assert!(again.contains("already spent"), "{again}");
    let mine = a.ok("list_my_offers", json!({}));
    let first = mine
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["proposal_json"] == json!(proposal))
        .unwrap();
    assert_eq!(first["status"], json!("closed"), "{first}");

    // ── Cancel: a second offer on another TEST coin ────────────────────
    let rest = a_coins
        .iter()
        .find(|u| u["asset_id"] == json!(asset) && u["confirmations"].as_u64().unwrap_or(0) >= 1)
        .expect("A keeps a confirmed TEST coin")
        .clone();
    let rest_outpoint = rest["outpoint"].as_str().unwrap().to_string();
    let second = a.ok(
        "swap_make",
        json!({ "utxo": rest_outpoint, "want_asset_id": lbtc, "want_amount_sats": PRICE }),
    );
    let second_json = second["proposal_json"].as_str().unwrap().to_string();
    let second_id = a.env.ok(
        "swap_publish",
        json!({ "proposal_json": second_json, "note": "templarlib live testnet test (cancelled)" }),
    );
    eprintln!(
        "[live] second offer ({} TEST at {rest_outpoint}) published as {second_id}",
        rest["amount"]
    );
    let cancel_txid = a.ok("swap_cancel", json!({ "offer_id": second["offer_id"] }));
    let cancel_txid = cancel_txid.as_str().unwrap().to_string();
    eprintln!("[live] cancel: {}", tx_link(&cancel_txid));
    let a_coins = a.wait_coins("A's cancel confirmed", TESTNET_CONFIRM_TIMEOUT, |c| {
        confirmed(coin_from(c, &cancel_txid, asset))
    });
    assert_eq!(
        coin_from(&a_coins, &cancel_txid, asset).unwrap()["amount"],
        rest["amount"]
    );
    assert_eq!(
        coin_sum(&a_coins, asset, 0),
        a_asset,
        "A still holds its TEST"
    );
    let refused = b.err("swap_take", json!({ "proposal_json": second_json }));
    eprintln!("[live] cancelled offer refused: {refused}");
    assert!(refused.contains("already spent"), "{refused}");
    let mine = a.ok("list_my_offers", json!({}));
    let cancelled = mine
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["offer_id"] == second["offer_id"])
        .unwrap();
    assert_eq!(cancelled["status"], json!("cancelled"), "{cancelled}");

    // ── The book's watcher closes both (it runs every 60 s) ────────────
    let status_of = |rows: &Value, id: &Value| -> String {
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| {
                r["source_id"] == *id
                    && r["settlement"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("liquidex"))
            })
            .map(|r| r["status"].as_str().unwrap_or("").to_string())
            .unwrap_or_default()
    };
    let feed = format!("{markets_url}?network=liquid-testnet&all");
    let watch = std::time::Instant::now();
    let mut closed = (String::new(), String::new());
    while watch.elapsed() < std::time::Duration::from_secs(300) {
        let rows = lab_get(&feed);
        closed = (status_of(&rows, &book_id), status_of(&rows, &second_id));
        if closed.0 != "open" && closed.1 != "open" && !closed.0.is_empty() && !closed.1.is_empty()
        {
            break;
        }
        std::thread::sleep(TESTNET_POLL);
    }
    eprintln!(
        "[live] book statuses after {} s: taken {:?}, cancelled {:?}",
        watch.elapsed().as_secs(),
        closed.0,
        closed.1
    );
    assert_eq!(closed.0, "filled", "the taken offer in the book");
    assert_eq!(closed.1, "cancelled", "the cancelled offer in the book");
    let rows = b.env.ok("list_markets", json!({}));
    assert!(
        !rows
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["proposal_json"] == json!(proposal)
                || r["proposal_json"] == json!(second_json)),
        "closed offers must leave the open book"
    );
    eprintln!("[live] done in {} s", run.elapsed().as_secs());
}

/// The manual tester's order, live: a wallet created and synced on Liquid
/// testnet, then the engine joins the lab, reopens the wallet, gets regtest
/// BTC through the lab's admin API, a block is mined, and a sync in the
/// same engine must show it. The lab's Electrum server sees a new block a
/// few seconds after bitcoind (about 5–7 s, measured): until then a sync
/// answers `ok` with the old balance, so the test syncs until it shows.
#[test]
#[ignore = "needs a running Templar testlab and Bitcoin/Liquid testnet Electrum (TEMPLAR_LIVE_TESTLAB_URL)"]
fn live_testlab_wallet_created_before_joining_sees_its_regtest_funds() {
    let lab = std::env::var("TEMPLAR_LIVE_TESTLAB_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8096".to_string());
    let lab = lab.trim_end_matches('/').to_string();
    let mut env = TestEnv::new();
    let words = env.ok("generate_mnemonic", json!({ "word_count": 12 }));
    let mnemonic = words
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Before the lab", "mnemonic": mnemonic, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();
    let synced = env.ok("sync_wallet", json!({ "wallet_id": id }));
    eprintln!("[live] testnet sync before joining: {synced}");

    env.ok("set_test_server", json!({ "url": lab }));
    let addr = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "BTC" }),
    )["address"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(addr.starts_with("bcrt1"), "{addr}");
    let sent = lab_post(
        &format!("{lab}/admin/api/send"),
        json!({ "network": "bitcoin-regtest", "address": addr, "amount": "0.01" }),
    );
    lab_post(
        &format!("{lab}/admin/api/mine"),
        json!({ "chain": "bitcoin", "blocks": 1 }),
    );
    eprintln!("[live] admin send to {addr}: {}", sent["txid"]);
    let started = std::time::Instant::now();
    for attempt in 1..=90 {
        let s = env.ok("sync_wallet", json!({ "wallet_id": id }));
        assert_eq!(s["btc"], json!("ok"), "{s}");
        let d = env.ok("get_wallet_summary", json!({ "wallet_id": id }));
        let btc = d["assets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["asset_id"] == json!("BTC"))
            .unwrap()["amount"]
            .as_i64()
            .unwrap();
        if btc == 1_000_000 {
            eprintln!(
                "[live] the regtest funds showed at sync {attempt}, after {:?}",
                started.elapsed()
            );
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("the regtest funds never showed in this engine");
}

// ── Live: the native peg on a Templar testlab ──────────────────────

impl LabWallet {
    /// Polls `peg_status` until `pred` holds (Electrum indexes a block, and
    /// the lab's federation bot pays, a few seconds after the fact — longer
    /// on a busy shared lab).
    fn wait_peg(&mut self, order_id: &str, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
        let mut last = Value::Null;
        for _ in 0..180 {
            last = self.env.ok("peg_status", json!({ "order_id": order_id }));
            if pred(&last) {
                return last;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        panic!("{what}: the order never got there: {last}");
    }
}

/// The native peg end to end on a running Templar testlab, through nothing
/// but the test-server profile: a fresh software wallet joins the lab and
/// is funded through the lab's admin API; peg-in (`peg_start` → `peg_fund`
/// pays the deposit from the wallet's own Bitcoin → mining → `claimable`,
/// a claim before that depth refused → `peg_claim` → `completed`, L-BTC up
/// by the deposit minus the claim fee); peg-out (`peg_start` → `peg_fund`
/// → mining → the lab's federation bot pays → `completed`, BTC up by the
/// amount); an over-limit peg-out and an expired peg-in address refused.
/// See docs/guides/LIVE_TESTS.md.
#[test]
#[ignore = "needs a running Templar testlab (TEMPLAR_LIVE_TESTLAB_URL)"]
fn live_testlab_native_peg_in_and_out() {
    let lab = std::env::var("TEMPLAR_LIVE_TESTLAB_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8096".to_string());
    let lab = lab.trim_end_matches('/').to_string();
    let config = lab_get(&format!("{lab}/api/config"));
    let regtest = &config["networks"]["liquid-regtest"];
    let lbtc = regtest["policy_asset"].as_str().unwrap().to_string();
    let max = regtest["peg"]["pegout_max_sat"].as_u64().unwrap();
    let mine = |chain: &str, n: u32| {
        let r = lab_post(
            &format!("{lab}/admin/api/mine"),
            json!({ "chain": chain, "blocks": n }),
        );
        eprintln!("[live] mined {n} {chain} block(s), tip {}", r["height"]);
    };
    // The admin API, not the public faucet: the faucet's per-IP budget is
    // shared with whoever else uses the lab. It mines a block after paying.
    let fund = |network: &str, address: &str, amount: &str| {
        let r = lab_post(
            &format!("{lab}/admin/api/send"),
            json!({ "network": network, "address": address, "amount": amount }),
        );
        eprintln!("[live] admin send {amount} → {address}: {}", r["txid"]);
    };

    let mut w = LabWallet::join(&lab, "Live peg");
    let net = w.env.ok("get_liquid_network", json!({}));
    assert_eq!(net["peg_provider"], json!("native"), "{net}");
    // Before any funds: both directions refused with the tag, naming the
    // chain and the asset (nothing is paid; the orders are cancelled).
    w.sync();
    for (direction, payout, says) in [
        ("in", w.address("LBTC"), "of BTC on Bitcoin regtest"),
        ("out", w.address("BTC"), "of L-BTC on Liquid regtest"),
    ] {
        let order = w.ok(
            "peg_start",
            json!({ "direction": direction, "amount_sats": 150_000, "payout_address": payout }),
        );
        let oid = order["order_id"].as_str().unwrap().to_string();
        let err = w.env.err("peg_fund", json!({ "order_id": oid }));
        eprintln!("[live] unfunded peg-{direction}: {err}");
        assert!(
            err.starts_with("PEG_INSUFFICIENT_FUNDS: this wallet has 0 sat"),
            "{err}"
        );
        assert!(err.contains(says), "{err}");
        w.env.ok("peg_cancel", json!({ "order_id": oid }));
    }
    let btc_addr = w.address("BTC");
    let lbtc_addr = w.address("LBTC");
    fund("bitcoin-regtest", &btc_addr, "0.01");
    fund("liquid-regtest", &lbtc_addr, "0.01");
    // A newer lab confirms admin payments in batches; mine them now.
    mine("bitcoin", 1);
    mine("liquid", 1);
    let btc0 = w.wait_balance("BTC", "BTC funded", |x| x == 1_000_000);
    let lbtc0 = w.wait_balance(&lbtc, "L-BTC funded", |x| x == 1_000_000);

    // ── Peg-in: 0.002 BTC ──────────────────────────────────────────────
    const PEGIN: u64 = 200_000;
    let quote = w.env.ok(
        "peg_quote",
        json!({ "direction": "in", "amount_sats": PEGIN }),
    );
    eprintln!("[live] peg-in quote: {quote}");
    let payout = w.address("LBTC");
    let order = w.ok(
        "peg_start",
        json!({ "direction": "in", "amount_sats": PEGIN, "payout_address": payout }),
    );
    let oid = order["order_id"].as_str().unwrap().to_string();
    let deposit = order["deposit_address"].as_str().unwrap().to_string();
    eprintln!(
        "[live] peg-in {oid}: deposit address {deposit}, valid through Liquid height {}",
        order["valid_until_liquid_height"]
    );
    assert!(deposit.starts_with('2'), "P2SH-P2WSH expected: {deposit}");
    let err = w.env.err("peg_claim", json!({ "order_id": oid }));
    assert!(err.starts_with("PEG_NOT_READY:"), "{err}");

    // Someone else pays the address first, less than the order expects
    // (the lab's admin API, 20 000 sats): listed and claimable on its own,
    // but not the order's deposit.
    fund("bitcoin-regtest", &deposit, "0.0002");
    mine("bitcoin", 1);
    let early = w.wait_peg(&oid, "the early payment", |o| {
        o["deposits"].as_array().is_some_and(|d| d.len() == 1)
    });
    assert_eq!(early["status"], json!("awaiting_deposit"), "{early}");
    assert_eq!(early["deposits"][0]["primary"], json!(false), "{early}");
    assert_eq!(early["deposits"][0]["amount_sats"], json!(20_000));
    let extra = early["deposits"][0]["outpoint"]
        .as_str()
        .unwrap()
        .to_string();
    let err = w.env.err("peg_cancel", json!({ "order_id": oid }));
    assert!(
        err.starts_with("PEG_NOT_READY:"),
        "paid address cancelled: {err}"
    );

    // The wallet pays the deposit from its own Bitcoin.
    let funded = w.env.ok("peg_fund", json!({ "order_id": oid }));
    let deposit_txid = funded["txid_deposit"].as_str().unwrap().to_string();
    eprintln!("[live] peg-in deposit txid {deposit_txid}");
    assert_eq!(funded["status"], json!("deposit_seen"));
    let err = w.env.err("peg_fund", json!({ "order_id": oid }));
    assert!(err.starts_with("PEG_NOT_READY:"), "funded twice: {err}");

    mine("bitcoin", 1);
    w.wait_peg(&oid, "one confirmation", |o| o["confirmations"] == json!(1));
    let err = w.env.err("peg_claim", json!({ "order_id": oid }));
    eprintln!("[live] claim at depth 1 refused: {err}");
    assert!(
        err.starts_with("PEG_NOT_READY:") && err.contains("1 of the 2"),
        "{err}"
    );

    mine("bitcoin", 1);
    let ready = w.wait_peg(&oid, "claimable", |o| o["status"] == json!("claimable"));
    assert_eq!(ready["deposit_received_sats"], json!(PEGIN));
    let claimed = w.env.ok("peg_claim", json!({ "order_id": oid }));
    let claim_txid = claimed["txid_claim"].as_str().unwrap().to_string();
    let pegged = claimed["payout_expected_sats"].as_u64().unwrap();
    eprintln!(
        "[live] peg-in claim txid {claim_txid}: {pegged} sats L-BTC (fee {})",
        PEGIN - pegged
    );
    assert_eq!(claimed["status"], json!("settling"));
    // The early, smaller payment is claimed by its outpoint.
    let claimed_extra = w
        .env
        .ok("peg_claim", json!({ "order_id": oid, "outpoint": extra }));
    let extra_row = claimed_extra["deposits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["outpoint"] == json!(extra))
        .unwrap()
        .clone();
    let extra_claim = extra_row["txid_claim"].as_str().unwrap().to_string();
    eprintln!("[live] extra deposit {extra} claim txid {extra_claim}");
    mine("liquid", 1);
    let done = w.wait_peg(&oid, "peg-in completed", |o| {
        o["status"] == json!("completed")
            && o["deposits"]
                .as_array()
                .is_some_and(|d| d.iter().all(|x| x["status"] == json!("completed")))
    });
    assert_eq!(done["txid_payout"], json!(claim_txid));
    let lbtc1 = w.wait_balance(&lbtc, "L-BTC pegged in", |x| x > lbtc0 + pegged as i64);
    let extra_in = lbtc1 - lbtc0 - pegged as i64;
    eprintln!("[live] the extra deposit brought {extra_in} sats L-BTC");
    assert!(
        extra_in > 19_900 && extra_in < 20_000,
        "L-BTC up by both claims: {extra_in}"
    );
    let btc1 = w.balance("BTC");
    assert!(
        btc1 < btc0 - PEGIN as i64,
        "BTC down by the deposit and its fee"
    );
    eprintln!(
        "[live] after the peg-in: BTC {btc0} → {btc1}, L-BTC {lbtc0} → {lbtc1} \
         (history {})",
        done["status_history"]
    );

    // ── Peg-out: 0.0005 L-BTC ──────────────────────────────────────────
    // At or above the lab's pegout_min_sat (100 000 when its config does
    // not say): smaller outputs are never paid.
    const PEGOUT: u64 = 150_000;
    let below = w.address("BTC");
    let err = w.err(
        "peg_start",
        json!({ "direction": "out", "amount_sats": 99_999, "payout_address": below }),
    );
    eprintln!("[live] peg-out below the lab's minimum refused: {err}");
    assert!(err.contains("below the minimum"), "{err}");
    let err = w.env.err(
        "peg_quote",
        json!({ "direction": "out", "amount_sats": max + 1 }),
    );
    assert!(err.contains("above the maximum"), "{err}");
    let btc_payout = w.address("BTC");
    let err = w.err(
        "peg_start",
        json!({ "direction": "out", "amount_sats": max + 1, "payout_address": btc_payout }),
    );
    eprintln!("[live] over-limit peg-out refused: {err}");
    assert!(err.contains("above the maximum"), "{err}");
    let order = w.ok(
        "peg_start",
        json!({ "direction": "out", "amount_sats": PEGOUT, "payout_address": btc_payout }),
    );
    let out_id = order["order_id"].as_str().unwrap().to_string();
    let sent = w.env.ok("peg_fund", json!({ "order_id": out_id }));
    let pegout_txid = sent["txid_deposit"].as_str().unwrap().to_string();
    eprintln!("[live] peg-out {out_id} txid {pegout_txid}");
    mine("liquid", 2);
    // The lab's bot mines a Bitcoin block right after it pays (its payment
    // is in a block 1-3 s later), so one status check may already see the
    // payout confirmed: `settling` with the payout and `completed` are
    // both the federation's payment, found.
    let paid = w.wait_peg(&out_id, "federation payment", |o| {
        !o["txid_payout"].is_null()
            && (o["status"] == json!("settling") || o["status"] == json!("completed"))
    });
    eprintln!("[live] payout found while {}", paid["status"]);
    let payout_txid = paid["txid_payout"].as_str().unwrap().to_string();
    eprintln!("[live] federation payout txid {payout_txid}");
    mine("bitcoin", 1);
    w.wait_peg(&out_id, "peg-out completed", |o| {
        o["status"] == json!("completed")
    });
    let btc2 = w.wait_balance("BTC", "BTC paid out", |x| x == btc1 + PEGOUT as i64);
    let lbtc2 = w.balance(&lbtc);
    assert!(
        lbtc2 < lbtc1 - PEGOUT as i64,
        "L-BTC down by the peg-out and its fee"
    );
    eprintln!(
        "[live] after the peg-out: BTC {btc1} → {btc2}, L-BTC {lbtc1} → {lbtc2} \
         (fee {})",
        lbtc1 - lbtc2 - PEGOUT as i64
    );

    // ── An expired peg-in address is never paid ────────────────────────
    // The lab's federation never changes, so a change is simulated: the
    // stored order is made to remember another federation script and a
    // window already past. The wallet re-reads the live federation, sees it
    // differs, and expires the order.
    let stale = w.ok(
        "peg_start",
        json!({ "direction": "in", "amount_sats": PEGIN, "payout_address": payout }),
    );
    let stale_id = stale["order_id"].as_str().unwrap().to_string();
    let path = w.env.dir.join("peg_orders.json");
    let mut store: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    for o in store["orders"].as_array_mut().unwrap() {
        if o["order_id"] == json!(stale_id) {
            o["valid_until_liquid_height"] = json!(0);
            o["native"]["fedpeg_script_hex"] = json!("51");
        }
    }
    std::fs::write(&path, store.to_string()).unwrap();
    let s = w.env.ok("peg_status", json!({ "order_id": stale_id }));
    assert_eq!(s["status"], json!("expired"), "{s}");
    let err = w.env.err("peg_fund", json!({ "order_id": stale_id }));
    eprintln!("[live] expired address refused: {err}");
    assert!(err.starts_with("PEG_EXPIRED:"), "{err}");
}

// ── Liquid co-signing guard ────────────────────────────────────────

/// A testnet PSET for the test mnemonic's `m/2121'/1'/0'/0/0` key (a loan
/// key: outside the wallet descriptor, signed through the fingerprint like
/// any co-signed input): one explicit 10 000-sat input declaring `sighash`,
/// one 9 000-sat payment and `fees` fee outputs of 1 000. Base64.
fn guard_pset(sighash: Option<u32>, fees: usize) -> String {
    use lwk_wollet::elements::pset::PsbtSighashType;
    key_pset("m/2121'/1'/0'/0/0", fees, |input, _| {
        input.sighash_type = sighash.map(PsbtSighashType::from_u32);
    })
}

/// A testnet PSET for the test mnemonic's key at `path`: one explicit
/// 10 000-sat input spending that key's P2WPKH and naming the key, then
/// changed by `edit` (which gets the key); one 9 000-sat payment and `fees`
/// fee outputs of 1 000. Base64.
fn key_pset(
    path: &str,
    fees: usize,
    edit: impl FnOnce(&mut lwk_wollet::elements::pset::Input, &lwk_wollet::bitcoin::PublicKey),
) -> String {
    use lwk_wollet::bitcoin::bip32::{DerivationPath, Xpriv};
    use lwk_wollet::bitcoin::secp256k1::Secp256k1;
    use lwk_wollet::bitcoin::PublicKey;
    use lwk_wollet::elements::pset::{Input, Output, PartiallySignedTransaction};
    use lwk_wollet::elements::{
        confidential, Address, AddressParams, AssetId, OutPoint, Script, TxOut, Txid,
    };
    use std::str::FromStr;

    let secp = Secp256k1::new();
    let master = Xpriv::from_str(&templar_core::master_xprv(MNEMONIC).unwrap()).unwrap();
    let path = DerivationPath::from_str(path).unwrap();
    let pk = PublicKey::new(
        master
            .derive_priv(&secp, &path)
            .unwrap()
            .private_key
            .public_key(&secp),
    );
    let lbtc = AssetId::from_str(templar_core::TESTNET_POLICY_ASSET).unwrap();
    let mut input = Input::from_prevout(OutPoint::new(Txid::from_byte_array([0x33; 32]), 0));
    input.witness_utxo = Some(TxOut {
        asset: confidential::Asset::Explicit(lbtc),
        value: confidential::Value::Explicit(10_000),
        nonce: confidential::Nonce::Null,
        script_pubkey: Address::p2wpkh(&pk, None, &AddressParams::LIQUID_TESTNET).script_pubkey(),
        witness: Default::default(),
    });
    input
        .bip32_derivation
        .insert(pk, (master.fingerprint(&secp), path));
    edit(&mut input, &pk);
    let mut pset = PartiallySignedTransaction::new_v2();
    pset.add_input(input);
    pset.add_output(Output::new_explicit(
        Script::from(vec![0u8, 20, 9, 9, 9]),
        9_000,
        lbtc,
        None,
    ));
    for _ in 0..fees {
        pset.add_output(Output::from_txout(TxOut::new_fee(1_000, lbtc)));
    }
    templar_core::LiquidWalletManager::pset_to_base64(&pset).unwrap()
}

/// `sign_pset` signs what LWK 0.9 signed and nothing else: an input of ours
/// asking for anything but SIGHASH_ALL, or a PSET without exactly one fee
/// output, is refused with a plain `err` and no signature; unset and
/// SIGHASH_ALL are signed SIGHASH_ALL. Inspection still describes them all.
#[test]
fn sign_pset_signs_sighash_all_and_one_fee_output_only() {
    let mut env = TestEnv::new();
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Cosigner", "mnemonic": MNEMONIC, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();

    for sighash in [0x02u32, 0x03, 0x81, 0x82, 0x83] {
        let pset = guard_pset(Some(sighash), 1);
        let d = env.ok(
            "inspect_pset",
            json!({ "wallet_id": id, "pset_base64": pset }),
        );
        assert_eq!(d["inputs"][0]["is_ours"], json!(true));
        let resp = env.call("sign_pset", json!({ "wallet_id": id, "pset_base64": pset }));
        assert_keys("sign_pset refusal", &resp, &["err"]);
        assert!(resp.get("ok").is_none(), "{resp}");
        let err = resp["err"].as_str().unwrap();
        assert!(
            err.contains(&format!("sighash type 0x{sighash:02x}"))
                && err.contains("SIGHASH_ALL only"),
            "0x{sighash:02x}: {err}"
        );
    }

    for (fees, words) in [
        (
            0,
            "PSET inspection failed: PSET doesn't contain a fee output",
        ),
        (2, "PSET inspection failed: Multiple fee outputs"),
    ] {
        let pset = guard_pset(None, fees);
        // Described…
        let d = env.ok(
            "inspect_pset",
            json!({ "wallet_id": id, "pset_base64": pset }),
        );
        assert_eq!(d["fee_sats"], json!(1_000 * fees as i64));
        // …but not signed, in LWK 0.9's words.
        let err = env.err("sign_pset", json!({ "wallet_id": id, "pset_base64": pset }));
        assert_eq!(err, words);
    }

    for sighash in [None, Some(0x01)] {
        let signed = env.ok(
            "sign_pset",
            json!({ "wallet_id": id, "pset_base64": guard_pset(sighash, 1) }),
        );
        let signed =
            templar_core::LiquidWalletManager::pset_from_base64(signed.as_str().unwrap()).unwrap();
        let sigs: Vec<_> = signed.inputs()[0].partial_sigs.values().collect();
        assert_eq!(sigs.len(), 1, "{sighash:?}");
        assert_eq!(sigs[0].last(), Some(&0x01), "{sighash:?}: SIGHASH_ALL byte");
    }
}

/// `sign_pset` never signs a taproot input of this wallet, on a mainnet or
/// a test path: LWK 0.9 never signed through `tap_key_origins`. The PSET
/// names the test mnemonic's key there only (no `bip32_derivation`).
#[test]
fn sign_pset_never_signs_a_taproot_input() {
    use lwk_wollet::bitcoin::bip32::{DerivationPath, Xpriv};
    use lwk_wollet::bitcoin::secp256k1::Secp256k1;
    use lwk_wollet::elements::pset::{Output, PartiallySignedTransaction};
    use lwk_wollet::elements::{confidential, AssetId, OutPoint, Script, TxOut, Txid};
    use std::str::FromStr;

    let mut env = TestEnv::new();
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Cosigner", "mnemonic": MNEMONIC, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();

    let secp = Secp256k1::new();
    let master = Xpriv::from_str(&templar_core::master_xprv(MNEMONIC).unwrap()).unwrap();
    let lbtc = AssetId::from_str(templar_core::TESTNET_POLICY_ASSET).unwrap();
    for path in ["m/86'/1776'/0'/0/0", "m/86'/1'/0'/0/0"] {
        let path = DerivationPath::from_str(path).unwrap();
        let (xonly, _) = master
            .derive_priv(&secp, &path)
            .unwrap()
            .to_keypair(&secp)
            .x_only_public_key();
        let mut input = lwk_wollet::elements::pset::Input::from_prevout(OutPoint::new(
            Txid::from_byte_array([0x55; 32]),
            0,
        ));
        input.witness_utxo = Some(TxOut {
            asset: confidential::Asset::Explicit(lbtc),
            value: confidential::Value::Explicit(10_000),
            nonce: confidential::Nonce::Null,
            script_pubkey: Script::new_v1_p2tr(
                &lwk_wollet::elements::secp256k1_zkp::Secp256k1::new(),
                xonly,
                None,
            ),
            witness: Default::default(),
        });
        input.tap_internal_key = Some(xonly);
        input
            .tap_key_origins
            .insert(xonly, (vec![], (master.fingerprint(&secp), path.clone())));
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_input(input);
        pset.add_output(Output::new_explicit(
            Script::from(vec![0u8, 20, 9, 9, 9]),
            9_000,
            lbtc,
            None,
        ));
        pset.add_output(Output::from_txout(TxOut::new_fee(1_000, lbtc)));
        let pset = templar_core::LiquidWalletManager::pset_to_base64(&pset).unwrap();

        let resp = env.call("sign_pset", json!({ "wallet_id": id, "pset_base64": pset }));
        assert_keys("sign_pset taproot refusal", &resp, &["err"]);
        assert!(resp.get("ok").is_none(), "{path}: {resp}");
        let err = resp["err"].as_str().unwrap();
        assert!(
            err.starts_with("Signing failed: refusing to sign input 0:")
                && err.contains("does not sign taproot inputs"),
            "{path}: {err}"
        );
    }
}

/// `sign_pset` signs a coin of the wallet only as the coin the wallet's
/// descriptor derives at the key's path. The reviewer's attack: the
/// wallet's own P2WPKH coin, declared as P2WSH of the P2PKH script code of
/// its key. Inspection shows nothing of the wallet's leaving it — the
/// signature would spend it all the same — so it is refused with a plain
/// `err`. (The core tests sign the same coin declared truthfully; here
/// LWK's inspection refuses an unblinded coin of the wallet before that.)
#[test]
fn sign_pset_refuses_a_wallet_coin_named_as_another_coin() {
    use lwk_wollet::elements::{Address, AddressParams};
    let mut env = TestEnv::new();
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Owner", "mnemonic": MNEMONIC, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();

    let disguised = key_pset("m/84'/1'/0'/0/0", 1, |input, pk| {
        let script_code = Address::p2pkh(pk, None, &AddressParams::LIQUID_TESTNET).script_pubkey();
        input.witness_utxo.as_mut().unwrap().script_pubkey = script_code.to_v0_p2wsh();
        input.witness_script = Some(script_code);
    });
    let d = env.ok(
        "inspect_pset",
        json!({ "wallet_id": id, "pset_base64": disguised }),
    );
    assert_eq!(d["inputs"][0]["is_ours"], json!(true));
    assert_eq!(d["inputs"][0]["script_type"], json!("p2wsh"));
    assert!(
        d["net_change"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v.as_i64().unwrap() >= -1_000),
        "the review shows no coin of the wallet leaving: {d}"
    );
    let resp = env.call(
        "sign_pset",
        json!({ "wallet_id": id, "pset_base64": disguised }),
    );
    assert_keys("sign_pset ownership refusal", &resp, &["err"]);
    let err = resp["err"].as_str().unwrap();
    assert!(
        err.starts_with("Signing failed: refusing to sign input 0:")
            && err.contains("not the coin this wallet derives"),
        "{err}"
    );

    // P2SH-wrapped, and the wallet's coin under the key of another index.
    let wrapped = key_pset("m/84'/1'/0'/0/0", 1, |input, _| {
        let program = input.witness_utxo.as_ref().unwrap().script_pubkey.clone();
        input.witness_utxo.as_mut().unwrap().script_pubkey = program.to_p2sh();
        input.redeem_script = Some(program);
    });
    let other_index = key_pset("m/84'/1'/0'/0/7", 1, |input, _| {
        let coin = key_pset("m/84'/1'/0'/0/0", 1, |_, _| {});
        let coin = templar_core::LiquidWalletManager::pset_from_base64(&coin).unwrap();
        input.witness_utxo = coin.inputs()[0].witness_utxo.clone();
    });
    for pset in [wrapped, other_index] {
        let err = env.err("sign_pset", json!({ "wallet_id": id, "pset_base64": pset }));
        assert!(
            err.starts_with("Signing failed: refusing to sign input 0:")
                && err.contains("not the coin this wallet derives"),
            "{err}"
        );
    }
}

/// `sign_pset` signs no peg-in input: the wallet's own claim is signed by
/// `peg_claim` alone, against its stored order. The input names the loan
/// key, so inspection describes it; signing is refused with a plain `err`.
#[test]
fn sign_pset_never_signs_a_peg_in_input() {
    let mut env = TestEnv::new();
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Owner", "mnemonic": MNEMONIC, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();

    let pegin = key_pset("m/2121'/1'/0'/0/0", 1, |input, _| {
        input.previous_output_index |= 1 << 30;
        input.pegin_claim_script = input.witness_utxo.as_ref().map(|o| o.script_pubkey.clone());
        input.pegin_value = Some(10_000);
    });
    let d = env.ok(
        "inspect_pset",
        json!({ "wallet_id": id, "pset_base64": pegin }),
    );
    assert_eq!(d["inputs"][0]["is_ours"], json!(true));
    let resp = env.call(
        "sign_pset",
        json!({ "wallet_id": id, "pset_base64": pegin }),
    );
    assert_keys("sign_pset peg-in refusal", &resp, &["err"]);
    let err = resp["err"].as_str().unwrap();
    assert!(
        err.starts_with("Signing failed: refusing to sign input 0:") && err.contains("peg-in"),
        "{err}"
    );
    // The same input without the peg-in flag signs as before.
    let plain = env.ok(
        "sign_pset",
        json!({ "wallet_id": id, "pset_base64": guard_pset(None, 1) }),
    );
    assert!(plain.as_str().is_some());
}

// ── Templar Protocol connector ─────────────────────────────────────

/// A testnet PSET spending a fake Templar Protocol escrow whose contract names the
/// test mnemonic's `2121'` key (borrower) and a second key (lender): one
/// external payout, one fee output. Generated by templar-core's
/// `liquid::protocol::tests::print_escrow_fixture`.
const ESCROW_FIXTURE: &str = "cHNldP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEBTgFJmoGFRfa645/AO2N/Kk4eZOWQysG8Om9tcapEQ2VMFAEAAAAAAA9CQAAiACCgE5MA82qHuUPx4nzHNwjxWCSc8+rg4rQ5CNB5Vs74AAEFclIhAhdnH707KagoCN5XkC2n+EOOzDitCmvJT01Ihb6KrdQaIQNjxKZ9muqLcb6BIp5cvl1jHmT6QMHHAlKIgyIYaGd7QlKuc2QhA2PEpn2a6otxvoEinly+XWMeZPpAwccCUoiDIhhoZ3tCrQOg8BmxaCIGAhdnH707KagoCN5XkC2n+EOOzDitCmvJT01Ihb6KrdQaGHPF2gpJCACAAQAAgAAAAIAAAAAABwAAACIGA2PEpn2a6otxvoEinly+XWMeZPpAwccCUoiDIhhoZ3tCGD9jWmNJCACAAQAAgAAAAIAAAAAABwAAAAEOICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiAQ8EAAAAAAf8BHBzZXQRCEBCDwAAAAAAB/wEcHNldBMgSZqBhUX2uuOfwDtjfypOHmTlkMrBvDpvbXGqRENlTBQAAQMITEAPAAAAAAAH/ARwc2V0AiBJmoGFRfa645/AO2N/Kk4eZOWQysG8Om9tcapEQ2VMFAEEFgAUAQIDBAUGBwgJCgsMDQ4PEBESExQAAQMI9AEAAAAAAAAH/ARwc2V0AiBJmoGFRfa645/AO2N/Kk4eZOWQysG8Om9tcapEQ2VMFAEEAAA=";

#[cfg(feature = "protocol")]
#[test]
fn get_protocol_escrow_xpub_has_the_protocol_shape() {
    let mut env = TestEnv::new();
    let id = env.create_test_wallet();
    let xpub = env.ok("get_protocol_escrow_xpub", json!({ "wallet_id": id }));
    let xpub = xpub.as_str().expect("keyorigin xpub string");
    assert!(
        xpub.starts_with("[73c5da0a/2121h/1h/0h]tpub"),
        "docs/CONNECTOR.md §2 shape expected, got {xpub}"
    );
    // The same value the core derives directly.
    assert_eq!(
        xpub,
        templar_core::escrow_xpub_from_mnemonic(MNEMONIC).unwrap()
    );

    // A watch-only wallet has no seed to derive the account from.
    let (fp, account) = templar_core::account_xpub_bip84(MNEMONIC).unwrap();
    let wo = env.ok(
        "create_watch_only_wallet",
        json!({
            "name": "Watch",
            "recv_desc": format!("wpkh([{fp}/84'/1'/0']{account}/0/*)"),
            "change_desc": format!("wpkh([{fp}/84'/1'/0']{account}/1/*)"),
        }),
    );
    let wo_id = wo["id"].as_str().unwrap().to_string();
    let err = env.err("get_protocol_escrow_xpub", json!({ "wallet_id": wo_id }));
    assert!(err.contains("software wallet"), "{err}");
    let err = env.err("get_protocol_escrow_xpub", json!({ "wallet_id": "nope" }));
    assert!(err.contains("not found"), "{err}");
}

#[cfg(feature = "protocol")]
/// The exact §9.1 challenge line a site sends; the proof is bound to it.
const CHALLENGE: &str = "Templar Protocol · access · http://127.0.0.1:8087 · \
                         nonce=AAAAAAAAAAAAAAAAAAAAAA · expires=2026-10-03T10:15:00Z · \
                         this signature never moves funds";

#[cfg(feature = "protocol")]
/// Proof of key, end to end through the shared API: the check is built for the
/// wallet's escrow key, reads as "not my coin, 0, OP_RETURN, fee 0", is
/// recognised as the check of its own challenge, signs once through the
/// ordinary `sign_pset` route and is still recognised afterwards; anything
/// else under the same challenge is refused with a reason.
#[test]
fn protocol_check_pset_is_built_signed_and_judged() {
    let mut env = TestEnv::new();
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Prover", "mnemonic": MNEMONIC, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();

    let check = env.ok(
        "protocol_check_pset",
        json!({ "wallet_id": id, "challenge": CHALLENGE }),
    );
    assert_keys(
        "protocol_check_pset",
        &check,
        &["pset_base64", "loan_key", "fingerprint"],
    );
    assert!(check["loan_key"]
        .as_str()
        .unwrap()
        .starts_with("[73c5da0a/2121h/1h/0h]tpub"));
    assert_eq!(check["fingerprint"], json!("73c5da0a"));
    let pset = check["pset_base64"].as_str().unwrap().to_string();

    // What the review screen's own reading shows.
    let d = env.ok(
        "inspect_pset",
        json!({ "wallet_id": id, "pset_base64": pset }),
    );
    assert_eq!(d["fee_sats"], json!(0));
    assert_eq!(d["inputs"].as_array().unwrap().len(), 1);
    assert_eq!(d["inputs"][0]["is_ours"], json!(true));
    assert_eq!(d["inputs"][0]["amount_sats"], json!(0));
    assert_eq!(d["inputs"][0]["script_type"], json!("p2wpkh"));
    assert_eq!(d["inputs"][0]["signed_by"], json!([]));
    assert_eq!(d["outputs"].as_array().unwrap().len(), 2);
    assert_eq!(d["outputs"][1]["kind"], json!("fee"));
    assert_eq!(d["has_unverified_outputs"], json!(false));

    // Judged: the check of this challenge, and of no other.
    let v = env.ok(
        "protocol_is_check_pset",
        json!({ "wallet_id": id, "challenge": CHALLENGE, "pset_base64": pset }),
    );
    assert_keys(
        "protocol_is_check_pset",
        &v,
        &["is_check", "reason", "loan_key_fingerprint"],
    );
    assert_eq!(v["is_check"], json!(true), "{v}");
    assert!(v["reason"].is_null());
    assert_eq!(v["loan_key_fingerprint"], json!("73c5da0a"));

    let other = env.ok(
        "protocol_is_check_pset",
        json!({ "wallet_id": id, "challenge": "another challenge", "pset_base64": pset }),
    );
    assert_eq!(other["is_check"], json!(false));
    assert!(other["reason"]
        .as_str()
        .unwrap()
        .contains("not a check PSET"));

    // A real escrow spend is never a proof, whatever the challenge says.
    let real = env.ok(
        "protocol_is_check_pset",
        json!({ "wallet_id": id, "challenge": CHALLENGE, "pset_base64": ESCROW_FIXTURE }),
    );
    assert_eq!(real["is_check"], json!(false));
    assert!(real["reason"].as_str().unwrap().contains("worth something"));

    // Garbage is a verdict too, not a crash.
    let junk = env.ok(
        "protocol_is_check_pset",
        json!({ "wallet_id": id, "challenge": CHALLENGE, "pset_base64": "not base64!" }),
    );
    assert_eq!(junk["is_check"], json!(false));

    // Signed through the ordinary route, exactly once, still the check.
    let signed = env.ok("sign_pset", json!({ "wallet_id": id, "pset_base64": pset }));
    let signed = signed.as_str().unwrap().to_string();
    let after = env.ok(
        "inspect_pset",
        json!({ "wallet_id": id, "pset_base64": signed }),
    );
    assert_eq!(after["inputs"][0]["signed_by"], json!(["73c5da0a"]));
    assert_eq!(after["sigs_have"], json!(1));
    let v = env.ok(
        "protocol_is_check_pset",
        json!({ "wallet_id": id, "challenge": CHALLENGE, "pset_base64": signed }),
    );
    assert_eq!(v["is_check"], json!(true));
    // And the site's verification, as the core implements it, accepts it.
    let parsed = templar_core::LiquidWalletManager::pset_from_base64(&signed).unwrap();
    templar_core::verify_check_signature(
        &parsed,
        CHALLENGE,
        check["loan_key"].as_str().unwrap(),
        &templar_core::LiquidNetwork::testnet(),
    )
    .unwrap();

    // Signing it again adds nothing — the route says so.
    let err = env.err(
        "sign_pset",
        json!({ "wallet_id": id, "pset_base64": signed }),
    );
    assert!(err.contains("No signature was added"), "{err}");

    // An empty challenge builds nothing.
    let err = env.err(
        "protocol_check_pset",
        json!({ "wallet_id": id, "challenge": "  " }),
    );
    assert!(err.contains("empty challenge"), "{err}");

    // A watch-only wallet has no loan key to prove.
    let (fp, account) = templar_core::account_xpub_bip84(MNEMONIC).unwrap();
    let wo = env.ok(
        "create_watch_only_wallet",
        json!({
            "name": "Watch",
            "recv_desc": format!("wpkh([{fp}/84'/1'/0']{account}/0/*)"),
            "change_desc": format!("wpkh([{fp}/84'/1'/0']{account}/1/*)"),
        }),
    );
    let wo_id = wo["id"].as_str().unwrap().to_string();
    let err = env.err(
        "protocol_check_pset",
        json!({ "wallet_id": wo_id, "challenge": CHALLENGE }),
    );
    assert!(err.contains("software wallet"), "{err}");
    let v = env.ok(
        "protocol_is_check_pset",
        json!({ "wallet_id": wo_id, "challenge": CHALLENGE, "pset_base64": pset }),
    );
    assert_eq!(v["is_check"], json!(false));

    // On regtest the testnet check is another chain's: refused there, and a
    // regtest check is built with regtest's LBTC.
    env.ok("set_liquid_network", json!({ "network": "regtest" }));
    let v = env.ok(
        "protocol_is_check_pset",
        json!({ "wallet_id": id, "challenge": CHALLENGE, "pset_base64": pset }),
    );
    assert_eq!(v["is_check"], json!(false));
    assert!(v["reason"].as_str().unwrap().contains("LBTC"), "{v}");
    let regtest = env.ok(
        "protocol_check_pset",
        json!({ "wallet_id": id, "challenge": CHALLENGE }),
    );
    assert_ne!(regtest["pset_base64"], check["pset_base64"]);
}

// ── Live acceptance against the Templar Protocol site (regtest) ────────────
//
// The same dispatch the app's bridge calls, driven against the running site
// (`cargo run -p templar-lend-ops -- up` in the protocol repository; the site reads
// its env from `data/regtest/regtest.env`). Ignored by default: each needs a
// link the site hands out to a browser.
//
//   TEMPLAR_LIVE_CONNECT_LINK  the `templar://connect?…` link of /wallet
//   TEMPLAR_LIVE_SIGN_LINK     a `templar://sign?…` link of a `proof` request
//                              (the check page of «Ritrova» / a 0.1.0 reconnect)
//   TEMPLAR_LIVE_MNEMONIC      the wallet to answer with (default: the test vector)
//   TEMPLAR_LIVE_OUT           where to write the portfolio JSON, for a fixture
//
// Run one with
//   TEMPLAR_LIVE_CONNECT_LINK='templar://connect?url=…&nonce=…' \
//     cargo test -p templarlib live_connect -- --ignored --nocapture

#[cfg(feature = "protocol")]
fn live_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} (see the comment above)"))
}

#[cfg(feature = "protocol")]
fn live_mnemonic() -> String {
    std::env::var("TEMPLAR_LIVE_MNEMONIC").unwrap_or_else(|_| MNEMONIC.to_string())
}

#[cfg(feature = "protocol")]
/// `templar://<action>?url=<percent-encoded>&nonce=<…>` → (url, nonce).
fn live_link(link: &str, action: &str) -> (String, String) {
    let (head, query) = link
        .split_once('?')
        .unwrap_or_else(|| panic!("no query in {link}"));
    assert!(
        head.trim_start_matches("templar://").trim_matches('/') == action,
        "expected a templar://{action} link, got {head}"
    );
    let mut url = String::new();
    let mut nonce = String::new();
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "url" => url = live_percent_decode(v),
            "nonce" => nonce = live_percent_decode(v),
            _ => {}
        }
    }
    assert!(!url.is_empty() && !nonce.is_empty(), "link lacks url/nonce");
    (url, nonce)
}

#[cfg(feature = "protocol")]
fn live_percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8(out).expect("utf-8 link")
}

#[cfg(feature = "protocol")]
fn live_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .expect("http client")
}

#[cfg(feature = "protocol")]
fn live_json(resp: reqwest::blocking::Response) -> (u16, Value) {
    let status = resp.status().as_u16();
    let text = resp.text().unwrap_or_default();
    let body = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
    (status, body)
}

#[cfg(feature = "protocol")]
fn live_get(url: &str) -> (u16, Value) {
    live_json(
        live_client()
            .get(url)
            .header("Accept", "application/json")
            .send()
            .unwrap_or_else(|e| panic!("GET {url}: {e}")),
    )
}

#[cfg(feature = "protocol")]
fn live_post(url: &str, body: &Value) -> (u16, Value) {
    live_json(
        live_client()
            .post(url)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .unwrap_or_else(|e| panic!("POST {url}: {e}")),
    )
}

#[cfg(feature = "protocol")]
fn live_bearer(method: &str, url: &str, token: &str, body: Option<&Value>) -> (u16, Value) {
    let client = live_client();
    let req = match method {
        "POST" => client.post(url),
        "DELETE" => client.delete(url),
        _ => client.get(url),
    }
    .header("Accept", "application/json")
    .bearer_auth(token);
    let req = match body {
        Some(b) => req.json(b),
        None => req,
    };
    live_json(req.send().unwrap_or_else(|e| panic!("{method} {url}: {e}")))
}

#[cfg(feature = "protocol")]
/// A regtest environment holding the live wallet, opened.
fn live_wallet(env: &mut TestEnv, site_policy_asset: Option<&str>) -> String {
    let mut params = json!({ "network": "regtest" });
    if let Some(p) = site_policy_asset {
        params["policy_asset"] = json!(p);
    }
    env.ok("set_liquid_network", params);
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Live", "mnemonic": live_mnemonic(), "liquid": true }),
    );
    created["id"].as_str().unwrap().to_string()
}

#[cfg(feature = "protocol")]
/// §3 v1.1 + §7 + §8 against the live site: connect with the proof of key
/// in the callback, get the portfolio token back, read the loans, mint a
/// one-time browser link. What the Loans screen does, minus the pixels.
#[test]
#[ignore = "needs the protocol's regtest site and TEMPLAR_LIVE_CONNECT_LINK"]
fn live_connect_with_proof_then_portfolio_and_open() {
    let (url, nonce) = live_link(&live_env("TEMPLAR_LIVE_CONNECT_LINK"), "connect");
    let (status, req) = live_get(&url);
    assert_eq!(status, 200, "connect request: {req}");
    assert_eq!(req["kind"], json!("connect"), "{req}");
    assert_eq!(req["nonce"], json!(nonce), "{req}");
    assert_eq!(req["network"], json!("liquid-regtest"), "{req}");
    let challenge = req["challenge"]
        .as_str()
        .expect("a v1.1 site sends a challenge")
        .to_string();
    assert!(
        challenge.starts_with("Templar Protocol · access · "),
        "{challenge}"
    );
    assert!(
        challenge.ends_with("this signature never moves funds"),
        "{challenge}"
    );
    let callback = req["callback"].as_str().unwrap().to_string();

    let mut env = TestEnv::new();
    let id = live_wallet(&mut env, req["policy_asset"].as_str());
    let info = env.ok("get_wallet_info", json!({ "wallet_id": id }));
    let ct_descriptor = info["liquid_descriptor"].as_str().unwrap().to_string();
    let escrow_xpub = env.ok("get_protocol_escrow_xpub", json!({ "wallet_id": id }));
    let address = env.ok(
        "generate_receive_address",
        json!({ "wallet_id": id, "asset": "LBTC" }),
    );

    // The proof: built from the site's challenge, signed like any PSET.
    // `TEMPLAR_LIVE_NO_PROOF=1` answers like Templar 0.1.0 instead — no
    // proof — which, once the site knows the key, must lead to a `proof`
    // signing request (§9.2) and hand out no token yet.
    let no_proof = std::env::var("TEMPLAR_LIVE_NO_PROOF").is_ok();
    let mut body = json!({
        "version": 1,
        "nonce": nonce,
        "network": "liquid-regtest",
        "ct_descriptor": ct_descriptor,
        "escrow_xpub": escrow_xpub,
        "receive_address": address["address"],
        "wallet_name": "Templar — Live acceptance",
        "signer": "software",
    });
    if !no_proof {
        let check = env.ok(
            "protocol_check_pset",
            json!({ "wallet_id": id, "challenge": challenge }),
        );
        let signed = env.ok(
            "sign_pset",
            json!({ "wallet_id": id, "pset_base64": check["pset_base64"] }),
        );
        body["proof"] = json!({ "kind": "check-pset", "pset": signed });
    }

    let (status, reply) = live_post(&callback, &body);
    assert_eq!(status, 200, "connect callback: {reply}");
    assert_eq!(reply["ok"], json!(true), "{reply}");
    eprintln!("connected; next = {}", reply["next"]);
    if no_proof {
        let next = reply["next"].as_str().unwrap_or_default();
        assert!(
            next.contains("/wallet/prove/"),
            "a v1 reconnect of a known key must lead to the check page, got {reply}"
        );
        assert!(
            reply["portfolio"].is_null(),
            "no token before the key is proved: {reply}"
        );
        return;
    }
    let portfolio = &reply["portfolio"];
    let p_url = portfolio["url"]
        .as_str()
        .expect("a v1.1 connect with a valid proof hands back portfolio.url");
    let token = portfolio["token"]
        .as_str()
        .expect("portfolio.token")
        .to_string();
    assert_eq!(token.len(), 43, "32 bytes base64url");

    // §7: the loans dashboard.
    let (status, p) = live_bearer("GET", p_url, &token, None);
    assert_eq!(status, 200, "portfolio: {p}");
    assert_eq!(p["version"], json!(1));
    assert_eq!(p["network"], json!("liquid-regtest"));
    assert!(p["tip_height"].is_u64(), "{p}");
    assert!(p["as_of"].is_i64() || p["as_of"].is_u64(), "{p}");
    assert_eq!(p["wallet"]["escrow_fingerprint"], json!("73c5da0a"));
    assert!(p["loans"].is_array(), "{p}");
    assert!(p["offers"].is_array(), "{p}");
    for l in p["loans"].as_array().unwrap() {
        assert_keys(
            "loan",
            l,
            &[
                "id",
                "ref",
                "role",
                "state",
                "principal",
                "collateral",
                "interest",
                "templar_fee",
                "opened_at",
                "start_height",
                "term_height",
                "blocks_left",
                "due_at_estimate",
                "owed",
                "next_action",
                "pending_request",
                "txids",
                "escrow_address",
            ],
        );
    }
    eprintln!(
        "portfolio: {} loan(s), {} offer(s), tip {}",
        p["loans"].as_array().unwrap().len(),
        p["offers"].as_array().unwrap().len(),
        p["tip_height"]
    );
    if let Ok(out) = std::env::var("TEMPLAR_LIVE_OUT") {
        std::fs::write(&out, serde_json::to_string_pretty(&p).unwrap()).unwrap();
        eprintln!("portfolio JSON written to {out}");
    }

    // §8: the one-time link, landing on the site's front page.
    let open_url = p_url.trim_end_matches("/connector/portfolio").to_string() + "/connector/open";
    let (status, o) = live_bearer("POST", &open_url, &token, Some(&json!({ "to": "/" })));
    assert_eq!(status, 200, "open: {o}");
    let link = o["url"].as_str().expect("one-time url");
    assert!(link.contains("/connector/open/"), "{link}");
    assert!(o["expires_at"].is_i64() || o["expires_at"].is_u64(), "{o}");
    eprintln!("one-time browser link (2 min, single use): {link}");

    // A wrong token is 401, and a wrong path on the open link is still same-site.
    let (status, _) = live_bearer(
        "GET",
        p_url,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        None,
    );
    assert_eq!(status, 401);
}

#[cfg(feature = "protocol")]
/// §9.2 / §9.5 against the live site: a `proof` signing request the site
/// built is recognised as the check of its own challenge by the wallet's
/// recomputation, signed once, and accepted by the site.
#[test]
#[ignore = "needs the protocol's regtest site and TEMPLAR_LIVE_SIGN_LINK (a proof request)"]
fn live_proof_request_is_recognised_signed_and_accepted() {
    let (url, nonce) = live_link(&live_env("TEMPLAR_LIVE_SIGN_LINK"), "sign");
    let (status, req) = live_get(&url);
    assert_eq!(status, 200, "sign request: {req}");
    assert_eq!(req["kind"], json!("sign"), "{req}");
    assert_eq!(req["nonce"], json!(nonce), "{req}");
    assert_eq!(req["action"], json!("proof"), "{req}");
    let challenge = req["challenge"].as_str().expect("challenge").to_string();
    let pset = req["pset"].as_str().expect("pset").to_string();
    let callback = req["callback"].as_str().unwrap().to_string();

    let mut env = TestEnv::new();
    let id = live_wallet(&mut env, req["policy_asset"].as_str());

    // The wallet's own reading: not a coin of ours in the usual sense, 0, fee 0.
    let d = env.ok(
        "inspect_pset",
        json!({ "wallet_id": id, "pset_base64": pset }),
    );
    assert_eq!(d["fee_sats"], json!(0), "{d}");
    assert_eq!(d["inputs"][0]["amount_sats"], json!(0), "{d}");

    // The site's check is byte-for-byte the wallet's own check.
    let v = env.ok(
        "protocol_is_check_pset",
        json!({ "wallet_id": id, "challenge": challenge, "pset_base64": pset }),
    );
    assert_eq!(v["is_check"], json!(true), "{v}");

    let signed = env.ok("sign_pset", json!({ "wallet_id": id, "pset_base64": pset }));
    let (status, reply) = live_post(
        &callback,
        &json!({ "version": 1, "id": req["id"], "nonce": nonce, "pset": signed }),
    );
    assert_eq!(status, 200, "signed callback: {reply}");
    assert_eq!(reply["ok"], json!(true), "{reply}");
    eprintln!("proof accepted; next = {}", reply["next"]);
    // §7: the token a v1 wallet did not get at connect arrives here, once
    // the key is proved — what `_storePortfolioFromSign` in the app keeps.
    let portfolio = &reply["portfolio"];
    assert!(
        portfolio["url"].is_string() && portfolio["token"].is_string(),
        "the signed callback of a proof request carries the portfolio object: {reply}"
    );
    let (status, p) = live_bearer(
        "GET",
        portfolio["url"].as_str().unwrap(),
        portfolio["token"].as_str().unwrap(),
        None,
    );
    assert_eq!(status, 200, "portfolio after proof: {p}");
    assert_eq!(p["wallet"]["escrow_fingerprint"], json!("73c5da0a"), "{p}");
    eprintln!(
        "portfolio token received with the proof; {} loan(s)",
        p["loans"].as_array().map_or(0, Vec::len)
    );
}

#[test]
fn inspect_pset_describes_a_protocol_escrow_spend() {
    let mut env = TestEnv::new();
    let created = env.ok(
        "create_wallet",
        json!({ "name": "Borrower", "mnemonic": MNEMONIC, "liquid": true }),
    );
    let id = created["id"].as_str().unwrap().to_string();

    let d = env.ok(
        "inspect_pset",
        json!({ "wallet_id": id, "pset_base64": ESCROW_FIXTURE }),
    );
    // Exact keys PsetInspection.fromJson reads (pset_inspection.dart).
    assert_keys(
        "inspect_pset",
        &d,
        &[
            "network",
            "fee_sats",
            "fee_display",
            "recipients",
            "inputs",
            "outputs",
            "sigs_have",
            "sigs_needed",
            "signers_present",
            "signers_missing",
            "can_finalize",
            "raw_pset",
        ],
    );
    assert_eq!(d["network"], json!("liquid-testnet"));
    assert_eq!(d["fee_sats"], json!(500));
    // The net-change lines the review leads with: none here, since every
    // output is explicit and none is this wallet's own; the list is still
    // there for the Dart side to read.
    assert!(d["net_change_lines"].is_array(), "{d}");
    for line in d["net_change_lines"].as_array().unwrap() {
        assert_keys(
            "net_change_lines[]",
            line,
            &["asset_id", "ticker", "amount_sats", "display_amount"],
        );
    }

    let inputs = d["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 1);
    assert_keys(
        "inputs[0]",
        &inputs[0],
        &[
            "index",
            "outpoint",
            "is_ours",
            "script_type",
            "witness_script",
            "witness_script_asm",
            "asset_id",
            "ticker",
            "amount_sats",
            "display_amount",
            "key_fingerprints",
            "signed_by",
        ],
    );
    assert_eq!(
        inputs[0]["is_ours"],
        json!(true),
        "our 2121' key is in the escrow"
    );
    assert_eq!(inputs[0]["script_type"], json!("p2wsh"));
    assert!(inputs[0]["witness_script"].is_string());
    assert!(inputs[0]["witness_script_asm"]
        .as_str()
        .unwrap()
        .contains("OP_CHECKMULTISIG"));
    assert_eq!(inputs[0]["amount_sats"], json!(1_000_000));
    assert_eq!(inputs[0]["ticker"], json!("LBTC"));
    assert!(inputs[0]["key_fingerprints"]
        .as_array()
        .unwrap()
        .contains(&json!("73c5da0a")));
    assert_eq!(inputs[0]["signed_by"], json!([]));

    let outputs = d["outputs"].as_array().unwrap();
    assert_keys(
        "outputs[0]",
        &outputs[0],
        &[
            "index",
            "kind",
            "script_type",
            "address",
            "asset_id",
            "ticker",
            "amount_sats",
            "display_amount",
        ],
    );
    let kinds: Vec<&str> = outputs
        .iter()
        .map(|o| o["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["external", "fee"]);
    assert_eq!(outputs[0]["amount_sats"], json!(999_500));
    assert_eq!(d["recipients"].as_array().unwrap().len(), 1);

    // Signing through the same route the co-sign screen and the templar://
    // handler use adds the borrower's escrow signature.
    let signed = env.ok(
        "sign_pset",
        json!({ "wallet_id": id, "pset_base64": ESCROW_FIXTURE }),
    );
    let signed = signed.as_str().unwrap().to_string();
    let after = env.ok(
        "inspect_pset",
        json!({ "wallet_id": id, "pset_base64": signed }),
    );
    assert_eq!(after["inputs"][0]["signed_by"], json!(["73c5da0a"]));
    assert_eq!(after["sigs_have"], json!(1));

    // On regtest the same PSET is refused: it carries testnet LBTC.
    env.ok("set_liquid_network", json!({ "network": "regtest" }));
    let err = env.err(
        "inspect_pset",
        json!({ "wallet_id": id, "pset_base64": ESCROW_FIXTURE }),
    );
    assert!(err.contains("Network mismatch"), "{err}");
    assert!(err.contains("Liquid testnet"), "{err}");
}

/// Without the `hardware` feature (the Android build) the hardware routes stay
/// in the contract: `hwi_status` says so explicitly, and every USB entry point
/// answers with the stable `HW_UNSUPPORTED` tag — never "Unknown method".
#[cfg(not(feature = "hardware"))]
#[test]
fn hardware_routes_answer_unsupported_without_the_feature() {
    let mut env = TestEnv::new();
    let v = env.ok("hwi_status", json!({}));
    assert_eq!(v["hardware_supported"], json!(false), "{v}");
    assert_eq!(v["hwi_usable"], json!(false), "{v}");
    assert_eq!(v["liquid_hw_signing"], json!(false), "{v}");
    assert_eq!(v["hid_device_count"], json!(0), "{v}");
    assert_eq!(v["native_families"], json!([]), "{v}");
    assert!(v["platform"].is_string(), "{v}");
    assert!(v["resolved_bin"].is_null(), "{v}");
    for method in [
        "enumerate_hw_devices",
        "enumerate_native_devices",
        "jade_ports",
        "import_hw_wallet",
        "sign_psbt_hw",
        "verify_hw_address",
        "set_hwi_path",
        "add_liquid_to_wallet",
    ] {
        let err = env.err(method, json!({}));
        assert!(err.starts_with("HW_UNSUPPORTED: "), "{method}: {err}");
    }
    // The pure descriptor helper is not hardware and must keep working.
    let ct = env.ok(
        "derive_liquid_descriptor",
        json!({ "btc_desc": "tpubDCVwWj4hEpeWNFcWe3Eo1DrkLnPC4c2iitjw5wAuTkSZgofJbRMD4KESh1uhsqLCCjcjR36JooEFwfWf1ezwmAfjcPCxc7KNtnfBCrMPdtT" }),
    );
    assert!(
        ct.as_str().unwrap_or("").starts_with("ct(elip151,elwpkh("),
        "{ct}"
    );
}
