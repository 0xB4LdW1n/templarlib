//! Embedding `templarlib` in a host: the lifecycle a business host follows,
//! run offline against a throwaway data directory.
//!
//! ```text
//! cargo run -p templarlib --example embed                 # the walkthrough
//! cargo run -p templarlib --example embed -- <method> ['<json params>']
//! ```
//!
//! The second form calls one method on a fresh, empty data directory and
//! prints the raw envelope, e.g. `-- get_liquid_network` or
//! `-- validate_cosigner_key '{"key":"..."}'`. Never pass a passphrase or a
//! recovery phrase on the command line: it stays in shell history.
//!
//! Nothing here touches the network: no method that syncs or broadcasts is
//! called. See `docs/INTEGRATION.md` for the reasoning behind each step.

use std::sync::Arc;

use serde_json::{json, Value};
use templarlib::TemplarLib;

/// Throwaway passphrase for the throwaway vault this example creates. A real
/// host reads the passphrase from its user and never stores or logs it.
const DEMO_PASSPHRASE: &str = "example-only passphrase, temp data dir";

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;

    if let Some(method) = args.first() {
        let params: Value = match args.get(1) {
            Some(raw) => serde_json::from_str(raw).map_err(|e| format!("params: {e}"))?,
            None => json!({}),
        };
        let engine = TemplarLib::with_data_dir(dir.path());
        println!("{}", engine.call(method, &params));
        return Ok(());
    }

    walkthrough(dir.path())
}

/// Unwraps the `{"ok": …}` / `{"err": "…"}` envelope every call returns.
fn ok(engine: &TemplarLib, method: &str, params: Value) -> Result<Value, String> {
    let mut response = engine.call(method, &params);
    if let Some(value) = response.get_mut("ok") {
        return Ok(value.take());
    }
    let reason = response["err"].as_str().unwrap_or("malformed envelope");
    Err(format!("{method}: {reason}"))
}

fn walkthrough(data_dir: &std::path::Path) -> Result<(), String> {
    // 1. One engine per data directory, for the life of the process. It takes
    //    an exclusive lock on `<data_dir>/app.lock`; a second engine (or a
    //    second process) on the same directory gets a startup error on every
    //    call instead.
    let engine = Arc::new(TemplarLib::with_data_dir(data_dir));
    println!("data dir     {}", data_dir.display());
    println!("version      {}", ok(&engine, "version", json!({}))?);
    println!("methods      {}", TemplarLib::methods().len());

    // 2. The vault. A fresh directory has none; a recovery phrase is never
    //    stored without one, so set it up before creating a software wallet.
    let status = ok(&engine, "vault_status", json!({}))?;
    println!("vault        {}", status["state"]);
    if status["state"] == "none" {
        ok(
            &engine,
            "setup_vault",
            json!({ "passphrase": DEMO_PASSPHRASE }),
        )?;
    }
    println!(
        "vault        {}",
        ok(&engine, "vault_status", json!({}))?["state"]
    );

    // 3. A software wallet with a Bitcoin and a Liquid side. The words go
    //    straight from one call into the next and are never printed.
    let words = ok(&engine, "generate_mnemonic", json!({ "word_count": 12 }))?;
    let mnemonic = words
        .as_array()
        .ok_or("generate_mnemonic: expected a word list")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let wallet = ok(
        &engine,
        "create_wallet",
        json!({ "name": "Example", "mnemonic": mnemonic, "liquid": true }),
    )?;
    let wallet_id = wallet["id"].as_str().ok_or("create_wallet: no id")?;
    println!(
        "wallet       {} ({}, liquid: {})",
        wallet["name"], wallet["wallet_type"], wallet["liquid_enabled"]
    );

    // 4. Opening a wallet is offline: no Electrum client is built until a
    //    sync or a broadcast. Addresses are derived locally.
    ok(&engine, "open_wallet", json!({ "wallet_id": wallet_id }))?;
    for asset in ["BTC", "LBTC"] {
        let address = ok(
            &engine,
            "generate_receive_address",
            json!({ "wallet_id": wallet_id, "asset": asset }),
        )?;
        println!("receive {asset:<5}{}", address["address"]);
    }
    let network = ok(&engine, "get_liquid_network", json!({}))?;
    println!(
        "liquid       {} via {}",
        network["network"], network["backend"]
    );

    // 5. Feature-gated methods exist only when the feature is compiled in.
    #[cfg(feature = "protocol")]
    {
        let key = ok(
            &engine,
            "get_protocol_escrow_xpub",
            json!({ "wallet_id": wallet_id }),
        )?;
        println!("escrow key   {key}");
    }
    #[cfg(not(feature = "protocol"))]
    println!(
        "escrow key   {}",
        engine.call(
            "get_protocol_escrow_xpub",
            &json!({ "wallet_id": wallet_id })
        )
    );

    // 6. Errors are values, not panics: an unknown method, bad parameters and
    //    a refused operation all come back as `{"err": "…"}`.
    println!("unknown      {}", engine.call("no_such_method", &json!({})));
    println!("bad params   {}", engine.call("open_wallet", &json!({})));

    // 7. Calls serialize on one internal mutex, so the engine can be shared
    //    across threads; long calls (sync, hardware) block the others.
    let shared = Arc::clone(&engine);
    let from_thread = std::thread::spawn(move || shared.call("vault_status", &json!({})))
        .join()
        .map_err(|_| "worker thread panicked")?;
    println!("from thread  {from_thread}");

    // 8. Locking drops the key and every decrypted secret and closes the
    //    wallet; reading the registry needs an unlock again.
    ok(&engine, "lock_vault", json!({}))?;
    println!("while locked {}", engine.call("list_wallets", &json!({})));
    ok(
        &engine,
        "unlock_vault",
        json!({ "passphrase": DEMO_PASSPHRASE }),
    )?;
    let wallets = ok(&engine, "list_wallets", json!({}))?;
    println!(
        "unlocked     {} wallet(s)",
        wallets.as_array().map_or(0, Vec::len)
    );
    Ok(())
}
