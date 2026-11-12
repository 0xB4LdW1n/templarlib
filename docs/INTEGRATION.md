# Embedding templarlib in a host

How a business host (a service, a desktop or mobile app, a CLI) runs the
engine: which features to build, where the data lives, how the vault is
unlocked, how calls and errors work, and what the threading model asks of
you. The runnable version of this page is
[`examples/embed.rs`](../examples/embed.rs):

```bash
cargo run -p templarlib --example embed
```

It runs offline against a temporary data directory and needs no secrets.
For every method's parameters and response, see [API.md](API.md).

## 1. Depend on the crate

Until the first tag, depend on a checkout by path:

```toml
[dependencies]
templarlib = { path = "../templarlib/crates/templarlib" }
serde_json = "1"
```

Pick the features ([ARCHITECTURE.md](ARCHITECTURE.md#features)):

| Host | Features |
|---|---|
| Desktop app or service with USB signers, talking to Templar Protocol | default (`hardware`, `protocol`) |
| No USB stack (mobile, a server without devices) | `default-features = false, features = ["protocol"]` |
| Wallet only, no Templar Protocol | `default-features = false, features = ["hardware"]` or no features |

```toml
templarlib = { path = "../templarlib/crates/templarlib", default-features = false, features = ["protocol"] }
```

Cargo reads `[profile.*]` only from the workspace root. If your workspace
builds these crates, copy the profiles from this repository's
[Cargo.toml](../Cargo.toml): `panic = "unwind"` in release, and
`opt-level = 3` for `argon2`, `blake2`, `chacha20poly1305`, `chacha20`,
`poly1305` in dev builds (otherwise an unlock takes many seconds in a debug
build).

## 2. Create one engine per data directory

```rust
use templarlib::TemplarLib;

let engine = TemplarLib::with_data_dir("/var/lib/my-host/wallet");
```

- `with_data_dir(dir)` keeps the wallets **and** the app config inside
  `dir`. Use it in any host that manages its own storage.
- `TemplarLib::new()` resolves the directory the way the desktop app does
  (`TEMPLAR_DATA_DIR`, then the saved config in the OS config directory,
  then an installer's `install.conf`, then `templar_wallet` under the OS
  data directory) and may write the OS-level config file. Prefer
  `with_data_dir` unless you want to share the desktop app's wallets.

The engine takes an exclusive lock on `<dir>/app.lock` for its lifetime.
A second engine on the same directory, in this process or another, does
not panic: every call it receives fails with the startup error
`Another Templar Wallet instance is already using this wallet data. …`.
Create the engine once at start-up and keep it; drop it to release the
lock.

Construction never fails and never touches the network. Check that the
engine is usable with a cheap call:

```rust
let status = engine.call("vault_status", &serde_json::json!({}));
if let Some(err) = status.get("err") {
    // the data directory is locked by another process, or the registry is
    // unreadable: report `err` and stop. Nothing on disk was changed.
}
```

`version` always answers, even then, so you can tell "engine loaded but
init failed" apart from "engine missing".

What is stored where: [ARCHITECTURE.md § Storage](ARCHITECTURE.md#storage).
Back up the whole directory; `registry.enc` and `vault.json` together are
the wallets.

## 3. Unlock the vault

A recovery phrase is never stored without a vault. The lifecycle:

```text
vault_status ── state "none"     ──► setup_vault {passphrase}   ──► unlocked
             ── state "locked"   ──► unlock_vault {passphrase}  ──► unlocked
             ── state "unlocked" ──► (already open in this engine)
lock_vault   ──► locked: the key and every decrypted secret are dropped
```

- `needs_migration: true` in `vault_status` means the directory holds
  recovery phrases in plaintext (an install older than the vault). Ask for
  a passphrase and call `setup_vault` before anything else: it encrypts and
  shreds them.
- While locked, `list_wallets` and every method that reads a secret or
  saves the registry fail with `Vault is locked — unlock with your
  passphrase first`.
- `setup_vault` and `unlock_vault` run Argon2id with at least 64 MiB of
  memory. Budget for that on small machines.
- A host that has its own secure key store can call `export_vault_key`
  once unlocked, keep `key_hex` there, and later call
  `unlock_vault_with_key` without the passphrase. Treat `key_hex` as the
  wallets themselves.

Where the passphrase comes from is the host's decision: a person typing
it, or a secret manager for an unattended service. Never put it on a
command line, in an environment dump or in a log.

## 4. Call methods

```rust
use serde_json::{json, Value};

fn ok(engine: &TemplarLib, method: &str, params: Value) -> Result<Value, String> {
    let mut reply = engine.call(method, &params);
    match reply.get_mut("ok") {
        Some(v) => Ok(v.take()),
        None => Err(reply["err"].as_str().unwrap_or("malformed reply").to_string()),
    }
}

let wallet = ok(&engine, "create_wallet",
    json!({ "name": "Treasury", "mnemonic": phrase, "liquid": true }))?;
let id = wallet["id"].as_str().unwrap();
ok(&engine, "open_wallet", json!({ "wallet_id": id }))?;
let sync = ok(&engine, "sync_wallet", json!({ "wallet_id": id }))?;
// {"btc": "ok", "liquid": "error: Electrum connection failed: …"}
```

- `call` takes the method name and one JSON object of parameters and
  returns `{"ok": value}` or `{"err": "message"}`. It does not panic on
  bad input and does not return `Result`.
- One wallet is open at a time. Methods that take a `wallet_id` open it
  when needed, closing the previous one; switching back and forth costs a
  reopen each time.
- Opening, deriving addresses, previews and PSBT / PSET inspection and
  signing are local. `sync_wallet`, sends, broadcasts, the order book and
  hardware devices go to the network or a device and block (§6).
- `sync_wallet` reports each chain separately and succeeds when the wallet
  opened. Read `btc` and `liquid` instead of assuming a sync happened.
- A multisig send this engine cannot finish returns
  `{"partial_psbt": …}` / `{"partial_pset": …}` instead of a txid; pass it
  to the other signers, then `combine_*` and `broadcast_*`.
- Before signing anything built elsewhere, call `inspect_psbt` /
  `inspect_pset` and show or check the result: `net_change` is the
  wallet's own reading of what it gains or pays.
- `TemplarLib::methods()` lists what this build accepts; use it to hide
  features the build does not have.

## 5. Handle errors

Errors are human-readable strings meant to be shown. A few start with a
stable tag a host can branch on:

| Prefix | Meaning | What a host does |
|---|---|---|
| `HW_UNSUPPORTED:` | the build has no `hardware` feature | hide USB signing; offer QR air-gap |
| `LIQUID_HW_UNSUPPORTED:` | a Liquid asset on a Bitcoin-only device or air-gap path | explain that only a Jade signs on Liquid |
| `HWI_MISSING`, `HWI_PERMISSION`, `DEVICE_NOT_READY`, `DEVICE_NOT_FOUND`, `SIGNING_FAILED` | device errors | show the text, offer a retry |
| `Vault is locked` | the vault needs unlocking | ask for the passphrase |
| `Unknown method:` | the method is not in this build | check `TemplarLib::methods()` |

Everything else: show the message, keep the state you had. A failed call
leaves the engine usable.

## 6. Threading

`TemplarLib` is `Send + Sync`. Share it behind an `Arc`; calls from any
thread are serialized on one internal mutex (BDK 0.30 is not thread-safe),
so they never run concurrently.

- A sync, a broadcast or a hardware prompt holds the engine until it ends;
  every other call waits. Electrum clients time out after a few seconds,
  but a device waiting for a button press does not. Do not call the engine
  from a UI thread or an async executor thread; use a dedicated worker
  thread or `spawn_blocking`.
- A panic inside a call poisons nothing for you: the next call recovers
  the state and goes on. If your host must survive a panic, wrap `call` in
  `std::panic::catch_unwind` and build with `panic = "unwind"`.
- Never create two engines on one data directory to get parallelism: the
  second one is refused (§2).

## 7. Treat some responses as secrets

`get_mnemonic`, `get_private_key`, `export_vault_key` and
`generate_mnemonic` return secrets, and the parameters of `setup_vault`,
`unlock_vault`, `unlock_vault_with_key`, `verify_vault_*`, `create_wallet`,
`create_multisig_wallet`, `verify_backup`, `derive_*_cosigner_xpub` carry
them. Do not log requests or responses wholesale; drop or wipe those
buffers after use. The wallet's FFI layer zeroizes every response string it
frees for this reason.

## 8. Networks and environment

The engine runs on Bitcoin testnet and Liquid testnet, or a local Liquid
regtest; mainnet is refused. Choose the Liquid network with
`set_liquid_network` (persisted in the data directory's config when you use
`with_data_dir`). Environment variables override the servers (Electrum,
`elementsd`, the order book, HWI) and can pin the network; they are listed
in [ARCHITECTURE.md](ARCHITECTURE.md#networks-and-chain-access). They are
read by the engine process, so set them before it starts.

For Templar Protocol: Today the protocol runs on a test regtest; in beta it will run on a server of ours; then Liquid mainnet.
The wallet side of the protocol, what the host must check and send over
HTTP, is in [CONNECTOR.md](CONNECTOR.md).
