# Architecture

How the two crates are cut, where state lives, how calls are serialized and
what ends up on disk. For the rules a change must keep, see
[CLAUDE.md](../CLAUDE.md); for the method list, [API.md](API.md).

## Crates and hosts

```text
host ──► TemplarLib::call(method, params) ──► dispatch ──► handlers ──► templar-core ──► BDK 0.30 / LWK 0.20
                                              (templarlib)                                 Electrum, elementsd RPC,
                                                                                           USB devices, HTTP services
```

| Package | Repository | Owns |
|---|---|---|
| `templar-core` | here, `crates/templar-core` | Bitcoin, Liquid, Miniscript, key derivation, signing, PSBT / PSET inspection, the vault, the wallet registry, chain backends, hardware drivers, QR (BC-UR). Stateless: every function takes what it needs. |
| `templarlib` | here, `crates/templarlib` | Process state, application workflows, the JSON method router, the DTOs, the single-instance lock on the data directory. |
| `wallet-ffi` | templar-wallet, `crates/wallet-ffi` | The C ABI the Flutter app loads: C strings, panic containment, zeroizing every response string it frees. |
| terminal client | templar-wallet, `apps/tui` | CLI parsing and terminal rendering over `TemplarLib`. |
| Flutter app | templar-wallet, `apps/gui` | Screens, navigation, platform integration. |
| Templar Protocol server | templar-protocol, `crates/templar-lend-connector`, `crates/templar-lend-ops` | Uses `templar-core` directly for escrow descriptors, settlement PSETs and a simulated wallet. |

A host never re-implements a wallet workflow. A workflow that needs
application state (the open wallet, the vault, the registry) goes in
`templarlib`; one that does not goes in `templar-core`.

## Layers inside `templarlib`

| File | Role |
|---|---|
| `src/lib.rs` | `TemplarLib` (the public facade), `METHODS` (every accepted method name), the mutex. |
| `src/dispatch.rs` | `dispatch()` wraps every result in `{"ok": …}` / `{"err": "…"}`. `try_dispatch()` answers `version` first, then fails every other call with the startup error if there is one, then routes by name: it deserializes the parameters into a DTO, opens the wallet when the method needs it (`ensure_wallet_open`), applies the network and asset guards, and calls a handler. |
| `src/handlers/` | The workflows, one module per area: `vault`, `registry`, `wallet_ops` (open, sync), `bitcoin` (dashboard, addresses, activity, UTXOs, sends, PSBT), `liquid` (network, sends, PSET, assets, the protocol methods), `hw` (USB devices, HWI, watch-only and hardware wallets), `backup`, `history`, `peg`, `swaps` (LiquiDEX), `cross_swaps` (BTC ↔ Liquid HTLC). |
| `src/state.rs` | `AppState`: everything one engine holds between calls. |
| `src/types.rs` | Request and response DTOs shared with hosts. Some handler-local DTOs live in their handler module (`peg`, `swaps`, `cross_swaps`, `history`, `backup`). |
| `src/contract_tests.rs` | Offline tests that drive `dispatch()` and assert the JSON keys hosts read. |

## State

One `AppState` per engine, created by `TemplarLib::new()` or
`TemplarLib::with_data_dir(dir)`:

| Field | Meaning |
|---|---|
| `data_dir` | Where everything is stored (see [Storage](#storage)). |
| `registry` | The wallet list, decrypted. Empty while a vault exists and is locked. |
| `vault` | The unlocked vault key, or `None` (no vault, or locked). Zeroized on drop. |
| `active_wallet_id`, `bitcoin`, `liquid` | The one open wallet: its BDK `WalletManager` and LWK `LiquidWalletManager`. Opening another wallet closes this one. |
| `last_sync_btc`, `last_sync_liquid`, `last_sync_at` | Per-chain outcome of the last `sync_wallet`, cleared on open. |
| `liquid_network`, `liquid_network_env_locked` | Liquid testnet or regtest (with its policy asset); locked when set by `TEMPLAR_LIQUID_NETWORK`. |
| `asset_registry` | Known Liquid assets for the active network. |
| `startup_error` | A fatal init condition: another process holds the data directory, or the registry cannot be read. Every call except `version` fails with it, so nothing can save over the data on disk. |
| `verify_failures`, `verify_lockout_until` | The throttle on `verify_vault_passphrase`. |
| `_instance_lock` | An exclusive advisory lock on `<data_dir>/app.lock`, held for the engine's lifetime. |

Only one wallet is open at a time. Methods that take a `wallet_id` open it
first when it is not the open one, which drops the previous wallet's
managers and sync state.

## Threading

BDK 0.30 is not thread-safe (`RefCell` inside), so the engine is one
`Mutex<AppState>`. `TemplarLib` is `Send + Sync`: a host may share it
behind an `Arc` and call it from any thread, but calls run one at a time,
in lock order. A sync, a broadcast or a hardware-device prompt holds the
lock for as long as it takes, and every other call waits. The Electrum
clients carry socket timeouts (5 s Bitcoin, 8 s Liquid) so a stalled server
cannot wedge the engine.

If a call panics while holding the lock, the next call recovers the
poisoned mutex and goes on: one bad call must not lock the user out. The
workspace builds with `panic = "unwind"` in release so that a host can
contain a panic with `catch_unwind` (the wallet's FFI crate does); a host
built with `panic = "abort"` turns any panic into a process exit.

## Storage

Everything lives under the data directory. Which directory:

1. `TemplarLib::with_data_dir(dir)`: `dir`. The app config is kept inside
   it too (`templar_wallet.json`), so a scratch engine never touches the
   user's real config.
2. `TemplarLib::new()`: `TEMPLAR_DATA_DIR` when set (config inside it, as
   above); otherwise the `data_dir` saved in the platform config file
   (`templar_wallet.json` in the OS config directory); on a first run with
   no config, the `data_dir` an installer wrote to `install.conf` beside
   the executable; otherwise `templar_wallet` under the OS data directory.

| Path | Content | Secret |
|---|---|---|
| `app.lock` | The single-instance lock. | no |
| `vault.json` | Vault header: KDF parameters, salt, a sealed verifier. | no (the key is never stored) |
| `registry.enc` | The wallet registry sealed with the vault key: recovery phrases, descriptors, frozen coins, Liquid configs. | sealed |
| `registry.json` (+ `.bak`, `.tmp`) | The plaintext registry of an install with no vault. Shredded when a vault is set up. A wallet with a recovery phrase cannot be created without a vault. | yes, on legacy installs |
| `templar_wallet.json` | App config (`data_dir`, last wallet, Liquid network) when the data directory was given explicitly. | no |
| `bdk_sw_<fingerprint>/`, `bdk_ms_<wallet id>/`, `bdk_hw_db/`, `bdk_watchonly_db/` | BDK sled databases (addresses, transactions, sync state). | no |
| LWK cache directories | `Wollet` persistence per network and descriptor; a cache, rebuilt when inconsistent. | no |
| `peg_orders.json`, `swap_offers.json`, `atomic_swaps.json` | Simulated peg orders, the wallet's own LiquiDEX offers, HTLC swap records. | no keys (swap keys and the maker's preimage are re-derived from the seed when needed) |
| `hwi/`, `venv/` | An HWI binary or virtualenv a host installed (with `hardware`). | no |

Writes of the registry and the JSON stores go through a temporary file and
a rename, so a crash leaves the previous version. A registry that fails to
parse is preserved, never overwritten, and reported as the startup error.

## Networks and chain access

- Bitcoin: testnet through Electrum (`TEMPLAR_ELECTRUM_URL` overrides the
  default server).
- Liquid: testnet through Electrum, or a local Elements regtest through
  `elementsd` JSON-RPC (default `http://127.0.0.1:18884`). Chosen with
  `set_liquid_network` or `TEMPLAR_LIQUID_NETWORK`; the backend with
  `TEMPLAR_LIQUID_BACKEND`, `TEMPLAR_LIQUID_ELECTRUM_URL`,
  `TEMPLAR_LIQUID_ELECTRUM_TLS`, `TEMPLAR_ELEMENTS_RPC_URL/USER/PASS`; the
  regtest policy asset with `TEMPLAR_LIQUID_REGTEST_POLICY_ASSET`.
- Order book and HTLC coordination: the local order book service
  (`services/orderbook` in templar-protocol, `http://127.0.0.1:3210` by
  default; `TEMPLAR_SWAP_BOOK_URL`, `TEMPLAR_SWAP_MARKETS_URL`,
  `TEMPLAR_SWAP_ADMIN_URL` override it).
- Hardware: Ledger and Jade in-process over USB; Trezor, Coldcard, KeepKey,
  BitBox through the `hwi` binary (`TEMPLAR_HWI_BIN` overrides the lookup).

No chain client is built when a wallet is opened, only when a method syncs
or broadcasts.

## Features

| Feature | Default | With it off |
|---|---|---|
| `hardware` | on | No USB stack in the build (no hidapi, serialport, Ledger client, `lwk_jade`, CBOR dialect, and no libudev on Linux). The 14 USB methods stay in `METHODS` and answer `HW_UNSUPPORTED: …`; `hwi_status` answers `hardware_supported: false`. QR air-gap signing, watch-only wallets and `derive_liquid_descriptor` remain. |
| `protocol` | on | No `templar_core::liquid::protocol`, and `get_protocol_escrow_xpub`, `protocol_check_pset`, `protocol_is_check_pset` are absent from `METHODS` and from dispatch. |

`templarlib`'s features forward to `templar-core`'s
(`protocol = ["templar-core/protocol"]`, `hardware =
["templar-core/hardware"]`), and `templarlib` depends on `templar-core`
with `default-features = false`, so turning a feature off on `templarlib`
really removes it. The Android build of the wallet uses `protocol` without
`hardware`. Why the protocol side is a feature:
[decision 0002](decisions/0002-protocol-feature-gate.md).
