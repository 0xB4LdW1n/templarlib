# CLAUDE.md — templarlib

The rules a change to this repository must keep. Each one exists because
breaking it loses funds, leaks a key or breaks a host silently. How the code
is laid out: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The method
contract: [docs/API.md](docs/API.md).

## 1. BDK 0.30 is not thread-safe

BDK 0.30 keeps `RefCell`s inside its wallet. While a sync runs, no other
method may touch the same wallet. The whole engine therefore sits behind one
`Mutex<AppState>` (`crates/templarlib/src/lib.rs`), and every call holds it
for its full duration.

- Never call into a `WalletManager` outside `TemplarLib::call`, and never
  hand a reference to `AppState`, a `WalletManager` or a
  `LiquidWalletManager` out of the lock.
- No background threads that touch wallet state, no async runtime inside a
  call.
- `TemplarLib::call` recovers a poisoned mutex on purpose: one panicking
  call must not lock a user out of their wallets. Keep it that way.
- Miniscript works inside `wsh()` only. `tr()` script paths and `musig()`
  need BDK 1.x; do not add them on 0.30.

## 2. LWK stays on 0.20

`lwk_wollet`, `lwk_signer`, `lwk_common` and `lwk_jade` stay on the 0.20
line, in step with the Templar Protocol server, which builds the same
escrow descriptors and PSETs from `templar-core`. Use the 0.20 API:
`WolletBuilder::with_legacy_fs_store` under the data directory (a cache
only: on an inconsistent cache it is deleted and rebuilt),
`Wollet::new(network, FakeStore)` when there is no data directory,
`get_details(&pset)`, `combine()`, `finalize(&mut pset)`; never the
deprecated `with_fs_persist` / `without_persist`. Software signers are
`SwSigner::new_with_network(…, Network::TestnetLiquid)`.

- A Liquid `ct()` descriptor wraps Elements scripts only (`elwpkh`,
  `elwsh`); plain `wpkh` inside `ct()` is rejected.
- Jade descriptors use the device's own SLIP-77 key, never ELIP-151.
- Liquid hardware signing is Jade only.

An LWK (or BDK) upgrade is a project of its own: it changes the Electrum
client and therefore the TLS stack (see [SECURITY.md](SECURITY.md)).

## 3. Offline-first

Opening a wallet, deriving addresses, inspecting and signing PSBTs / PSETs
must work with no network. Electrum and Elements RPC clients are built only
in the sync and broadcast paths (`make_electrum_blockchain` in
`bitcoin/wallet.rs`, `LiquidChain` in `liquid/chain.rs`), never in a wallet
constructor. The Electrum clients carry a socket timeout (5 s on Bitcoin,
8 s on Liquid); a new network client needs one too, because a stalled
server would otherwise hold the engine mutex, and every host call, forever.

## 4. The vault

Recovery phrases and signing descriptors are sealed at rest with Argon2id
and XChaCha20-Poly1305 (`crates/templar-core/src/vault.rs`).

- A recovery phrase is never written in plaintext. `create_wallet`, and
  `create_multisig_wallet` with local keys, refuse without a vault
  (`require_encryption_for_seed`).
- Every handler that reads a secret or saves the registry calls
  `ensure_unlocked` first. Saving while a vault is locked would write a
  plaintext `registry.json` beside `registry.enc` and lose the wallet on
  the next unlock.
- `setup_vault` writes the header (salt) before the sealed registry, and
  rolls back on failure. Keep that order.
- `KdfParams::CURRENT` is checked at compile time (≥ 64 MiB, ≥ 3 passes).
  `KdfParams::FAST_FOR_TESTS` is for tests only.
- Secrets live in `Zeroizing` buffers. A type that carries a key has no
  `Debug` derive (`VaultKeyParams`).
- `verify_vault_passphrase` stays throttled (5 wrong tries, 60 s lockout)
  and grants no session.

## 5. Frozen coins are never spent

The frozen set lives on the registry entry (`WalletEntry.frozen`,
`crates/templar-core/src/frozen.rs`). Every transaction builder takes it
(`AppState::frozen_on`): BDK leaves the coins out as unspendable, LWK
through `set_wallet_utxos` where LWK allows it (payments that move only
L-BTC) and refuses otherwise. Every signer runs `refuse_frozen_inputs`
before a key touches the transaction, including PSBTs and PSETs built by
someone else. A new spend or sign path must do both.

## 6. Test networks only

Bitcoin testnet; Liquid testnet or a local Liquid regtest. Mainnet is
refused: keys on a mainnet coin type are refused at signing
(`liquid/pset.rs`), LiquiDEX proposals on mainnet L-BTC are refused, BDK
wallets are built for testnet. Do not add a mainnet path, a mainnet
default, or a setting that unlocks one.

- Peg-in / peg-out, the public asset registry and the public order book do
  not exist on regtest: those methods call `require_liquid_testnet`.
- Switching the Liquid network closes the open wallet. A wallet opened on
  one network must never be driven against the other's chain.
- Templar Protocol: Today the protocol runs on a test regtest; in beta it will run on a server of ours; then Liquid mainnet.

## 7. Feature gates

`hardware` and `protocol` are both default and both optional. CI builds
with them off; a change must too:

```bash
cargo check  --locked -p templar-core --no-default-features
cargo clippy --locked -p templarlib --no-default-features --all-targets -- -D warnings
```

- `hardware` off: the USB methods **stay** in `METHODS` and answer the
  stable tag `HW_UNSUPPORTED: …` (`dispatch.rs`), so a host can explain
  instead of showing "Unknown method". QR air-gap signing is pure Rust and
  stays.
- `protocol` off: `liquid::protocol` and the three methods
  `get_protocol_escrow_xpub`, `protocol_check_pset`,
  `protocol_is_check_pset` are **absent** from `METHODS` and from dispatch.
- Gate a feature's method name in `METHODS`, its dispatch arm, its
  handler and its tests together; only the plain DTOs in `types.rs` may
  stay ungated.

## 8. The JSON contract

`TemplarLib::call` returns `{"ok": value}` or `{"err": "message"}` and
nothing else. Hosts (the Flutter app, the terminal client, server hosts)
decode these shapes by key name.

- Adding a method: add it to `METHODS` and to `dispatch.rs`
  (`method_catalog_is_unique_and_points_at_dispatch_routes` checks both),
  document it in [docs/API.md](docs/API.md), add a contract test.
- Never rename or remove a response key, or change its type. Add new keys
  with `#[serde(default)]` on the DTO so older payloads still decode.
- Error strings that start with a tag (`HW_UNSUPPORTED:`,
  `LIQUID_HW_UNSUPPORTED:`, and the hardware tags `HWI_MISSING`,
  `HWI_PERMISSION`, `DEVICE_NOT_READY`, `DEVICE_NOT_FOUND`,
  `SIGNING_FAILED`) are matched by hosts. Keep the tag; the text after it may change.
- `version` answers before the startup-error gate; every other method fails
  with the startup error when the data directory is locked by another
  process or the registry is unreadable. Keep both.
- `crates/templarlib/src/contract_tests.rs` drives `dispatch()` against a
  throwaway data directory, offline, and asserts the exact keys hosts read.
  A shape change without a contract test change is a bug.

## 9. Never log

Logging goes to stderr with `eprintln!("[templarlib] …")`. Never log, print,
put in an error message or in a panic message:

- recovery phrases, passphrases, the vault key (`key_hex`), master private
  keys (`get_private_key`), descriptors that embed a `tprv` (use
  `templar_core::public_descriptor` before a descriptor reaches a device
  or an error);
- Elements RPC credentials (`LiquidBackend::describe` leaves them out);
- Templar Protocol bearer tokens, one-time link secrets, challenge
  signatures and proof PSETs;
- whole responses of `get_mnemonic`, `get_private_key`, `export_vault_key`
  and `verify_backup` parameters.

Logging a data directory path, a network name, a wallet count or a txid is
fine.

## 10. Before a commit

The gate CI runs, in [CONTRIBUTING.md](CONTRIBUTING.md#the-gate). Code,
comments and docs are in English. Docs follow the code: when they disagree,
fix the doc.
