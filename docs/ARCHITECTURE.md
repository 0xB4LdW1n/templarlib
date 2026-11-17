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

## Liquid signing checks

A Liquid PSET built elsewhere (a cosigner, a protocol site) passes these
before a key touches it. The co-signing routes (`sign_pset`, `sign_pset_hw`)
run them in `ensure_pset_signable`, before any key is unlocked:
`inspect_pset` (network, mainnet derivation paths), exactly one fee output,
no taproot input among the inputs this wallet signs and SIGHASH_ALL only on
the others, outputs whose amounts the commitments prove, then the frozen
coins. Every signer in `templar-core` —
`LiquidWalletManager::sign`, `sign_pset_with_mnemonic`, issuance, reissuance
and burn, `LiquidMultisigSetup::sign_pset_with_mnemonics`, the Jade's
`sign_pset` and `sign_multisig_pset` — runs the fee and sighash rules again
for its own key (`refuse_unsafe_signing`, `liquid/pset.rs`), so no route
reaches a key without them. The wallet does not sign taproot inputs on
Liquid. LWK 0.9 enforced these rules itself; 0.20 signs whatever sighash
type an input declares, and signs taproot inputs through `tap_key_origins`
at any path, a mainnet coin type included. LiquiDEX signs its own
`SIGHASH_SINGLE|ANYONECANPAY` maker input without these signers.

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
| `peg_orders.json`, `swap_offers.json`, `atomic_swaps.json` | Peg orders (addresses, txids, a peg-in's claim script and derivation index, signed transactions kept until they are seen on chain), the wallet's own LiquiDEX offers, HTLC swap records. | no keys (swap keys and the maker's preimage are re-derived from the seed when needed) |
| `hwi/`, `venv/` | An HWI binary or virtualenv a host installed (with `hardware`). | no |

Writes of the registry and the JSON stores go through a temporary file and
a rename, so a crash leaves the previous version. A registry that fails to
parse is preserved, never overwritten, and reported as the startup error.

## Networks and chain access

Which servers the engine talks to is decided in one place,
`templar_core::endpoints::Endpoints`, built by `AppState::endpoints` over
the stored test-server profile. Every value has the same precedence and
reports its source: **env** (an environment variable) > **profile** (a
joined Templar test server) > **setting** (a regtest policy asset set by
hand) > **default**.

- Liquid network: testnet, or an Elements regtest. Chosen with
  `set_liquid_network` or `TEMPLAR_LIQUID_NETWORK`; joining a test server
  switches to its regtest. A regtest's policy asset (and genesis, for a
  lab whose genesis is not the stock `liquidregtest` one):
  `TEMPLAR_LIQUID_REGTEST_POLICY_ASSET` > the lab's > the one set by hand >
  stock.
- Liquid backend (`LiquidBackend::resolve`): `TEMPLAR_LIQUID_BACKEND`
  (`electrum` | `elements_rpc`, with `TEMPLAR_LIQUID_ELECTRUM_URL`,
  `TEMPLAR_LIQUID_ELECTRUM_TLS`, `TEMPLAR_ELEMENTS_RPC_URL/USER/PASS`) >
  on regtest, `TEMPLAR_ELEMENTS_RPC_URL` > on regtest, the lab's Electrum
  server > the default: Blockstream's testnet Electrum, or `elementsd`
  JSON-RPC on `http://127.0.0.1:18884` for regtest. A test server never
  changes how Liquid testnet is reached. The resolved backend is pinned on
  the open wallet (`LiquidWalletManager::set_chain_backend`), so sync,
  broadcast and LiquiDEX deep checks use it.
- Bitcoin (`Endpoints::bitcoin_backend`): testnet through Electrum, except
  beside a lab's Liquid regtest whose `bitcoin_network` is `regtest`:
  Bitcoin regtest through the lab's Electrum, with its BDK databases under
  `<data_dir>/bitcoin-regtest/`. `TEMPLAR_ELECTRUM_URL` overrides the server
  of either. Keys, descriptors, coin selection and signing are the same on
  both.
- Order book and HTLC coordination: the order book service
  (`services/orderbook` in templar-protocol): its routes `…/api/book`,
  `…/api/markets`, `POST …/api/offers` (publish) and `…/api/atomic-swaps`
  on the lab's `orderbook_url`, else `http://127.0.0.1:3210`;
  `TEMPLAR_SWAP_BOOK_URL`, `TEMPLAR_SWAP_MARKETS_URL`,
  `TEMPLAR_SWAP_ADMIN_URL` (publish, for old admin-route setups) override
  single routes.
- Hardware: Ledger and Jade in-process over USB; Trezor, Coldcard, KeepKey,
  BitBox through the `hwi` binary (`TEMPLAR_HWI_BIN` overrides the lookup).
- Peg provider (`Endpoints::peg_provider`): the lab's native Elements peg
  on its own regtest, when its config names `"native"` with complete
  terms; on Liquid testnet, SideSwap's swap service when the joined lab's
  config names `"sideswap"` for testnet (the endpoint:
  `TEMPLAR_SIDESWAP_URL` > SideSwap's testnet default); none otherwise
  (testnet has no parent chain; a plain regtest has no peg). See
  [Peg](#peg).

### Untrusted servers

- **Deadlines.** A socket timeout bounds one read; a server trickling a
  byte before each one would hold the engine mutex for ever.
  `templar_core::net::DeadlineStream` bounds a whole step instead (connect,
  TLS, upgrade, each request): SideSwap and the peg's Bitcoin chain view
  use it. Name resolution is outside it. The BDK and LWK Electrum clients
  still carry per-read timeouts only.
- **HTTP.** `templar_core::http` is how the engine reads the order book,
  the HTLC coordinator, the asset registry and the peg's Esplora: no
  redirects, connect and whole-request timeouts, bounded bodies, error
  texts without the URL and reduced to a printable excerpt.
- **Chain identity.** Bitcoin regtest and testnet wallets derive the same
  scripts. Every sync, broadcast and lookup of a `WalletManager`, and the
  peg's chain view, first checks the Electrum server's block 0 is the
  network's genesis (`bitcoin::wallet::require_genesis`).
- **Swap coordinator.** Cross-chain swaps keep the terms the wallet
  created or accepted and rebuild both HTLCs from them on every step; a
  coordinator row that disagrees is refused, so a coordinator can stall a
  swap but not redirect a payment.

### Test servers

`set_test_server` fetches `<url>/api/config` (`templar_core::test_server`,
contract version 1 of the Templar testlab), validates it as a trust
boundary (http(s) only, no redirects, 64 KiB and 10 s bounds, 64-hex ids,
`tcp://`/`ssl://` Electrum URLs, nothing naming a mainnet) and stores it in
the app config (`AppConfig.test_server`). Only its `liquid-regtest` block
and `orderbook_url` are applied. `<data_dir>/regtest_instance` records the
lab `instance_id` the regtest data was synced against; when it differs
(the lab reset its chains, or the wallet joined or left a lab) the regtest
chain caches (`liquid-regtest/`, `bitcoin-regtest/`) and regtest swap
offers are dropped, never keys or the registry.

No chain client is built when a wallet is opened, only when a method syncs
or broadcasts.

## Peg

`handlers/peg/` keeps the orders (`peg_orders.json`) and routes each step
to the provider of the active network; `handlers/peg/native.rs` is the
native provider, built from `templar_core::peg` (the peg-out script, the
Bitcoin chain view, claim-evidence checks), `LiquidChain::fed_peg` and
`LiquidWalletManager::{pegin_address, create_pegin_claim, create_pegout}`.

- **Peg-in.** The federation comes from the Liquid chain itself (the full
  dynafed header at the current epoch boundary); the deposit address is
  LWK's `pegin_address` over one of the wallet's external indexes, a
  P2SH-P2WSH address on the lab. The order stores the index, the epoch
  height and the federation script and program, so the same address is
  rebuilt at claim time. An address is only guaranteed valid through a
  Liquid height; past it, a status check renews it while the federation is
  unchanged and expires the order otherwise. Deposits are followed on the
  wallet's Bitcoin Electrum server: every output paying the address is
  recorded by outpoint (at most 64 per order) and claimable on its own.
  The order follows the deposit the wallet paid, else the first carrying
  at least the expected amount, so a dust payment by whoever saw the
  address cannot take the order over; a transaction paying the address
  more than once is `unclaimable` (LWK claims a transaction that pays the
  address exactly once; the lab operator can recover it).
- **Claim evidence.** The wallet's Bitcoin Electrum server is the chain
  view; the lab's Esplora only supplies the raw deposit and its merkle
  proof. `verify_pegin_evidence` requires the transaction to pay the
  address exactly once, the proof to commit to it (LWK's `PeginFunding`),
  the transaction to be the one Electrum lists, the proof's block hash to
  be Electrum's block at that height, and the depth to be reached. LWK
  alone checks only the proof against its own header.
- **Claim.** `add_pegin_input` with an empty manual coin selection (no
  wallet coin, frozen or not) and everything but the fee to the payout
  address; signed by `LiquidWalletManager::sign`, so the signing guard
  runs; the finalized transaction is checked to spend only the peg-in.
  The signed claim is stored on its deposit before the broadcast; a retry
  sends those bytes, a status check follows the claim by its txid first,
  and a refused rebroadcast builds a new claim only if the deposit's block
  changed (a reorg), so a lost answer never leads to a double claim.
- **Peg-out.** LWK has no peg-out builder. The peg-out output is added as
  an ordinary LWK `Recipient` whose script is `OP_RETURN <parent genesis>
  <Bitcoin scriptPubKey>` and which has no blinding key — exactly how LWK
  builds a burn — so LWK selects coins, adds change and the fee, and
  blinds the other outputs around the explicit one, balanced. The builder
  checks the output came out explicit; the finalized transaction is
  checked with Elements' own `pegout_data()` (one peg-out, the amount, the
  policy asset, the genesis, the destination). The guard counts only
  empty-script outputs as fees, so the `OP_RETURN` output is not one.
  The Bitcoin genesis is read from the wallet's Bitcoin server and must be
  the one the Liquid chain is pegged to. A peg-out below the lab's
  `pegout_min_sat` (default 100 000) is refused: the lab never pays it.
  *Residual risk:* the parent genesis the output names is LWK's for a
  custom Elements chain (Bitcoin regtest's), checked against the Bitcoin
  server the lab publishes, not against the Liquid chain itself: the
  wallet's Electrum view of Liquid does not carry the chain's parent
  (elementsd's `getsidechaininfo` does). A lab whose elementsd were pegged
  to another parent than the Bitcoin regtest it publishes would turn a
  peg-out into a burn. The lab's contract (`api-config.md`) fixes the
  parent as its Bitcoin regtest; a successful peg-in claim on the same
  chain also proves it, since elementsd checks the claim's parent genesis.
- **SideSwap** (`handlers/peg/sideswap.rs`, `templar_core::sideswap`) on
  Liquid testnet: a custodial swap by a third party over JSON-RPC on a
  WebSocket (tungstenite, rustls with ring). One socket per engine call,
  15 s for TCP + TLS + upgrade and 15 s per call, as deadlines for the
  whole step (`templar_core::net`), 64 KiB messages. Only the receive
  address, the direction and a fee rate are sent. Answers are parsed
  strictly; a server whose policy asset is not Liquid testnet L-BTC is
  refused; a deposit address must belong to the chain it is paid on; a
  status must name the order's own addresses and only moves an order
  forward; the deposit the wallet paid is the only one followed; a payout
  counts only if it is new to the receive address (recorded when the order
  opened), not counted by another order, in a block on the wallet's own
  chain view and worth at least the quote (on Liquid, read from the synced
  wallet that owns the address); `failed` is taken on SideSwap's word only
  for a deposit paid from elsewhere. SideSwap's testnet runs on Bitcoin testnet3, the chain of the
  wallet's default testnet Electrum.
- **Signing only on request.** `peg_status` / `peg_list` read chains and
  never sign. `peg_fund` and `peg_claim` sign; each signed transaction is
  written to the order before its broadcast and rebroadcast as is on a
  retry, so a lost answer never pays twice.

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
