# Changelog

All notable changes to `templar-core` and `templarlib`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org): while the version starts
with 0, any release may change the method contract.

## [Unreleased]

### Repository

- `templar-core` and `templarlib` now live in their own repository,
  split out of the Templar Wallet repository with their git history. The
  workspace builds on its own; the wallet app, its terminal client and the
  Templar Protocol server depend on it by path until the first tag
  ([decision 0001](docs/decisions/0001-split-library-repository.md)).
- Dual licence: `MIT OR Apache-2.0` (`LICENSE-MIT`, `LICENSE-APACHE`).
- CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)): formatting,
  clippy with `-D warnings`, tests, the build with the optional features
  off, the examples, `cargo deny` and `cargo audit`, on every push to
  `main`, every pull request and once a day. The advisories accepted for
  the old TLS stacks of the BDK 0.30 / LWK 0.9 Electrum clients are listed
  in [SECURITY.md](SECURITY.md#known-advisories-accepted).
- Documentation: [README](README.md), [CLAUDE.md](CLAUDE.md),
  [architecture](docs/ARCHITECTURE.md), [method reference](docs/API.md),
  [integration guide](docs/INTEGRATION.md) with a runnable offline example
  (`cargo run -p templarlib --example embed`), and the
  [connector contract](docs/CONNECTOR.md), moved here from the protocol
  repository because it is the public contract the wallet implements.

### Added

- `protocol` feature (default on) on both crates. It gates
  `templar_core::liquid::protocol` and the methods
  `get_protocol_escrow_xpub`, `protocol_check_pset` and
  `protocol_is_check_pset`; with it off they are absent from `METHODS` and
  from dispatch ([decision 0002](docs/decisions/0002-protocol-feature-gate.md)).
  No behaviour change with the default features.
- Proof of key ([connector §9](docs/CONNECTOR.md#9-proof-of-key--the-check-pset)):
  `templar-core` builds the check PSET of a site's challenge for the
  wallet's loan key (`check_pset`), judges one (`check_pset_shape`,
  `is_check_pset`) and verifies its signature as a site would
  (`verify_check_signature`). Methods `protocol_check_pset` and
  `protocol_is_check_pset`. A Jade-backed wallet offers its BIP87 account
  as the loan key; proving it through a Jade is refused with a clear
  message.
- `inspect_pset` returns `net_change_lines`: the net change per asset with
  ticker and formatted amount.
- Fee bumping: `preview_fee_bump` (RBF, CPFP, cancel).
- Order book markets and publishing: `list_markets`, `swap_publish`.
- Bitcoin testnet ↔ Liquid testnet HTLC swaps: `atomic_swap_create`,
  `atomic_swap_join`, `atomic_swap_list`, `atomic_swap_fund`,
  `atomic_swap_claim`, `atomic_swap_refund`, coordinated by the local
  order book service.

### Changed

- The application engine moved out of the wallet's FFI crate into
  `templarlib`: `TemplarLib::call(method, params)` with the stable
  `{"ok": …}` / `{"err": "…"}` envelope, `METHODS`, and the DTOs in
  `templarlib::types`, shared by every host.

## [0.1.0] — 2026-09-24

Templar Wallet 0.1.0, the first public release. `templar-core` shipped in
it as it is here; the engine now in `templarlib` then lived inside the
wallet's FFI crate. Testnet only: Bitcoin testnet and Liquid testnet, plus a
local Liquid regtest for development. Mainnet is refused by design.

### Wallets

- Software single-sig (BIP84) with Bitcoin and, optionally, Liquid from the
  same recovery phrase.
- Multisig on Bitcoin (P2WSH, BIP48 keys) and Liquid (BIP87 keys, shared
  blinding key); keys from this device, other devices, hardware wallets or
  QR.
- Miniscript policy engine: templates, fragments, validator (inside
  `wsh()`).
- Watch-only wallets from descriptors, hardware wallets (Ledger and Jade
  over USB in-process, Trezor / Coldcard / KeepKey / BitBox through HWI)
  and air-gapped signing over animated QR (BC-UR).

### Security

- Recovery phrases sealed in a vault (Argon2id + XChaCha20-Poly1305) behind
  a passphrase; nothing secret written in the clear.
- Co-signing refuses a transaction whose amounts it cannot prove: Bitcoin
  inputs without consistent previous outputs, Liquid outputs whose blinded
  amounts do not open.
- Fee rates held to 0.1–1000 sat/vB, absurd fees refused, every Bitcoin
  transaction signals RBF.

### Coin control

- Frozen coins: a frozen coin stays in the balance but is never spent;
  automatic selection, MAX and consolidation leave it out, and a PSBT or
  PSET that would spend it, even one built by a co-signer or a protocol
  site, is refused before signing. On Liquid, a payment that moves an asset
  other than L-BTC cannot leave coins out yet and is refused with the
  reason.
- Consolidation of Bitcoin coins, reviewed and signed like any other
  transaction.

### Everything else

- Sends with several recipients, MAX, manual inputs; BIP21 receive.
- PSBT / PSET co-signing: inspect, sign, combine, broadcast.
- Liquid assets: issuance, reissuance and burn on testnet; LiquiDEX swaps;
  peg-in / peg-out against a simulated provider.
- Templar Protocol connector: the escrow account key and PSET inspection a
  wallet needs to connect to a site and sign loan transactions.

[Unreleased]: https://github.com/0xB4LdW1n/templarlib/compare/62bf911...HEAD
[0.1.0]: https://github.com/0xB4LdW1n/templarlib/commit/62bf911
