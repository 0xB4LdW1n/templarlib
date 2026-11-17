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
  the old TLS stack of the BDK 0.30 Electrum client are listed in
  [SECURITY.md](SECURITY.md#known-advisories-accepted).
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
- Test servers: `get_test_server`, `set_test_server`, `clear_test_server`.
  One setting, a Templar testlab's base URL, joins the wallet to a lab:
  its `/api/config` (version 1) is fetched, validated (http(s) only, no
  redirects, size and time bounds, well-formed ids and URLs, nothing naming
  a mainnet) and stored; the Liquid network becomes the lab's regtest
  (policy asset, genesis, its Electrum server: no RPC access needed), the
  Bitcoin side runs on the lab's Bitcoin regtest (`bcrt1…`, data under
  `bitcoin-regtest/`), and the order book is the lab's. Liquid testnet is
  never changed. The answer lists every server in use and its source
  (`env` | `profile` | `setting` | `default`). When the lab resets its
  chains (`instance_id`), the regtest chain caches and regtest swap offers
  are dropped; keys and the wallet list never are.
- `get_liquid_network` answers with `backend_source` and `test_server`.
- Native peg-in / peg-out on a joined test server's regtest (the lab's
  Elements peg between its Bitcoin regtest and its Liquid regtest), in
  place of the simulated provider: real deposit addresses bound to the
  wallet's claim scripts, real claims and real federation payments. New
  methods `peg_fund` (pay an order's deposit from its wallet: the BTC of a
  peg-in, the peg-out transaction) and `peg_claim` (claim a peg-in once
  deep enough), the only peg steps that sign. Before a claim the deposit's
  merkle proof is checked against the wallet's own Bitcoin Electrum view
  (the transaction it lists, the block it has at that height, the depth),
  not only against the proof's own header. New statuses `claimable` and
  `expired`; new `PegOrder` keys `provider`, `confirmations`,
  `confirmations_required`, `deposit_received_sats`, `txid_claim`,
  `valid_until_liquid_height`, `last_error`; new quote keys `provider`,
  `confirmations_required`, `network_fee_included`; `get_liquid_network`
  names the `peg_provider` or why there is none. Stable tags
  `PEG_UNAVAILABLE`, `PEG_NOT_READY`, `PEG_EXPIRED`, `PEG_PROOF_REJECTED`.
- Native peg-ins follow every payment to the deposit address:
  `PegOrder.deposits` (`PegDeposit`: `outpoint`, `amount_sats`,
  `confirmations`, `status` including `unclaimable`, `txid_claim`,
  `primary`, `note`), each claimable with `peg_claim {order_id,
  outpoint}`. The lab's optional `peg.pegout_min_sat` (default 100 000) is
  honoured: smaller native peg-outs are refused (the lab would burn them)
  and quoted as the minimum; the profile shows it.
- SideSwap on Liquid testnet, when the joined test server's config names
  it for testnet: the same peg methods open SideSwap swap orders (a
  custodial third-party service on Bitcoin testnet3, not a peg; provider
  `sideswap`, no `peg_claim`). Endpoint `TEMPLAR_SIDESWAP_URL`, default
  SideSwap's testnet. New status `failed`, new order key `expires_at`.
  New dependency: `tungstenite` (WebSocket).
- `swap_publish` refusals carry a tag per HTTP status of the order book:
  `BOOK_RATE_LIMITED`, `BOOK_CHAIN_UNREACHABLE`, `BOOK_DUPLICATE`,
  `BOOK_PUBLISH_DISABLED`, `BOOK_REJECTED`, `BOOK_UNAVAILABLE`,
  `BOOK_UNREACHABLE`.
- LiquiDEX proposals made by this wallet carry the optional
  `blinding_nonce` on their output leg, and the taker uses it (see Fixed).
- `templar-core`: `endpoints::Endpoints` (the one resolver of servers and
  backends), `test_server` (profile parsing and fetch),
  `LiquidBackend::resolve`, `LiquidNetwork::regtest_with_genesis` and an
  optional `genesis_hash` on `LiquidRegtest`, `BitcoinBackend` with the
  `WalletManager::*_on` constructors, `LiquidWalletManager::set_chain_backend`,
  and `verify_proposal_with` / `proposal_utxo_unspent_with` /
  `broadcast_transaction_with` (an explicit chain handle).

### Changed

- `list_utxos` names the address of a Bitcoin coin too (`address`, as it
  already did on Liquid, in the wallet's network encoding), so a host can
  group the coins that share one. `WalletManager::utxo_address` derives it
  from the coin's script, offline.
- The peg methods no longer refuse regtest as such: `peg_quote`,
  `peg_start`, `peg_fund` and `peg_claim` need a provider for the active
  network (`PEG_UNAVAILABLE: <why>` otherwise; Liquid testnet has none);
  `peg_status`, `peg_list` and `peg_cancel` work on stored orders anywhere.
  Orders of the retired simulated provider still list; an open one is
  closed as `expired` once and nothing can be paid to it.
- `swap_publish` posts to the order book's public, chain-verified
  `POST /api/offers` instead of the admin route (which answers 401 on a
  book with an admin password). `TEMPLAR_SWAP_ADMIN_URL` still overrides
  the URL.
- The order book's URLs, the HTLC coordinator (no longer hardcoded) and
  the chain backends come from one resolver: environment variables keep
  working and win over a test server, which wins over the defaults.
- `list_my_offers` lists the offers of the active Liquid network (offers
  stored before the network was recorded show on both).
- Taking, cancelling, deep-verifying and refreshing LiquiDEX offers go
  through the wallet's resolved chain backend instead of the environment's.
- A LiquiDEX proposal refused for failing verification says which check
  failed.

- The application engine moved out of the wallet's FFI crate into
  `templarlib`: `TemplarLib::call(method, params)` with the stable
  `{"ok": …}` / `{"err": "…"}` envelope, `METHODS`, and the DTOs in
  `templarlib::types`, shared by every host.
- Liquid runs on LWK 0.20 (`lwk_wollet`, `lwk_common`, `lwk_signer`,
  `lwk_jade`), up from 0.9, with `elements` 0.27, `elements-miniscript` 0.5
  and `electrum-client` 0.25. `lwk_wollet` keeps the features 0.9 had on by
  default. The Liquid Electrum connection now runs on rustls 0.23 and
  webpki-roots 1.x, so the old-TLS advisories that remain are BDK's alone
  ([SECURITY.md](SECURITY.md#known-advisories-accepted)). No method,
  response key or error tag changed, and the LiquiDEX v0 proposal format is
  unchanged. What a host can see differently comes from LWK:
  - `inspect_pset`, and the Liquid signing routes that inspect first,
    answer with an error when an output's blind proofs do not match its
    commitments, where the output used to come back flagged `unverified`;
    `inspect_pset` describes a PSET with no fee output, or several (the
    fee is their sum), instead of refusing it — signing it is still
    refused, in the same words as before; a recipient paid in the clear
    carries its address; `net_change` leaves out assets whose net change
    is zero.
  - Transaction history and `list_received_external_addresses` also count
    outputs paid to the wallet's scripts in the clear.
  - LWK selects the L-BTC inputs of a payment instead of spending them all.
  - TLS Electrum connections on Liquid always validate the server's name.
- Liquid signing refuses what LWK 0.9 never signed. LWK 0.20's software
  signer and Jade sign with whatever sighash type a PSET input declares,
  where 0.9 always produced SIGHASH_ALL; a SIGHASH_NONE, SINGLE or
  ANYONECANPAY signature would let whoever holds the PSET change what it
  pays. Every Liquid signer of `templar-core` now runs
  `refuse_unsafe_signing` for its key first, and `sign_pset` /
  `sign_pset_hw` run it before any key is unlocked: an input this wallet
  signs may declare no sighash type or SIGHASH_ALL only, and the PSET must
  have exactly one fee output (`refuse_bad_fee_outputs`, LWK 0.9's rule and
  words).
- The wallet does not sign taproot inputs on Liquid. LWK 0.9 never signed
  through `tap_key_origins`; 0.20's software signer does, at whatever path
  the PSET names — a mainnet coin type included, which the mainnet-path
  check (it reads `bip32_derivation`) does not see. `refuse_unsafe_signing`
  refuses every taproot input one of the wallet's keys would sign, on every
  route above. Other parties'
  inputs are not judged, and LiquiDEX keeps signing its maker input
  SIGHASH_SINGLE|ANYONECANPAY with its own signer.
- Rust API of `templar-core`: `LiquidNetwork::elements`, `from_elements`,
  `jade_network` and `LiquidWalletManager::elements_network` use LWK's
  `Network` (`TestnetLiquid`, `CustomElements`) in place of the removed
  `ElementsNetwork`, and the `elements` types it hands out (`Pset`,
  `Transaction`, …) are `elements` 0.27's.

### Fixed

- Security review of the peg branch:
  - a stored test-server profile is validated again when loaded (an
    invalid one is dropped, with testnet as the fallback; it used to
    panic the engine), and the app config is written atomically; lab
    peg confirmations are capped at 1000;
  - SideSwap and the peg's Bitcoin chain view are bounded by a deadline
    per step, not only per read;
  - the order book, the HTLC coordinator, the asset registry and the
    peg's Esplora are read with no redirects, bounded bodies and error
    texts without URLs; a login in the publish URL is never echoed;
  - a peg-in claim whose broadcast answer was lost is sent again, never
    signed twice; an order with a signed deposit, or a peg-in whose
    address was already paid, cannot be cancelled;
  - a SideSwap order completes only on a payout the wallet sees in a
    block, new, not another order's, worth at least the quote;
  - every Bitcoin sync, broadcast and lookup checks the Electrum server
    is on the wallet's network (block 0);
  - cross-chain swaps rebuild both HTLCs from the terms the wallet
    accepted and refuse a coordinator that disagrees.

- A LiquiDEX maker's wallet never saw the payment of a taken offer: the
  taker sealed the maker output's rangeproof with a random secret, which
  the maker cannot rewind. Found on the first live regtest run. Makers now
  reveal the secret (`blinding_nonce`) and takers use it; it opens only the
  amount and blinders the proposal already reveals. Signatures and sighashes
  are unchanged.
- Liquid Electrum servers without TLS (`tcp://`, or
  `TEMPLAR_LIQUID_ELECTRUM_TLS=0`) failed with "Cannot validate the domain
  without tls"; domain validation now applies only with TLS.

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
