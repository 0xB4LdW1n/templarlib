# Method reference

Every method `TemplarLib::call` accepts, read from
`crates/templarlib/src/dispatch.rs`, the handlers in
`crates/templarlib/src/handlers/` and the DTOs in
`crates/templarlib/src/types.rs`. When this page and the code disagree, the
code is right and this page has a bug.

**100 methods** with the default features (`METHODS` in
`crates/templarlib/src/lib.rs`, also `TemplarLib::methods()`):

- 97 always present;
- 3 only with the `protocol` feature, marked **[protocol]**: without it they
  are absent from `METHODS` and answer `Unknown method`;
- 14 of the 97 marked **[hardware]** need the `hardware` feature: without it
  they stay in `METHODS` and answer `HW_UNSUPPORTED: Hardware wallets over
  USB are not available on this platform. Use a QR air-gap wallet to sign
  instead.`

## Conventions

**Envelope.** Every call returns exactly one of

```json
{"ok": <value>}
{"err": "<human-readable message>"}
```

A method that has nothing to return answers `{"ok": null}`.

**Parameters** are one JSON object. Unknown keys are ignored. A missing
required key, or a value of the wrong type, fails with serde's message, e.g.
`{"err": "missing field `wallet_id`"}`. Methods listed with "Params: none"
ignore whatever they are given; pass `{}`.

**Types** in the tables: `string`, `bool`, `int` (JSON integer; `i64`
unless noted), `u64` / `u32` / `u8` / `usize` (non-negative integers; a
negative value is a parameter error), `f32` (JSON number), `[T]` (array),
`T?` (may be `null` or absent). Amounts are in base units (satoshis, or the
asset's smallest unit). Outpoints are `"txid:vout"`. PSBTs and PSETs are
base64.

**Opens the wallet.** Methods marked *opens* take a `wallet_id` and make
that wallet the open one first if it is not already (closing the previous
one). An unknown id then fails with `Wallet not found: <id>`.

**Network.** Methods marked *network* talk to an Electrum server, an
`elementsd` node, the order book service or a device, and hold the engine
for as long as that takes. Everything else is local.

### Errors every method can return

| Error | When |
|---|---|
| the startup error, e.g. `Another Templar Wallet instance is already using this wallet data. …` or `Wallet storage could not be read: …` | Another engine holds the data directory, or the registry is unreadable. Every method except `version` fails with it. |
| `Unknown method: <name>` | Not in `METHODS` (including the protocol methods when the feature is off). |
| serde messages (`missing field …`, `invalid type …`) | Bad parameters. |
| `Vault is locked — unlock with your passphrase first` | A vault exists and is locked, and the method reads a secret or saves the registry. |
| `Wallet not found` / `Wallet not found: <id>` | Unknown `wallet_id`. |
| `Bitcoin wallet not open` / `Liquid wallet not open` | The wallet has no side on that chain (a Bitcoin-only wallet asked for Liquid, a Liquid-only device entry asked for Bitcoin). |
| `<feature> is not available on Liquid regtest. Switch the Liquid network to testnet in Settings to use it.` | Peg and the public asset registry on regtest. |
| `HW_UNSUPPORTED: …` | A [hardware] method in a build without `hardware`. |
| `LIQUID_HW_UNSUPPORTED: …` | A Liquid asset on a Bitcoin-only hardware or air-gap path. |
| Hardware tags `HWI_MISSING`, `HWI_PERMISSION`, `DEVICE_NOT_READY`, `DEVICE_NOT_FOUND`, `SIGNING_FAILED` | Prefixes of device errors; the text after the tag explains. |
| Order-book tags `BOOK_RATE_LIMITED`, `BOOK_CHAIN_UNREACHABLE`, `BOOK_DUPLICATE`, `BOOK_PUBLISH_DISABLED`, `BOOK_REJECTED`, `BOOK_UNAVAILABLE`, `BOOK_UNREACHABLE` | Prefixes of `swap_publish` refusals ([`swap_publish`](#swap_publish)). |

Hosts should key on the tags, not on the text after them.

## Shared types

Response objects used by several methods. Fields are listed as `name:
type`; optional ones may be `null`.

**WalletSummary** (`WalletSummaryDto`): `id: string`, `name: string`,
`wallet_type: "singlesig" | "multisig" | "watch_only" | "policy"`,
`network: string`, `balance_sats: int`, `tx_count: usize`,
`last_sync_at: int` (Unix s), `is_watch_only: bool`, `type_label: string`,
`liquid_enabled: bool`, `bitcoin_enabled: bool`, `device_model: string?`,
`master_fingerprint: string?`, `xpub: string?`, `required_sigs: usize?`,
`total_signers: usize?`.

**TxOutputSpec** (a send recipient, parameter): `address: string`
(required), `amount_sats: int` (required; 0 allowed only with `send_max`),
`asset_id: string?` (Liquid; defaults to the call's `asset_id`),
`send_max: bool?` (at most one output).

**TxPreview** (`TxPreviewDto`): `chain: "bitcoin" | "liquid"`,
`recipient_address`, `amount_display`, `fee_sats: int`, `fee_display`,
`total_display`, `fee_rate: f64` (0 on Liquid), `vsize_est: int`,
`inputs: [TxIo]`, `outputs: [TxIo]`. **TxIo**: `outpoint: string?` (inputs
only), `address`, `amount_sats: int`, `is_change: bool`, `asset_id?`,
`ticker?`, `amount_display?`.

**Partial send**: a send that this device cannot finish alone (multisig
below threshold) returns, instead of a txid string,
`{"partial_psbt": string, "sigs_have": usize, "sigs_needed": usize?}` on
Bitcoin or
`{"partial_pset": string, "sigs_have": u32, "sigs_needed": usize, "chain": "liquid"}`
on Liquid. Nothing was broadcast.

**AddressInfo** (`AddressInfoDto`): `address`, `index: u32`, `asset`,
`label: string?`, `received_sats: int`, `derivation_path: string?`.

**PsbtInspection** (`PsbtInspectionDto`): `inputs: [{outpoint,
amount_sats: int?, display_amount, utxo_status: "ok" | "missing" |
"conflicting", is_mine: bool?}]`, `outputs: [{address, amount_sats,
display_amount, is_mine: bool?}]`, `fee_sats: int?` (null when an input
amount is unknown), `fee_display`, `sigs_present: usize`,
`sigs_required: usize?`, `signers: [{fingerprint, has_signed}]`,
`policy_hint`, `raw_psbt`, `finalized: bool`, `utxo_check` (worst input
status; anything but `"ok"` is refused at signing), `ownership_known: bool`
(a Bitcoin wallet was open).

**PsetInspection** (`PsetInspectionDto`): `network` (`liquid-testnet` |
`liquid-regtest`), `fee_sats: int`, `fee_display`, `recipients:
[{address?, asset_id?, ticker?, amount_sats?, display_amount?,
unverified}]`, `inputs: [{index, outpoint, is_ours, script_type,
witness_script?, witness_script_asm?, asset_id?, ticker?, amount_sats?,
display_amount?, key_fingerprints: [string], signed_by: [string],
threshold: u32?, unverified}]`, `outputs: [{index, kind: "own" | "escrow"
| "external" | "fee", script_type, address?, asset_id?, ticker?,
amount_sats?, display_amount?, unverified}]`, `sigs_have: u32`,
`sigs_needed: u32`, `signers_present: [string]`, `signers_missing:
[string]`, `can_finalize: bool`, `raw_pset`, `has_unverified_outputs: bool`
(signing is refused while true), `net_change: {asset_id: int}` (what this
wallet gains, negative = pays), `net_change_lines: [{asset_id, ticker,
amount_sats: int, display_amount}]`.

**IssueResult** (`IssueResultDto`): `asset_id`, `token_id: string?`,
`txid`, `registry_registered: bool`, `proof_url`, `proof_content`.

**LiquidNetwork** (`LiquidNetworkDto`): `network` (`liquid-testnet` |
`liquid-regtest`), `short_name` (`testnet` | `regtest`), `policy_asset`
(L-BTC id), `backend` (`electrum` | `elements_rpc`),
`backend_description` (no credentials), `env_locked: bool`,
`regtest_default_policy_asset`, `backend_source` (`env` | `profile` |
`default`: where the backend came from), `test_server: string?` (base URL
of the joined test server).

**TestServer** (`TestServerDto`), the answer of the three test-server
methods:

- `configured: bool`: a test server is joined.
- `profile: TestServerProfile?`: what the server's `/api/config` said,
  validated and normalised (no trailing slashes, lowercase hex):
  `base_url`, `name`, `version: u32`, `fetched_at: u64` (Unix s),
  `orderbook_url`, `regtest: {instance_id, policy_asset, genesis_hash,
  liquid_electrum_url, bitcoin_network, bitcoin_electrum_url,
  bitcoin_esplora_url, faucet_url, peg: {provider, pegin_confirmations:
  u32?, pegout_confirmations: u32?, pegout_max_sat: u64?}}`,
  `testnet: {faucet_url: string?, peg: {provider, …}?}?` (display only).
- `check: {reachable: bool, error: string?, server_instance_id: string?,
  stale: bool}?`: a live look at the server (`set_test_server`, and
  `get_test_server` with `check: true`). `stale` = the server now says
  something else than the stored profile (its chains were reset); call
  `set_test_server` again to apply it.
- `applied: {liquid_network, network_switched: bool, wallet_closed: bool,
  regtest_cache_reset: bool}?`: what `set_test_server` / `clear_test_server`
  changed; null on `get_test_server`. With `wallet_closed`, reopen the
  wallet (`open_wallet`); with `regtest_cache_reset`, its next sync
  rescans the regtest chains.
- `active`: the servers in use now, each with where it came from
  (`env` | `profile` | `setting` | `default`):
  `{liquid_network, env_locked: bool,
  orderbook: {origin, book, markets, publish, atomic_swaps} (each {url,
  source}), liquid: {network, policy_asset, genesis_hash: string? (a
  custom regtest genesis), params_source, backend (`electrum` |
  `elements_rpc`), backend_description, backend_source}, bitcoin:
  {network (`bitcoin-testnet` | `bitcoin-regtest`), electrum_url,
  source}}`. No credentials appear.

**PegOrder** (`PegOrderDto`): `order_id`, `wallet_id`, `direction` (`in` =
BTC → L-BTC, `out` = L-BTC → BTC), `status` (`awaiting_deposit` |
`deposit_seen` | `confirming` | `settling` | `completed` | `cancelled`),
`deposit_address`, `deposit_expected_sats: u64`, `payout_address`,
`payout_expected_sats: u64`, `created_at: u64`, `updated_at: u64`,
`eta_minutes: u32`, `txid_deposit?`, `txid_payout?`, `simulated: bool`,
`status_history: [{status, at: u64}]`.

**SwapLeg** (`SwapLegDto`): `asset_id`, `ticker`, `amount_sats: u64`,
`display_amount`.

**SwapAnalysis** (`SwapAnalysisDto`): `valid: bool`, `checks: [{name, ok:
bool?, note: string?}]`, `maker_offers: SwapLeg`, `maker_wants: SwapLeg`,
`network` (`testnet` | `mainnet` | `regtest` | `unknown`), `takeable:
bool`, `take_block_reason: string?`.

**MyOffer** (`MyOfferDto`): `offer_id` (`of_<8 hex>`), `kind`, `status`
(`open` | `closed` | `cancelled`), `created_at: u64`, `offers: SwapLeg`,
`wants: SwapLeg`, `proposal_json`, `utxo`.

**AtomicSwap** (`MyAtomicSwap`): `offer_id: u64`, `wallet_id`, `role`,
`key_index: u32`, `row: {id: u64, network, status, state, created_at,
updated_at}`, `next_action`, `can_fund: bool`, `can_claim: bool`,
`can_refund: bool`. `row.state` carries both legs (`offered_*`,
`wanted_*`: chain, asset id, ticker, name, precision, amount), the
`payment_hash`, both parties' keys and timeouts, contract addresses and
scripts, funding, claim and refund txids, `preimage_hex` once published,
and `note`.

---

## Engine and network

### `version`

The crate version, e.g. `"0.1.0"`. Answered before the startup-error gate,
so a host can tell "engine loaded, init failed" from "engine missing".
Params: none. Returns: `string`. Errors: none.

### `get_data_dir`

Params: none. Returns: `string`, the data directory in use. Errors: the
common ones.

### `get_liquid_network`

Params: none. Returns: **LiquidNetwork**. Errors: the common ones.

### `set_liquid_network`

Switch the Liquid network. Persists the choice and, when the network
changes, closes the open wallet: reopen and resync it. With a test server
joined, `regtest` is the server's regtest (its policy asset and genesis);
testnet is never changed by a test server.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `network` | string | yes | `testnet` \| `regtest` (`liquid-testnet` / `liquid-regtest` accepted) |
| `policy_asset` | string? | no | regtest only: the node's L-BTC asset id (hex); empty = the stock `liquidregtest` one |

Returns: **LiquidNetwork** after the switch. Errors: unknown network or bad
asset id; `The Liquid network is fixed by TEMPLAR_LIQUID_NETWORK for this
session; …`; `Could not save the network setting: …`; a `policy_asset`
other than the joined test server's (`Liquid regtest is the test server's
(…) … Clear the test server to use another regtest.`).

### `get_test_server`

The joined Templar test server ("testlab") and the servers in use.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `check` | bool | no | also fetch the server's `/api/config` now (*network*, at most 10 s) and report `check` |

Returns: **TestServer** (`applied` null; `check` null unless asked and a
server is joined). Errors: the common ones. An unreachable server is not
an error: `check.reachable` is false and the stored profile stays in use.

### `set_test_server`

*network*. Join a test server with one setting: fetch
`<url>/api/config`, validate it, store it in the app config and apply it.
After the call the Liquid network is the lab's regtest (unless
`TEMPLAR_LIQUID_NETWORK` fixes it), the regtest chain is reached through
the lab's Liquid Electrum server, the Bitcoin side runs on the lab's
Bitcoin regtest (`bcrt1…` addresses, its own data under
`bitcoin-regtest/`), and the order book (book, markets, publish, HTLC
coordinator) is the lab's. Liquid testnet keeps its own servers. The open
wallet is closed. When the lab's `instance_id` differs from the one the
regtest data was synced against, the regtest chain caches and regtest swap
offers are dropped (never keys or the wallet list). Call it again to
refresh a stale profile.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `url` | string | yes | the server's base URL, e.g. `http://127.0.0.1:8096`; one trailing slash is ignored |

Returns: **TestServer**. Errors (nothing is applied):
`Invalid test server URL: …` (not `http`/`https`, credentials, query or
fragment, or the server redirects); `Cannot reach the test server: …`;
`The test server answered HTTP <n> for /api/config`; `The test server's
/api/config is larger than 65536 bytes`; `This test server needs a newer
wallet (its config is version <n>; …)`; `The test server's config is
invalid: <field> …` (the field is named); `The test server's config names a
mainnet (…)`; `Could not save the settings: …`.

### `clear_test_server`

Leave the joined test server: the profile is forgotten, the order book and
backends return to the environment and defaults, a Liquid network on the
lab's regtest returns to testnet, the open wallet is closed and the lab's
regtest caches are dropped. Params: none. Returns: **TestServer**. Errors:
`Could not save the settings: …`.

## Vault

### `vault_status`

Params: none. Returns: `{initialized: bool, unlocked: bool, state: "none" |
"locked" | "unlocked", needs_migration: bool, plaintext_seed_wallets:
usize}`. `needs_migration` is true when recovery phrases are stored in
plaintext (an install that predates the vault): the host should require a
passphrase before anything else. Errors: the common ones.

### `setup_vault`

Create the vault, migrate any plaintext registry into it and shred the
plaintext files. Leaves the vault unlocked. Argon2id runs with the
production parameters (≥ 64 MiB): expect it to take a noticeable moment.

| Param | Type | Req. |
|---|---|---|
| `passphrase` | string | yes |

Returns: `null`. Errors: `A vault is already set up on this device. Use
unlock instead.`; `Encryption setup failed, nothing was changed: …`.

### `unlock_vault`

| Param | Type | Req. |
|---|---|---|
| `passphrase` | string | yes |

Returns: `null`; the registry is loaded. Errors: `No vault is set up on this
device`; wrong passphrase (the vault's error message); a registry that fails
to decrypt or parse (the session stays locked).

### `unlock_vault_with_key`

Unlock from the key a previous `export_vault_key` returned (the biometric
path: no passphrase, no Argon2id).

| Param | Type | Req. | Notes |
|---|---|---|---|
| `key_hex` | string | yes | 64 hex characters |

Returns: `null`. Errors: `No vault is set up on this device`; `Vault key
must be 64 hex characters (32 bytes), got N`; `Vault key is not valid hex`;
`The stored vault key does not match this vault — unlock with your
passphrase`.

### `export_vault_key`

Params: none. Returns: `{key_hex: string}`, the unlocked vault key. Treat the
response as a secret: store it only in a platform keystore and wipe it.
Errors: `No vault is set up on this device`; `Vault is locked — unlock with
your passphrase before exporting its key`.

### `lock_vault`

Drop the key and every decrypted secret and close the open wallet. Params:
none. Returns: `null`. Errors: the common ones.

### `verify_vault_passphrase`

Prove the passphrase without changing the session (the gate in front of a
seed reveal). Five wrong tries lock it for 60 seconds.

| Param | Type | Req. |
|---|---|---|
| `passphrase` | string | yes |

Returns: `null`. Errors: `No vault is set up on this device`; `Wrong app
password — N attempts left`; `Too many wrong attempts — locked for 60s`;
`Too many wrong attempts — try again in Ns`.

### `verify_vault_key`

The stored-key twin of `verify_vault_passphrase`; not throttled.

| Param | Type | Req. |
|---|---|---|
| `key_hex` | string | yes |

Returns: `null`. Errors: as `unlock_vault_with_key`, ending in `— confirm
with your passphrase`.

## Wallets and keys

### `list_wallets`

Reloads the registry from disk, then lists it. Params: none. Returns:
`[WalletSummary]`. Errors: vault locked; registry read errors.

### `generate_mnemonic`

| Param | Type | Req. | Notes |
|---|---|---|---|
| `word_count` | usize | yes | 12 or 24 |

Returns: `[string]`, the words. A secret: never log it. Errors: `… word
count must be 12 or 24, got N`.

### `create_wallet`

A software single-sig wallet (BIP84 on Bitcoin; optionally a Liquid side
from the same phrase).

| Param | Type | Req. | Notes |
|---|---|---|---|
| `name` | string | yes | |
| `mnemonic` | string | yes | space-separated BIP39 phrase |
| `liquid` | bool | no | default `false` |

Returns: **WalletSummary**. Errors: vault locked; `Set an app password first
— Templar will not store a recovery phrase on this computer unencrypted
(Settings → Security).` when no vault exists; invalid mnemonic.

### `create_multisig_wallet`

An M-of-N multisig (P2WSH, BIP48 keys), optionally with a Liquid side
(BIP87 keys, shared blinding key).

| Param | Type | Req. | Notes |
|---|---|---|---|
| `name` | string | yes | |
| `required_sigs` | usize | yes | M |
| `total_signers` | usize | yes | N |
| `cosigner_xpubs` | [string] | yes | `[fingerprint/path]xpub`, no wildcard |
| `local_mnemonics` | [string]? | no | phrases of the keys this device signs with; each must match one xpub; empty = watch-only coordinator |
| `local_mnemonic` | string? | no | legacy single key, used when `local_mnemonics` is absent |
| `liquid_xpubs` | [string] | no | BIP87 keys `[fp/87h/1h/0h]tpub…`, same order as `cosigner_xpubs`; empty = Bitcoin only |
| `liquid_capable_keys` | usize? | no | keys able to sign on Liquid; below M the Liquid side is refused; absent = not checked |

Returns: **WalletSummary**. Errors: vault locked; no vault while
`local_mnemonics` is non-empty; key normalization errors; a local phrase
that matches no xpub; a Liquid side below threshold.

### `repair_multisig_wallet`

Rebuild a multisig descriptor saved in a broken shape (a nested key
descriptor) from its normalized keys; same wallet, same addresses.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: **WalletSummary**. Errors: vault locked; not a multisig; a local
signing key the registry cannot rebuild (refused rather than turned
watch-only).

### `rename_wallet`

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `new_name` | string | yes |

Returns: `null`. Errors: vault locked; wallet not found.

### `delete_wallet`

Remove the wallet from the registry and its BDK database. Irreversible
for a software wallet without a backup of its phrase.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `null`. Errors: vault locked; wallet not found.

### `enable_liquid`

Add the Liquid side to a software wallet created Bitcoin-only, from its
stored phrase.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `null`. Errors: vault locked; wallet not found; not a software
wallet.

### `validate_cosigner_key`

Normalize whatever a co-signer sent (bare keyorigin key, descriptor, `h`
for hardened, SLIP-132 versions) to `[fingerprint/path]tpub…`.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `key` | string | yes | |
| `liquid` | bool | no | check as the Liquid (BIP87) key instead of BIP48 |

Returns: `{normalized: string, fingerprint: string, path: string, warning:
string?}`. `warning` is set when the key parses but is probably not the one
meant. Errors: the reason the key is unusable.

### `derive_cosigner_xpub`

| Param | Type | Req. |
|---|---|---|
| `mnemonic` | string | yes |

Returns: `string`, the BIP48 cosigner key `[fp/48'/1'/0'/2']tpub…`.
Errors: invalid mnemonic.

### `derive_liquid_cosigner_xpub`

| Param | Type | Req. |
|---|---|---|
| `mnemonic` | string | yes |

Returns: `string`, the BIP87 Liquid cosigner key `[fp/87'/1'/0']tpub…`.
Errors: invalid mnemonic.

### `get_cosigner_xpub`

`derive_cosigner_xpub` for a stored software wallet.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `string`. Errors: vault locked; wallet not found; `Only software
wallets can export a cosigner key`.

### `get_liquid_cosigner_xpub`

`derive_liquid_cosigner_xpub` for a stored software wallet.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `string`. Errors: as `get_cosigner_xpub`.

### `get_mnemonic`

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `[string]`, the recovery phrase. A secret: gate it behind
`verify_vault_passphrase` and never log it. Errors: vault locked; wallet
not found; `This wallet has no seed phrase stored on this device`.

### `get_private_key`

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `string`, the master extended private key (`tprv…`). A secret, as
above. Errors: vault locked; wallet not found; `This wallet has no private
key stored on this device`.

### `verify_backup`

Check a phrase typed back from a paper backup against the wallet, without
storing it.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `mnemonic` | string | yes |

Returns: `{matched: bool, reason: "ok" | "checksum" | "mismatch" |
"no_reference", derived_fingerprint: string, expected_fingerprint: string,
fingerprint_match: bool}`. Errors: vault locked; wallet not found.

## Open, sync and read

### `open_wallet`

Build the wallet's BDK and LWK managers. Offline.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `null`. Errors: `Wallet not found: <id>`; descriptor or database
errors.

### `sync_wallet`

*opens*, *network*. Sync both chains; one failing does not stop the
other.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `{btc: string, liquid: string}`, each `"ok"`, `"skipped"` (no
side on that chain) or `"error: <reason>"`. Errors: only when the wallet
cannot be opened.

### `get_wallet_summary`

*opens*. The dashboard: balances per asset and recent activity.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `{wallet_id, wallet_name, total_balance_display, sync_state:
"never" | "synced" | "partial" | "error", assets: [{asset_id, ticker,
name, amount: int, display_amount, fiat_estimate: string?, status,
utxo_count: usize, is_native: bool}], recent_activity: [{txid, direction:
"incoming" | "outgoing" | "self", chain: "bitcoin" | "liquid", amount,
ticker, timestamp: int, confirmations: u32, note?, counterparty?}],
liquid_network}`. Errors: the common ones.

### `get_wallet_info`

*opens*. Keys and descriptors (public).

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `{id, name, network, master_fingerprint, derivation_path,
script_type, xpub, receive_descriptor, change_descriptor,
multipath_descriptor: string?, liquid_descriptor: string?,
master_blinding_key: string?, has_seed: bool, has_passphrase: bool,
last_backup_at: int?, cosigner_keys: [string], required_sigs: u32?,
local_fingerprints: [string], liquid_network}`. Errors: the common ones.

### `generate_receive_address`

*opens*. Offline.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `asset` | string | yes | `LBTC`, `L-BTC` or `liquid` for Liquid; anything else is Bitcoin |
| `fresh` | bool | no | `true` advances the index; default: the current unused address |

Returns: **AddressInfo**. Errors: the chain's side is missing.

### `list_previous_addresses`

*opens*. External addresses that have received funds.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `asset` | string | yes | as `generate_receive_address` |
| `fresh` | bool | no | ignored |

Returns: `[AddressInfo]`. Errors: the chain's side is missing.

### `list_activity`

*opens*. Both chains, from the last sync.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `[{txid, direction, chain, amount, ticker, timestamp: int,
confirmations: u32, fee: string?, fee_sats: int?, fee_rate: f64?, vsize:
int, is_replaceable: bool, can_rbf: bool, can_cpfp: bool, can_cancel: bool,
fee_bump_unavailable_reason: string?, note?, counterparty?,
fiat_estimate?}]`. Errors: the common ones.

### `get_balance_history`

*opens*. Points for a balance chart, from the last sync.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `{points: [{ts: int, btc_sats: int, lbtc_sats: int}], btc_sats:
int, lbtc_sats: int, has_bitcoin: bool, has_liquid: bool}`. Errors: the
common ones.

## Coins

### `list_utxos`

*opens*.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `chain` | string | yes | `liquid` (any case) for Liquid; anything else is Bitcoin |

Returns: `[{outpoint, amount: int, display_amount, confirmations: u32,
state: "available" | "frozen" | "dusty" | "unconfirmed", label?, address?,
ticker?, asset_id?}]`. Errors: the chain's side is missing.

### `set_utxos_frozen`

Freeze or unfreeze coins. A frozen coin is never spent and never signed for.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `chain` | string | yes | `btc` / `bitcoin` or `liquid` / `lbtc` / `l-btc` (any case) |
| `outpoints` | [string] | yes | |
| `frozen` | bool | yes | |

Returns: `null`. Errors: vault locked; `Unknown chain: <chain>`; malformed
outpoint; wallet not found.

### `build_consolidation_psbt`

*opens*. An unsigned PSBT spending exactly the given coins to one fresh
address of the wallet. Sign with `sign_psbt`, send with
`broadcast_signed_psbt`.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `outpoints` | [string] | yes | |
| `chain` | string | yes | Bitcoin only (`BTC`) |
| `fee_rate` | f32 | yes | sat/vB |

Returns: `string`, the PSBT. Errors: Liquid chain; frozen or unknown coins;
fee rate out of range.

### `consolidate_utxos`

*opens*, *network*. The one-shot form: build, sign with the software key,
broadcast. Params as `build_consolidation_psbt`. Returns: `string`, the
txid. Errors: as above, plus signing and broadcast errors.

## Sending

### `preview_transaction`

*opens*. Build the transaction and report it, without signing.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `asset_id` | string | yes | `BTC` for Bitcoin; otherwise the Liquid asset id |
| `fee_rate` | f32 | yes | sat/vB, Bitcoin only (Liquid uses a flat fee) |
| `outputs` | [TxOutputSpec]? | no | the recipients; overrides `address` / `amount_sats` |
| `address` | string | no | legacy single recipient |
| `amount_sats` | int | no | legacy single amount |
| `utxos` | [string]? | no | coins to spend (manual coin control); absent = automatic |

Returns: **TxPreview**. Errors: `No outputs given`; `Every output needs an
address`; `Every output needs a non-zero amount (or MAX)`; `Only one output
can send the maximum`; `MAX resolves to zero — …`; fee rate outside
0.1–1000 sat/vB; insufficient funds; frozen coins requested; on Liquid, a
non-L-BTC payment while coins are frozen.

### `send_transaction`

*opens*, *network*. Build, sign with the keys on this device, broadcast.
Params as `preview_transaction`.

Returns: `string`, the txid, or a **Partial send** object when more
signatures are needed. Errors: as `preview_transaction`, plus signing and
broadcast errors.

### `preview_fee_bump`

*opens*. Build (not sign) a replacement or child transaction for a
Bitcoin transaction of this wallet.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `txid` | string | yes | |
| `action` | string | yes | `speed_up` \| `cancel` |
| `method` | string | no | `auto` (default) \| `rbf` \| `cpfp`; ignored for `cancel` |
| `fee_rate` | f32 | yes | new rate, sat/vB |

Returns: `{method: "rbf" | "cpfp" | "cancel", original_txid, psbt_base64,
old_fee_sats: int, old_fee_rate: f64, old_vsize: int, new_fee_sats: int,
new_fee_rate: f64, new_vsize: int, extra_fee_sats: int,
effective_fee_rate: f64, total_fee_sats: int}`. Sign the PSBT with
`sign_psbt`. Errors: `Invalid transaction id: …`; `This transaction cannot
be sped up with RBF or CPFP`; the reason RBF / CPFP / cancel is not
possible.

### `build_unsigned_psbt`

*opens*. Bitcoin only: the unsigned PSBT for an air-gap or external signer.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `asset_id` | string | no | empty, `BTC` or `bitcoin`; a Liquid id is refused |
| `fee_rate` | f32 | yes | |
| `outputs`, `address`, `amount_sats`, `utxos` | | no | as `preview_transaction` |

Returns: `string`, the PSBT. Errors: `LIQUID_HW_UNSUPPORTED: …`; as
`preview_transaction`.

### `broadcast_signed_psbt`

*opens*, *network*. Finalize and broadcast a fully signed PSBT.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `psbt_base64` | string | yes |

Returns: `string`, the txid. Errors: not finalizable; broadcast errors.

## PSBT (Bitcoin co-signing)

### `inspect_psbt`

Decode a PSBT. Uses the open Bitcoin wallet, if any, to mark own inputs and
outputs; opens nothing.

| Param | Type | Req. |
|---|---|---|
| `psbt_base64` | string | yes |

Returns: **PsbtInspection**. Errors: not a PSBT.

### `sign_psbt`

Add this wallet's software signature(s). Refuses inputs whose previous
outputs are missing or inconsistent, and frozen coins.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `psbt_base64` | string | yes |

Returns: `string`, the signed PSBT. Errors: wallet not found; a watch-only
wallet; a frozen input; an input whose previous output is missing or
conflicting; `This wallet's key signs none of the inputs in this
transaction — …`.

### `combine_psbts`

Merge signed copies of one transaction. No wallet needed.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `psbts` | [string] | yes | the copy being handed out first |

Returns: `string`, the combined PSBT. Errors: copies of different
transactions; unreadable PSBT.

## PSET (Liquid co-signing)

All four need the wallet's Liquid side: amounts in a PSET are blinded and
only the wallet's blinding key reads them.

### `inspect_pset`

*opens*.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `pset_base64` | string | yes |

Returns: **PsetInspection**. Errors: unreadable PSET; a PSET of another
network or with keys on a mainnet path; an output whose blind proofs do not
match its commitments.

### `sign_pset`

*opens*. Add this wallet's software signature(s): a software wallet, or a
multisig's local keys. Matches on the master fingerprint in the PSET, so it
also signs PSETs built elsewhere (multisig co-signing, Templar Protocol
escrows and check PSETs).

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `pset_base64` | string | yes |

Returns: `string`, the signed PSET. Errors: `Open this wallet's Liquid side
before signing a Liquid transaction`; `PSET inspection failed: PSET doesn't
contain a fee output` and `PSET inspection failed: Multiple fee outputs`
(exactly one fee output is signed; `inspect_pset` still describes the
others); `Signing failed: refusing to sign input <n>: it is a taproot
input, …` (the wallet does not sign taproot inputs on Liquid);
`Signing failed: refusing to sign input <n>: it asks for sighash type
0x<hh>, …` (an input this wallet signs may declare no sighash type or
SIGHASH_ALL only); `Refusing to sign: an output of this transaction claims
an amount or asset its commitment does not prove, …`; a frozen input; `This wallet's key lives on a device — use the device to
sign.`; a multisig holding no local key; a policy wallet; `No signature
was added — …`.

### `combine_psets`

*opens*.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `psets` | [string] | yes | signed copies of the same transaction, original included; at least two |

Returns: `string`, the combined PSET. Errors: `Combining needs at least two
signed copies of the transaction.`; LWK combine errors.

### `broadcast_pset`

*opens*, *network*. Finalize and broadcast.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `pset_base64` | string | yes |

Returns: `string`, the txid. Errors: missing signatures; broadcast errors.

## QR (BC-UR)

### `ur_psbt_encode`

| Param | Type | Req. | Notes |
|---|---|---|---|
| `psbt_base64` | string | yes | |
| `max_fragment_len` | usize | no | bytes per frame, default 100 |

Returns: `[string]`, animated `ur:crypto-psbt` frames. Errors: not base64.

### `ur_pset_encode`

| Param | Type | Req. | Notes |
|---|---|---|---|
| `pset_base64` | string | yes | |
| `max_fragment_len` | usize | no | default 100 |

Returns: `[string]`, `ur:bytes` frames (the UR registry has no PSET type).
Errors: not base64; not a PSET.

### `ur_decode_parts`

| Param | Type | Req. | Notes |
|---|---|---|---|
| `parts` | [string] | yes | every frame scanned so far, any order |

Returns: `{progress: f64, complete: bool, kind: "psbt" | "pset" |
"descriptor" | "", psbt_base64: string?, pset_base64: string?, descriptor:
string?, keyorigin: string?}`. Errors: `No QR data`; frames that are not
UR.

## Liquid assets

### `issue_asset`

*opens*, *network*. Issue an asset and submit it to the testnet asset
registry.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `name` | string | yes | |
| `ticker` | string | yes | |
| `precision` | u8 | yes | |
| `domain` | string | yes | the issuer's domain, for the registry proof |
| `amount_sats` | int | yes | > 0 |
| `reissuance_tokens` | int | yes | ≥ 0 |

Returns: **IssueResult**. `registry_registered` is false when the
submission did not go through (on regtest it is not attempted); publish
`proof_content` at `proof_url` and call `reregister_asset`. Errors: `The
amount must be a positive number`; `The reissuance tokens cannot be
negative`; `Precision must be between 0 and 8`; build and broadcast
errors.

### `reissue_asset`

*opens*, *network*.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `asset_id` | string | yes | |
| `amount_sats` | int | yes | > 0 |

Returns: **IssueResult**. Errors: reissuance errors (no reissuance token
in the wallet, a frozen token); as `issue_asset`.

### `burn_asset`

*opens*, *network*.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `asset_id` | string | yes | |
| `amount_sats` | int | yes | > 0 |

Returns: `string`, the txid. Errors: insufficient balance; as above.

### `reregister_asset`

*opens*, *network*. Submit an issued asset to the testnet registry again.
Refused on regtest.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `asset_id` | string | yes |
| `name` | string | yes |
| `ticker` | string | yes |
| `precision` | u8 | yes |
| `domain` | string | yes |

Returns: `{registered: bool}`. Errors: `The Liquid asset registry is not
available on Liquid regtest. …`.

## Hardware, watch-only and air-gap

### `hwi_status`

Diagnostics for the hardware setup. Present in every build.

Params: none. Returns: `{hardware_supported: bool, resolved_bin: string?,
version: string?, platform: "macos" | "windows" | "linux" | "android" |
"unknown", udev_rules_installed: bool?, liquid_hw_signing: bool,
hid_device_count: usize, native_families: [string], hwi_usable: bool}`.
`udev_rules_installed` is null outside Linux. Without `hardware`:
`hardware_supported: false` and everything off. Errors: the common ones.

### `set_hwi_path`

**[hardware]**

| Param | Type | Req. |
|---|---|---|
| `path` | string | yes |

Returns: `null`. Errors: `No hwi binary at <path>`.

### `enumerate_hw_devices`

**[hardware]**, *network* (USB, through HWI). Params: none. Returns:
`[{model, fingerprint, path}]`. Errors: `HWI_MISSING: …`, `HWI_PERMISSION:
…` and the other device tags.

### `enumerate_native_devices`

**[hardware]**. Devices this build talks to in-process. Params: none.
Returns: `[{family: "ledger" | "trezor" | "coldcard" | …, model, transport:
"hid" | "serial", path, vendor_id: u16, product_id: u16, serial_number:
string?, drivable: bool}]`. Errors: device tags.

### `jade_ports`

**[hardware]**. Serial ports that may carry a Jade, without opening them.
Params: none. Returns: `[string]`. Errors: none beyond the common ones.

### `import_hw_wallet`

**[hardware]**, *network* (device). Pair a device as one wallet with a
Bitcoin side and, optionally, a Liquid side (Jade only).

| Param | Type | Req. | Notes |
|---|---|---|---|
| `name` | string | yes | |
| `fingerprint` | string | yes | the device's master fingerprint |
| `liquid` | bool | no | also pair Liquid |

Returns: `{wallet: WalletSummary, fingerprint, device_model,
bitcoin_descriptor, liquid_descriptor: string?, liquid_error: string?,
liquid_requested: bool}`. A Liquid failure does not fail the call: the
Bitcoin wallet exists and `liquid_error` says why. Errors: vault locked;
device tags.

### `import_jade_liquid_wallet`

**[hardware]**, *network* (device). A Liquid-only wallet from a connected
Jade.

| Param | Type | Req. |
|---|---|---|
| `name` | string | yes |

Returns: **WalletSummary** (`bitcoin_enabled: false`). Errors: vault
locked; device errors.

### `add_liquid_to_wallet`

**[hardware]**, *network* (device). Pair the Liquid side onto a hardware
wallet set up Bitcoin-only.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: **WalletSummary**. Errors: vault locked; `This wallet already has
a Liquid side.`; `Only a hardware wallet can read a Liquid descriptor from
its device.`; `LIQUID_HW_UNSUPPORTED: …` for an air-gapped or non-Jade
device; device errors.

### `create_watch_only_wallet`

A wallet from public descriptors; with `airgap` it signs over QR.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `name` | string | yes | |
| `recv_desc` | string | yes | receive descriptor, or a multipath one |
| `change_desc` | string | no | |
| `liquid_ct_desc` | string | no | pairs a Liquid watch-only side |
| `airgap` | bool | no | `true` = signs via QR; `false` = no spending |

Returns: **WalletSummary**. Errors: vault locked; invalid descriptors.

### `derive_liquid_descriptor`

Present in every build. The Liquid CT descriptor matching a Bitcoin
single-sig key.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `btc_desc` | string | yes | bare xpub / tpub or a `wpkh(...)` descriptor |

Returns: `string`. Errors: unsupported descriptor.

### `get_hw_cosigner_xpub`

**[hardware]**, *network* (device). The device's BIP48 cosigner key.

| Param | Type | Req. |
|---|---|---|
| `fingerprint` | string | yes |

Returns: `string`. Errors: device tags.

### `get_jade_liquid_cosigner_xpub`

**[hardware]**, *network* (device). A Jade's BIP87 Liquid key.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `fingerprint` | string | yes | the Jade expected; empty = whichever is connected |

Returns: `string`. Errors: a different Jade; device errors.

### `verify_hw_address`

**[hardware]**, *opens*, *network* (device). Show the next receive address
on the device and return it once confirmed.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `string`. Errors: not a hardware wallet; device tags.

### `send_transaction_hw`

**[hardware]**, *opens*, *network*. Bitcoin only: build, sign on the
device, broadcast. Params as `preview_transaction` (`asset_id` empty,
`BTC` or `bitcoin`). Returns: `string`, the txid. Errors:
`LIQUID_HW_UNSUPPORTED: …`; device tags; as `send_transaction`.

### `sign_transaction_hw`

**[hardware]**, *opens*, *network* (device). As `send_transaction_hw` but
stops after signing, so a failed broadcast does not cost another approval
on the device. Returns: `string`, the signed PSBT; send it with
`broadcast_signed_psbt`. Errors: as `send_transaction_hw`.

### `sign_psbt_hw`

**[hardware]**, *network* (device). Sign any PSBT with the device whose
fingerprint is given (multisig co-signing). Uses the open wallet's public
descriptor when there is one.

| Param | Type | Req. |
|---|---|---|
| `fingerprint` | string | yes |
| `psbt_base64` | string | yes |

Returns: `string`, the signed PSBT. Errors: frozen input; device tags.

### `sign_pset_hw`

**[hardware]**, *opens*, *network* (device). Sign a PSET with a Jade;
registers a multisig on the device first.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `pset_base64` | string | yes |

Returns: `string`, the signed PSET. Errors: as `sign_pset`'s checks;
`This multisig wallet has no Liquid side.`; device errors.

## Templar Protocol

The wallet side of [CONNECTOR.md](CONNECTOR.md). HTTP to the site is the
host's job; these methods supply the keys and the checks.

### `get_protocol_escrow_xpub`

**[protocol]**. The loan key the `templar://connect` callback sends as
`escrow_xpub`: `[fp/2121h/1h/0h]tpub…` for a software wallet, the BIP87
account `[fp/87h/1h/0h]tpub…` for a Jade (plugged in and unlocked).
Does not open the wallet.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `string`. Errors: wallet not found; a non-Jade hardware wallet;
`Templar Protocol escrow keys come from a single-seed software wallet; …`
for multisig and policy wallets.

### `protocol_check_pset`

**[protocol]**. Build the unsigned check PSET of
[CONNECTOR.md §9.1](CONNECTOR.md#91-challenge-and-shape) for the site's
challenge and this wallet's loan key, on the active Liquid network. Sign it
with `sign_pset` and send it as `proof`. Does not open the wallet.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `challenge` | string | yes | the exact challenge text the site sent |

Returns: `{pset_base64, loan_key, fingerprint}` (`fingerprint` lower-case
hex). Errors: `Proof of key through a Jade is not supported yet: …`; `Only
a single-seed software wallet can prove a Templar Protocol loan key.`;
`check PSET: empty challenge`.

### `protocol_is_check_pset`

**[protocol]**. Whether a PSET is exactly the check of `challenge` for this
wallet's key on the active network ([§9.5](CONNECTOR.md#95-what-the-wallet-must-show-and-refuse)).
Recomputed here, never taken from the site.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `challenge` | string | yes |
| `pset_base64` | string | yes |

Returns: `{is_check: bool, reason: string?, loan_key_fingerprint: string}`.
A wrong shape, an unreadable PSET or an unsupported wallet is a `false`
verdict with the reason, not an error. Errors: wallet not found; an
invalid stored key.

## Peg-in / peg-out (simulated)

A simulated provider: no real funds move. Refused on regtest. Orders are
kept in `peg_orders.json`.

### `peg_quote`

| Param | Type | Req. | Notes |
|---|---|---|---|
| `direction` | string | yes | `in` \| `out` |
| `amount_sats` | u64 | yes | |

Returns: `{direction, amount_sats: u64, rate: f64, service_fee_sats: u64,
network_fee_sats: u64, receive_sats: u64, min_sats: u64, max_sats: u64,
eta_minutes: u32, simulated: bool}`. Errors: `Unknown peg direction …`;
`Amount is below the minimum of N sats` / `above the maximum`; regtest.

### `peg_start`

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `direction` | string | yes |
| `amount_sats` | u64 | yes |
| `payout_address` | string | yes |

Returns: **PegOrder**. Errors: as `peg_quote`; wallet not found.

### `peg_status`

| Param | Type | Req. |
|---|---|---|
| `order_id` | string | yes |

Returns: **PegOrder** (advanced along its simulated timeline). Errors:
unknown order; regtest.

### `peg_list`

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `[PegOrder]`. Errors: regtest.

### `peg_cancel`

| Param | Type | Req. |
|---|---|---|
| `order_id` | string | yes |

Returns: **PegOrder**. Errors: unknown order; `Order can no longer be
cancelled (status: …)` once the deposit has been seen; regtest.

## LiquiDEX swaps

Swaps through signed LiquiDEX proposals. The order book is the joined test
server's, else the local order book service on `127.0.0.1:3210`;
`TEMPLAR_SWAP_BOOK_URL`, `TEMPLAR_SWAP_MARKETS_URL` and
`TEMPLAR_SWAP_ADMIN_URL` override single routes (see
[ARCHITECTURE.md](ARCHITECTURE.md#networks-and-chain-access); the URLs in
use are in **TestServer** `active.orderbook`). The active Liquid network is
sent with every read. Chain checks, takes and cancels go through the active
Liquid network's backend. Mainnet proposals are never signed.

A proposal made here carries, on its output leg, the optional
`blinding_nonce`: the secret the taker seals the maker's output rangeproof
with, so the maker's wallet can unblind the payment. It reveals nothing the
legs do not already reveal; proposals without it are still taken (the
maker's wallet may then not see the payment).

### `list_swaps`

*network*.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `include_unavailable` | bool | no | include taken / unavailable rows |

Returns: `[{id: u64, available: bool, receive: SwapLeg, pay: SwapLeg,
price: f64, price_display, created, verified: bool, verify_note: string?,
proposal_json, network, takeable: bool, kind}]`. Errors: the book cannot be
reached or parsed.

### `list_markets`

*network*. The unified market feed.

| Param | Type | Req. |
|---|---|---|
| `include_unavailable` | bool | no |

Returns: `[{id, source_id: u64, status, settlement, demo: bool, available:
bool, maker_gives: Leg, maker_wants: Leg, price_display, note, created_at:
u64, proposal_json, verified: bool, takeable: bool, block_reason:
string?}]`, where `Leg` = `{chain, network, asset_id, ticker, name,
precision: u8, amount_sats: u64, display_amount}`. Rows with `demo: true`
are display data only. Errors: as `list_swaps`.

### `swap_verify`

| Param | Type | Req. | Notes |
|---|---|---|---|
| `proposal_json` | string | yes | |
| `deep` | bool | no | also check prevouts and unspent state on chain (*network*) |

Returns: **SwapAnalysis**. Errors: unparsable proposal.

### `swap_take_preview`

*opens*, *network*.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `proposal_json` | string | yes | |
| `fee_rate` | f32? | no | |

Returns: `{you_receive: SwapLeg, you_pay: SwapLeg, fee_sats: u64,
fee_display, change: [SwapLeg], analysis: SwapAnalysis}`. Errors: a
non-takeable proposal (the block reason); insufficient funds.

### `swap_take`

*opens*, *network*. Take the proposal: verify deeply, sign, broadcast.
Params as `swap_take_preview`. Returns: `string`, the txid. Errors: the
block reason; frozen coins; as above.

### `swap_make`

*opens*. Offer one UTXO's full amount for an asset. Offline: signs the
proposal and stores it; nothing is broadcast until a taker takes it.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `utxo` | string | yes | outpoint of the coin to offer |
| `want_asset_id` | string | yes | |
| `want_amount_sats` | u64 | yes | |

Returns: **MyOffer**. Errors: a frozen or unknown coin; mainnet L-BTC
asked for.

### `swap_make_prepare`

*opens*, *network*. Self-send to create a coin of exactly `amount_sats`,
for offering an amount no single coin holds.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `asset_id` | string | yes | |
| `amount_sats` | u64 | yes | |
| `fee_rate` | f32? | no | accepted and ignored (Liquid flat fee) |

Returns: `string`, the txid. Errors: `Amount must be greater than zero`;
insufficient funds; broadcast errors.

### `swap_publish`

*network*. Publish a signed proposal to the order book's public
`POST /api/offers`, which verifies it against the chain before storing it
(`TEMPLAR_SWAP_ADMIN_URL` replaces the URL, for old setups that publish
through the admin route).

| Param | Type | Req. |
|---|---|---|
| `proposal_json` | string | yes |
| `note` | string | no |

Returns: `u64`, the book's id. Errors: a proposal that fails verification
(the first failing check); `Liquid mainnet proposals cannot be published`;
the book refusing, tagged by its HTTP status (the text after the tag
includes the book's own message and may change):

| Tag | Status | Meaning |
|---|---|---|
| `BOOK_REJECTED:` | 400, 401, 413, 415, 422 | the offer or the request was refused (bad proposal, coin spent, wrong network, too large; 401: the admin route of a protected book) |
| `BOOK_PUBLISH_DISABLED:` | 403 | the book takes no public offers for this network |
| `BOOK_DUPLICATE:` | 409 | the same proposal is already in the book |
| `BOOK_RATE_LIMITED:` | 429 | too many publishes; the text says when to retry |
| `BOOK_CHAIN_UNREACHABLE:` | 503 | the book cannot verify on the chain now (or is full); nothing stored |
| `BOOK_UNAVAILABLE:` | 404, 405, other | no publish route, or another server error |
| `BOOK_UNREACHABLE:` | none | the book could not be reached |

### `list_my_offers`

*opens*. This wallet's offers on the active Liquid network, newest first
(offers stored before the network was recorded show on both); open ones get
a best-effort status refresh (*network*).

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `[MyOffer]`. Errors: the store cannot be read.

### `swap_cancel`

*opens*, *network*. Cancel an open offer by spending its coin back to the
wallet (allowed even when the coin is frozen: it is the only way to stop
the signed offer).

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `offer_id` | string | yes |

Returns: `string`, the txid. Errors: unknown or closed offer; broadcast
errors.

## Bitcoin ↔ Liquid HTLC swaps

Testnet only, software wallets with both chains. The order book service
(`active.orderbook.atomic_swaps`) coordinates the public state; keys and the maker's preimage are
derived from the seed and never sent. All six are *opens* and *network*,
and fail with `Cross-chain swaps v1 require Liquid testnet`, `Cross-chain
swaps v1 currently require a software wallet` or `Open a wallet with both
Bitcoin and Liquid enabled` when those conditions are not met.

### `atomic_swap_create`

Publish an offer.

| Param | Type | Req. | Notes |
|---|---|---|---|
| `wallet_id` | string | yes | |
| `direction` | string | yes | `btc-to-liquid` \| `liquid-to-btc` (what you offer → what you want) |
| `btc_amount_sats` | u64 | yes | |
| `liquid_asset_id` | string | yes | |
| `liquid_ticker` | string | yes | |
| `liquid_name` | string | yes | |
| `liquid_precision` | u8 | no | default 8 |
| `liquid_amount_sats` | u64 | yes | |
| `note` | string | no | |

Returns: **AtomicSwap**. Errors: `Direction must be btc-to-liquid or
liquid-to-btc`; amounts; the service refusing.

### `atomic_swap_join`

Join an offer as taker.

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |
| `offer_id` | u64 | yes |

Returns: **AtomicSwap**. Errors: `Offer is no longer open`; `This wallet
already participates in the swap`; `Maker refund window is too short;
create a fresh offer`; the service refusing.

### `atomic_swap_list`

| Param | Type | Req. |
|---|---|---|
| `wallet_id` | string | yes |

Returns: `[AtomicSwap]`, this wallet's swaps.

### `atomic_swap_fund`

Fund this side's HTLC. Params: `wallet_id: string`, `offer_id: u64` (both
required). Returns: **AtomicSwap**. Errors: `<role> cannot fund while swap
is <status>`; funding errors.

### `atomic_swap_claim`

Claim the other side's HTLC (the maker reveals the preimage; the taker
uses the published one). Params as `atomic_swap_fund`. Returns:
**AtomicSwap**. Errors: `<role> cannot claim while swap is <status>`;
`Maker preimage is not published`; claim errors.

### `atomic_swap_refund`

Refund this side's HTLC after its timeout. Params as `atomic_swap_fund`.
Returns: **AtomicSwap**. Errors: `Refund unlocks at Unix time N`; refund
errors.
