# Running the ignored tests

`cargo test --workspace` is offline and is the gate. Fifteen tests are
`#[ignore]`d because they need something the gate does not have: a local
Elements regtest node, a running Templar testlab, a running Templar
Protocol site, a public Electrum server, a public faucet, or time. This guide says what each one needs and how to run it.

List them:

```bash
cargo test --workspace -- --ignored --list
```

## Against a local Elements regtest node

| Test | Crate | What it proves |
|---|---|---|
| `regtest_node_sync_and_send_end_to_end` | templarlib | open a wallet on regtest, get funded, sync through `elementsd` RPC, see the balance, send, see it move |
| `liquid_multisig_round_trip_on_regtest` | templarlib | a 2-of-2 Liquid multisig: one copy builds a spend, the other co-signs from its own data directory, the first finalizes and broadcasts |

Both expect the node the Templar Protocol uses for development:
`elementsd -chain=liquidregtest` with JSON-RPC on `http://127.0.0.1:18884`,
user and password `templar`, and a loaded wallet named `ops` holding
regtest L-BTC (they fund from it and mine with it). With access to the
templar-protocol repository, its operator console sets exactly that up:

```bash
# in templar-protocol
cargo run -p templar-lend-ops -- up       # start elementsd, create and fund `ops`
cargo run -p templar-lend-ops -- status   # node, tip, balances
```

Any other node works if it matches the endpoint, credentials and `ops`
wallet above. Then, here:

```bash
cargo test -p templarlib regtest_node -- --ignored --nocapture
cargo test -p templarlib liquid_multisig_round_trip_on_regtest -- --ignored --nocapture
```

Each test uses throwaway data directories; nothing of yours is touched.
`cargo run -p templar-lend-ops -- down` stops the node, `reset` deletes the
chain.

## Against a running Templar testlab

| Test | Crate | What it proves |
|---|---|---|
| `live_testlab_liquidex_make_publish_take_cancel` | templarlib | LiquiDEX end to end with nothing but the test-server profile: two fresh software wallets join the lab (`set_test_server`), get L-BTC and an issued asset from the lab's admin API and regtest BTC from its public faucet (one small request); A prepares an exact coin (`swap_make_prepare`), makes and publishes an offer (the same proposal again is `BOOK_DUPLICATE`); B finds it in `list_markets`, verifies it deep, previews and takes it; both balances move by the offer and the price; a second offer is cancelled; neither can be taken again; the order book's watcher closes both |
| `live_testlab_issue_token_and_sell_for_lbtc` | templarlib | a user's own token sold for L-BTC, the manual test in the app: two fresh software wallets join the lab and get L-BTC through the admin API (A 0.01 for fees, B 0.5 to pay); A issues "Templar Token" (`TMPL`, precision 2, domain `templar.red`, 1 000 000 base units = 10 000.00 TMPL, one reissuance token) with `issue_asset` — no registry call on regtest (`registry_registered: false`) — and its dashboard names it `TMPL` / `Templar Token`; A prepares an exact 100.00 TMPL coin, offers it for 0.05 L-BTC and publishes it; B finds it verified and takeable in `list_markets`, verifies it deep, previews and takes it; A is paid exactly the price and gives exactly the coin, B pays the price plus the previewed fee; A then reissues 5 000.00 TMPL (`reissue_asset`) and burns 10.00 (`burn_asset`), each mined and checked; the book's watcher closes the offer |
| `live_testlab_wallet_created_before_joining_sees_its_regtest_funds` | templarlib | the manual tester's order in one engine: a wallet created and synced on Liquid testnet (needs the public testnet Electrum servers), then the lab joined, the wallet reopened, regtest BTC sent through the admin API and mined; a sync in the same engine shows it. The lab's Electrum sees a new block about 5–7 s after bitcoind, and until then a sync answers `ok` with the old balance, so the test syncs until the funds show (it prints after how long) |
| `live_testlab_native_peg_in_and_out` | templarlib | the native Elements peg with nothing but the test-server profile: a fresh software wallet joins the lab; before any funds, a peg-in and a peg-out are refused by `peg_fund` with `PEG_INSUFFICIENT_FUNDS` naming the chain and the asset (orders cancelled); it gets regtest BTC and L-BTC from the lab's admin API; peg-in: `peg_start`; someone else pays the address first, less than expected (20 000 sats): listed in `deposits`, not the order's own, and the order can no longer be cancelled; `peg_fund` (the wallet pays the deposit from its own Bitcoin) → a claim at one confirmation is `PEG_NOT_READY` → mined to depth → `claimable` → `peg_claim` → the early payment claimed by its `outpoint` → `completed`, the L-BTC balance up by exactly both claims; peg-out: one below the lab's `pegout_min_sat` and one over its maximum refused, `peg_start` → `peg_fund` → mined → the lab's federation bot pays → `completed`, the BTC balance up by exactly the amount; an expired peg-in address (a federation change, simulated in the stored order) refused with `PEG_EXPIRED` |

| `live_testlab_wallet_funds_itself_from_the_faucet` | templarlib | `test_server_faucet`: a fresh wallet asks the lab's public faucet for L-BTC and BTC (two requests), each paid to a fresh address of its own on the right chain; after one block each, the balances are exactly what the faucet reported; on testnet the call is refused. **Skips** (prints `SKIPPED`) when the lab's `/api/config` has no `faucet` list |
| `live_testlab_registered_token_is_named_for_another_wallet` | templarlib | the order book's asset registry: A issues a token with no domain (regtest), the engine announces it (`book_registered: true`; `reregister_asset` again is idempotent), A offers 100.00 of it; B's `list_markets` row, take preview and, after the take, its summary row show the ticker, the name and precision 2 (`100.00`), marked `metadata_source: "book"`. **Skips** when the book has no `/api/assets` |

The LiquiDEX test needs the Templar testlab (the `templar-testlab`
repository) running with its order book, on loopback with no admin password (the test mines
through the lab's admin API, `POST /admin/api/mine`), and one asset issued
by the lab:

```bash
# in templar-testlab, with [orderbook] binary = a built templar-orderbook
# (cargo build --release -p templar-orderbook in templar-protocol)
./target/release/templar-testlab up
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"name":"Live Swap Token","ticker":"LST","precision":2,"amount":100000}' \
  http://127.0.0.1:8096/admin/api/assets
```

Then, here:

```bash
cargo test -p templarlib live_testlab -- --ignored --nocapture
```

The peg test needs only the stack (`up`), not the order book or an
issued asset; it runs alone with

```bash
cargo test -p templarlib live_testlab_native_peg -- --ignored --nocapture
```

It funds its wallet through the lab's admin API (`POST /admin/api/send`,
open on loopback without a password), not the public faucet, and mines
both chains (`POST /admin/api/mine`). One run takes about 40 seconds,
moves 0.0022 BTC in and 0.0015 L-BTC out, and prints every txid.

Both tests mine the blocks they need through the admin API and never
rely on the lab mining one per payment: since its hardening the lab
confirms faucet and admin payments only in batches, and its public
faucet takes at most 0.1 coin per request, 3 requests per address and
10 per client an hour, within a budget shared by all testers.

| Variable | Effect |
|---|---|
| `TEMPLAR_LIVE_TESTLAB_URL` | the lab's base URL; default `http://127.0.0.1:8096` |
| `TEMPLAR_LIVE_TESTLAB_ASSET` | the asset A offers (one the lab's faucet can send); default the newest in the lab's `GET /api/assets` — set it to the issued test asset when `templar-testlab smoke` has issued newer tokens the lab can no longer pay out (`elementsd sendtoaddress: Insufficient funds`) |

One run takes about a minute (most of it waiting for the book's watcher,
which runs every 60 s) and makes one public-faucet request (0.01 BTC);
the rest comes through the admin API. Each run uses throwaway data
directories; `templar-testlab down` stops the stack.

The faucet test needs a lab whose `/api/config` lists its faucet; it makes
two public-faucet requests (within the per-address and per-client
limits). The registry test needs an order book with the asset registry
(`/api/assets`) and a chain backend for its regtest; it funds through the
admin API. Run them with

```bash
cargo test -p templarlib live_testlab_wallet_funds -- --ignored --nocapture
cargo test -p templarlib live_testlab_registered_token -- --ignored --nocapture
```

On 2026-11-17 the owner's lab still ran the older binaries (no faucet
list, no `/api/assets`): both skipped, and neither was run against the
new pieces.

The issuance test needs the stack and its order book, but no issued
asset and no public faucet (everything comes through the admin API); it
runs alone with

```bash
cargo test -p templarlib live_testlab_issue -- --ignored --nocapture
```

On 2026-11-17 it passed in about 67 s and printed every txid. Fees seen:
41 sats for the issuance, 40 for the preparation, 377 for the take (the
taker pays it), 47 for the reissuance, 38 for the burn. Only the issuer
knows the token's name: neither the taker's engine nor the order book
reads the contract committed in the issuance, and regtest has no
registry, so the book names it `Unregistered asset` with the asset id's
first 8 hex digits as ticker (e.g. `80D249A8`) and precision 8, and the
taker's dashboard shows the asset id's prefix as name and ticker. Amounts
are right in base units, but 100.00 TMPL shows as `0.00010000` there.
That is still what an order book without the asset registry gives (the
issuance then reports `book_registered: false`, `book_error: "this order
book has no asset registry"`, as on 2026-11-17 against the owner's lab);
with the registry, `issue_asset` announces the token and other wallets
name it (`live_testlab_registered_token_is_named_for_another_wallet`).

## Against SideSwap's public testnet API

| Test | Crate | What it proves |
|---|---|---|
| `live_sideswap_testnet_quote_and_orders` | templarlib | the SideSwap provider on Liquid testnet: a fresh wallet on testnet beside a (local, fake) test server whose config names SideSwap for testnet; `peg_quote` in both directions from SideSwap's real `server_status`; a quote below SideSwap's minimum refused; then one order per direction: opened, followed (`peg_status`), refused by `peg_claim` and cancelled — or, when SideSwap refuses to open it, the refusal surfaces as an error and nothing is stored |

It needs only the network: SideSwap's testnet endpoint
(`wss://api-testnet.sideswap.io/json-rpc-ws`; `TEMPLAR_SIDESWAP_URL`
overrides it).

```bash
cargo test -p templarlib live_sideswap -- --ignored --nocapture
```

No funds move: SideSwap's deposit addresses are never paid. On
2026-11-15 SideSwap's testnet answered `server_status`, but refused both
orders: peg-out with `disabled on testnet`, peg-in with an internal error
of its own backend; the test then checks the refusals, not an order.

## Against public Liquid testnet and the local order book

| Test | Crate | What it proves |
|---|---|---|
| `live_testnet_liquidex_make_publish_take_cancel` | templarlib | LiquiDEX end to end on public Liquid testnet with no test server joined: two software wallets get coins from the public faucet (A its TEST asset and L-BTC for fees, B L-BTC), each payment confirmed before the next request; A prepares an exact coin (`swap_make_prepare`), waits for its block, makes an offer of TEST for L-BTC whose output leg carries a `blinding_nonce`, publishes it to the local order book's testnet book, which verifies it on chain (the same proposal again is `BOOK_DUPLICATE`); B finds it in `list_markets` (verified, takeable), verifies it deep (`network: testnet`), previews and takes it; after the block both wallets show the trade, and A's wallet unblinds the L-BTC it was paid (a coin of exactly the price from the take's txid, and the dashboard balance); a second take is refused; a second offer is published, cancelled (`swap_cancel`) and refused to B; the book's watcher marks the first `filled` and the second `cancelled` |

It needs:

- the order book (`templar-orderbook`) running on `http://127.0.0.1:3210`
  with its default testnet chain backend (Blockstream's public Liquid
  testnet Electrum); `curl http://127.0.0.1:3210/api/health` shows
  `"public_publish": {… "liquid-testnet": "chain"}`. The engine's defaults
  already point there when no test server is joined;
- the network: Blockstream's Liquid testnet Electrum
  (`elements-testnet.blockstream.info:50002`) for both wallets, Bitcoin
  testnet Electrum for the Bitcoin half of `sync_wallet` (its failure is
  ignored), and the public faucet `https://liquidtestnet.com/api/faucet`.

No `TEMPLAR_*` variable is needed; do not join a test server.

```bash
cargo test -p templarlib live_testnet_liquidex -- --ignored --nocapture
```

| Variable | Effect |
|---|---|
| `TEMPLAR_LIVE_TESTNET_DIR` | a directory for the two wallets' data directories (`maker/`, `taker/`), kept after the run. A rerun reopens the same wallets and asks the faucet only for what they lack; without it each run uses throwaway directories and asks the faucet three times |

The faucet pays 100 000 sats of L-BTC (`action=lbtc`) or 5 000 base units
of its TEST asset (`action=test`,
`38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5`) per
request, allows 3 requests a minute, and serves about one payment per
block: it spends its own change, so a request made before its previous
payment confirmed answers HTTP 200 with
`{"result": "error", "error": "…InsufficientFunds…"}`. The test makes each
request only after the previous one is confirmed and never retries one; a
refusal fails the run with the faucet's answer.

The test offers 2 000 base units of TEST (2.000 TEST: the registry gives
it precision 3) for 20 000 sats of L-BTC; the second offer is the
remaining TEST coin. Liquid testnet makes a block about every minute; the
test syncs every 15 s and allows 15 minutes per confirmation, and prints
how long each wait took and every txid as a Blockstream explorer link.
On 2026-11-17 two runs passed: each faucet payment confirmed in about
40 s, the prepared coin in about 60 s, the take and the cancel in 40–60 s,
the book's deep verification took about 1.7 s, and the watcher had closed
both offers within 15 s of the cancel's confirmation. A run with funded
wallets takes 3–5 minutes; each missing faucet payment adds about a
minute. Fees seen: 40 sats for the preparation and for the cancel, 377
for the take (the taker pays it).

Neither the engine nor the order book knows the TEST asset's metadata:
the engine reads no public registry for assets it did not issue, and the
book names an unknown asset `Unregistered asset` with ticker `38FCA2D9`
and precision 8 until its admin adds it. Amounts are right in base
units, but both show 2 000 units as `0.00002000`.

## Against a running Templar Protocol site

Built only with the `protocol` feature (the default).

| Test | Link it needs | What it proves |
|---|---|---|
| `live_connect_with_proof_then_portfolio_and_open` | `TEMPLAR_LIVE_CONNECT_LINK`: the `templar://connect?…` link of the site's `/wallet` page | connect with the proof of key in the callback ([CONNECTOR.md](../CONNECTOR.md) §3, §9.3), receive the portfolio token, read the loans (§7), mint a one-time browser link (§8) |
| `live_proof_request_is_recognised_signed_and_accepted` | `TEMPLAR_LIVE_SIGN_LINK`: a `templar://sign?…` link of a `proof` request (the check page of «Find your loans», or a reconnect by a wallet without inline proof) | the wallet recognises the site's check PSET as the check of its own challenge (§9.5), signs it once, and the site accepts it (§9.2) |

Start the regtest node as above, then the site as the templar-protocol
repository describes; the site reads its environment from
`data/regtest/regtest.env` there. Open the site in a browser, copy the link
it shows, and run:

```bash
TEMPLAR_LIVE_CONNECT_LINK='templar://connect?url=…&nonce=…' \
  cargo test -p templarlib live_connect -- --ignored --nocapture

TEMPLAR_LIVE_SIGN_LINK='templar://sign?url=…&nonce=…' \
  cargo test -p templarlib live_proof_request -- --ignored --nocapture
```

Optional variables:

| Variable | Effect |
|---|---|
| `TEMPLAR_LIVE_MNEMONIC` | the wallet to answer with; default: the BIP39 test vector `abandon … about` |
| `TEMPLAR_LIVE_NO_PROOF` | set to anything: connect without a proof, as a 0.1.0 wallet does; once the site knows the key it must answer with a proof request and no token |
| `TEMPLAR_LIVE_OUT` | a file path: write the portfolio JSON there, for a fixture |

Links are single use and expire (a connect token after 10 minutes, a
challenge after 10): copy a fresh one for every run. The mnemonic is a
test wallet's; never use a phrase that holds anything.

## Other ignored tests

| Test | Crate | Needs | Run |
|---|---|---|---|
| `debug_watch_only_scan` | templar-core | Bitcoin testnet Electrum (`TEMPLAR_ELECTRUM_URL` or the default server) | `cargo test -p templar-core debug_watch_only_scan -- --ignored --nocapture`: prints each UTXO's keychain and index for a fixed testnet xpub; a debugging probe, it asserts nothing about your setup |
| `print_escrow_fixture` | templar-core | nothing | `cargo test -p templar-core print_escrow_fixture -- --ignored --nocapture`: prints the escrow PSET fixture the contract tests pin; regenerate it only when the escrow shape changes on purpose |
| `measure_current_kdf_cost` | templar-core | time | `cargo test -p templar-core measure_current_kdf_cost -- --ignored --nocapture`: prints what one Argon2id derivation with the production parameters costs on this machine (dev builds compile Argon2 optimised, so no `--release` is needed) |
