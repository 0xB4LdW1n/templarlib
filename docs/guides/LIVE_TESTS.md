# Running the ignored tests

`cargo test --workspace` is offline and is the gate. Nine tests are
`#[ignore]`d because they need something the gate does not have: a local
Elements regtest node, a running Templar testlab, a running Templar
Protocol site, a public Electrum server, or time. This guide says what each one needs and how to run it.

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
| `live_testlab_liquidex_make_publish_take_cancel` | templarlib | LiquiDEX end to end with nothing but the test-server profile: two fresh software wallets join the lab (`set_test_server`), get L-BTC, an issued asset and regtest BTC from its public faucet; A prepares an exact coin (`swap_make_prepare`), makes and publishes an offer (the same proposal again is `BOOK_DUPLICATE`); B finds it in `list_markets`, verifies it deep, previews and takes it; both balances move by the offer and the price; a second offer is cancelled; neither can be taken again; the order book's watcher closes both |
| `live_testlab_native_peg_in_and_out` | templarlib | the native Elements peg with nothing but the test-server profile: a fresh software wallet joins the lab, gets regtest BTC and L-BTC from the lab's admin API; peg-in: `peg_start` → `peg_fund` (the wallet pays the deposit from its own Bitcoin) → a claim at one confirmation is `PEG_NOT_READY` → mined to depth → `claimable` → `peg_claim` → `completed`, the L-BTC balance up by exactly the claim's output; peg-out: an over-limit peg-out refused, `peg_start` → `peg_fund` → mined → the lab's federation bot pays → `completed`, the BTC balance up by exactly the amount; an expired peg-in address (a federation change, simulated in the stored order) refused with `PEG_EXPIRED` |

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
moves 0.002 BTC in and 0.0005 L-BTC out, and prints every txid.

| Variable | Effect |
|---|---|
| `TEMPLAR_LIVE_TESTLAB_URL` | the lab's base URL; default `http://127.0.0.1:8096` |
| `TEMPLAR_LIVE_TESTLAB_ASSET` | the asset A offers (one the lab's faucet can send); default the newest in the lab's `GET /api/assets` |

One run takes about a minute (most of it waiting for the book's watcher,
which runs every 60 s) and makes four faucet requests; the lab allows ten
per client per hour (`[faucet] per_ip_per_hour`), so restart the lab's
server, or wait, after the second run in an hour. Each run uses throwaway
data directories; `templar-testlab down` stops the stack.

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
