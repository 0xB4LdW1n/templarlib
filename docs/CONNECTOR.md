# Templar Protocol — wallet connector protocol (v1, 2026-09-03; both sides implemented 2026-09-06)

How a user's own wallet (Templar Wallet first) takes part in a Templar Protocol loan without the
server ever holding the user's keys. Two channels, both zero-JS on the web side:

1. **Paste (works today, no wallet change):** the site shows a PSET (base64 + QR-SVG); the
   user signs it in the wallet's "Co-sign" screen and pastes the signed PSET back into the
   `/wallet/pset` form. The server combines, finalizes and broadcasts.
2. **Deep link + callback:** the site renders a plain `<a href="templar://…">`.
   The wallet opens, fetches the request, shows it, signs after user confirmation, and POSTs
   the signed PSET straight back to the server. The web page meta-refreshes until the
   signature has arrived. No browser JavaScript is involved at any point.

Both channels carry the same request object.

This is the public contract between a Templar Protocol site and any wallet. It lives in this
repository because `templarlib` implements the wallet side: which library method serves which
step, and what stays with the host application, is in §11. Section numbers are stable; code
comments cite them as `docs/CONNECTOR.md §n`.

## 1. Networks

| `network` value | LWK `ElementsNetwork` | Policy asset (L-BTC) | Address prefix |
|---|---|---|---|
| `liquid-testnet` | `LiquidTestnet` | `144c6543…9a49` | `tlq1` / `tex1` |
| `liquid-regtest` | `ElementsRegtest { policy_asset }` | `5ac9f65c…b225` (default `elementsd -chain=liquidregtest`) | `el1` / `ert1` |
| `liquid` | `Liquid` | `6f0279e9…526d` | `lq1` / `ex1` — **not enabled** |

Today the protocol runs on a test regtest; in beta it will run on a server of ours; then Liquid mainnet.

A wallet must refuse a request whose `network` differs from the network it is running on.

On `liquid-regtest` a request may also carry `policy_asset`: the node's 64-hex L-BTC asset
id (`TEMPLAR_LEND_REGTEST_POLICY_ASSET` on the site). Two regtest chains differ only by that
id, so a wallet can check it is on the *same* regtest, or offer to switch to it with the
right id prefilled. The field is optional and backward compatible (added 2026-09-17): it is
absent on testnet, where the name fixes the id, and a wallet that does not know it ignores
it. The mock backend advertises the configured `TEMPLAR_LEND_NETWORK` (default testnet) exactly
like the real one; `mock` is never a wire value.

## 2. Escrow contract the wallet will be asked to sign

CT descriptor (LWK-native miniscript, one per loan):

```
ct(slip77(<32-byte view key>),
   elwsh(or_d(multi(2, <B>/<0;1>/*, <L>/<0;1>/*),
              and_v(v:pk(<L>/<0;1>/*), after(<term_height>)))))
```

`<B>` / `<L>` are the borrower's and lender's **escrow account keys in keyorigin form**
`[fingerprint/2121h/1h/0h]tpub…` (hardened path `m/2121'/1'/0'` below the BIP39 master
key). The concrete per-loan child index is derived from the loan commitment hash; the PSET
input carries `witness_script` and `bip32_derivation` entries `[fingerprint/2121h/1h/0h/0/i]`
for both keys, so a signer only needs its master key and matches on **fingerprint** — no
descriptor import is required to sign (this is exactly what `lwk_signer::SwSigner::sign`
does, and what `templarlib`'s `sign_pset` relies on).

Any keyorigin xpub works technically; Templar Protocol uses `2121'/1'/0'` so escrow keys never
collide with the wallet's spending keys (`84'/1'/0'`) or BIP87 multisig keys (`87'/1'/0'`).

Origination also spends the party's **ordinary wallet inputs** (collateral from the
borrower's `elwpkh` wallet, principal from the lender's). For those the server needs the
party's public CT descriptor (watch-only: SLIP-77 blinding key + xpub) to select and unblind
UTXOs; the wallet signs them like any other send.

## 3. Wallet registration (`templar://connect`)

The user clicks "Connect Templar Wallet" on `/wallet`. The link:

```
templar://connect?url=<https://host/wallet/connect/<token>>&nonce=<random>
```

The wallet GETs `url` (JSON, `Accept: application/json`):

```json
{
  "version": 1,
  "kind": "connect",
  "site": "Templar Protocol demo",
  "network": "liquid-regtest",
  "policy_asset": "5ac9f65c…b225",
  "nonce": "…",
  "callback": "https://host/wallet/connect/<token>",
  "challenge": "Templar Protocol · access · https://host · nonce=… · expires=2026-10-03T10:15:00Z · this signature never moves funds",
  "expires_at": 1757000000
}
```

(`challenge` is new in v1.1, §9.) After the user picks a Liquid wallet and confirms, the wallet POSTs to `callback`
(`Content-Type: application/json`):

```json
{
  "version": 1,
  "nonce": "…",
  "network": "liquid-regtest",
  "ct_descriptor": "ct(slip77(…),elwpkh([fp/84h/1h/0h]tpub…/<0;1>/*))",
  "escrow_xpub": "[fp/2121h/1h/0h]tpub…",
  "receive_address": "el1qq…",
  "wallet_name": "Templar — Alice",
  "signer": "software" | "jade",
  "proof": { "kind": "check-pset", "pset": "<signed base64>" }   // v1.1, optional, §9
}
```

Server replies `200 {"ok":true,"next":"https://host/wallet","portfolio":{"url":"https://host/connector/portfolio","token":"<opaque>"}}` (the `portfolio` object is v1.1, §7) or `4xx {"ok":false,"error":"…"}`.

> **v1.1:** the connect JSON carries a `challenge`; a wallet that implements v1.1 answers with a
> `proof` (§9) so that reconnecting the same wallet re-attaches its loans in one step. A v1 wallet (Templar 0.1.0) sends
> no proof: when the `escrow_xpub` is already known, the site opens a proof request (§9.2) and answers
> `next` = `https://host/wallet/prove/<id>` — the page that shows that request's `templar://sign` link, its QR and the
> `SQ-check.pset` file; the browser still waiting on `/wallet` is sent there too — and attaches the session only after
> that signature (the connect token is spent either way). A never-seen xpub needs no proof. A wrong signature answers
> `400 {"ok":false,"error":"proof refused: …"}` and is remembered on the token; an unknown `proof.kind` is refused;
> attempts are capped (§9.1, `429`).

The site registers a **watch-only** wallet for the user (never a mnemonic) and stores the
escrow xpub. From now on every signing step for that user goes to the wallet.

A Jade-backed wallet sends its BIP87 account `[fp/87h/1h/0h]tpub…` as `escrow_xpub`; the site
accepts it as a loan key beside `2121h` (§10). Proving that key through a Jade is not supported
yet: the check of §9 needs a zero-value input the device has not been tested with, so the
wallet refuses every proof route for a Jade and the site falls back to a signing request.

## 4. Signing request (`templar://sign`)

```
templar://sign?url=<https://host/wallet/requests/<id>>&nonce=<random>
```

GET `url` returns:

```json
{
  "version": 1,
  "kind": "sign",
  "id": "req_8f3a…",
  "site": "Templar Protocol demo",
  "network": "liquid-regtest",
  "policy_asset": "5ac9f65c…b225",
  "nonce": "…",
  "action": "origination" | "payment_preparation" | "repayment" | "installment" |
            "payment_claim" | "collateral_claim" | "renewal" | "default" |
            "liquidation" | "swap",
  "loan_ref": "SQ-42",
  "summary": {
    "role": "borrower",
    "lines": [
      { "label": "You receive", "amount": "9,950 tUSDt" },
      { "label": "Collateral locked in the covenant", "amount": "0.01000000 tLBTC" },
      { "label": "Origination fee", "amount": "500 sat tLBTC" },
      { "label": "Templar fee, out of what you receive", "amount": "50 tUSDt" },
      { "label": "Term", "amount": "4,320 blocks (≈ 3 days)" }
    ]
  },
  "pset": "cHNldP8B…",
  "escrow": { "descriptor": "ct(slip77(…),elwsh(or_d(…)))", "address": "el1qq…" },
  "callback": "https://host/wallet/requests/<id>/signed",
  "expires_at": 1757000000
}
```

An origination carries Templar's fee at opening: a confidential
output of `⌊P · opening_fee_bps / 10 000⌋` in the principal asset to Templar's address,
which the wallet lists as an external recipient. A "Templar fee, …" line explains it for both
roles; when the borrower pays it, "You receive" is P minus the fee, and when the lender pays
it, the lender sends P plus the fee.

Wallet behaviour:

1. Verify `network` matches; verify `callback` has the same origin as `url`; require HTTPS
   unless the host is `localhost`/`127.0.0.1`.
2. Inspect the PSET locally (`inspect_pset`) and **show the wallet's own view** (recipients,
   fee, what leaves the wallet) next to the site's `summary`. Never trust the summary alone.
3. Sign only after explicit user confirmation. Never auto-sign, never store the PSET.
4. POST to `callback`:

```json
{ "version": 1, "id": "req_8f3a…", "nonce": "…", "pset": "<signed base64>" }
```

5. On `200 {"ok":true,"next":"…"}` show success and offer "Open in browser" (`next`).
   On `4xx` show the error. The wallet does **not** broadcast: the server combines the
   parties' signatures, finalizes and broadcasts (the server's facilitator role).

Rejections the wallet must make: network mismatch; expired request; PSET whose inputs
signed by this wallet do not match what the summary says leaves the wallet; a callback
on a different host.

## 5. Web side (Templar Protocol site — implemented)

| Route | Kind | Notes |
|---|---|---|
| `POST /wallet/connect` | HTML form (session + CSRF) | creates a connect token (10 min); `/wallet` then renders the `templar://connect` link, its QR code and meta-refreshes every 5 s until the wallet has answered (`POST /wallet/connect-cancel` drops it) |
| `GET /wallet/connect/{token}` | JSON, §3 | no cookie needed or created; a browser (`Accept: text/html`) is redirected to `/wallet` |
| `POST /wallet/connect/{token}` | JSON callback, §3 | checks `version`, `nonce`, `network`, the descriptor and (in the backend) the escrow key shape; single use; `200 {"ok":true,"next":"<public>/wallet"}`. A refusal is also remembered on the token and shown to the browser on the waiting page; the link stays valid, so the wallet can answer again |
| `GET /wallet/requests/{id}` | JSON, §4 | the request lives 60 min; `410` once signed, expired or abandoned; a browser (`Accept: text/html`) gets the signature page instead (§10): the owner's session only, 404 for anyone else, a «request expired or closed» page (`410`) once the round is done |
| `GET /wallet/requests/{id}/pset` | HTML (session) | the unsigned PSET as `SQ-<n>-<action>.pset` (`text/plain`, `Content-Disposition: attachment`) for the request's owner while the round is open; 404 otherwise |
| `POST /wallet/requests/{id}/signed` | JSON callback, §4 | merges the signed copy (same transaction, terms still verified from the signer's own wallet view, at least one new signature); when it was the last signature the site finalizes + broadcasts **inside this request** and answers `{"ok":true,"next":"<public>/loans/<n>"}`; any refusal is `4xx {"ok":false,"error":"…"}` |
| `POST /wallet/pset` | HTML form | the manual way in: `request=<id>` + the signed PSET, pasted (`application/x-www-form-urlencoded`, `via = paste`) or uploaded as a file (`multipart/form-data`, field `pset_file`, ≤ 64 KiB, `via = upload`), same acceptance path as the callback |
| `POST /loans/{id}/cancel-settlement` | HTML form | either party abandons the round; an origination goes back to an open offer |
| `GET /connector/portfolio` | JSON, §7 | `Authorization: Bearer <portfolio.token>` (no cookie): the wallet's loans dashboard; `401` for a missing, unknown or revoked token, `429` above 60 requests a minute per token |
| `DELETE /connector/portfolio` | JSON, §7 | bearer token; revokes it («Forget site»): `{"ok":true}`, then every use answers `401`. The site's «Remove this wallet» revokes too |
| `POST /connector/open` | JSON, §8 | bearer token, optional `{"to":"/loans/1"}`: a one-time link (`url`, `expires_at` = now + 120 s) bound to the token's row; `to` is reduced to a same-site path (default `/`) |
| `GET /connector/open/{t}` | HTML (session) | spends the link once: the browser's session is rotated onto the wallet's row, the cookie set, `303` to `to` with a flash «Signed in with Templar Wallet “<label>”»; a used, expired or garbled link renders the plain «Link expired or already used — open it again from the wallet» page (`410`) |

The site's public origin comes from `TEMPLAR_LEND_PUBLIC_URL` (default `http://<bind>`); the
wallet only accepts plain `http` for `localhost` / `127.0.0.1`, so a phone on the LAN needs
an https front. `network` is the connector's network name
(`liquid-testnet` \| `liquid-regtest`, §1; the mock backend advertises the configured
`TEMPLAR_LEND_NETWORK` too, never `mock`) and `policy_asset` follows §1.

Every loan step is a two-phase settlement behind the server's backend trait
(`prepare_settlement` → signing requests for the external parties → `accept_signature` →
`complete_settlement`). Parties whose keys the server holds are signed at prepare time,
so a round only ever lists the connected wallets. RuggedBytes installment loans use unilateral
authority chains: preparation/repayment/collateral-return claim need only the borrower;
payment claim/renewal/terminal penalty need only the lender. Bullet origination/repayment keep
their existing cooperative roles; bullet liquidation needs only the lender.

**Headless stand-in:** `cargo run -p templar-lend-ops -- wallet-sim <name> init|address|connect <link>|sign <link>`
(in the templar-protocol repository) does what the wallet's screens do (`templar-core` + plain HTTP), and
`scripts/regtest-smoke.sh --templar` there drives the whole hand-off on the local regtest with it.

## 6. Out of scope

Wallet-side broadcasting, mainnet, hardware-signer-specific flows beyond what `sign_pset_hw` already does.

---

# v1.1 (2026-10-03) — portfolio, access link, proof of key, other wallets

The site still holds no private key. Everything below is public-key identity plus two
wallet-facing reads. Field names are final unless marked *(builder decides)*.

## 7. Portfolio (`GET /connector/portfolio`) — the wallet's loans dashboard

Issued at connect: `portfolio.token` is an opaque 32-byte base64url secret bound to the connected
user row and wallet; the site stores only its SHA-256 (`connector_tokens`: id, user_id, token_hash,
created_at, last_used_at, revoked_at). The wallet keeps it with the connected site (`ProtocolStore`).
Request: `GET /connector/portfolio` with `Authorization: Bearer <token>` (no cookie). Response:

```json
{
  "version": 1, "site": "Templar Protocol", "network": "liquid-regtest", "tip_height": 1234, "as_of": 1759480000,
  "wallet": { "label": "Templar — Alice", "escrow_fingerprint": "0bae4c8d" },
  "loans": [{
    "id": 1, "ref": "SQ-1", "role": "borrower", "state": "active",
    "principal":  { "asset": "<id>", "ticker": "rUSDt", "amount": "10000",  "sats": 1000000000000 },
    "collateral": { "asset": "<id>", "ticker": "rLBTC", "amount": "0.5",    "sats": 50000000 },
    "interest":   { "ticker": "rUSDt", "amount": "200", "sats": 20000000000, "rate_bps": 200 },
    "templar_fee": { "asset": "<id>", "ticker": "rLBTC", "amount": "0.00078125", "sats": 78125, "payer": "borrower" },
    "opened_at": 1759470000, "start_height": 118, "term_height": 168, "blocks_left": 50,
    "due_at_estimate": 1759473000,
    "owed": { "ticker": "rUSDt", "amount": "10200", "sats": 1020000000000 },
    "next_action": { "kind": "repay", "label": "Repay 10,200 rUSDt before ≈ 50 min", "url": "https://host/loans/1" },
    "pending_request": { "id": "req_…", "action": "repayment", "link": "templar://sign?url=…&nonce=…", "expires_at": 1759481000 },
    "txids": { "origination": "…", "repayment": null, "liquidation": null },
    "escrow_address": "el1…"
  }],
  "offers": [{ "id": 5, "side": "lend", "state": "open", "principal": { "…": "…" }, "collateral": { "…": "…" },
               "rate_bps": 250, "duration_blocks": 43200, "url": "https://host/offers/5" }]
}
```

`next_action.kind` ∈ `sign | repay | claim | wait | none`; `pending_request` is `null` when nothing waits
for this wallet. `state` uses the site's loan states (`originating | active | repaid | defaulted |
liquidated`). Amounts are whole coins as strings (English format, no separators) plus base units.
`401` for a bad/revoked token, `429` above the rate limit (60 requests a minute per token, valid or not;
in memory, forgotten on restart). Revocation: the site's «Remove this wallet» and the wallet's «Forget
site» (`DELETE /connector/portfolio` with the bearer token).

**Built:** the token is issued on both connect paths that bind a wallet to a row — a fresh
registration and a v1.1 known-key reconnect with a valid proof (§9.3) — never on a proof-pending answer:
a v1 wallet (Templar 0.1.0) reconnecting a known key gets no token, since it has no Loans screen to
use it in; a v1.1 wallet always sends the proof inline. Issuing revokes the row's earlier token. `tip_height` is the
backend's chain tip; `wallet.escrow_fingerprint` is the master fingerprint of the loan key. Per loan:
`interest` = the frozen loan fee with `rate_bps` = the nominal rate; `templar_fee` = `F` of the opening
transaction with its payer; `owed` = what closes the loan now (the repay page's quote, principal +
interest while originating, 0 once closed); `blocks_left` = `term_height − tip` (saturating, 0 once
closed); `due_at_estimate` = `as_of + blocks_left · 60`; `next_action.label` is the dashboard's own
«what happens now» title (English), `kind` `sign` whenever a signature of this wallet waits (`url` = the
signature page), else `repay` for a repayment/installment step, `claim` for a liquidation, `wait` for a
waiting state (or the lender's «report a miss»), `none` once closed; `pending_request` = that open
signing request (`action`, `templar://sign` link, `expires_at`). `offers` = the row's own offers
(`side`, `state` = the offer status, `rate_bps`, `duration_blocks`). Each bearer request stamps
`last_used_at`. Headless stand-in: `templar-lend-ops wallet-sim <name> portfolio` (prints the JSON) after a
`connect` (the sim keeps the `portfolio` object in its file).
A v1 wallet that reconnects a known key gets no token on the proof-pending answer; the signed callback of
its proof request (§9.2) answers `{"ok":true,"next":…,"portfolio":{…}}` instead, so the token arrives
once the key is proved.

## 8. Access link (`POST /connector/open`) — «Open on Templar Protocol»

`POST /connector/open` with the bearer token, optional JSON body `{"to": "/loans/1"}` →
`{"url": "https://host/connector/open/<one-time>", "expires_at": <now+120>}`. The wallet opens `url` in the
system browser. `GET /connector/open/<one-time>` consumes it (single use, 2 minutes, bound to the token's
user row), sets the session cookie on that row and redirects to `to` (same-origin path only, default `/`)
with a flash «Signed in with Templar Wallet “Alice”». A used or expired link renders a plain page with
«Open it again from the wallet». This is the only way a browser session is bound to a wallet without
a signature in that browser: the signature happened in the wallet when it connected (§9).

**Built:** the link's secret is 32 random bytes, base64url; the site stores its SHA-256 in
`open_links` (`token_hash, user_id, to, expires_at, used_at`) with `to` already reduced to a same-site
path (`safe_back`, default `/`). `GET /connector/open/{t}` runs inside the session layer: the browser's
session (created on the spot for a fresh browser) is rotated onto the row (`session::attach_to_user`,
audit `session.attach … browser`), the `sid` cookie set on the `303`, the flash shown on the landing
page. Spending is a guarded `UPDATE … WHERE used_at IS NULL AND expires_at > now`, so two taps on the
same link see one winner; the loser, an expired link and a malformed `t` get the same `410` page. Tokens
and link secrets are never logged. Headless stand-in: `templar-lend-ops wallet-sim <name> open [path]` prints
the one-time URL.

## 9. Proof of key — the check PSET

### 9.1 Challenge and shape

The site issues `challenge` = `"Templar Protocol · access · <origin> · nonce=<16 bytes base64url> ·
expires=<RFC 3339 UTC, now+10 min> · this signature never moves funds"`. Nonces are single use, stored
with their expiry (`challenges`: nonce, purpose ∈ `connect | reenter | manual`, key_fingerprint?,
expires_at, used_at). Rate limit (built): 5 attempts per minute per client and per key, in memory
(`AppState.proofs`); the client is the first `X-Forwarded-For` address when a proxy sets one, else the
browser's session id or the connect token (the server never sees a socket address itself). A capped
attempt answers `429` on the wallet routes and a flash on the pages. The nonce is 16 random bytes,
base64url without padding (22 characters).

The **check PSET** for loan key `K` (account xpub, `2121h` or `87h`) is deterministic from
(`challenge`, `K`):

```
pk        = K/0/0 (non-hardened)
fake_txid = sha256("templar-proof" ‖ challenge)            (bytes of the UTF-8 string)
input 0   previous_txid = fake_txid, previous_output_index = 0, sequence 0xffffffff
          witness_utxo = { asset: policy asset (explicit), value: 0 (explicit), script_pubkey: P2WPKH(pk) }
          bip32_derivation[pk] = (fingerprint of K, path of K + /0/0)
          sighash_type = SIGHASH_ALL
output 0  OP_RETURN(challenge bytes), value 0 explicit, policy asset
output 1  fee output, value 0 explicit, policy asset               (LWK requires exactly one fee output)
locktime 0; PSET v2, Elements (not a Bitcoin PSBT)
```

It can never be broadcast (the prevout does not exist; value 0, fee 0). The sighash (segwit v0, Elements
variant) commits to `fake_txid`, hence to origin, nonce and expiry: a proof is valid for one site and
one challenge only. The policy asset is the network's, so a check for testnet is not a check for
regtest. Either side may build it: the **site** builds it when it already knows `K`
(§9.2, §10); a **v1.1 wallet** builds it itself from `challenge` + its own key (§9.3).

### 9.2 Proof through `templar://sign` (works with Templar 0.1.0)

A signing request (§4) with `"action": "proof"`, `"loan_ref": ""`, `summary.role` = `"owner"`, lines
«This signature never moves funds» · «Site: <origin>» · «Expires: in N min», `pset` = the check PSET,
a `challenge` field with the exact text of §9.1 (for a wallet that recomputes the check, §9.5), and
`escrow` omitted — verified on the 0.1.0 parser (`protocol_link.dart`, now
`apps/gui/lib/features/protocol/models/protocol_link.dart` in templar-wallet): `escrow`, `loan_ref` and `pset`
are optional there and `escrow` is guarded before use, so nothing is sent for it. Request ids are
`prf_…`; they live on the same URLs as loan signatures (`GET /wallet/requests/<id>`, `POST
/wallet/requests/<id>/signed`), and a browser on the GET is redirected to the page `/wallet/prove/<id>`.
The wallet's own reading shows one input that is not its coin, amount 0, an OP_RETURN and fee 0.
Callback as §4; the site verifies §9.4 and answers `next` = `/wallet` (connect, «Another wallet») or `/`
(re-entry); the page then gives the browser a fresh session id and the welcome.

### 9.3 Proof inside the connect callback (v1.1 wallets)

`"proof": {"kind": "check-pset", "pset": "<signed base64>"}` built from the connect `challenge` and the
wallet's loan key; later `{"kind": "message", "signature": "<65-byte recoverable, base64>"}` over the
same challenge string with the legacy «Bitcoin Signed Message» prefix (preferred when present). The
message variant is not implemented on the wallet side: `templar-core` has no message signing, and the
LWK release that adds `Signer::sign_message` (≥ 0.15) is beyond the 0.9 line this library stays on. With a valid proof the site attaches the
browser session to the row that owns `escrow_xpub` — the person's loans come back; without one, the
0.1.0 path (§9.2) is used when the xpub is known.

### 9.4 Verification (site)

1. Structure: PSET v2, exactly 1 input and 2 outputs, prevout = (`fake_txid` of an unused, unexpired
   challenge, 0), `witness_utxo` value 0 / policy asset / `P2WPKH(pk)` where `pk` = `K/0/0` of the
   registered (or submitted) xpub, output 0 = `OP_RETURN(challenge)` value 0, output 1 = fee 0.
2. Signature: `partial_sigs[pk]` present, DER + `0x01`, low-S; recompute the segwit v0 sighash
   (`SighashCache::segwitv0_sighash` with the P2WPKH script code and value 0) and
   `secp256k1::verify_ecdsa`.
3. Burn the nonce (`used_at`), bind the session. Store nothing but the xpub already stored and the
   challenge row; never log the PSET. Built: on a wallet callback the browser's session row moves
   onto the key's row (`sessions.user_id`, no cookie to set) and the check page rotates its id on the
   next visit; a signature pasted on the page rotates at once (`Set-Cookie`). The site's copy of the
   check is rebuilt from the challenge and the stored key: nothing the signer wrote is trusted but the
   signature.
4. Message variant: `signed_msg_hash(challenge)`, `MessageSignature::from_base64`, `recover_pubkey` ==
   `pk`.

Steps 1–2 are also implemented in `templar-core` (`verify_check_signature`), so the wallet's own
tests prove what a site will accept.

### 9.5 What the wallet must show and refuse

Under action `proof`, refuse anything that is not the exact shape of §9.1 for the request's `challenge`
(recompute `fake_txid`, check 1 input / 0 value / OP_RETURN / fee 0 / own key at `/0/0`); show the
challenge text, the site origin and the expiry; say «This signature never moves funds». The 0.1.0
review screen already shows the wallet's own reading (not-my-coin, 0, OP_RETURN) next to the site's
lines.

## 10. Other wallets: «Another wallet» and «Find your loans»

`GET/POST /wallet/manual` — paste the watch-only CT descriptor and the loan key (`[fp/87h/1h/0h]tpub…`
from `lwk_cli signer xpub --kind bip87`, or `2121h` from Templar), with an optional name and the
first-wallet terms gate; a malformed key or descriptor is refused on the page with the fields kept.
Built: step 1 opens a proof request (purpose `manual`, the descriptor and the name held on the
`proof_requests` row — not a wallet yet) and leads to `/wallet/prove/<id>`, the check page: what is
signed (statement · site · key · expiry, the challenge text), the check PSET as text and as the
`SQ-check.pset` download (`GET /wallet/requests/<id>/pset`), the command
`lwk_cli signer sign --signer <name> --pset "$(cat SQ-check.pset)"`, the upload or paste box (`POST
/wallet/pset`, `request = prf_…`; no Templar step). A valid signature (§9.4) registers the wallet the
way a Templar callback does (`connect_wallet`: the real backend syncs the descriptor, the mock
simulates it) with `wallet_connector = 'manual'`, `wallet_signer = 'file'`, `signer_kind = 'watch'`,
then `/wallet` with the flash. The descriptor warning: the site sees that wallet's balance — use a
wallet only for Templar. The mock backend accepts `87h` keys beside `2121h`.

`GET/POST /wallet/reenter` («Find your loans») — visitor-reachable (links on the welcome and
on the chooser): paste the loan key; a key some row holds (matched as written or by its bare `tpub…`,
so `h` and `'` spellings meet) opens a check (purpose `reenter`) on the same page — with the
`templar://sign` link and QR too when that row's wallet is Templar; a valid signature attaches the
browser to that row (fresh session id) and leads to `/` with «Welcome back: your loans are here».
An unknown or malformed key answers «No loans for this key» after the same 400 ms pause a
wrong signature takes; the lookup counts against the browser's cap, the signatures against the key's.
No bare-key view. Templar users use «Connect wallet» instead (§3 + §9).

Schema v7 holds it: `challenges` (§9.1), `proof_requests` (id, purpose, nonce, sign_nonce,
visitor_id, owner_id, token, escrow_xpub, ct_descriptor, wallet_label, status, via, times) and
`connect_tokens.challenge`. One open check per browser: a new request cancels the earlier pending one.

Loan signing for manual wallets: each request page (`GET /wallet/requests/{id}` with
`Accept: text/html`) offers the unsigned PSET as text and as `SQ-<n>-<action>.pset`, a paste box
and a file upload (`multipart/form-data`, ≤ 64 KiB), 60-minute life; acceptance = `POST /wallet/pset`
(same path as the paste fallback, `via = upload`). The «Sign with Templar Wallet» step of that page is
shown only when the signer's wallet is Templar (`SignRequestView.templar`).

## 11. The wallet side in this library

`templarlib` (with the `protocol` feature) supplies the keys, the reading of a PSET and the checks;
the host application does the HTTP, the link parsing, the user confirmation and the storage of the
connected site. Method details: [API.md](API.md#templar-protocol).

| Step | Library | Host application |
|---|---|---|
| §1 network check | `get_liquid_network` (`network`, `policy_asset`); `set_liquid_network` to switch to the site's regtest | compare with the request's `network` / `policy_asset`; refuse or offer to switch |
| §3 connect callback | `get_wallet_info` → `liquid_descriptor` (`ct_descriptor`); `get_protocol_escrow_xpub` (`escrow_xpub`; a Jade's BIP87 account); `generate_receive_address` with `asset: "LBTC"` (`receive_address`) | GET the request, POST the callback, keep `portfolio` |
| §3 / §9.3 inline proof | `protocol_check_pset` (unsigned check for the site's `challenge`), then `sign_pset` | put the signed PSET in `proof`; for a Jade, send no proof |
| §4 sign request | `inspect_pset` (recipients, fee, `net_change`, output kinds `own` / `escrow` / `external` / `fee`); `sign_pset`, or `sign_pset_hw` on a Jade | origin, HTTPS and expiry checks; show the wallet's reading beside `summary`; confirmation; POST the signed PSET |
| §4 refusals | `sign_pset` refuses a PSET of another network, keys on a mainnet path, outputs whose commitments do not prove their amounts, and frozen coins | refuse a mismatched network, an expired request, a callback on another host, and a PSET whose own-wallet outflow disagrees with `summary` |
| §9.2 / §9.5 proof request | `protocol_is_check_pset` (recomputes the check of the request's `challenge` for this wallet's key; a verdict with the reason) | sign only on `is_check: true`; show challenge, origin, expiry and «This signature never moves funds» |
| §4.5 broadcast | none: the wallet never broadcasts a protocol PSET | — |
| §7, §8 portfolio and access link | none | bearer-token HTTP |

The library stores nothing about a site: no request, no PSET, no token.
