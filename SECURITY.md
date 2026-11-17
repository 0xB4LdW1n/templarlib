# Security

This library holds keys and decides what gets signed, so security reports
come before any other work.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting
instead: the repository's **Security** tab → **Report a vulnerability**.
Include what you did, what happened, and the commit you tested.

You will get an answer within a few days. A fix lands on `main` and in the
next release, and the report is credited in [CHANGELOG.md](CHANGELOG.md)
unless you ask otherwise.

## Scope

Both crates in this repository, `templar-core` and `templarlib`, with
default features and with `hardware` or `protocol` turned off.

The library runs on Bitcoin testnet and Liquid testnet, plus a local Liquid
regtest for development, and refuses mainnet by design. No report can put
real funds at risk today; the key handling, the vault and the signing checks
are the ones mainnet will use, and that is what matters. Templar Protocol: Today the protocol runs on a test regtest; in beta it will run on a server of ours; then Liquid mainnet.

Particularly interesting:

- reading a recovery phrase, a private key or the vault key without the
  passphrase, or finding one written to disk or to a log in plaintext (the
  vault is Argon2id + XChaCha20-Poly1305, `crates/templar-core/src/vault.rs`);
- a transaction that inspection reports one way while the signature commits
  to another (`crates/templar-core/src/bitcoin/psbt.rs`,
  `crates/templar-core/src/liquid/pset.rs`, the `inspect_*` and `sign_*`
  methods);
- spending a frozen coin, or making the library sign for a coin or a key it
  should not, sign one of its inputs with a sighash type other than
  SIGHASH_ALL, or sign a taproot input at all — the wallet does not sign
  taproot inputs on Liquid (`refuse_unsafe_signing` in
  `crates/templar-core/src/liquid/pset.rs`);
- a Liquid input whose signature spends a coin other than the one the PSET
  names: a key of the wallet signs a coin of the wallet only as the coin
  its descriptor derives at that key's path, and any other key of ours
  only a P2WPKH or P2WSH coin whose declared script is the one the
  signature commits to (no P2SH wrapper, no P2PKH script code inside a
  P2WSH, a `non_witness_utxo` that agrees). A wallet coin that inspection
  does not count as the wallet's but a key of the wallet signs is a bug
  ([Liquid signing checks](docs/ARCHITECTURE.md#liquid-signing-checks));
- a peg-in input signed by any route but `peg_claim` for one of the
  wallet's own orders (`LiquidWalletManager::sign_own_pegin_claim`);
- a Templar Protocol check PSET ([docs/CONNECTOR.md §9](docs/CONNECTOR.md#9-proof-of-key--the-check-pset))
  that the wallet accepts as a proof but that can move funds, or that is
  valid for another site or challenge;
- a mainnet key, coin or proposal that gets signed;
- a server the wallet reads (a test server, the order book or HTLC
  coordinator, SideSwap, an Electrum or Esplora server) that makes it pay,
  claim or sign something other than what the user asked for, or that
  holds the engine beyond its deadlines (see
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#untrusted-servers)). Known
  and accepted: a peg-out names the parent genesis LWK knows for the lab's
  chain (Bitcoin regtest), checked against the lab's published Bitcoin
  server, not read from the Liquid chain itself
  ([Peg](docs/ARCHITECTURE.md#peg)).

Out of scope: the hosts (the Templar Wallet app, its terminal client, the
Templar Protocol server) live in their own repositories; report there. A
host that logs a response carrying a secret is a host bug.

## Known advisories, accepted

`cargo deny check` and `cargo audit` run in CI and on a daily schedule. The
advisories below are ignored, with the same list in [deny.toml](deny.toml)
(with reasons) and [.cargo/audit.toml](.cargo/audit.toml). An entry is
removed as soon as its crate leaves `Cargo.lock`. `cargo audit` also prints
informational warnings about unmaintained or unsound crates deeper in the
graph; those do not fail CI, and `cargo deny` fails on an unmaintained
crate only when this workspace depends on it directly.

**Old TLS stack pinned by the Bitcoin Electrum client.** BDK 0.30 pulls
`electrum-client` 0.18 (rustls 0.21, rustls-webpki 0.101, webpki-roots
0.22), and that line has no fixed release. This stack is used only for
Electrum connections to the configured Bitcoin servers. LWK 0.20, and
`templar-core` in step with it, use `electrum-client` 0.25 on the same
rustls 0.23, rustls-webpki 0.103 and webpki-roots 1.x as every other HTTPS
client (reqwest), kept on fixed versions by `Cargo.lock`.

| Advisory | Crate | Issue | Removed by |
|---|---|---|---|
| RUSTSEC-2026-0346 | rustls 0.21 | `Debug` output of client session values exposes TLS secrets | BDK upgrade off `electrum-client` 0.18 |
| RUSTSEC-2026-0349 | rustls 0.21 | an unauthenticated ServerHello can downgrade later connections to classical key exchange | BDK upgrade off `electrum-client` 0.18 |
| RUSTSEC-2026-0098 | rustls-webpki 0.101 | name constraints for URI names incorrectly accepted | BDK upgrade off `electrum-client` 0.18 |
| RUSTSEC-2026-0099 | rustls-webpki 0.101 | name constraints accepted for certificates asserting a wildcard name | BDK upgrade off `electrum-client` 0.18 |
| RUSTSEC-2026-0104 | rustls-webpki 0.101 | reachable panic in certificate revocation list parsing | BDK upgrade off `electrum-client` 0.18 |
| RUSTSEC-2026-0382 | rustls-webpki 0.101 | certificate verification may accept distrusted intermediates | BDK upgrade off `electrum-client` 0.18 |
| RUSTSEC-2026-0381 | webpki-roots 0.22 | bundled roots allow trust in distrusted emSign intermediates | BDK upgrade off `electrum-client` 0.18 |

**Unmaintained crate.**

| Advisory | Crate | Issue | Removed by |
|---|---|---|---|
| RUSTSEC-2021-0127 | serde_cbor 0.11 | unmaintained (informational) | `templar-core`'s Jade dialect and `lwk_jade` both moving to a maintained CBOR crate. Only in builds with the `hardware` feature. |

The upgrades that remove them are tracked here. BDK and LWK upgrades are
deliberate projects ([CLAUDE.md](CLAUDE.md) §1–2): the BDK major changes
the wallet API and the sync model, and the LWK version must move together
with the Templar Protocol server. No date is set.
