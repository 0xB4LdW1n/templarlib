# 0001 — The library gets its own repository

Status: accepted, 2026-11-12.

## Context

`templar-core` (chain and wallet primitives) and `templarlib` (the JSON
engine) lived inside the Templar Wallet repository, next to the Flutter
app, the wallet's C ABI crate and the terminal client. Three hosts use
them:

- the Flutter app, through `crates/wallet-ffi` in templar-wallet;
- the terminal client, `apps/tui` in templar-wallet;
- the Templar Protocol server, whose `templar-lend-connector` and
  `templar-lend-ops` crates use `templar-core` for escrow descriptors,
  settlement PSETs and the simulated wallet.

The server therefore depended on a checkout of the wallet application to
get a library, and the library's public contract (the methods, the
connector) was documented across both repositories.

## Decision

- `crates/templar-core` and `crates/templarlib` move to this repository
  with their git history; the workspace builds on its own and carries the
  profiles the wallet used (`panic = "unwind"` and LTO in release, Argon2
  and the AEAD optimised in dev).
- Licence `MIT OR Apache-2.0`.
- Until the first tag, each host depends on a sibling checkout by path
  (`../templarlib/crates/...`), with a note in its manifest to switch to a
  git tag. After the first tag, hosts pin a tag.
- The connector contract the wallet implements moves here as
  [docs/CONNECTOR.md](../CONNECTOR.md), since this repository is public and
  holds the wallet side of it.
- CI here gates the library on its own: formatting, clippy, tests, the
  build with optional features off, the examples, `cargo deny`,
  `cargo audit`.

## Consequences

- A change that spans the library and a host is two commits in two
  repositories; the library change lands first.
- Cargo honours `[profile.*]` only at a workspace root: a host that builds
  these crates in its own workspace must copy the profiles
  ([INTEGRATION.md](../INTEGRATION.md#1-depend-on-the-crate)).
- The host repositories' GitHub CI cannot build them until they switch
  from the path dependency to a tag.
- Host-specific code stays out of this repository: no Flutter, no C ABI, no
  terminal rendering, no server logic.
