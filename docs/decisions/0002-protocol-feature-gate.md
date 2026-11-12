# 0002 — The Templar Protocol wallet side is a feature

Status: accepted, 2026-11-12.

## Context

The library carries the wallet side of Templar Protocol: the escrow account
key (`m/2121'/1'/0'`), the proof-of-key check PSET and its verification
(`templar_core::liquid::protocol`), and three engine methods,
`get_protocol_escrow_xpub`, `protocol_check_pset` and
`protocol_is_check_pset`. A host that embeds the engine as a plain Bitcoin
and Liquid wallet has no use for them, and their presence in `METHODS`
advertises a capability that host does not offer.

## Decision

A `protocol` feature on both crates, on by default:

- `templar-core`: `protocol = []` gates the `liquid::protocol` module and
  its re-exports. It is pure Rust and adds no dependency.
- `templarlib`: `protocol = ["templar-core/protocol"]` gates the three
  method names in `METHODS`, their dispatch arms, their handlers and their
  contract tests. With the feature off they are absent: calling one
  answers `Unknown method: …`. Their DTOs in `templarlib::types` stay
  public in every build; they carry no protocol logic.

This differs from `hardware` on purpose. Without `hardware` the USB
methods stay in `METHODS` and answer `HW_UNSUPPORTED: …`, because a host
that runs the same wallets on several platforms needs to explain why a
device does not work on this one. A host built without `protocol` has no
protocol flows at all, so there is nothing to explain.

## Consequences

- With the default features nothing changes for existing hosts.
- CI builds and lints both crates with default features off.
- Code outside the gate must not call into `liquid::protocol`. A shared
  helper either moves out of the module or is gated with it.
- [docs/API.md](../API.md) marks the three methods **[protocol]**.
