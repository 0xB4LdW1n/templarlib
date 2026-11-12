# templarlib

A Bitcoin and Liquid wallet engine in Rust, driven through one JSON call:

```rust
let engine = templarlib::TemplarLib::with_data_dir("./wallet-data");
let reply = engine.call("vault_status", &serde_json::json!({}));
// {"ok": {"state": "none", "initialized": false, …}}  or  {"err": "…"}
```

It holds the wallets, the encrypted vault, the signing checks and the chain
access, so a host only has to render screens or run business logic around
it. It is built on BDK 0.30 (Bitcoin, Miniscript in `wsh()`) and LWK 0.9
(Liquid, confidential assets, PSET). Today it runs on Bitcoin testnet and
Liquid testnet, plus a local Liquid regtest for development; mainnet is
refused.

| Crate | What it is |
|---|---|
| [`crates/templar-core`](crates/templar-core) | Chain and wallet primitives: wallets, Miniscript policies, multisig, PSBT / PSET inspection and signing, the vault, the registry, hardware signers, QR (BC-UR). No application state. |
| [`crates/templarlib`](crates/templarlib) | The stateful engine: `TemplarLib::call(method, params)`, the list of accepted methods (`METHODS`), the DTOs. |

Hosts today: the Templar Wallet app (Flutter, through a thin C ABI) and its
terminal client, and the Templar Protocol server, which uses `templar-core`
for its wallet side.

## Try it in 5 minutes

You need a stable Rust toolchain (CI pins 1.95.0). On Linux, the USB stack
also needs `libudev-dev` and `pkg-config`; see [Features](#features) to build
without it.

```bash
git clone https://github.com/0xB4LdW1n/templarlib
cd templarlib
cargo build --workspace            # the first build compiles BDK and LWK: a few minutes
cargo run -p templarlib --example embed
```

The example creates a throwaway data directory, sets up a vault, creates a
wallet, derives a Bitcoin and a Liquid address, shows what an error looks
like and locks the vault again. It needs no network and no secrets.

Call any single method against a fresh data directory:

```bash
cargo run -p templarlib --example embed -- version
cargo run -p templarlib --example embed -- get_liquid_network
cargo run -p templarlib --example embed -- generate_receive_address '{"wallet_id":"x","asset":"BTC"}'
```

The last one answers `{"err":"Wallet not found: x"}`: every failure comes
back as a value, never as a panic or an exception.

## Features

Both are on by default.

| Feature | Adds | Turn it off when |
|---|---|---|
| `hardware` | USB signers: Ledger and other HID devices, Jade over serial, HWI. Needs `libudev` on Linux. | The target has no USB stack (the Android build). The hardware methods stay in the method list and answer `HW_UNSUPPORTED: …`. |
| `protocol` | The wallet side of Templar Protocol: `get_protocol_escrow_xpub`, `protocol_check_pset`, `protocol_is_check_pset`. | The host never talks to the protocol. The three methods disappear from the list. |

```bash
cargo build -p templarlib --no-default-features --features protocol
```

## Documentation

| Read | To |
|---|---|
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | embed the engine in your own host |
| [docs/API.md](docs/API.md) | look up a method: parameters, response, errors |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | understand the crates, state, threading and storage |
| [docs/CONNECTOR.md](docs/CONNECTOR.md) | implement the Templar Protocol wallet connector |
| [docs/guides/LIVE_TESTS.md](docs/guides/LIVE_TESTS.md) | run the ignored regtest and live-site tests |
| [docs/decisions/](docs/decisions/) | see why the repository is shaped this way |
| [CONTRIBUTING.md](CONTRIBUTING.md) | send a change |
| [SECURITY.md](SECURITY.md) | report a vulnerability |
| [CHANGELOG.md](CHANGELOG.md) | see what changed |

## Status

Alpha. Versions start at 0.1.0 and any 0.x release may change the method
contract. Nothing is published to crates.io yet; hosts depend on a checkout
of this repository by path until the first tag.

Templar Protocol: Today the protocol runs on a test regtest; in beta it will run on a server of ours; then Liquid mainnet.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this
work, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
