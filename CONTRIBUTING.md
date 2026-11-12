# Contributing

Read [CLAUDE.md](CLAUDE.md) first: it lists the rules a change must keep
(thread safety, the vault, frozen coins, test networks only, the JSON
contract, what is never logged). Security issues go through
[SECURITY.md](SECURITY.md), not through a pull request.

## Setup

- Rust: CI pins **1.95.0** (`RUST_TOOLCHAIN` in
  [.github/workflows/ci.yml](.github/workflows/ci.yml)); use the same
  version so `clippy -D warnings` sees the same lints.
  `rustup toolchain install 1.95.0 --component clippy rustfmt`.
- Linux: `libudev-dev` and `pkg-config` for the `hardware` feature (hidapi,
  serialport). macOS and Windows need nothing else.
- For the dependency checks: `cargo install --locked cargo-deny cargo-audit`.

The first build compiles BDK and LWK and takes a few minutes. Debug builds
compile Argon2 and the AEAD optimised (see `[profile.dev.package.*]` in
[Cargo.toml](Cargo.toml)), so vault tests run at real speed.

## The gate

Every command below runs in CI on every push to `main` and every pull
request. Run them before you push:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo check --locked -p templar-core --no-default-features
cargo clippy --locked -p templarlib --no-default-features --all-targets -- -D warnings
cargo build --locked --workspace --examples
cargo deny check
cargo audit
```

`--locked` fails when `Cargo.lock` no longer matches the manifests. If your
change adds or bumps a dependency, run the build once without `--locked`,
commit the updated `Cargo.lock`, and make sure the gate then passes with it.

The tests are offline. A few are `#[ignore]`d because they need a local
Elements regtest node or a running Templar Protocol site; they are not part
of the gate. How to run them: [docs/guides/LIVE_TESTS.md](docs/guides/LIVE_TESTS.md).

## Commits

- English, imperative, lower-case [Conventional Commits](https://www.conventionalcommits.org)
  prefix: `feat:`, `fix:`, `docs:`, `build:`, `ci:`, `chore:`, `refactor:`,
  `test:`. A scope is optional: `feat(protocol): …`.
- Subject ≤ 72 characters; the body says why, not what the diff already
  shows.
- One logical step per commit. A refactor and a behaviour change are two
  commits.

## Pull requests

A pull request needs:

- the gate green;
- a test for every behaviour change; a change to a method's parameters or
  response comes with a contract test in
  `crates/templarlib/src/contract_tests.rs`;
- [docs/API.md](docs/API.md) updated when a method is added, changed or
  removed, and `METHODS` / `dispatch.rs` kept in step;
- a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for
  anything a host or a user would notice;
- a note in the description when it touches signing, the vault, frozen
  coins or the connector: say what you checked;
- no new dependency without a reason in the description; its licence must
  be on the allow-list in [deny.toml](deny.toml).

## Licence

By contributing you agree that your contribution is dual-licensed under
[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), as the rest of the
repository, without additional terms.
