# Validating Lightning Signer

Please see the
[VLS Project Overview](./docs/Overview/intro.md)
for more information.  Our [web site](https://vls.tech/).

## Limitations

The following remain to be implemented:

* `vlsd --recover-to` can only handle a simple force-close by us.  It cannot sweep a force-close or a breach by the peer.  It also cannot sweep HTLC outputs.
* there is no facility to recover from loss of signer state.
* on-chain tracking is not fully implemented, so a malicious node can steal funds by failing to remedy a breach (for example)

## Additional Crates

- a `no_std` VLS wire protocol encoder/decoder - in [./vls-protocol](./vls-protocol)
- a `no_std` protocol handler for VLS - in [./vls-protocol-signer](vls-protocol-signer/README.md)
- a replacement for the UNIX CLN `hsmd` binary, implemented in Rust in [./vls-proxy](./vls-proxy).

## Development Information

[Check out our Docs](./docs/README.md)

### Recommended Rust Version

We recommend using the nightly version of Rust only in specific cases, such as for `cargo fmt` and `no-std`. Otherwise, we explicitly recommend using the stable version.

### Formatting Code

Enable formatting precommit hooks:

    ./scripts/enable-githooks

For some reason, the `ignore` configuration for rustfmt is only available on the nightly channel,
even though it's documented as stable.

    rustup install nightly

    cargo +nightly fmt

### Building Validating Lightning Signer

Build VLS and related crates:

    cargo build

### Workspace Structure

This is a Cargo workspace with multiple crates:

**Workspace members** (built with `cargo build`):
- Core: `vls-core`, `vls-protocol`, `vls-protocol-signer`, `vls-persist`, `vls-frontend`
- Integration: `vls-proxy`, `vlsd`, `vls-cli`
- Support: `bolt-derive`, `vls-policy-derive`, `vls-util`

**Excluded crates** (require special build steps):
- `vls-signer-stm32` - STM32 microcontroller port (requires `cargo +nightly-2024-10-13`)
- `embedded` - Bare-metal implementation
- `wasm` - WebAssembly build
- `lnrod` - LDK-based Lightning node reference
- `lightning-storage-server` - Cloud storage service
- `vls-core-test` - Benchmarking utilities

Use `./scripts/build-all` to build all crates including excluded ones.

### Running Unit Tests

    cargo test

To enable logging for a failing test (adjust log level to preference):

    RUST_LOG=trace cargo test

### Running System Tests

Some crates have system tests that require additional features:

    cargo test --features system-test

For vls-proxy specifically:

    cargo test --package vls-proxy --test frontend_system_test --features system-test

### Important Feature Flags

When testing or developing, be aware of these feature flags:

**vls-core**:
- `test_utils` - Required for comprehensive testing (enables testing utilities)
- `no-std` - For embedded/bare-metal environments
- `grpc` - Auto-conversion to tonic::Status
- `debug` - Enable state tracing
- `txoo-source` - UTXO oracle integration

**vls-protocol**:
- `developer` - Test-only helpers and additional tests
- `log-secrets` - ⚠️ DANGEROUS: Prints secrets in debug output (never use in production)

Example:

    cargo build --features system-test,redb-kvv
    cargo test --package vls-core --features test_utils

### Using llvm-cov for Code Coverage

Dependencies:

    cargo +stable install cargo-llvm-cov --locked

Run coverage:

    ./scripts/run-llvm-cov

Changing linker to `mold` instead of `ld`:

    cp .cargo/config.sample.toml .cargo/config.toml

### Updating Dependencies

There are a few crates with lock files. You can update them all and
view the results of `cargo audit` in one command:

    scripts/update-all

### Additional Development Scripts

The `scripts/` directory contains helpful development tools:

- `./scripts/build-all` - Build all crates including excluded ones (embedded, wasm, lnrod, etc.)
- `./scripts/build-nostd` - Build no_std targets
- `./scripts/clean-all` - Clean all build artifacts across workspace
- `./scripts/fmt-all` - Format all crates with nightly rustfmt
- `./scripts/do-all` - Run a command across all workspace members

## Benchmarks

### Running Benchmarks

    cargo bench -p vls-core --bench secp_bench

Note that you might need to add `--features=test_utils` if you want to run all benches in vls-core.

Without optimizations:

    cargo bench -p vls-core --bench secp_bench --profile=dev

Expect something like:

```
    test fib1_bench        ... bench:           1 ns/iter (+/- 0)
    test fib_bench         ... bench:      17,247 ns/iter (+/- 198)
    test hash_bench        ... bench:         258 ns/iter (+/- 2)
    test secp_create_bench ... bench:      49,981 ns/iter (+/- 642)
    test sign_bench        ... bench:      25,692 ns/iter (+/- 391)
    test verify_bench      ... bench:      31,705 ns/iter (+/- 1,445)
```

i.e. around 30 microseconds per secp256k1 crypto operation.  We also see
that creating a secp context is expensive, but not prohibitively so.
