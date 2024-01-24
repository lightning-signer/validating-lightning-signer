# Validating Lightning Signer

Please see the
[VLS Project Overview](https://gitlab.com/lightning-signer/docs/-/blob/master/README.md)
for more information.  Our [web site](https://vls.tech/).

## Limitations

The following remain to be implemented:

* `vlsd2 --recover-to` can only handle a simple force-close by us.  It cannot sweep a force-close or a breach by the peer.  It also cannot sweep HTLC outputs.
* there is no facility to recover from loss of signer state.
* on-chain tracking is not fully implemented, so a malicious node can steal funds by failing to remedy a breach (for example)

## Additional Crates

- a `no_std` VLS wire protocol encoder/decoder - in [./vls-protocol](./vls-protocol)
- a `no_std` protocol handler for VLS - in [./vls-protocol-signer](vls-protocol-signer/README.md)
- a replacement for the UNIX CLN `hsmd` binary, implemented in Rust in [./vls-proxy](./vls-proxy).

## Development Information

[Additional HOWTO Documentation](./contrib/howto/README.md)

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

### Running Unit Tests

    cargo test

To enable logging for a failing test (adjust log level to preference):

    RUST_LOG=trace cargo test

### Using llvm-cov for Code Coverage

Dependencies:

    cargo +stable install cargo-llvm-cov --locked

Run coverage:

    ./scripts/run-llvm-cov

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
