# Validating Lightning Signer

Please see the
[VLS Project Overview](https://gitlab.com/lightning-signer/docs/-/blob/master/README.md)
for more information.  Our [web site](https://vls.tech/).

# Limitations

The following remain to be implemented:

* `vlsd2 --recover-close` can only handle a simple force-close by us.  It cannot sweep a force-close or a breach by the peer.  It also cannot sweep HTLC outputs.
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
    
### Using [kcov](https://github.com/SimonKagstrom/kcov) for Code Coverage

Dependencies:

    sudo dnf install -y elfutils-devel curl-devel binutils-devel

or
    
    sudo apt-get install -y libcurl4-openssl-dev libelf-dev libdw-dev binutils-dev libiberty-dev

Build v38 of kcov from git@github.com:SimonKagstrom/kcov.git .

Ensure `kcov --verify /tmp/x a.out` does not complain about `libbfd`.

More dependencies:

    cargo install cargo-kcov
    cargo install cargo-coverage-annotations

Run coverage:

    ./scripts/run-kcov
    ./scripts/run-kcov --lib
    ./scripts/run-kcov --test functional_test
        
View Coverage Report:

    [target/kcov/cov/index.html](target/kcov/cov/index.html)
