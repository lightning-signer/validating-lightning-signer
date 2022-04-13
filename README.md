# A BOLT-style protocol adapter for Validating Lightning Signer (VLS)

For now, we have in this repo:

- a `no_std` CLN-compatible wire protocol encoder/decoder crate in [./vls-protocol](./vls-protocol)
- a `no_std` VLS handler for the protocol - in [./vls-protocol-signer](vls-protocol-signer/README.md) - to be split to a separate crate
- a replacement for the UNIX `hsmd` binary, implemented in Rust in [./vls-proxy](./vls-proxy). This binary is suitable for replacing `hsmd` when running C-Lightning integration tests.

TODO:

- split out the signer gRPC v2 binary from the `vls-proxy` crate.

## Development Information

### Formatting Code

Enable formatting precommit hooks:

    ./scripts/enable-githooks

For some reason, the `ignore` configuration for rustfmt is only available on the nightly channel,
even though it's documented as stable.

    rustup install nightly

    cargo +nightly fmt
