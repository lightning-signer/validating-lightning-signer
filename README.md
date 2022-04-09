# A BOLT-style protocol adapter for Validating Lightning Signer (VLS)

For now, we have in this repo:

- a `no_std` CLN-compatible wire protocol encoder/decoder crate in [./vls-protocol](./vls-protocol)
- a `no_std` VLS handler for the protocol - in [./vls-protocol-signer](vls-protocol-signer/README.md) - to be split to a separate crate
- a replacement for the UNIX `hsmd` binary, implemented in Rust in [./vls-proxy](./vls-proxy). This binary is suitable for replacing `hsmd` when running C-Lightning integration tests.

TODO:

- split out the signer gRPC v2 binary from the `vls-proxy` crate.
