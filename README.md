# Validating Lightning Signer

Please see the
[VLS Project Overview](https://gitlab.com/lightning-signer/docs/-/blob/master/README.md)
for more information.  Our [web site](https://vls.tech/).

# Starting the gRPC server

The gRPC server is a reference implementation of a signer which listens for requests from the node and from the admin CLI over gRPC.

It can be started via:
```
alias vlsd="cargo run --bin vlsd"
alias vls-cli="cargo run --bin vls-cli --"
vlsd
```

The server will persist its state to `.lightning-signer` in the current directory.

# Using the admin CLI

Assuming the server is running (see above), the admin CLI can be invoked as follows:
```shell
vls-cli [ARGUMENTS]
```
For example, to get help, run:
```
cargo run --bin vls-cli -- help
```

Here is an example session:

```shell
# this outputs the new mnemonic phrase to stderr
node_id=$(vls-cli node new)

# alternatively, supply the mnemonic phrase on stdin
# vls-cli node new --mnemonic

# insert an address into the allowlist
vls-cli -n $node_id allowlist add tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z
vls-cli -n $node_id allowlist list

channel_id=$(vls-cli channel new -n $node_id)
vls-cli channel list -n $node_id
```

## Additional Crates

- a `no_std` CLN-compatible wire protocol encoder/decoder crate in [./vls-protocol](./vls-protocol)
- a `no_std` VLS handler for the protocol - in [./vls-protocol-signer](vls-protocol-signer/README.md)
- a replacement for the UNIX `hsmd` binary, implemented in Rust in [./vls-proxy](./vls-proxy). This binary is suitable for replacing `hsmd` when running C-Lightning integration tests.

## Development Information

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

    cargo test --features test_utils
    
To enable logging for a failing test (adjust log level to preference):

    RUST_LOG=trace cargo test
    
### Running the gRPC Server

    cargo run --bin vlsd

### Using [kcov](https://github.com/SimonKagstrom/kcov) for Code Coverage

Dependencies:

    sudo dnf install -y elfutils-devel
    sudo dnf install -y curl-devel
    sudo dnf install -y binutils-devel

Build v38 of kcov from git@github.com:SimonKagstrom/kcov.git .

More dependencies:

    cargo install cargo-kcov
    cargo install cargo-coverage-annotations

Run coverage:

    ./scripts/run-kcov
    ./scripts/run-kcov --lib
    ./scripts/run-kcov --test functional_test
        
View Coverage Report:

    [target/kcov/cov/index.html](target/kcov/cov/index.html)
