# Rust Lightning Signer

Please see the
[Rust Lightning Signer Project Overview](https://gitlab.com/lightning-signer/docs/-/blob/master/README.md)
for more information.

# Starting the gRPC server

The gRPC server is a reference implementation of a signer which listens for requests from the node and from the admin CLI over gRPC.

It can be started via:
```
cargo run --bin server
```

The server will persist it's state to `.lightning-signer` in the current directory.

# Using the admin CLI

Assuming the server is running (see above), the admin CLI can be invoked as follows:
```shell
cargo run --bin client -- [ARGUMENTS]
```
For example, to get help, run:
```
cargo run --bin client -- help`
```

Here is an example session:

```shell
# this outputs the new mnemonic phrase to stderr
node_id=$(cargo run --bin client -- node new)

# alternatively, supply the mnemonic phrase on stdin
# cargo run --bin client -- node new --mnemonic

# insert an address into the allowlist
cargo run --bin client -- -n $node_id allowlist add tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z
cargo run --bin client -- -n $node_id allowlist list

channel_id=$(cargo run --bin client -- channel new -n $node_id)
cargo run --bin client -- channel list -n $node_id
```

## Development Information

### Formatting Code

For some reason, the `ignore` configuration for rustfmt is only available on the nightly channel,
even though it's documented as stable.

    rustup install nightly

    cargo +nightly fmt

### Building Rust Lightning Signer

    cargo build

or if you want to disable grpc (grpc is the only default feature):

    cargo build --no-default-features
    
### Running Unit Tests

    cargo test
    
To enable logging for a failing test (adjust log level to preference):

    RUST_LOG=trace cargo test
    
### Running the Server

    cargo run --bin server

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
    ./scripts/run-kcov-functional
    ./scripts/run-kcov-all
        
View Coverage Report:

    [target/kcov/cov/index.html](target/kcov/cov/index.html)
