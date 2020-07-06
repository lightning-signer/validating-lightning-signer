# Rust Lightning Signer

Please see the
[Rust Lightning Signer Project Overview](https://gitlab.com/lightning-signer/docs/-/blob/master/README.md)
for more information.

## Development Information

### Formatting Code

For some reason, the `ignore` configuration for rustfmt is only available on the nightly channel,
even though it's documented as stable.

    rustup install nightly

    cargo +nightly fmt

### Building Rust Lightning Signer

    cargo build
    
### Running Unit Tests

    cargo test
    
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
    
Run coverage:

    ./scripts/run-kcov
    ./scripts/run-kcov-functional
    ./scripts/run-kcov-all
        
View Coverage Report:

    [target/kcov/cov/index.html](target/kcov/cov/index.html)

Check coverage annotations in source files:

    cargo coverage-annotations
