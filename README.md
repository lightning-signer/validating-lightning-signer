# Rust Lightning Signer

Please see the
[Rust Lightning Signer Project Overview](https://gitlab.com/lightning-signer/docs/-/blob/master/README.md)
for more information.

## Development Information

### Building Rust Lightning Signer

    cargo build
    
### Running Unit Tests

    cargo test
    
### Running the Server

    cargo run --bin server

### Using [Tarpaulin](https://github.com/xd009642/tarpaulin) for Code Coverage

Basic coverage:

    cargo install cargo-tarpaulin
    cargo tarpaulin

Check coverage annotations in source files:

    cargo install cargo-coverage-annotations
    cargo tarpaulin
    cargo coverage-annotations |& sort > coverage.txt
    diff coverage-false-positives.txt coverage.txt
