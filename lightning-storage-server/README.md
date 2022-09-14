# Motivation

The Lightning Storage Service provides a way for Lightning nodes and signers ("clients") to store state in the cloud in a secure way.  By storing redundant copies, the client can ensure that the state was not rolled back.

Future work will include a way to atomically commit across multiple LSS providers.

# Design

The server stores versioned key-value pairs in an atomic way.  The versions must be strictly monotonic without gaps.  Any violation of the versioning rule will result in an aborted transaction and the conflicting values in the database will be returned.

The client authenticates itself to the server using a secret/public keypair and a shared secret derived from that and the server keypair.  Each client has a separate storage key namespace.

Key-value pairs can be retrieved by key prefix.  The returned values are retrieved atomically.

The client internally appends an HMAC that covers:

- the key
- the version, as 8 bytes big endian
- the value

# TODO

- HMAC

# Try it

```sh
cargo run --bin lssd

cargo run --bin lss-cli init

cargo run --bin lss-cli put xx1 0 11
# will conflict
cargo run --bin lss-cli put xx1 0 11

cargo run --bin lss-cli put xy1 0 11
cargo run --bin lss-cli put xy2 0 22

cargo run --bin lss-cli get xx
cargo run --bin lss-cli get xy
cargo run --bin lss-cli get xy1
```
