# Motivation

The Lightning Storage Service provides a way for Lightning nodes and signers ("clients") to store state in the cloud securely.  By storing redundant copies, the client can ensure that the state was not rolled back.

Future work will include a way to atomically commit across multiple LSS providers.

# Security Model - Signer

These are the assumptions for the security model in case of a signer, such as VLS:

- the node does not collude with the storage provider
- if more than one storage provider is used, they do not collude with each other
- there may be a MITM between the signer and the storage provider

The last assumption derives from the fact that the signer may be in a secure enclave, and not directly connect to the storage provider.

# Security Model - Node

These are the assumptions for the security model in case of a node, such as one written using LDK:

- if more than one storage provider is used, they do not collude with each other

# Design

The server stores versioned key-value pairs in an atomic transaction.  The versions must be strictly monotonic without gaps.  Any violation of the versioning rule will result in an aborted transaction and the conflicting values in the database will be returned.

The client authenticates itself to the server using a secret/public keypair and a shared secret derived from that and the server keypair.  Each client has a separate storage key namespace.

Key-value pairs can be retrieved by key prefix.  The returned values are retrieved atomically.

The client internally appends an HMAC that covers:

- the key
- the version, as 8 bytes big endian
- the value

The server returns an HMAC using a shared secret that covers the stored items (`put`) or retrieved items (`get`).  A nonce is also covered in the case of a `get`.  This can be used to prove to a signer in a secure enclave that there was no replay attack by a MITM, and that the server was actually reached for the operation.

# Try it

```sh
cargo run --bin lssd

alias lss-cli="cargo run --bin lss-cli --"

lss-cli init

lss-cli put xx1 0 11
# will conflict
lss-cli put xx1 0 11

lss-cli put xy1 0 11
lss-cli put xy2 0 22

lss-cli get xx
lss-cli get xy
lss-cli get xy1
```
