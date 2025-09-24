## Overview

vls-protocol is the wire-protocol and core-types crate for the Validating Lightning Signer (VLS) and its clients. It defines the protocol message registry and schemas, provides strongly typed models for common fields and cryptographic primitives, and implements consensus (de)serialization using serde_bolt and derive macros.

The crate supports both `std` and `no_std` builds, and includes utilities for handling Partially Signed Bitcoin Transactions (PSBTs). The streaming PSBT support decodes without retaining full input transactions, validates or populates `witness_utxo`, and records which inputs are segwit to reduce memory use and avoid malleability pitfalls.

## Crate Features
- `std` (default): enables standard library integration through dependencies (`serde_bolt/std`, `txoo/std`, `vls-core/std`).
- `no-std`: builds for `no_std` environments; see `#![no_std]` gate in `lib.rs`.
- `developer`: includes developer/test-only helpers like `MeasuredWriter` and enables additional tests.
- `log-secrets` (dangerous): enables printing secret values in debug output; never enable in production.

## Usage Notes
- Use the types in `model.rs` for fixed-size fields and keys when defining or handling messages.
- Use `psbt::StreamedPSBT` to parse PSBTs when memory pressure is a concern; it validates and populates `witness_utxo` and records per-input segwit status.
- Prefer error types from `error.rs` and bubble them up via the crate `Result<T>`.

## Testing
- Unit tests cover models and PSBT streaming, including vectors from `fixtures/`.
- Some tests require the `developer` feature and use `serde_bolt` test utilities.

## Protocol Messages

HSMD protocol messages are declared in the core lightning repository: [hsmd_wire.csv](https://github.com/ElementsProject/lightning/blob/master/hsmd/hsmd_wire.csv)

Always keep request message definitions sorted by their numeric message ID in both places:
- `types.csv` must be sorted ascending by the `id` column.
- `src/msgs.rs` must list the corresponding Rust message variants/handlers in the same ascending ID order.

When adding a new message:
- Add the request and (if applicable) the reply entries to `types.csv` with the correct `status` (e.g., `done` or `missing`).
- Add the matching Rust definitions in `src/msgs.rs` in the same sorted position (by `id`).
- Keep request/reply pairs adjacent.

**Note**: Run the system’s tests defined in [VLS HSMD](https://gitlab.com/lightning-signer/vls-hsmd) before opening a PR related to protocol message changes with the latest CLN version.
