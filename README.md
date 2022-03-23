# A Greenlight adapter for Lightning Signer

For now, we have in this repo:

- a `no_std` C-Lightning wire protocol encoder/decoder crate in [./greenlight-protocol](./greenlight-protocol)
- a `no_std` handler for an augmented `hsmd` protocol - in [./greenlight-signer](./greenlight-signer/README.md) - to be split to a separate crate
- a proof-of-concept replacement for the UNIX `hsmd` binary, implemented in Rust in [./greenlight-signer-hsmd](./greenlight-signer-hsmd). This binary is suitable for replacing `hsmd` when running C-Lightning integration tests.

Current test success:

```
====== 57 failed, 323 passed, 82 skipped, 23 errors in 559.64s (0:09:19) =======
```
