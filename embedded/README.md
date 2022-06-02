# Running

To run the embedded test, first prepare your environment:

```shell
sudo ./scripts/install-deps
rustup +nightly target add thumbv7m-none-eabi
```

Then:

```shell
source ./scripts/env.sh && cargo +nightly run --target thumbv7m-none-eabi
```

Output should be something like:

```text
heap size 458752
secp buf size 192
Seed WIF: L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D
Address: bc1qpx9t9pzzl4qsydmhyt6ctrxxjd4ep549np9993
stub channel IDs: d7d6fecaec52609d0f087c13184dd3a8fd06cc9c2b5189f26415027907896cf3 cd719b3bc3a2a951daa4b2e6b0aa5a7bc79ec8c7c18925064c7e352c9a9bcae5
used memory 16540
```

# Testing / Coverage

To test on your CPU rather than a device / emulator, run:

```shell
cargo +nightly test --no-default-features --features std tests
```
