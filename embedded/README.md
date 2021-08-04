# Running

To run the embedded test, first prepare your environment:

```shell
sudo ./scripts/install-deps
rustup target add thumbv7m-none-eabi
```

Then:

```shell
source ./scripts/env.sh && cargo run --target thumbv7m-none-eabi
```

Output should be something like:

```text
heap size 524288
secp buf size 66240
Seed WIF: L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D
Address: bc1qpx9t9pzzl4qsydmhyt6ctrxxjd4ep549np9993
stub channel ID: 0614c30f3f3d34a695c76be742f953a0dce6d1f4edb6c6b856fc27a04266f275
channel ID: 0614c30f3f3d34a695c76be742f953a0dce6d1f4edb6c6b856fc27a04266f275
used memory 201432
```

Note that this heap size is required because of the amount of stack used by libsecp256k1 when initializing a context.  This will be greatly reduced once libsecp256k1 uses static multiplication tables.

