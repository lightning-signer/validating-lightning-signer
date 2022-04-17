#### Setup

```
rustup override set nightly
```

#### Running

```
cargo run --features stm32f412
cargo run --features stm32f413
```

#### SD Card Setup

For now, please format the root device, without any partitions.

```sh
sudo mkfs.vfat -F32 /dev/sdX
```

#### Reference

- [32F412GDISCOVERY User Manual](https://www.st.com/resource/en/user_manual/um2032-discovery-kit-with-stm32f412zg-mcu-stmicroelectronics.pdf)
- [32F413HDISCOVERY User Manual](https://www.st.com/resource/en/user_manual/um2135-discovery-kit-with-stm32f413zh-mcu-stmicroelectronics.pdf)
