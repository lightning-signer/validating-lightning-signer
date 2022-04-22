#### Setup

```
rustup override set nightly
```

#### Running

Connect the `ST_LINK` port to host computer using USB cable.

```
cargo run --features stm32f412
cargo run --features stm32f413
```

#### SD Card Setup

For now, please format the root device, without any partitions.

```sh
sudo mkfs.vfat -F32 /dev/sdX
```

#### Connecting to Serial Port

Additionally connect the `USB_USER` (`stm32f412`) or `USB_OTG_FS`
(`stm32f413`) port to host computer with a second USB cable.

Connect to the serial connection with a suitable tool:
```sh
sudo screen /dev/ttyACM1 19200
```

Device will echo typed characters ...

#### Reference

- [32F412GDISCOVERY User Manual](https://www.st.com/resource/en/user_manual/um2032-discovery-kit-with-stm32f412zg-mcu-stmicroelectronics.pdf)
- [32F413HDISCOVERY User Manual](https://www.st.com/resource/en/user_manual/um2135-discovery-kit-with-stm32f413zh-mcu-stmicroelectronics.pdf)
