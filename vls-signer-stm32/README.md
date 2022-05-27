#### Setup

```
rustup override set nightly
rustup target add thumbv7em-none-eabihf
```

#### SD Card Setup

For now, please format the root device, without any partitions.

```sh
sudo mkfs.vfat -F32 /dev/sdX
```

#### Hardware Test

Connect the `ST_LINK` port to host computer using USB cable.  Omit the
`sdio` feature if you don't have an SDcard inserted.

```
cargo run --features stm32f412,sdio --release --bin test
cargo run --features stm32f413,sdio --release --bin test
```

Note that compiling with `--release` greatly reduces flash size, and therefore flashing time.

#### Connecting to Serial Port

Additionally connect the `USB_USER` (`stm32f412`) or `USB_OTG_FS`
(`stm32f413`) port to host computer with a second USB cable.

Connect to the serial connection with a suitable tool:
```sh
sudo screen /dev/ttyACM1 19200
```

Device will echo typed characters ...

#### Run Signer Demo

1. Connect the `ST_LINK` port to the host computer using a USB cable.

2. From a terminal shell in this directory run the `demo_signer`:
   - Set the `--features` flag to the specific board model you are using.
   - Omit the `sdio` feature if you don't have a formatted SDcard inserted.

For example, using the STM32F413:
```
cargo run --features stm32f413,sdio --release --bin demo_signer
```
Wait for the demo_signer to finish loading and start executing, it will display
"init" when it is ready.

3. Connect the user serial port (`USB_USER` on the `stm32f412` or
   `USB_OTG_FS` on the `stm32f413`) to the host computer.

4. In a second terminal shell, change directories to the top-level
   `vls-hsmd` directory and execute the desired test:
```
make config-experimental test-one VLS_MODE=cln:serial TEST=tests/test_pay.py::test_pay
```

#### Reference

- [32F412GDISCOVERY User Manual](https://www.st.com/resource/en/user_manual/um2032-discovery-kit-with-stm32f412zg-mcu-stmicroelectronics.pdf)
- [32F413HDISCOVERY User Manual](https://www.st.com/resource/en/user_manual/um2135-discovery-kit-with-stm32f413zh-mcu-stmicroelectronics.pdf)
