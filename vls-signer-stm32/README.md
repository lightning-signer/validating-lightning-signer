#### Setup

```
sudo apt install gcc-arm-none-eabi gdb-multiarch -y
sudo apt install libudev-dev -y
sudo apt install screen -y

rustup override set nightly
rustup target add thumbv7em-none-eabihf

cargo install probe-run

sudo adduser $USER dialout
```

Follow [udev rules setup instructions](https://probe.rs/docs/getting-started/probe-setup/)

#### SD Card Setup

For now, please format the root device, without any partitions.

```sh
sudo mkfs.vfat -F32 /dev/sdX
```

#### Hardware Test

Connect the `ST_LINK` port to host computer using USB cable.

```
cargo run --features stm32f412 --release --bin test
cargo run --features stm32f413 --release --bin test
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

For example, using the STM32F413:
```
cargo run --features stm32f413,debug --release --bin demo_signer
```
Wait for the demo_signer to finish loading and start executing, it will display
"init" when it is ready.

3. Connect the user serial port (`USB_USER` on the `stm32f412` or
   `USB_OTG_FS` on the `stm32f413`) to the host computer.

4. In a second terminal shell, change directories to the top-level
   `vls-hsmd` directory and execute the desired test:
```
make config-experimental test-one VLS_MODE=cln:serial TEST=tests/test_plugin.py::test_forward_event_notification VLS_SERIAL_SELECT=2
```

#### Interesting integration tests

3 channels, nice routing:
```
make config-experimental test-one VLS_MODE=cln:serial TEST=tests/test_pay.py::test_pay_retry VLS_SERIAL_SELECT=2
```

3 channels, ok routing:
```
make config-experimental test-one VLS_MODE=cln:serial TEST=tests/test_pay.py::test_forward VLS_SERIAL_SELECT=2
```

4 channels, nice closing:
```
make config-experimental test-one VLS_MODE=cln:serial TEST=tests/test_closing.py::test_closing_different_fees
```

1 channel, nice invoice, receive:
```
make config-experimental test-one VLS_MODE=cln:serial TEST=tests/test_closing.py::test_closing_different_fees VLS_SERIAL_SELECT=2
```

Example of invoice approval:
```
make config-experimental test-one VLS_MODE=cln:serial TEST=tests/test_pay.py::test_pay_retry VLS_SERIAL_SELECT=1
```

Example of sending keysends:
```
make config-experimental test-one VLS_MODE=cln:serial TEST=tests/test_pay.py::test_keysend VLS_SERIAL_SELECT=1
```


#### Reference

- [32F412GDISCOVERY User Manual](https://www.st.com/resource/en/user_manual/um2032-discovery-kit-with-stm32f412zg-mcu-stmicroelectronics.pdf)
- [32F413HDISCOVERY User Manual](https://www.st.com/resource/en/user_manual/um2135-discovery-kit-with-stm32f413zh-mcu-stmicroelectronics.pdf)
