#### Setup

On Debian (or Ubuntu):
```
sudo apt install gcc-arm-none-eabi gdb-multiarch -y
sudo apt install libudev-dev -y
sudo apt install screen -y
```

On Fedora:
```
sudo dnf install arm-none-eabi-gcc-cs gdb -y
sudo dnf install -y arm-none-eabi-gcc-cs-c++.x86_64 arm-none-eabi-newlib.noarch
sudo dnf install libusbx-devel systemd-devel -y
sudo dnf install glibc-devel.i686 glibc-devel -y
sudo dnf install screen -y
```

```
# IMPORTANT - run this in the vls-signer-stm32 subdirectory, where this README is.
rustup override set nightly

rustup target add thumbv7em-none-eabihf

# Don't build it here because the override above is in effect
(cd $HOME && cargo install probe-run)

sudo usermod -a -G dialout $USER
newgrp dialout
```

Follow [udev rules setup instructions](https://probe.rs/docs/getting-started/probe-setup/)

#### SD Card Setup

For now, please format the root device, without any partitions.

```sh
sudo parted /dev/sdX --script mklabel gpt
sudo mkfs.vfat -F32 /dev/sdX
```

#### Run Signer Demo

1. Connect the `ST_LINK` port to the host computer using a USB cable.

2. From a terminal shell in this directory run the `demo_signer`:
```
make run
```

Wait for the demo_signer to finish loading and start executing, it will display
`waiting for node` when it is ready.

3. Connect the user serial port (`USB_OTG_FS`) to the host computer.

4. In a second terminal shell, change directories to the top-level
   `vls-hsmd` directory and execute the desired test:
```
make test-one VLS_MODE=cln:serial TEST=tests/test_plugin.py::test_forward_event_notification VLS_SERIAL_SELECT=2
```

>Note: `demo_signer` is only for test purposes. It should only be ran with CLN in `developer` mode and has a required build feature `developer` on the binary.

#### Rerunning the current image

If you want to rerun the signer but do not wish to re-flash the device, perhaps after a crash:
```
make rerun
```

#### Specifying additional features

If you would like to build and run w/ additional features set the
`EXTRA_FEATURES` env variable when running the demo_signer:
```
make EXTRA_FEATURES=debug,log_pretty_print run
```

#### Interesting integration tests

3 channels, nice routing:
```
make test-one VLS_MODE=cln:serial TEST=tests/test_pay.py::test_pay_retry VLS_SERIAL_SELECT=2
```

3 channels, ok routing:
```
make test-one VLS_MODE=cln:serial TEST=tests/test_pay.py::test_forward VLS_SERIAL_SELECT=2
```

4 channels, nice closing:
```
make test-one VLS_MODE=cln:serial TEST=tests/test_closing.py::test_closing_different_fees
```

1 channel, nice invoice, receive:
```
make test-one VLS_MODE=cln:serial TEST=tests/test_closing.py::test_closing_different_fees VLS_SERIAL_SELECT=2
```

Example of invoice approval:
```
make test-one VLS_MODE=cln:serial TEST=tests/test_pay.py::test_pay_retry VLS_SERIAL_SELECT=1
```

Example of sending keysends:
```
make test-one VLS_MODE=cln:serial TEST=tests/test_pay.py::test_keysend VLS_SERIAL_SELECT=1
```

This generally runs the signer out of memory (100 concurrent channels), useful for tuning:
```
make test-one VLS_MODE=cln:serial TEST=tests/test_connection.py::test_funding_cancel_race VLS_SERIAL_SELECT=1
```

#### Reference

- [32F412GDISCOVERY User Manual](https://www.st.com/resource/en/user_manual/um2032-discovery-kit-with-stm32f412zg-mcu-stmicroelectronics.pdf)
- [32F413HDISCOVERY User Manual](https://www.st.com/resource/en/user_manual/um2135-discovery-kit-with-stm32f413zh-mcu-stmicroelectronics.pdf)
