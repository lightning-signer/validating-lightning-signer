## Setup VLS STM32 Probe testnet Service

**IMPORTANT** This service allows the STM32 to be programmed and
controlled by the host for development. It should not be run in
production!

### Setup Service

The `vls-probe-testnet` service can be run as the normal user (`user`).

Setup the probe service directory:
```
mkdir -p $(HOME)/vls-probe/testnet
cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/vls-probe-testnet $(HOME)/vls-probe/
```

Install the udev rules file:
```
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/68-vls-stm32.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Install systemd unit file:
```
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/vls-probe-testnet.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Install log rotation config file (edit to suit preferences):
```
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/vls-probe-testnet.logrotate /etc/logrotate.d/vls-probe-testnet
```

Enable the  service for automatic start on system boot:
```
sudo systemctl enable vls-probe-testnet
```

If you want to start the service now:
```
sudo systemctl start vls-probe-testnet
```

View status:
```
sudo systemctl status vls-probe-testnet
```

View logs:
```
sudo journalctl --follow -u vls-probe-testnet
```
