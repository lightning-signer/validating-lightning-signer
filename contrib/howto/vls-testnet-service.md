## Setup VLS testnet Service

### Configure Service

Configure the VLS service on the `VLSHOST`.

Add `vls` user and group:
```
sudo /usr/sbin/groupadd vls
sudo /usr/sbin/useradd -g vls -c "Validating Lightning Signer" -m vls
```

Setup config files:
```
sudo touch /home/vls/ALLOWLIST
sudo chown vls:vls /home/vls/ALLOWLIST
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/artifacts/vlsd2.toml /home/vls/vlsd2.toml
sudo chown vls:vls /home/vls/vlsd2.toml
```

Install systemd unit file:
```
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/artifacts/vls-testnet.service /lib/systemd/system/
sudo systemctl daemon-reload
```

If you would like to allow legacy anchor channels (non-zero-fee anchors) you should
add the following line to `/home/vls/vlsd2.toml`:
```
policy-filter = "policy-channel-safe-type-anchors:warn"
```

Optionally enable PERMISSIVE mode:

[FIXME - move this to the config file, see:
https://gitlab.com/lightning-signer/validating-lightning-signer/-/issues/259]

Add `Environment=VLS_PERMISSIVE=1` after the existing `Environment=...` line:
```
sudo vi /lib/systemd/system/vls-testnet.service
sudo systemctl daemon-reload
```

Enable the  service for automatic start on system boot:
```
sudo systemctl enable vls-testnet
```

If you want to start the service now:
```
sudo systemctl start vls-testnet
```

View status:
```
sudo systemctl status vls-testnet
```

View logs:
```
sudo journalctl --follow -u vls-testnet
```

Install log rotation config file (edit to suit preferences):
```
sudo cp ~/lightning-signer/vls-hsmd/vls/howto/artifacts/vls-testnet.logrotate /etc/logrotate.d/vls-testnet
```
