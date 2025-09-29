## Setup VLS testnet Service

### Configure Service

Configure the VLS service on the `VLSHOST`.

Add `vls` user and group:
```
sudo /usr/sbin/groupadd vls
sudo /usr/sbin/useradd -g vls -c "Validating Lightning Signer" -m vls
```

Setup config files:
```bash
# become root user
touch /home/vls/.lightning-signer/ALLOWLIST
cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/vlsd.toml /home/vls/.lightning-signer/vlsd.toml
echo "rpc-user = <ADMIN_USER>" >> /home/vls/.lightning-signer/vlsd.toml
echo "rpc-pass = <ADMIN_SERVER_PASSWORD>" >> /home/vls/.lightning-signer/vlsd.toml
```

Create `~vls/.lightning-signer/testnet-env`:
```
sudo -u vls bash << 'EOF'
cat > ~vls/.lightning-signer/testnet-env << EOF2
REMOTE_SIGNER_ALLOWLIST=/home/vls/.lightning-signer/ALLOWLIST
VLS_PERMISSIVE=1
EOF2
EOF
```

Make sure vls owns everything:
```
sudo chown -R vls:vls /home/vls/.lightning-signer
```

Install systemd unit file:
```
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/vls-testnet.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Install log rotation config file (edit to suit preferences):
```
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/vls-testnet.logrotate /etc/logrotate.d/vls-testnet
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
