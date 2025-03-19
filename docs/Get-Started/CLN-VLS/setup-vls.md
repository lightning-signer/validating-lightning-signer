---
layout: layouts/docs.njk
title: Setup VLS Service
eleventyNavigation:
  key: Setup VLS Service
  parent: CLN & VLS
  order: 5
---

## Setup VLS testnet Service

### Configure Service

Configure the VLS service on the `VLSHOST`.

Add `vls` user and group:
```bash
sudo /usr/sbin/groupadd vls
sudo /usr/sbin/useradd -g vls -c "Validating Lightning Signer" -m vls
```

Setup config files:
```bash
# become root user
touch /home/vls/.lightning-signer/ALLOWLIST
cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/vlsd2.toml /home/vls/.lightning-signer/vlsd2.toml
echo "rpc-user = <ADMIN_USER>" >> /home/vls/.lightning-signer/vlsd2.toml
echo "rpc-pass = <ADMIN_SERVER_PASSWORD>" >> /home/vls/.lightning-signer/vlsd2.toml
```

Create `~vls/.lightning-signer/testnet-env`:
```bash
sudo -u vls bash << 'EOF'
cat > ~vls/.lightning-signer/testnet-env << EOF2
REMOTE_SIGNER_ALLOWLIST=/home/vls/.lightning-signer/ALLOWLIST
VLS_PERMISSIVE=1
EOF2
EOF
```

Make sure vls owns everything:
```bash
sudo chown -R vls:vls /home/vls/.lightning-signer
```

Install systemd unit file:
```bash
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/vls-testnet.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Install log rotation config file (edit to suit preferences):
```bash
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/vls-testnet.logrotate /etc/logrotate.d/vls-testnet
```

If you would like to allow legacy anchor channels (non-zero-fee anchors) you should
add the following line to `/home/vls/vlsd2.toml`:
```bash
policy-filter = "policy-channel-safe-type-anchors:warn"
```

Enable the  service for automatic start on system boot:
```bash
sudo systemctl enable vls-testnet
```

If you want to start the service now:
```bash
sudo systemctl start vls-testnet
```

View status:
```bash
sudo systemctl status vls-testnet
```

View logs:
```bash
sudo journalctl --follow -u vls-testnet
```
