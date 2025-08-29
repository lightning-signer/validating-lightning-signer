---
layout: layouts/docs.njk
title: Setup Bitcoind Service
description: Configure bitcoind testnet service for VLS. Setup bitcoin user, systemd service, and RPC configuration for Lightning node integration.
eleventyNavigation:
  key: Setup Bitcoind Service
  parent: CLN & VLS
  order: 2
---

# Setup Bitcoind  Service

You can skip this entirely if you already have bitcoin installed as a service.

This procedure presumes you've already performed the
[One Time Setup](./one-time-setup.md) `Install Bitcoind` section.

### Configure Service

Configure the bitcoind service on the `CLNHOST`.

Add `bitcoin` user and group:
```bash
sudo /usr/sbin/groupadd bitcoin
sudo /usr/sbin/useradd -g bitcoin -c "bitcoin" -m bitcoin
```

Install sample config:
```bash
sudo mkdir -p /home/bitcoin/.bitcoin
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/bitcoin.conf /home/bitcoin/.bitcoin
```

Edit the config file, change the `rpcpassword` to something random:
```bash
sudo vi /home/bitcoin/.bitcoin/bitcoin.conf
```

Make sure bitcoin owns everything:
```bash
sudo chown -R bitcoin:bitcoin  /home/bitcoin/.bitcoin
```

Install systemd unit file:
```bash
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/bitcoind-testnet.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Install log rotation config file (edit to suit preferences):
```bash
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/bitcoind-testnet.logrotate /etc/logrotate.d/bitcoind-testnet
```

On Fedora we have to enable permissive mode for SELinux, change `SELINUX=permissive`
```bash
sudo vi /etc/selinux/config
```

Enable the  service for automatic start on system boot:
```bash
sudo systemctl enable bitcoind-testnet
```

If you want to start the service now:
```bash
sudo systemctl start bitcoind-testnet
```

View status:
```bash
sudo systemctl status bitcoind-testnet
```
