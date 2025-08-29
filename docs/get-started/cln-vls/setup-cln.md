---
layout: layouts/docs.njk
title: Setup CLN Service
description: Setup Core Lightning service with VLS remote signing. Configure CLN with proper RPC settings and systemd integration.
eleventyNavigation:
  key: Setup CLN Service
  parent: CLN & VLS
  order: 4
---

# Setup CLN Service

### Configure Service

Configure the CLN service on the `CLNHOST`.

Add `cln` user and group:
```bash
sudo /usr/sbin/groupadd cln
sudo /usr/sbin/useradd -g cln -c "Core Lightning" -m cln
sudo adduser cln dialout # (`SERIAL` only)
sudo mkdir -p ~cln/.lightning
sudo chown -R cln:cln ~cln
```

Create a cln config file:
```bash
sudo -u cln bash << 'EOF'
cat > ~cln/.lightning/testnet-config << EOL
log-level=info
bitcoin-rpcuser=rpcuser
bitcoin-rpcpassword=6ffb57ab46aa726
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcport=18332
experimental-anchors
experimental-offers
EOL
EOF
```

Edit the file, change the `bitcoin-rpcpassword` value to match your `bitcoind-testnet`.
```bash
sudo -u bitcoin grep rpcpassword ~bitcoin/.bitcoin/bitcoin.conf
sudo -u cln vi ~cln/.lightning/testnet-config
```

Add the following lines only if you are using `SERIAL`:
```bash
subdaemon=hsmd:remote_hsmd_serial
max-concurrent-htlcs=4
```

Add the following line instead if you are using `SOCKET`:
```bash
subdaemon=hsmd:remote_hsmd_socket
```

Configure your firewall/router to forward an external port to the
`CLHOST`.  Add the following lines to the config, the `announce-addr`
should be set to the external firewall address/port.
```
bind-addr=0.0.0.0:19735
announce-addr=23.93.101.158:19735
```

Create `~cln/.lightning/testnet-setenv`:
```bash
sudo -u cln bash << 'EOF'
cat > ~cln/.lightning/testnet-setenv << EOL
VLS_PORT=17701
VLS_SERIAL_PORT=/dev/vls-stm32
VLS_NETWORK=testnet
# If your SOCKET signer is remote, have the proxy listen to all interfaces.
# Alternatively, set up a secure tunnel to the signer.
# VLS_BIND=0.0.0.0
BITCOIND_RPC_URL=http://rpcuser:6ffb57ab46aa726@localhost:18332
RUST_LOG=info
BITCOIND_CLIENT_TIMEOUT_SECS=60
# Dynamically set VLS_CLN_VERSION
VLS_CLN_VERSION=$(/usr/local/bin/lightningd --version)
export VLS_PORT VLS_SERIAL_PORT VLS_NETWORK BITCOIND_RPC_URL RUST_LOG BITCOIND_CLIENT_TIMEOUT_SECS VLS_CLN_VERSION VLS_BIND
EOL
EOF
```

Edit the file, change the `BITCOIND_RPC_URL` value to match your `bitcoind-testnet`:
```bash
sudo -u bitcoin grep rpcpassword ~bitcoin/.bitcoin/bitcoin.conf
sudo -u cln vi ~cln/.lightning/testnet-setenv
```

Make sure cln owns everything:
```bash
sudo chown -R cln:cln  /home/cln/
```

Install systemd unit file:
```bash
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/cln-testnet.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Install log rotation config file (edit to suit preferences):
```bash
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/cln-testnet.logrotate /etc/logrotate.d/cln-testnet
```

Enable the  service for automatic start on system boot:
```bash
sudo systemctl enable cln-testnet
```

If you want to start the service now:
```bash
sudo systemctl start cln-testnet
```

View status:
```bash
sudo systemctl status cln-testnet
```

View logs:
```bash
sudo journalctl --follow -u cln-testnet
```
