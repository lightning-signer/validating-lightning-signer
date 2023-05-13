## Setup CLN testnet Service

### Configure Service

Configure the CLN service on the `CLNHOST`.

Add `cln` user and group:
```
sudo /usr/sbin/groupadd cln
sudo /usr/sbin/useradd -g cln -c "Core Lightning" -m cln
sudo adduser cln dialout # (`SERIAL` only)
sudo mkdir -p ~cln/.lightning
sudo chown -R cln:cln ~cln
```

Create a cln config file in `~cln/.lightning/testnet-config`, adjust values
(at least the `bitcoin-rpcpassword`) for your bitcoind installation:
```
log-level=info
bitcoin-rpcuser=rpcuser
bitcoin-rpcpassword=6ffb57ab46aa726
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcport=18332
```

Add the following line only if you are using `SERIAL`:
```
subdaemon=hsmd:remote_hsmd_serial
```

Add the following line instead if you are using `SOCKET`:
```
subdaemon=hsmd:remote_hsmd_socket
```

Configure your firewall/router to forward an external port to the
`CLHOST`.  Add the following lines to the config, the `announce-addr`
should be set to the external firewall address/port.
```
bind-addr=0.0.0.0:19735
announce-addr=23.93.101.158:19735
```

Create `~cln/.lightning/testnet-env` with (adjust bitcoind url for your
bitcoind installation):
```
VLS_PORT=17701
VLS_SERIAL_PORT=/dev/ttyACM0
VLS_NETWORK=testnet
# If your SOCKET signer is remote, have the proxy listen to all interfaces.
# Alternatively, set up a secure tunnel to the signer.
# VLS_BIND=0.0.0.0
BITCOIND_RPC_URL=http://rpcuser:6ffb57ab46aa726@localhost:18332
GREENLIGHT_VERSION=v0.11.0.1-62-g92cc76a
```

Update `~cln/.lightning/testnet-env` to CLN version:
```
sudo su cln
cd ~cln/.lightning/
grep -v GREENLIGHT_VERSION testnet-env > testnet-env.new &&
  echo "GREENLIGHT_VERSION=`lightningd --version`" >> testnet-env.new &&
  mv testnet-env.new testnet-env
```

Install systemd unit file:
```
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/artifacts/cln-testnet.service /lib/systemd/system/
sudo systemctl daemon-reload
```

Enable the  service for automatic start on system boot:
```
sudo systemctl enable cln-testnet
```

If you want to start the service now:
```
sudo systemctl start cln-testnet
```

View status:
```
sudo systemctl status cln-testnet
```

View logs:
```
sudo journalctl --follow -u cln-testnet
```

Install log rotation config file (edit to suit preferences):
```
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/artifacts/cln-testnet.logrotate /etc/logrotate.d/cln-testnet
```
