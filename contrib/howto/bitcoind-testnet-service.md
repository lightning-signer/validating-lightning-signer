## Setup Bitcoind testnet Service

You can skip this entirely if you already have bitcoin installed as a service.

This procedure presumes you've already performed the
[One Time Setup](one-time-setup.md) `Install Bitcoind` section.

### Configure Service

Configure the bitcoind service on the `CLNHOST`.

Add `bitcoin` user and group:
```
sudo /usr/sbin/groupadd bitcoin
sudo /usr/sbin/useradd -g bitcoin -c "bitcoin" -m bitcoin
```

Install sample config:
```
sudo mkdir -p /home/bitcoin/.bitcoin
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/bitcoin.conf /home/bitcoin/.bitcoin
```

Edit the config file, change the `rpcpassword` to something random:
```
sudo vi /home/bitcoin/.bitcoin/bitcoin.conf
```

Make sure bitcoin owns everything:
```
sudo chown -R bitcoin:bitcoin  /home/bitcoin/.bitcoin
```

Install systemd unit file:
```
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/bitcoind-testnet.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Install log rotation config file (edit to suit preferences):
```
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/bitcoind-testnet.logrotate /etc/logrotate.d/bitcoind-testnet
```

Enable the  service for automatic start on system boot:
```
sudo systemctl enable bitcoind-testnet
```

If you want to start the service now:
```
sudo systemctl start bitcoind-testnet
```

View status:
```
sudo systemctl status bitcoind-testnet
```
