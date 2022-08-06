
#### Setup

1. Follow the [First Time Setup Instructions](https://gitlab.com/lightning-signer/vls-hsmd/-/blob/main/SETUP.md).

Setup bitcoind service

    sudo /usr/sbin/groupadd bitcoin
    sudo /usr/sbin/useradd -g bitcoin -c "bitcoin" -m bitcoin

    sudo mkdir -p /home/bitcoin/.bitcoin
    sudo cp bitcoin.conf /home/bitcoin/.bitcoin
    sudo chown -R bitcoin:bitcoin  /home/bitcoin/.bitcoin

    sudo cp bitcoind-testnet.service /lib/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable bitcoind-testnet
    sudo systemctl start bitcoind-testnet

Build vls:

    cd ~/lightning-signer/vls-hsmd && make build-standard

Install CLN:

    cd ~/lightning-signer/vls-hsmd/lightning
    poetry run make
    sudo make install

Install `remote_hsmd_socket`:

    sudo cp ~/lightning-signer/vls-hsmd/vls/target/debug/remote_hsmd_socket \
        /usr/local/libexec/c-lightning/

Install `vlsd2`:

    sudo cp ~/lightning-signer/vls-hsmd/vls/target/debug/vlsd2 /usr/local/bin

Make vls user/group:

    sudo /usr/sbin/groupadd vls
    sudo /usr/sbin/useradd -g vls -c "Validating Lightning Signer" -m vls

    sudo touch /home/vls/ALLOWLIST
    sudo chown vls:vls /home/vls/ALLOWLIST

    sudo cp vls-testnet.service /lib/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable vls-testnet
    sudo systemctl start vls-testnet

    sudo journalctl --follow -u vls-testnet

Make cln user/group

    sudo /usr/sbin/groupadd cln
    sudo /usr/sbin/useradd -g cln -c "Core Lightning" -m cln

Create a cln config file in `~cln/.lightning/testnet-config`, adjust values
for your bitcoind installation:
```
log-level=info
bitcoin-rpcuser=rpcuser
bitcoin-rpcpassword=6ffb57ab46aa726
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcport=18332
subdaemon=hsmd:remote_hsmd_socket
```

Create `~cln/.lightning/testnet-env` with:
```
VLS_PORT=17701
VLS_NETWORK=testnet
BITCOIND_RPC_URL=http://rpcuser:6ffb57ab46aa726@localhost:18332
GREENLIGHT_VERSION=v0.11.0.1-62-g92cc76a
```

Update `~cln/.lightning/testnet-env` to CLN version:

    cd ~cln/.lightning/
    grep -v GREENLIGHT_VERSION testnet-env > testnet-env.new &&
      echo "GREENLIGHT_VERSION=`lightningd --version`" >> testnet-env.new &&
      mv testnet-env.new testnet-env

Setup the service config:

    sudo cp cln-testnet.service /lib/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable cln-testnet
    sudo systemctl start cln-testnet
    
Watch logs:

    sudo journalctl --follow -u cln-testnet
    sudo journalctl --follow -u vls-testnet
