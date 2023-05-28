## Setup CLBOSS and CLN Plugins

This section may be skipped if you do not wish to run CLBOSS or standard CLN plugins.

### Stop Running Services

If the services are currently running it is best to stop them:
```
sudo systemctl stop cln-testnet vls-testnet
```

### Install CLBOSS
```
sudo apt update
sudo apt install build-essential pkg-config libev-dev libcurl4-gnutls-dev libsqlite3-dev -y
sudo apt install dnsutils -y
sudo apt install git automake autoconf-archive libtool -y

sudo chown -R user:user /usr/local/src
cd /usr/local/src
git clone --recurse-submodules https://github.com/ksedgwic/clboss.git
cd clboss
git checkout vls-testnet-mods
autoreconf -i
./configure
make -j `nproc`
sudo make install
```

Add to `~cln/.lightning/testnet-config`:
```
important-plugin=/usr/local/bin/clboss
clboss-auto-close=true
```

### Install CLN plugins
Setup plugins
```
sudo pip3 install pyln-client pyln-testing

cd /usr/local/src
git clone --recurse-submodules https://github.com/lightningd/plugins.git && cd plugins

# make sure the summary plugin is ready to go, this should politly demure:
summary/summary.py
```

Add to `~cln/.lightning/testnet-config`:
```
plugin=/usr/local/src/plugins/summary/summary.py
```

### Start Services Again

If the services should be running:
```
sudo systemctl start cln-testnet vls-testnet
```
