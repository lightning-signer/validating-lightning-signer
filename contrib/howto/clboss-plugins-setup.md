## Setup CLBOSS and CLN Plugins

This section may be skipped if you do not wish to run CLBOSS or standard CLN plugins.

### Stop Running Services

If the services are currently running it is best to stop them:
```
sudo systemctl stop cln-testnet vls-testnet
```

### Install CLBOSS

On Debian (and Ubuntu):
```
sudo apt update
sudo apt install build-essential pkg-config libev-dev libcurl4-gnutls-dev libsqlite3-dev -y
sudo apt install dnsutils -y
sudo apt install git automake autoconf-archive libtool -y
```

On Fedora:
```
sudo dnf update
sudo dnf groupinstall "Development Tools" -y
sudo dnf install pkg-config libev-devel libcurl-devel libsqlite3x-devel -y
sudo dnf install dnsutils -y
sudo dnf install git automake autoconf-archive libtool -y
```

On Both:
```
sudo chown -R $USER:$USER /usr/local/src
cd /usr/local/src
git clone --recurse-submodules https://github.com/ZmnSCPxj/clboss.git
cd clboss
git checkout master
autoreconf -i
./configure
make -j `nproc`
sudo make install
```

Add to cln config:
```
sudo -u cln vi ~cln/.lightning/testnet-config
```
```
important-plugin=/usr/local/bin/clboss
clboss-auto-close=true
```

### Install CLN plugins

Note - the summary plugin is "archived" as of 2024-02.

Setup plugins
```
sudo pip3 install pyln-client pyln-testing

cd /usr/local/src
git clone --recurse-submodules https://github.com/lightningd/plugins.git && cd plugins

# make sure the summary plugin is ready to go, this should politly demure:
archived/summary/summary.py
```

Add to `~cln/.lightning/testnet-config`:
```
plugin=/usr/local/src/plugins/archived/summary/summary.py
```

### Start Services Again

If the services should be running:
```
sudo systemctl start cln-testnet vls-testnet
```
