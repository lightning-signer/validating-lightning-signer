## Update CLN+VLS Software

This procedure presumes you've already performed the [One Time Setup](one-time-setup.md)

This procedure refers to the machine running the Core Lightning Node
and VLS proxies as the `CLNHOST`.  This procedure refers to the
machine running the VLS signer as the `VLSHOST`.  In development these
hosts may be the same.

Some of the build may be completed before stopping running daemons but
generally the install steps require the executable files to not be in
use.

### Update Build Tree

Update git 

```
cd ~/lightning-signer/vls-hsmd
git fetch --all --recurse-submodules --tags
```

#### Checkout desired branch/tag

A good default choice is main:
```
git checkout main
```

Instead, if you want to be on a specific branch:
```
git checkout the-branch
```

Instead, if you want to update the branch you are on:
```
git pull
```

Instead, if the branch you were on was force pushed:
```
git reset --hard origin/the-branch
```

### Build Software

Align the submodules (`vls` and `lightning`):
```
make setup
```

Build:
```
cd ~/lightning-signer/vls-hsmd && make build
cd ~/lightning-signer/vls-hsmd/lightning && poetry run make
```

### Stop Daemons

If you are running the software you need to quiesce it.

On the `CLNHOST`:
```
sudo systemctl stop cln-testnet
ps uaxgwww | grep cln
```

On the `VLSHOST` [if you are running in `SOCKET` mode]:
```
sudo systemctl stop vls-testnet
ps uaxgwww | grep vls
```

If your `CLNHOST` and `VLSHOST` are the same:
```
sudo systemctl stop cln-testnet vls-testnet
ps uaxgwww | egrep 'cln|vls'
```

If you are running the signer on an STM32 in `SERIAL` mode no action
is required, the signer can be left idle.

### Install Software

#### Install CLN components on the `CLNHOST`:
```
cd ~/lightning-signer/vls-hsmd/lightning
sudo make install
/usr/local/bin/lightningd --version
```

Update `~cln/.lightning/testnet-env` to CLN version:
```
sudo -u cln bash -c 'cd ~cln/.lightning/ && \
  grep -v VLS_CLN_VERSION testnet-env > testnet-env.new && \
  echo "VLS_CLN_VERSION=`lightningd --version`" >> testnet-env.new && \
  mv testnet-env.new testnet-env'
```

#### Install VLS proxies on the `CLNHOST`:
```
sudo cp ~/lightning-signer/vls-hsmd/vls/target/debug/remote_hsmd_serial \
    /usr/local/libexec/c-lightning/
sudo cp ~/lightning-signer/vls-hsmd/vls/target/debug/remote_hsmd_socket \
    /usr/local/libexec/c-lightning/
/usr/local/libexec/c-lightning/remote_hsmd_serial --git-desc
/usr/local/libexec/c-lightning/remote_hsmd_socket --git-desc
```

#### Install the VLS signer on the `VLSHOST` if you are running in `SOCKET` mode:
```
sudo cp ~/lightning-signer/vls-hsmd/vls/target/debug/vlsd2 /usr/local/bin
/usr/local/bin/vlsd2 --git-desc
```

#### [Flash the STM32 Signer](./stm32-flash.md) if you are running in `SERIAL` mode.

### Contemplate State Changes

Generally, you don't do anything.  But if you did want to
change/erase/revert something this is a good time to do it.

If you do want to alter CLN state on the `CLNHOST`:
```
sudo -u cln bash -c 'cd ~/.lightning && exec bash'
# do stuff
exit
```

If you do want to alter VLS signer state on the `VLSHOST`:
```
sudo -u vls bash -c 'cd ~/.lightning-signer && exec bash'
# do stuff
exit
```

If you are using a STM32 signer in `SERIAL` mode you can hold the blue
button while resetting with the black button to enter setup mode.  You
can also mount the sdcard in a development machine and view/alter the
state.

### Start Daemons

If you are running the signer on an STM32 press the black button to
reset it.  The signer will disply "waiting for node" when it is ready.

On the `VLSHOST` [if you are running in `SOCKET` mode]:
```
sudo systemctl start vls-testnet
```

On the `CLNHOST`:
```
sudo systemctl start cln-testnet
```

If your `CLNHOST` and `VLSHOST` are the same:
```
sudo systemctl start cln-testnet vls-testnet
```

Individual status checks:
```
sudo systemctl status cln-testnet
sudo systemctl status vls-testnet
```

Quick summary status:
```
for svc in \
bitcoind-testnet \
txood-testnet \
cln-testnet \
vls-testnet \
; do SYSTEMD_COLORS=1 systemctl status $svc | head -n 3; done
```
