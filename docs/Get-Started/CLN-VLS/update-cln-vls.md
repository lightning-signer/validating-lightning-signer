---
layout: layouts/docs.njk
title: Update CLN & VLS
eleventyNavigation:
  key: Update CLN & VLS
  parent: CLN & VLS
  order: 7
---



# Update CLN+VLS Software

This procedure presumes you've already performed the [One Time Setup](./one-time-setup.md)

This procedure refers to the machine running the Core Lightning Node
and VLS proxies as the `CLNHOST`.  This procedure refers to the
machine running the VLS signer as the `VLSHOST`.  In development these
hosts may be the same.

Some of the build may be completed before stopping running daemons but
generally the install steps require the executable files to not be in
use.

### Update Build Tree

Update git 

```bash
cd ~/lightning-signer/vls-hsmd
git fetch --all --recurse-submodules --tags
```

#### Checkout desired branch/tag

A good default choice is main:
```bash
git checkout main
```

Instead, if you want to be on a specific branch:
```bash
git checkout the-branch
```

Instead, if you want to update the branch you are on:
```bash
git pull
```

Instead, if the branch you were on was force pushed:
```bash
git reset --hard origin/the-branch
```

### Build Software

Align the submodules (`vls` and `lightning`):
```bash
make setup
```

Build:
```bash
cd ~/lightning-signer/vls-hsmd && make build
```

### Stop Daemons

If you are running the software you need to quiesce it.

On the `CLNHOST`:
```bash
sudo systemctl stop cln-testnet
ps uaxgwww | grep cln
```

On the `VLSHOST` [if you are running in `SOCKET` mode]:
```bash
sudo systemctl stop vls-testnet
ps uaxgwww | grep vls
```

If your `CLNHOST` and `VLSHOST` are the same:
```bash
sudo systemctl stop cln-testnet vls-testnet
ps uaxgwww | egrep 'cln|vls'
```


### Install Software

#### Install CLN components on the `CLNHOST`:
```bash
cd ~/lightning-signer/vls-hsmd && sudo make install
```

### Contemplate State Changes

Generally, you don't do anything.  But if you did want to
change/erase/revert something this is a good time to do it.

If you do want to alter CLN state on the `CLNHOST`:
```bash
sudo -u cln bash -c 'cd ~/.lightning && exec bash'
# do stuff
exit
```

If you do want to alter VLS signer state on the `VLSHOST`:
```bash
sudo -u vls bash -c 'cd ~/.lightning-signer && exec bash'
# do stuff
exit
```

### Start Daemons

On the `VLSHOST` [if you are running in `SOCKET` mode]:
```bash
sudo systemctl start vls-testnet
```

On the `CLNHOST`:
```bash
sudo systemctl start cln-testnet
```

If your `CLNHOST` and `VLSHOST` are the same:
```bash
sudo systemctl start cln-testnet vls-testnet
```

Individual status checks:
```bash
sudo systemctl status cln-testnet
sudo systemctl status vls-testnet
```

Quick summary status:
```bash
for svc in \
bitcoind-testnet \
txood-testnet \
cln-testnet \
vls-testnet \
; do SYSTEMD_COLORS=1 systemctl status $svc | head -n 3; done
```
