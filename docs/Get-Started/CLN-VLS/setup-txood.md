---
layout: layouts/docs.njk
title: Setup TXOOD Service
eleventyNavigation:
  key: Setup TXOOD Service
  parent: CLN & VLS
  order: 3
---

# Setup the TXOOD Oracle

Setup the TXOOD service on the `TXOHOST`.  The TXOOD service wants to
be co-located with a bitcoind server so it can utilize its datastore
directly.

### Prerequisites

Ensure that `bitcoind-testnet` service is running.


### Install nginx

On Debian (and Ubuntu):
```bash
sudo apt-get update
sudo apt-get install -y nginx
```

On Fedora:
```bash
sudo dnf update
sudo dnf install -y nginx
```

On Both:
```bash
sudo systemctl start nginx
sudo systemctl enable nginx
```

Connect to `http://localhost:80` and verify you see "Wecome to nginx!"

### Build txood

```bash
cd ~/lightning-signer
git clone --recurse-submodules https://gitlab.com/lightning-signer/txoo.git && cd txoo
cargo build --release -p txood
sudo cp ~/lightning-signer/txoo/target/release/txood /usr/local/bin/
```

### Configure web directory

```shell
sudo mkdir /var/www/html/txoo
sudo chown bitcoin:bitcoin /var/www/html/txoo
```

### Optional - allow directory listing

Apply the following configuration to nginx:

Modify `/etc/nginx/sites-available/default` as root:
```bash
sudo patch /etc/nginx/sites-available/default - << 'EOF'
--- /etc/nginx/sites-available/default~	2022-07-26 18:32:17.000000000 -0700
+++ /etc/nginx/sites-available/default	2023-05-01 15:27:35.779068369 -0700
@@ -51,6 +51,10 @@
 		try_files $uri $uri/ =404;
 	}
 
+	location /txoo {
+		autoindex on;
+	}
+
 	# pass PHP scripts to FastCGI server
 	#
 	#location ~ \.php$ {
EOF
```

Restart nginx:
```bash
sudo systemctl restart nginx
```

### Setup service

```shell
sudo -u bitcoin mkdir -p ~bitcoin/.txoo/testnet/
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/txood-testnet.service /etc/systemd/system/
```

Edit `/etc/systemd/system/txood-testnet.service`, set correct `user:pass`:
```bash
sudo -u bitcoin grep rpcpassword ~bitcoin/.bitcoin/bitcoin.conf
sudo vi /etc/systemd/system/txood-testnet.service
```

Install log rotation config file (edit to suit preferences):
```bash
sudo cp ~/lightning-signer/vls-hsmd/vls/contrib/howto/assets/txood-testnet.logrotate /etc/logrotate.d/txood-testnet
```

If your `bitcoind-testnet` is caught up you can enable `txood`
otherwise come back when it finishes syncing:
```bash
sudo -u bitcoin bitcoin-cli --testnet getblockchaininfo
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable txood-testnet
sudo systemctl start txood-testnet
systemctl status txood-testnet
journalctl -u txood-testnet
```

### Setup web sync

On Fedora:
```bash
sudo dnf install cronie cronie-anacron
```

```shell
sudo cp ~/lightning-signer/txoo/contrib/{sync-txoo-local,render-txoo} /usr/local/bin/
sudo crontab -u bitcoin -e
```

```bash
* * * * * /usr/local/bin/sync-txoo-local
```
