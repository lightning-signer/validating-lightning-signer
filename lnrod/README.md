# lnrod

A node implementation using LDK.

## Setup
```shell
git clone git@gitlab.com:lightning-signer/lnrod.git && cd lnrod

cargo build

# Add bitcoind config to ~/.bitcoin/bitcoin.conf:
rpcuser=user
rpcpassword=pass
fallbackfee=0.0000001

```

## Usage
```shell
# Start bitcoind in regtest mode
bitcoind -regtest -daemon

# Create wallet, unload and reload w/ autoload
bitcoin-cli --regtest createwallet default
bitcoin-cli --regtest unloadwallet default
bitcoin-cli --regtest loadwallet default true

a_mine=`bitcoin-cli -regtest getnewaddress` && echo $a_mine

# Advance 101 blocks
bitcoin-cli -regtest generatetoaddress 101 $a_mine

alias lnrod=target/debug/lnrod
alias lnrcli=target/debug/lnrcli

lnrod --regtest
lnrod --regtest --datadir ./data2 --rpcport 8802 --lnport 9902

# get the second node ID
node2=`lnrcli -c http://127.0.0.1:8802 node info | jq -r .node_id` && echo $node2

# connect the first node to the second
lnrcli peer connect $node2 127.0.0.1:9902

# create channel
lnrcli channel new $node2 1000000

# mine 6 blocks to activate channel
bitcoin-cli --regtest generatetoaddress 6 $a_mine

# see that channel is active
lnrcli channel list

# create invoice and pay it
invoice=`lnrcli -c http://127.0.0.1:8802 invoice new 1000 | jq -r .invoice` && echo $invoice
lnrcli payment send $invoice

# see new channel balance
lnrcli channel list
```

## Integration test

If you have `bitcoind` in your path, and a recent Rust toolchain:

```shell
python3 -m venv ./venv
source ./venv/bin/activate
pip3 install -r requirements.txt
cargo install vls-proxy --git=https://gitlab.com/lightning-signer/validating-lightning-signer.git --root=. --features=developer --bin=vlsd
cargo build
./scripts/compile-proto
SIGNER=vls-grpc ./tests/integration-test.py
```

or to test disaster recovery:

```shell
SIGNER=vls-grpc ./tests/integration-test.py --test-disaster bitcoind
```

note that the log file for the signer 3 disaster recovery is in `./test-output/vls3-recover.log`.

if you are developing locally, you can use the `--dev` flag to run against binaries built from your local VLS source tree:

```shell
# Set this to `target/debug` subdirectory of the VLS repo.
# Defaults to `../vls/target/debug`.
export DEV_BINARIES_PATH=...
SIGNER=vls-grpc ./tests/integration-test.py --dev --test-disaster bitcoind
```

to test disaster recovery with the Blockstream Esplora backend:

```shell
./scripts/launch-esplora-testnet
COOKIE=`docker exec esplora-regtest cat /data/bitcoin/regtest/.cookie`
SIGNER=vls-grpc ./tests/integration-test.py --dev --bitcoin http://$COOKIE@localhost:18443 --test-disaster=esplora
```

## Enabling Frontend

```shell
export VLS_CHAINFOLLOWER_ENABLE=1
```

### Using [kcov](https://github.com/SimonKagstrom/kcov) for Code Coverage

Dependencies:

```shell
sudo dnf install -y elfutils-devel
sudo dnf install -y curl-devel
sudo dnf install -y binutils-devel
```

Build v38 of kcov from git@github.com:SimonKagstrom/kcov.git .

More dependencies:

```shell
cargo install cargo-kcov
cargo install cargo-coverage-annotations
```

Run coverage:

```shell
./scripts/run-kcov-all
```

View Coverage Report:

```shell
[target/kcov/cov/index.html](target/kcov/cov/index.html)
```

Check coverage annotations in source files:

```shell
cargo coverage-annotations
```

## License

Licensed under either:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
