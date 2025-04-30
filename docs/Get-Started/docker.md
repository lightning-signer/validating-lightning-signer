---
layout: layouts/docs.njk
title: Run VLS on Docker
eleventyNavigation:
  key: Run VLS on Docker
  parent: Get Started
  order: 1
---


## Installing Docker

### Docker Documentation

Docker Engine is available on a variety of Linux distros, macOS, and Windows 10 through Docker Desktop, and as a static binary installation. Refer to the official [docker documentation](https://docs.docker.com/engine/install/)

- [Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Fedora](https://docs.docker.com/engine/install/fedora/)

**Note**: The compose files present within this repository make use of docker compose v2 the minimum supported version is `v2.26.0`.

## VLS standalone Setup

Below are the steps required to run `vlsd` as a standalone container.

### Docker Image

```bash
# Build the latest docker image
cd vlsd
docker build -t vlsd .
```

### Volume Creation

```bash
docker volume create vls_data
```

### Environment Variables

VLS container needs the follwing environment variables set:
- `BITCOIND_RPC_URL`: URL of `bitcoind`'s RPC port.
- `VLS_NETWORK`: `testnet` or `regtest`.

Frequently used optional environment variables are:
- `VLS_PERMISSIVE`
- `RUST_LOG`

### `vlsd` Command Arguments

Required command arguments:
- `connect`: URL of `remote_hsmd_socket` running in the lightning node.

For information on all possible arguments to `vlsd` see [documentation](https://gitlab.com/lightning-signer/validating-lightning-signer/-/blob/main/vls-proxy/src/config.rs?ref_type=heads).

### Build Arguments

For building the container its required to provide following build arguments:
- `VLS_REPO` url for git repo to use for building binaries.
- `VLS_GIT_HASH` commit sha/tag/branch to use from git repo.
- `TXOO_PUBLIC_KEY` public key for trusted TXOO.

### Running container

There is a `docker-compose.yml` in the `vlsd` folder which can be used to run a standalone `vlsd` service with `network_mode` set to host.

```bash
cd vlsd
export VLS_REPO=$VLS_REPO
export VLS_GIT_HASH=$VLS_GIT_HASH
export TXOO_PUBLIC_KEY=$TXOO_PUBLIC_KEY
docker compose up
```

**_Note_**: Make sure to set `BITCOIND_RPC_URL` and `CLN_REMOTE_HSMD_URL` as either environment variables or in the `docker-compose.yml` file before running the above command.

If you wish to run it as a standalone container without using `docker compose` you can use the following command:

```bash
docker run \
  -d \
  --rm \
  --name vlsd \
  --network host \
  --build_arg VLS_GIT_HASH=$VLS_GIT_HASH
  --build_arg VLS_REPO=$VLS_REPO
  --build_arg TXOO_PUBLIC_KEY=$TXOO_PUBLIC_KEY
  -e VLS_NETWORK=testnet \
  -e BITCOIND_RPC_URL=$BITCOIND_RPC_URL \
  --mount 'type=volume,src=vls_data,dst=/home/vls/.lightning-signer' \
  vlsd \
  --connect=$CLN_REMOTE_HSMD_URL
```

## Single Node Setup

You can run `bitcoind`, `lightningd`, `txood` and `vlsd` on a single node using available docker compose file in the main directory.

**_Note_**: Use this only for experimentation and testing purposes as running `vlsd` on the same machine as `CLN` is not as secure as running it on dedicated hardware.

### Volume Creation

Testnet:

```bash
docker volume create bitcoin_data
docker volume create lightning_data
docker volume create txoo_data
docker volume create vls_data
```

The `regtest` docker compose configuration doesn't use external volumes.  The automatically created volumes can be destroyed via the `down --volumes` docker compose command.

### Docker Compose Run

```bash
docker compose --profile vls up --build
```

### Selecting Bitcoin Chains

We have two possible overrides over the default `testnet` configuration in `docker-compose.yml`:
- `docker-compose.testnet.yml`
- `docker-compose.regtest.yml`

To use override we have to pass it down both the config using `-f` flag:
```bash
export DOCKER_COMPOSE_OVERRIDE=docker-compose.testnet.yml
export COMPOSE_PROJECT_NAME=testnet
docker compose --profile vls -f docker-compose.yml -f $DOCKER_COMPOSE_OVERRIDE up --build
```

__Note__: Even while using `testnet` running using the override is recommended as that will expose the `P2P` port for `bitcoind` and `P2P` port for `lightningd` on the host.

### Single Node without VLS

To run a single node without `vls` service we can use the same `docker-compose.yml` file in the main directory by just removing the `profile` flag `vls` from all commands.

```bash
docker compose -f docker-compose.yml -f $DOCKER_COMPOSE_OVERRIDE up --build
```

Above command will run `bitcoind`, `lightningd` and `txood` services on a single node.

### First Time Chain Sync

It's quite possible that while syncing for the first time `bitcoind` would be unresponsive to rpc calls made by `core-lightning`, `vls`, etc. To remedy such scenario where other containers would fail to start we can instead start with just `bitcoind` and `txood`
```bash
docker compose --profile vls stop
docker compose -f docker-compose.yml -f docker-compose.testnet.yml up bitcoin-core txoo -d
```

Let the chain sync you can check its progress using `bitcoin-cli` or by checking status of docker container's health
```bash
docker container exec bitcoind-test bitcoin-cli getblockchaininfo
docker ps
```

Also, given there is a dependency of `core-lightning` on `txoo` it is a good idea to wait sometime so that all attestations are available for it to retrieve and `txoo` is healthy. `txoo` container health can be checked using `docker`
```bash
docker ps
```

After the chain sync has completed we can stop the containers and restart the whole system again
```bash
docker compose --profile vls stop
docker compose --profile vls -f docker-compose.yml -f docker-compose.testnet.yml up -d
```

## Interacting with Containers

We can use the `docker container exec <CONTAINER_NAME> <COMMAND>` command to interact with containers and interact with setup using command line tools like `bitcoin-cli`, `lightning-cli`, `vls-cli`, etc.

### Regtest Commands

Generate Address for node:
```bash
docker container exec bitcoind-regtest bitcoin-cli getnewaddress
```

Generate Blocks
```bash
docker container exec bitcoind-regtest bitcoin-cli generatetoaddress 50 $NODE_ADDRESS
```

### Testnet CLN + CLBOSS Commands

```bash
# Create a connection to a random node (maybe from 1ML.com)
docker container exec lightningd-test lightning-cli --testnet connect \
  02ae1e6091d2a9c4db5096558668d2456b1c0e9067cb72273eab1199bcfb208888 67.227.190.47:9735

# Allocate an onchain address to fund the node
docker container exec lightningd-test lightning-cli --testnet newaddr

# List onchain and channel funds
docker container exec lightningd-test lightning-cli --testnet listfunds

# Show CLBOSS status
docker container exec lightningd-test lightning-cli --testnet clboss-status | less

# Show node summary status
docker container exec lightningd-test lightning-cli --testnet summary
```

## Debugging Containers

Checking running status and health of containers
```bash
docker ps
```

Getting logs from container
```bash
# CONTAINER_NAME=lightningd-test
docker container logs $CONTAINER_NAME > $CONTAINER_NAME.log
```

Restarting containers
```bash
cd vls-container
docker compose --profile vls stop
# to start testnet
docker compose --profile vls up
```

Generating Backtrace from CLN core dump
```bash
# attach to the lightningd container
docker container exec -u root -it lightningd-test sh

# install gdb
apk add gdb
gdb /usr/libexec/c-lightning/plugins/pay /home/lightning/.lightning/testnet/core

# get backtrace
bt
```

Delete containers
```bash
cd vls-container
docker compose --profile vls down
```

**NOTE**: If you want to start fresh make sure to delete the created docker volumes as well.

## Choosing Versions

The currently set default versions for services is as follows in the [.env](.env) file:
- **Bitcoin Core**: v26.0
- **Core Lightning**: v24.02.2
- **TXOO**: v0.8.1
- **VLS**: v0.12.0

You just can switch to a particular version/commit for a service by updating the git hash and then rebuilding the service:
```bash
cd vls-container
# update bitcoin core version
sed -i 's/23.0/23.2/g' .env
# build images again
docker compose --profile vls build
```

Note: For `bitcoind` its also important to update the `BITCOIN_SHA256SUMS_HASH`. It is the *SHA256 HASH* of `SHA256SUMS` file.



## References

- [bitcoind](https://github.com/ruimarinho/docker-bitcoin-core/blob/master/23/alpine/Dockerfile) by @ruimarinho
- [lightningd with clboss](https://github.com/tsjk/docker-core-lightning/blob/main/Dockerfile) by @tsjk
- [elements lightning](https://github.com/ElementsProject/lightning/blob/master/contrib/docker/Dockerfile.alpine) by @ElementsProject
- [docker compose](https://github.com/LukasBahrenberg/lightning-dockercompose/blob/master/docker-compose.yaml) by @LukasBahrenberg
