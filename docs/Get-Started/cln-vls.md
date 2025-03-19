---
layout: layouts/docs.njk
title: CLN & VLS
eleventyNavigation:
  key: CLN & VLS
  parent: Get Started
  order: 2
---

## Setup testnet CLN+VLS+CLBOSS server in `SOCKET` mode

In `SOCKET` mode th VLS signer runs on the `VLSHOST`.  In production
this host is rigorously secured.

The `CLNHOST` can be any general purpose unix computer capable of
running a lightning node and some associated services.

The `TXOHOST` can be any general purpose unix computer capable of
running a bitcoind and a txood oracle.

In development and testing the `CLNHOST`, `VLSHOST`, and `TXOHOST` may be the same host.

Steps:

1. [One Time Setup](./CLN-VLS/one-time-setup.md)
2. [Setup Bitcoind testnet Service](./CLN-VLS/setup-bitcoind.md)
3. [Setup TXOOD testnet Service](./CLN-VLS/setup-txood.md)
4. [Setup CLN testnet Service](./CLN-VLS/setup-cln.md)
5. [Setup VLS testnet Service](./CLN-VLS/setup-vls.md)
6. [Setup CLBOSS and CLN Plugins](./CLN-VLS/setup-clboss.md)
7. [Update CLN+VLS Software](./CLN-VLS/update-cln-vls.md)
8. [Configure journalctl](./CLN-VLS/config-journalctl.md)
