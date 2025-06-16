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

1. [One Time Setup](./cln-vls/one-time-setup.md)
2. [Setup Bitcoind testnet Service](./cln-vls/setup-bitcoind.md)
3. [Setup TXOOD testnet Service](./cln-vls/setup-txood.md)
4. [Setup CLN testnet Service](./cln-vls/setup-cln.md)
5. [Setup VLS testnet Service](./cln-vls/setup-vls.md)
6. [Setup CLBOSS and CLN Plugins](./cln-vls/setup-clboss.md)
7. [Update CLN+VLS Software](./cln-vls/update-cln-vls.md)
8. [Configure journalctl](./cln-vls/config-journalctl.md)
