## Setup testnet CLN+VLS+CLBOSS server in `SOCKET` mode

In `SOCKET` mode th VLS signer runs on the `VLSHOST`.  In production
this host is rigorously secured.

The `CLNHOST` can be any general purpose unix computer capable of
running a lightning node and some associated services.

In development and testing the `CLNHOST` and `VLSHOST` may be the same host.

Steps:
1. [One Time Setup](one-time-setup.md)
2. [Setup Bitcoind testnet Service](./bitcoind-testnet-service.md)
3. [Setup CLN testnet Service](./cln-testnet-service.md)
4. [Setup VLS testnet Service](./vls-testnet-service.md)
5. [Setup CLBOSS and CLN Plugins](./clboss-plugins-setup.md)
6. [Update CLN+VLS Software](./update.md)
