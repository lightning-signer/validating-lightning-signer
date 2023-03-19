## Setup testnet CLN+VLS+CLBOSS server using STM32 in `SERIAL` mode

In `SERIAL` mode the VLS signer runs on a
[Discovery kit with STM32F413ZH MCU](https://www.st.com/en/evaluation-tools/32f413hdiscovery.html)
connected by a serial usb cable to the `CLNHOST`.

The `CLNHOST` can be any general purpose unix computer capable of
running a lightning node and some associated services.

Optional instructions for [Intel NUC8 Demo Unit Setup](./nuc8-setup.md)

Steps:
1. [One Time Setup](one-time-setup.md)
2. [Setup Bitcoind testnet Service](./bitcoind-testnet-service.md)
3. [Setup CLN testnet Service](./cln-testnet-service.md)
4. [Setup CLBOSS and CLN Plugins](./clboss-plugins-setup.md)
5. [Update CLN+VLS Software](./update.md)
