# Greenlight Lightning Signer

This crate implements a signer for C-lightning / Greenlight.

It is both:

- a `no_std` library for implementing the greenlight protocol in embedded environments 
- a binary for Unix systems that replaces the C-lightning `hsmd`

## Running with C-lightning

Build C-lightning from the [lightning-signer `remote_hsmd` branch](https://github.com/lightning-signer/c-lightning/tree/remote-hsmd), and then:

```shell
ln -sf ../../greenlight-signer/target/debug/greenlight-signer-hsmd lightningd/remote_hsmd_greenlight
export GREENLIGHT_VERSION=`./lightningd/lightningd --version`
export SUBDAEMON=hsmd:remote_hsmd_greenlight
export ALLOWLIST=`pwd`/contrib/remote_hsmd/TESTING_ALLOWLIST

pytest $THETEST
```
