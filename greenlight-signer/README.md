# Greenlight Lightning Signer

This crate implements a signer for C-lightning / Greenlight.

It is both:

- a `no_std` library for implementing the greenlight protocol in embedded environments 
- a binary for Unix systems that replaces the C-lightning `hsmd`

## Status

Done:

- a skeleton `hsmd` binary, implementing the fd passing dance

To do:

- complete the `hsmd` binary
- complete the `no_std` library
- split into two crates (library, binary)

## Running with C-lightning

Build C-lightning from the lightning-signer `remote_hsmd` branch, and then:

```shell
ln -sf ../../rust-lightning-signer/target/debug/greenlight-signer lightningd/lightning_hsmd
export GREENLIGHT_VERSION=`./lightningd/lightningd --version`

pytest $THETEST
```

