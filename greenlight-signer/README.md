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

In the lightning-signer `remote-hsmd` branch, apply this patch:

```
-                self.use_rsignerd = True
+                self.use_rsignerd = False
```

Build C-lightning from the lightning-signer `remote_hsmd` branch, and then:

```shell
ln -sf ../../rust-lightning-signer/target/debug/greenlight-signer lightningd/remote_hsmd
export GREENLIGHT_VERSION=`./lightningd/lightningd --version`
export SUBDAEMON=hsmd:remote_hsmd
export ALLOWLIST=`pwd`/contrib/remote_hsmd/TESTING_ALLOWLIST

pytest $THETEST
```
