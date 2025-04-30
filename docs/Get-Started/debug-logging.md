---
layout: layouts/docs.njk
title: Enable Debug Logging
eleventyNavigation:
  key: Enable Debug Logging
  parent: Get Started
  order: 5
---


## Enabling Debugging

First since the logs will be much larger, consider [increasing journalctl
limits](./CLN-VLS/config-journalctl.md)

The following lines need to be changed:

`~cln/.lightning/testnet-config`:
```bash
log-level=debug
```

`~cln/.lightning/testnet-setenv`:
```bash
RUST_LOG=debug
```

`~vls/.lightning-signer/vlsd.toml`:
```bash
log-level = "debug"
```

### Log filter script

The log filter script can be used to filter logs for information about specific
channels.

Using journalctl:
```bash
journalctl \
  --since 12:00 \
  --output=short-full | \
logfilter \
  --all \
  --funding=1f7a9acb92aa7b35f9758412b9bbd019f2d427e18e5911801ef289675e8caee1:0 \
  --dbid=47 \
  --channelid=02146e28a3d43205b99d93c758b18d302be0086655d5a23e9bea9a6509da907dbd2a00000000000000 \
  --watches
```

Using historical rolled (and compressed) logfiles:
```bash
logcat remote_hsmd_socket.log | \
logfilter \
  --proxy \
  --dbid=47
```
