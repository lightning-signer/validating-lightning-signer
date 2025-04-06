---
layout: layouts/docs.njk
title: Pitfalls
eleventyNavigation:
  key: Pitfalls
  parent: Security
---


# Overview

This document describes some exploits/pitfalls which the lightning-signer must mitigate.

* [Shared Allowlist](./pitfall-shared-allowlist.md)

## Fee calculation when signer invoked multiple times

- Real inputs: 2 + 2 BTC
- Malory wants to sign a tx with output 3.
- Malory asks signer to sign tx with inputs 2 + 1 and then with inputs 1 + 2, where the signer signs the 2 input each time
- Signer thinks total is 3 each time, but it's actually 4
- 1 BTC is burned as fees

Taproot fixes this (signs all input values at once).
