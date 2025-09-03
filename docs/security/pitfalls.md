---
layout: layouts/docs.njk
title: Pitfalls
description: Security pitfalls VLS prevents - fee manipulation, shared allowlists, and validation exploits. Critical mitigations for Lightning signers.
eleventyNavigation:
  key: Pitfalls
  parent: Security
---


# Pitfalls

This document describes some exploits/pitfalls which the lightning-signer must mitigate.

## Fee calculation when signer invoked multiple times

- Real inputs: 2 + 2 BTC
- Malory wants to sign a tx with output 3.
- Malory asks signer to sign tx with inputs 2 + 1 and then with inputs 1 + 2, where the signer signs the 2 input each time
- Signer thinks total is 3 each time, but it's actually 4
- 1 BTC is burned as fees

### Mitigations: 

Taproot fixes this (signs all input values at once).

## Shared Allowlist

If a channel connects two nodes which have common allowlist entries an
attacker may steal half of the channel funds.
* Common allowlists are likely between "team" nodes (nodes controlled by the same owner).

### Details:

* The attacker compromises one of the nodes.
* The attacker causes the channel to be balanced (roughly same balance
  on each side).
* The attacker proposes a mutual-close transaction which sends half of
  the funds to a common allowlisted entry and sends the other half to
  himself.
* Each of the signers thinks the funds going to the allowlisted entry
  is their output and signs the transaction.
* A similar attack can be used with a dual-funding transaction where
  each signer thinks the same change output is theirs.

### Mitigations:

* Don't allow any unknown outputs for funding and mutual closing
  transactions for team channels.
