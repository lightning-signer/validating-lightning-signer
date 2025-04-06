---
layout: layouts/docs.njk
title: Shared Allowlist
eleventyNavigation:
  key: Shared Allowlist
  parent: Pitfalls
---


### Summary:

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
