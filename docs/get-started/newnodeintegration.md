---
layout: layouts/docs.njk
title: New Node Integration
eleventyNavigation:
  key: Node Integration
  parent: Get Started
  order: 8
---

## Protocol

Minimal set of protocol messages for integration:

* `HsmdInit2`
* `NodeInfo` (for L1 xpub and node pubkey)
* `SignWithdrawal` (general L1 signing, but also needed for sweeping closed channel to L1 wallet)
* `GetPerCommitmentPoint2`
* `NewChannel`
* `SetupChannel`
* `ValidateCommitmentTx2`
* `RevokeCommitmentTx`
* `ValidateRevocation`
* `SignRemoteCommitmentTx2`
* `SignLocalCommitmentTx2` 
* `SignMutualCloseTx2`
* `GetChannelBasepoints`

if you don't want to maintain your own node secret (also see `NodeInfo` above):

* `Ecdh` 
* `SignMessage` 
* `SignChannelAnnouncement`
* `SignNodeAnnouncement`
