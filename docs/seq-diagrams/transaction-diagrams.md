---
layout: layouts/docs.njk
title: Transaction Diagrams
eleventyNavigation:
  key: Transaction Diagrams
  parent: Sequence Diagrams
---

## Lightning Transaction Signing Details

The Lightning Node makes requests to the Remote Signer to generate
signatures for lightning operations.  These outputs and transactions
are discussed in depth in [BOLT #3](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md).

<br>

These diagrams show the remote signing API calls used to generate
signatures for each transaction in the lightning flow.

<br>

Diagrams maintained using [app.diagrams.net](https://app.diagrams.net/)

<br>

<br>

## `to_local` and `to_remote` Output Signing

[BOLT #3 - to_local and to_remote Outputs](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#to_local-output)

<br>

<div align="center">
    <img src="../assets/to-lclrmt-details.svg" width="600" height="600" class="rev-invert">
</div>

<br>

## `to_local_anchor` and `to_remote_anchor` Output Signing

[BOLT #3 - to_local_anchor and to_remote_anchor Outputs](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#to_local_anchor-and-to_remote_anchor-output-option_anchor_outputs)

<br>

<div align="center">
    <img src="../assets/anchor-details.svg" width="600" height="600" class="rev-invert">
</div>

<br>

## Offered HTLC Output Signing

[BOLT #3 - Offered HTLC Outputs](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#offered-htlc-outputs)

<br>

<div align="center">
    <img src="../assets/offered-htlc-details.svg" width="600" height="800" class="rev-invert">
</div>

<br>

## Received HTLC Output Signing

[BOLT #3 - Received HTLC Outputs](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#received-htlc-outputs)

<br>

<div align="center">
    <img src="../assets/received-htlc-details.svg" width="600" height="800" class="rev-invert">
</div>

<br>

## Closing Transaction Signing

[BOLT #3 - Closing Transaction](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#closing-transaction)
<br>

<div align="center">
    <img src="../assets/closing-details.svg" width="600" height="400" class="rev-invert">
</div>

<br>
