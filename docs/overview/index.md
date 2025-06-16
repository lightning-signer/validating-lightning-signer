---
layout: layouts/docs.njk
title: VLS Documentation (__VERSION__)
eleventyNavigation:
  key: Overview
  parent: __VERSION__
  order: 1
---

Improving Lightning security with fully validated remote signing.

You can go directly to the [code repository for VLS](https://gitlab.com/lightning-signer/validating-lightning-signer).

You can also go to the [VLS website](https://vls.tech/).

## Motivation

[Lightning nodes are in effect hot
wallets](https://medium.com/@devrandom/securing-lightning-nodes-39410747734b?)
with substantial balances that must stay on-chain to provide channel
liquidity.

## Proposed Solution

We propose to sequester the private keys and secrets in one or more hardened
policy signing devices. We have a reference
[Validating Lightning Signer implementation](https://gitlab.com/lightning-signer/validating-lightning-signer)
in Rust. It currently has a gRPC interface, but other APIs are possible.

When run in external signing mode the Lightning node would use an alternate
signing module which replaces signing with proxy calls to the policy
signing devices.

The external signing device applies a complete set of policy controls
to ensure that the proposed transaction is safe to sign. Having a
[complete set of policy controls](../security/policy-controls.md)
protects the funds even in the case of
a complete compromise of the node software. This will require some
overlap in logic between the node software and the policy signer.

<div align="center">
    <img src="../assets/system-overview.svg" width="700" height="500" class="rev-invert"> 
</div>


## Diagrams

#### [Transaction Signing Diagrams](../seq-diagrams/)

## Roadmap

The development of this approach has several distinct stages.  You
can see the [project roadmap here](https://vls.tech/roadmap/).

## Chat

You can join us on [Matrix](https://matrix.to/#/#vls-general:matrix.org).

## Documents

* [Securing Lightning Nodes](https://medium.com/@devrandom/securing-lightning-nodes-39410747734b?)

* [Lightning Signing Policy Controls](../security/policy-controls.md)
