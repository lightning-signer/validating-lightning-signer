---
layout: layouts/docs.njk
title: Blind Signing is Worse
eleventyNavigation:
  key: Blind Signing
  parent: Overview
  order: 2
---
##

VLS separates your Lightning private keys and security rule validation from your Lightning node, into a discrete signing device. This improves LN security for users by reducing the attack surface.

This enhances security compared to existing blind signing nodes by validating that requests from the node are following the Lightning security model. You can sleep soundly, knowing a compromised LN node does not mean loss of funds.

As the Lightning network implementations of Taproot, Musig2 and FROST mature in the coming months, VLS will be a necessity in creating seamless multi-sig Lightning network channels.

## Background

A **Signer** is a component that performs cryptographic operations, separately from a wallet. A Bitcoin hardware wallet is an example of a Signer, where private keys are controlled on a hardened device. There is currently no complete solution for a hardware signer for the Lightning network.

A **Blind Signer** is a signer that does not perform validation. There are several consumer Lightning wallets and node implementations that as of today support only blind signing. I believe these configurations are insecure.

A **Validating Signer** performs a comprehensive set of policy checks to ensure that the keys are not misused. For example, a validating Bitcoin hardware wallet checks the destination, amount and change outputs in collaboration with the user.

A layer-2 validating signer is significantly more complex, because of the complexity of the Lightning protocol.

While a Blind Signer is a technical step on the road to the higher security of a Validating Signer, by itself it actually **reduces security** if deployed in production. This is because it presents **two points of attack - at the node and at the signer.**

## The VLS Project

The Validating Lightning Signer project aims to close the gap for securing the Lightning ecosystem. It is an open-source Rust library and reference implementation. The project is approaching Beta, which is the point where the main goal will be met: _funds are safe even if the node is completely compromised_.

The task is relatively complex because of the complexity of the Lightning protocol. There are more than [50 policies](../Security/policy-controls/) that must be enforced, and many of them require stateful inspection of the protocol.

Both servers and consumer devices are targeted, the latter via a Rust `no_std` compilation mode.

## Signing Configurations

Here are some of the potential configurations of a Lightning node:

* Monolithic node
* Node with a separate Blind Signer
* Node with a separate Validating Signer - the signer ensures that the Lightning state machine ran correctly and funds are not at risk

## The (In)security of Blind Signing

<img src="../assets/blind-signing-diagram.svg" class="theme-toggle-image" alt="Blind signing diagram">


* The monolithic case has one point of attack - at the node.
* The blind signing case has **two points of attack** - at the node and at the Signer. A blind signer will perform any signing operation the node requests, so **a compromised node will still result in loss of funds**. And obviously, a compromised signer will also result in loss of funds. This is worse than a monolithic node because funds can be lost if **either** is compromised.
* The validated signing case has just one point of attack with a small attack surface

## Wallets with Blind Signers Must Trust the Node Operator

Blind signing wallets where the node is run by an LSP (Lightning Service Provider) are not self-custodial because the LSP can unilaterally control the funds. The LSP merely has to provide the Signer with a transaction that sends the funds to the LSP or another destination.

## Examples of Blind Signing Exploits

A compromised node can unilaterally submit transactions to be signed by the blind Signer.  The following can result in the funds being stolen:

* The node submits a mutual closing transaction which sends funds to the attacker's address
* The node asks the blind signer to sign a revoked transaction which will cause loss of all funds when published
* And [many more ...](../Security/potential-exploits)

A compromised node can also lose funds when it doesn't follow the Lightning protocol. Some potential exploits include:

* The node fails to validate the counter-party's revocation, and the counter-party broadcasts an old commitment transaction that sends most of the funds to the counter-party
* The node fails to claim input HTLCs when routing payments, leading to the gradual loss of all funds
* And [many more ...](../Security/potential-exploits)

## Validating Signers

In the Validating Signer case, a compromise of the Lightning node will not result in the loss of funds. The security of such a setup is only dependent on the security of the Signer. The Signer can be hardened as needed for the specific use case.

Some of the validation rules that a validated Signer can implement include:

* Don't sign a revoked commitment transaction
* Don't revoke a signed commitment transaction
* Don't close a channel to an unapproved destination
* Routed payments must have at least as much input as output value
* Payments must claim at least as much from the input as was claimed from us on the output
* And many more ...

## Conclusion

Blind signers reduce the security of Lightning nodes and are subject to [many exploits](../Security/potential-exploits).

Validating signers improve security by reducing the attack surface. The VLS project aims to provide a library and reference implementation for enterprise servers and consumer devices.
