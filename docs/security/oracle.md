---
layout: layouts/docs.njk
title: UTXO Oracle
description: UTXO oracle integration for VLS chain validation. Track on-chain state, detect breaches, and verify channel activity for security.
eleventyNavigation:
  key: UTXO Oracle
  parent: Security
---


## Motivation

The Lightning Signer must be aware of on-chain state in order to prevent the loss of funds.

Without knowledge of on-chain state, the Signer cannot know if the node is getting close to a deadline, such as a breach-remedy deadline or an HTLC expiry.  The Signer also needs to know whether a channel is currently active on-chain before it can safely route payments offered on that channel.

Therefore, the Signer must be able to receive a concise proof that a specific TXO is in or is not in the current UTXO set.  This requires an attestation of both the chain tip and the UTXO set at the tip.

## Summary

The attestations needed can be implemented by signing a utreexo root or signing compact filters.  One of these types of proofs, plus SPV proofs, is enough to concisely prove to a Signer what is the state of a UTXO at the current chain tip.

## Dealing with a Deadline

When receiving a UTXO proof, the signer has to check that it is recent enough to allow a reaction on-chain.  In particular, it must allow enough time to publish a commitment transaction if an HTLC expires soon, or publish a breach-remedy tx if a revoked commitment was published by the counterparty.

Since a compromised node may censor any communication, the Signer must have an out-of-band connection to the operator.  This may be a secure display in the case of a consumer application.

In the case of a deployment in a data-center, a heartbeat may be used.  In case of a problem, the Signer would stop publishing the heartbeat, which would trigger a monitoring alert.  The operator would then move the signer to a clean disaster-recovery node that has logic to force-close or apply breach-remedy as necessary.

## Oracle Requirements

Oracle requirements are driven by the on-chain events the Signer must track for safety.

### Events Tracked

The following on-chain events must be tracked by the Signer for safety:

- **Channel active** - funding TXO is on-chain and unspent.  Signer may release payment pre-images and route payments after this event is active for enough blocks.
- **Funding impossible** - a funding input is double-spent.  Once double-spend is buried, the channel may be forgotten.
- **Closed by us** - our commitment is on-chain (we force-closed)
- **Closed by counterparty** - counterparty commitment is on-chain
- **HTLC Success/Failure is on-chain** - a 2nd level HTLC transaction is on-chain
- **2nd level HTLC swept** - sweep is on-chain.  Once all sweeps are on-chain and buried, channel may be forgotten by Signer.
- **Breached by counterparty** - counterparty revoked commitment is on-chain.  Remedy must be published in a timely manner.
- **Breach remedied** - remedy tx is on-chain.  Once all outputs are claimed by a breach-remedy tx, and those are buried, channel may be forgotten by Signer.

### Requirements

The events above can be safely tracked by the Signer given the following type of proofs:

- **UTXO inclusion** - Signer must receive a proof that a TXO is in the chain-tip UTXO set.  This is required for the **channel active** event.

- **Transaction inclusion** - Signer must receive a proof that a TX is included at chain tip.  The ability to do this allows tracking of events other than channel-active.  This is just an SPV proof.

### Non Requirements

It would be helpful for the Signer to be aware of the current on-chain fee market.  At first glance, such a requirement could be fulfilled by the same oracle.  However, given that the total fee for the block can be derived from the coinbase transaction, it is enough to present the coinbase to the Signer for it to derive the average fee rate for the block in a trustless manner.

## UTXO Inclusion Proofs

We can use one of the following proof methods:

- SPV + proof of non-spend.  An example of proof of non-spend is compact filters.  If an address is not included in the block filter, we know that UTXOs matching the address were not spent.  An initial SPV proof together with continuing proofs of non-inclusion for each block lets us know that a UTXO is currently active.  In the rare case of a false-positive in the filter the proof would be inconclusive, so the Signer will need to see the entire block.

- Proof of inclusion.  An example of proof of inclusion is utreexo.

## Signer On-chain API

The signer and the node maintain a "UTXO Watch Set".  Funding transaction inputs are automatically added to this set after the signer signs the funding transaction. As new blocks come in, the node provides proof-of-inclusion for the watch set, or spending transactions for any TXOs that were spent in the current block.

### API Calls

These calls are made asynchronously to all other API calls and have a relatively loose deadline (minutes/hours), which are less than but comparable to CLTV deadlines.

`ConnectBlock(height, oracle_signatures, block_header, utxo_set_root, utxo_batch_proof, spending_txs, spending_spv_batch_proof) -> new_watches`

A new block came in.  For each watched UTXO, a proof-of-inclusion is included in the `utxo_batch_proof` unless the TXO was spent in this block. If the TXO was spent in this block, the spending transaction is included along with an SPV proof. The signer returns a set of spending transaction outputs it is interested in further tracking.

`DisconnectBlock(height, hash)`

A block was disconnected due to a reorg.  Any change to watch set is rolled back.

### Watched UTXOs

The UTXO watch set automatically includes funding transaction inputs.  The following are further added by the signer as blocks come in:

- when funding is confirmed: funding TXO
- when non-revoked counterparty commitment tx is confirmed: to-remote output, HTLC outputs
- when revoked counterparty commitment tx is confirmed: all outputs
- when our commitment tx is confirmed: to-local output, HTLC outputs
- when 2nd level HTLC tx is confirmed: the output

In these cases nothing needs to be added to the watch set:

- when mutual-close is confirmed
- when 2nd level HTLC tx output is spent
- when breach-remedy tx is confirmed
- when funding input is double-spent by a transaction we don't recognize

## SPV Security

We assume that the signer has no network connectivity.  The signer has to depend on an external data source for identifying the longest chain.  Without this information, a minority of the hash-power, together with a sibyl attack can fool us into following a minority chain and make us miss on-chain events.

There are two ways for the signer to obtain this knowledge:

- the UTXO oracles can attest to the longest chain
- the chain provided by the node can be examined for hash power fluctuations

Since we already depend on the set of UTXO oracles for security, it is tempting to choose the first option and have them attest to the longest chain.  However, if the Bitcoin consensus mechanism starts including UTXO commitments, we hope to be able to do away with the oracles.

In the second option, we assume that the nominal hash power produces a block every 10 minutes.  If we see a significant enough slowdown in the block rate, we suspect that an attack is in progress and alert the operator.

The simulation in https://gitlab.com/lightning-signer/blockgap/ shows that false-positive alerts would occur about once a year if we alert whenever the hash power appears to decrease to 25% in a 4-hour window.  This would allow us to detect 25% of the network hash power attempting to sibyl attack us.
