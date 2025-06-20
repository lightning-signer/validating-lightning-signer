---
layout: layouts/docs.njk
title: Policy Controls
eleventyNavigation:
  key: Policy Controls
  parent: Security
---

# Policy Controls

## Overview

This document describes a set of validation rules that collectively
ensure funds are not lost to theft.  The rules are separated into a
*mandatory* set, which ensures the integrity of the basic Lightning
protocol and an *optional* set, which includes use-case specific validation
rules.

Some validation rules will change with the evolution of the Lightning protocol - e.g.
[dual funding](https://github.com/lightningnetwork/lightning-rfc/pull/524) and splicing.

## Mandatory Validation Rules

## Generic Errors
* Generic Error - A generic validation error that was caused by an user input <br>
  `policy-generic-error`

## Opening a Channel
* Delay - the local and remote imposed to_self_delay must be reasonable <br>
  `policy-channel-contest-delay-range-holder`,
  `policy-channel-contest-delay-range-counterparty`

* Safe modes - the channel mode must be safe (e.g. not plain anchors, only zero-fee) <br>
  `policy-channel-safe-mode`

## Onchain Transactions (funding tx, simple sweeps)

* Funding Output - for a funding transaction, the funding output must have the
  right scriptPubKey and be spendable by the previously signed initial
  commitment transaction (multi-output TBD) <br>
  `policy-onchain-output-scriptpubkey`,
  `policy-onchain-output-match-commitment`,
  `policy-onchain-initial-commitment-countersigned`

* Beneficial value - all outputs must be to the layer-one wallet, an allowlisted destination,
  or fund a channel.  Funding an inbound channel does not provide beneficial value to the
  local node since initially all the channel funds are claimable by the counterparty. <br>
  `policy-onchain-no-unknown-outputs`,
  `policy-onchain-no-channel-push`,
  `policy-onchain-no-fund-inbound`,

* Change - the output derivation path for a wallet address must be reasonable <br>
  `policy-onchain-wallet-path-predictable` <br>
  ACTION: implement

* Fee - the fee must be reasonable <br>
  `policy-onchain-fee-range`

* Format - the transaction fields must be standard (e.g. version field) <br>
  `policy-onchain-format-standard`

* Non-malleable - an onchain transaction which funds one or more channels must
  not have any non-segwit inputs. <br>
  `policy-onchain-funding-non-malleable`

## Validating a Commitment Transaction

Before we sign a counterparty commitment transaction or accept the signature on a holder commitment transaction, the following rules are checked.

Note that several rules may be checked in one comparison, in which case the prefix tag `policy-commitment` is used in the code.

* Input - the single input must spend the funding output <br>
  `policy-commitment-input-single`,
  `policy-commitment-input-match-funding`

* Value - if we are the funder, the value to us of the initial
  commitment transaction should be equal to our funding value <br>
  `policy-commitment-initial-funding-value`

* Format - version, locktime and sequence must be as specified in BOLT 3 <br>
  `policy-commitment-version`,
  `policy-commitment-locktime`,
  `policy-commitment-sequence`

* Output - the outputs must be at most one to-local, at most one
  to-remote and HTLCs (and anchors, as below). <br>
  `policy-commitment-singular-to-holder`,
  `policy-commitment-singular-to-counterparty`,
  `policy-commitment-no-unrecognized-outputs`

* Funded - if this is not the first commitment, the funding UTXO must
  be active on chain with enough depth <br>
  `policy-commitment-spends-active-utxo` <br>
  ACTION: implement via UTXO oracle on open and periodically

* Initial - the initial commitment must have no HTLCs <br>
  `policy-commitment-first-no-htlcs`

* HTLC in-flight value - the inflight value should not be too large <br>
  `policy-commitment-htlc-inflight-limit` <br>
  ACTION: should this be only applied to received HTLCs?  HTLCs we offer
  are separately controlled by `policy-commitment-htlc-routing-balance`.

* Fee - must be in range <br>
  `policy-commitment-fee-range`

* Number of HTLC outputs - must not be too large <br>
  `policy-commitment-htlc-count-limit`

* HTLC routing - each offered HTLC must be balanced via a received HTLC <br>
  `policy-commitment-htlc-routing-balance`

* HTLC receive channel validity - the funding UTXO of the receiving
  channel must be active on chain with enough depth <br>
  `policy-commitment-htlc-received-spends-active-utxo` <br>
  ACTION: implement

* Our revocation pubkey - must be correct <br>
  `policy-commitment-revocation-pubkey`

* The `to_self_delay` on the `to_local` output must be as negotiated for channel <br>
  `policy-commitment-to-self-delay-range`
  
* The delayed payment pubkey in the to_local output must be correct <br>
  `policy-commitment-broadcaster-pubkey`

* The remotepubkey in the to_remote output must be correct <br>
  `policy-commitment-countersignatory-pubkey`

* Our revocation pubkey - must be correct <br>
  `policy-commitment-htlc-revocation-pubkey`

* The HTLC pubkeys must be correct <br>
  `policy-commitment-htlc-counterparty-htlc-pubkey`
  `policy-commitment-htlc-holder-htlc-pubkey` <br>
  ACTION: implement tests

* The cltv_expiry on received HTLC outputs must be reasonable <br>
  `policy-commitment-htlc-cltv-range` <br>
  ACTION: currently off by default - `policy.use_chain_state`.  also needs
  to detect when new HTLCs are added to the commitment transaction.
  
* Offered payment hash - must be related to received HTLC payment hash <br>
  `policy-commitment-htlc-offered-hash-matches` <br>
  ACTION: isn't this redundant with `policy-commitment-htlc-routing-balance`?
  or implement.

* Trimming - outputs are trimmed if under the bitcoin dust limit.  It is
  critical that the holder's commitment does not violate the bitcoin
  dust limit so that it is valid and can be transmitted if necessary <br>
  `policy-commitment-outputs-trimmed` <br>
  ACTION: implement tests for signing counterparty transaction

* Revocation - the previous commitment transaction was properly
  revoked by peer disclosing secret.  This includes both checking
  that the secret matches the commitment point and that the secrets 
  are consistent with the compact secret storage scheme in BOLT-3. <br>
  `policy-commitment-previous-revoked`

* No breach - if signing a local commitment or HTLC transaction, we must not
  have revoked it <br>
  `policy-commitment-holder-not-revoked` <br>
  ACTION: phase 1 HTLC signing does not check.  This is not a security
  problem because the antecedent commitment can't get into the blockchain,
  but should we check anyway?

* Retries - any retries of this operation must have same data <br>
  `policy-commitment-retry-same` <br>
  ACTION: remove. Revocation revokes all commitments with the same revocation key.

* Anchors:
  - If neither `option_anchor_outputs` or `option_anchors_zero_fee_htlc`
    are in force no anchor outputs shall be present. <br>
    `policy-commitment-anchors-not-when-off` <br>
    ACTION: implement

  - If either `option_anchor_outputs` or `option_anchors_zero_fee_htlc`
    are in force the to-local and to-remote outputs must each have an
    associated anchor output. <br>
    `policy-commitment-anchor-to-holder`,
    `policy-commitment-anchor-to-counterparty` <br>
    ACTION: implement
    
    * Anchor outputs must be the correct amount. <br>
      `policy-commitment-anchor-amount`
      
    * The `option_static_remotekey` flag must be on. <br>
      `policy-commitment-anchor-static-remotekey` <br>
      ACTION: implement
      
    * Anchor outputs must each be locked by the correct side's funding-key. <br>
      `policy-commitment-anchor-match-fundingkey` <br>
      ACTION: implement tests

## Payments

These validation rules are also enforced at commitment signing time, but are separated for clarity.

* A settled offered HTLC must have a known preimage.  <br>
  `policy-commitment-payment-settled-preimage` <br>
  ACTION: implement

* An outgoing payment must be to a destination allow-list (optional).  <br>
  `policy-commitment-payment-allowlisted`
  ACTION: implement

* An outgoing payment must be under a certain velocity (optional).  <br>
  `policy-commitment-payment-velocity` <br>
  NOTE: this is implemented as a warning in `add_invoice`, and the invoice is not allowed to be paid later on.

* An outgoing payment must be approved out-of-band (optional).  <br>
  `policy-commitment-payment-approved`

* The amount sent must not be greater than the amount in the invoice.  <br>
  `policy-commitment-payment-invoiced`

* The invoice must not have expired.  <br>
  `policy-invoice-not-expired`

* Do not route payments through our node. Alternatively implement the "Routing Hub" policies below. <br>
  `policy-no-routing` <br>
  ACTION: implement


## Validating a Holder Commitment and Revoking Previous Commitment Transaction

Before we revoke a commitment by releasing its revocation secret, the
following rules are checked:

* New commitment - the remote must have signed the new commitment
  transaction <br>
  `policy-revoke-new-commitment-signed`

* New commitment - the commitment transaction must have had all the
  policy checks pass as in the previous section <br>
  `policy-revoke-new-commitment-valid`

* No close - we did not sign a closing transaction <br>
  `policy-revoke-not-closed`
  ACTION: implement

## HTLC Transactions

Before we sign an HTLCSuccess or HTLCTimeout transaction, the
following rules are checked:

* Format - version, locktime and sequence must be as specified in BOLT 3 <br>
  `policy-htlc-version`,
  `policy-htlc-locktime`,
  `policy-htlc-sequence`

* The HTLCTimeout locktime (`cltv_expiry`) must be reasonable <br>
  `policy-htlc-cltv-range` <br>
  ACTION: implement

* Our revocation pubkey - must be correct <br>
  `policy-htlc-revocation-pubkey`

* The `to_self_delay` on the output of both HTLCSuccess and HTLCTimeout must be as negotiated <br>
  `policy-htlc-to-self-delay`

* Our delayed payment pubkey - must be correct <br>
  `policy-htlc-delayed-pubkey`

* Fee - must be in range <br>
  `policy-htlc-fee-range` <br>

## Mutual Closing Transaction

Before we sign a cooperative closing transaction, the following
rules are checked:

* Destination - the destination must be allowlisted or in the layer-one
  wallet. If the destination is specified as an
  upfront_shutdown_script it will be checked both at the time the
  channel is opened and again at mutual close. If a destination has
  been removed from the allowlist during the time the channel is open
  the mutual close signature request will fail and a force-close of
  the channel is required<br>
  `policy-mutual-destination-allowlisted`

* Value - the value to us should be as in the last commitment transaction <br>
  `policy-mutual-value-matches-commitment`

* Fee - must be in range <br>
  `policy-mutual-fee-range`

* No pending HTLCs <br>
  `policy-mutual-no-pending-htlcs`

## Sweep Transactions

Before we sign a delayed output, counterparty commitment HTLC output,
or justice sweep transaction, the following rules are checked:

* Format - version and sequence must be as specified in BOLT 3 <br>
  `policy-sweep-version`,
  `policy-sweep-sequence`
  
* Format - locktime must not be too far in the future <br>
  `policy-sweep-locktime`

* Destination - destination must be whitelisted <br>
  `policy-sweep-destination-allowlisted`

* Fee - must be in range <br>
  `policy-sweep-fee-range` <br>
  ACTION: implement

# L1 Transactions

* Maximum size - the transaction must be under a certain size <br>
  `policy-onchain-max-size`

# Optional Validation Rules
## Funding Transaction

* Maximum - the amount funded in a channel must be under a certain amount <br>
  `policy-funding-max` <br>
  ACTION: implement tests

* Velocity - the amount funded must be under a certain amount per unit time <br>
  `policy-velocity-funding` <br>
  ACTION: implement

## Commitment Transaction

* Velocity - the amount transferred to peer must be under a certain
  amount per unit time <br>
  `policy-velocity-transferred` <br>
  ACTION: implement

# Use-case Specific Validation Rules
## Merchant

* No sends - balances must only increase until closing or loop-out <br>
  `policy-merchant-no-sends` <br>
  ACTION: implement

## Routing Hub

* Balanced routing - ensure as much is claimed on input as can be claimed on output <br/>
  `policy-routing-balanced` <br>
  ACTION: implement tests

* No sends - balances must only change via HTLC settlement <br>
  `policy-routing-deltas-only-htlc`
