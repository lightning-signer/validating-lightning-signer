### [Back to Lightning-Signer Home](README.md)

# Overview

This document describes a set of policy controls that collectively
ensure funds are not lost to theft.  The controls are separated into a
*mandatory* set, which ensures the integrity of the basic Lightning
protocol and an *optional* set, which includes use-case specific
controls.

Some controls will change with the evolution of the Lightning protocol - e.g.
[dual funding](https://github.com/lightningnetwork/lightning-rfc/pull/524) and splicing.

# Mandatory Policy Controls

## Opening a Channel

* Delay - the local and remote imposed to_self_delay must be reasonable <br>
  `policy-channel-contest-delay-range`

## Onchain Transactions (funding tx, simple sweeps)

* Funding Output - for a funding transaction, the funding output must have the
  right scriptPubKey and be spendable by the previously signed initial
  commitment transaction (multi-output TBD) <br>
  `policy-onchain-output-scriptpubkey`,
  `policy-onchain-output-match-commitment`,
  `policy-onchain-initial-commitment-countersigned`
  
* Beneficial value - all outputs must be to the layer-one wallet, an allowlisted destination,
  or fund a channel.  Funding an inbound channel does not provide beneficial value to the
  local node since initially all of the channel funds are claimable by the counterparty. <br>
  `policy-onchain-no-unknown-outputs`,
  `policy-onchain-no-channel-push`,
  `policy-onchain-no-fund-inbound`,

* Change - the output derivation path for a wallet address must be reasonable <br>
  `policy-onchain-wallet-path-predictable`

* Fee - the fee must be reasonable <br>
  `policy-onchain-fee-range`

* Format - the transaction fields must be standard (e.g. version field) <br>
  `policy-onchain-format-standard`

## Signing a Commitment Transaction

Before we sign a commitment transaction, the following controls are checked:

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
  `policy-commitment-singular`,
  `policy-commitment-no-unrecognized-outputs`

* Funded - if this is not the first commitment, the funding UTXO must
  be active on chain with enough depth <br>
  `policy-commitment-spends-active-utxo`

* Initial - the initial commitment must have no HTLCs <br> `policy-commitment-first-no-htlcs`

* HTLC in-flight value - the inflight value should not be too large <br>
  `policy-commitment-htlc-inflight-limit`

* Fee - must be in range <br>
  `policy-commitment-fee-range`

* Number of HTLC outputs - must not be too large <br>
  `policy-commitment-htlc-count-limit`

* HTLC routing - each offered HTLC must be balanced via a received HTLC <br>
  `policy-commitment-htlc-routing-balance`

* HTLC receive channel validity - the funding UTXO of the receive
  channel must be active on chain with enough depth <br>
  `policy-commitment-htlc-received-spends-active-utxo`

* Our revocation pubkey - must be correct <br>
  `policy-commitment-revocation-pubkey`

* The to_self_delay on the to_local output must be as negotiated for channel <br>
  `policy-commitment-to-self-delay`
  
* The delayed payment pubkey in the to_local output must be correct <br>
  `policy-commitment-broadcaster-pubkey`

* The remotepubkey in the to_remote output must be correct <br>
  `policy-commitment-countersignatory-pubkey`

* Our revocation pubkey - must be correct <br>
  `policy-commitment-htlc-revocation-pubkey`

* The HTLC pubkeys must be correct <br>
  `policy-commitment-htlc-counterparty-htlc-pubkey`
  `policy-commitment-htlc-holder-htlc-pubkey`

* The cltv_expiry on received HTLC outputs must be reasonable <br>
  `policy-commitment-htlc-cltv-range`
  
* Offered payment hash - must be related to received HTLC payment hash <br>
  `policy-commitment-htlc-offered-hash-matches`

* Trimming - outputs are trimmed if under the bitcoin dust limit.  It is
  critical that the holder's commitment does not violate the bitcoin
  dust limit so that it is valid and can be transmitted if necessary <br>
  `policy-commitment-outputs-trimmed`

* Revocation - the previous commitment transaction was properly
  revoked by peer disclosing secret.  Note that this requires
  unbounded storage. <br>
  `policy-commitment-previous-revoked`

* No breach - if signing a local commitment transaction, we must not
  have revoked it <br>
  `policy-commitment-holder-not-revoked`

* Retries - any retries of this operation must have same data <br>
  `policy-commitment-retry-same`

* Anchors:
  - If `option_anchor_outputs` is not in force no anchor outputs shall
    be present. <br>
    `policy-commitment-anchors-not-when-off`

  - If `option_anchor_outputs` is in force the to-local and to-remote
    outputs must each have an associated anchor output. <br>
    `policy-commitment-anchor-to-holder`,
    `policy-commitment-anchor-to-counterparty`
    
    * Anchor outputs must be the correct amount. <br>
      `policy-commitment-anchor-amount`
      
    * The `option_static_remotekey` flag must be on. <br>
      `policy-commitment-anchor-static-remotekey`
      
    * Anchor outputs must each be locked by the correct side's funding-key. <br>
      `policy-commitment-anchor-match-fundingkey`

## Payments

These policy controls are also enforced at commitment signing time, but are separated for clarity.

* A settled offered HTLC must have a known preimage.  <br>
  `policy-commitment-payment-settled-preimage`

* An outgoing payment must be to a destination allow-list (optional).  <br>
  `policy-commitment-payment-allowlisted`

* An outgoing payment must be under a certain velocity (optional).  <br>
  `policy-commitment-payment-velocity`

* An outgoing payment must be approved out-of-band (optional).  <br>
  `policy-commitment-payment-approved`

* The amount sent must not be greater than the amount in the invoice.  <br>
  `policy-commitment-payment-invoiced`

* Do not route payments through our node. Alternatively implement the "Routing Hub" policies below. <br>
  `policy-no-routing`


## Validating a Holder Commitment and Revoking Previous Commitment Transaction

Before we revoke a commitment by releasing its revocation secret, the
following controls are checked:

* New commitment - the remote must have signed the new commitment
  transaction <br>
  `policy-revoke-new-commitment-signed`

* New commitment - the commitment transaction must have had all the
  policy checks pass as in the previous section <br>
  `policy-revoke-new-commitment-valid`

* No close - we did not sign a closing transaction <br>
  `policy-revoke-not-closed`

## HTLC Transactions

Before we sign an HTLCSuccess or HTLCTimeout transaction, the
following controls are checked:

* Format - version, locktime and sequence must be as specified in BOLT 3 <br>
  `policy-htlc-version`,
  `policy-htlc-locktime`,
  `policy-htlc-sequence`

* The HTLCTimeout locktime (cltv_expiry) must be reasonable <br>
  `policy-htlc-cltv-range`

* Our revocation pubkey - must be correct <br>
  `policy-htlc-revocation-pubkey`

* The to_self_delay on the output of both HTLCSuccess and HTLCTimeout must be as negotiated <br>
  `policy-htlc-to-self-delay`

* Our delayed payment pubkey - must be correct <br>
  `policy-htlc-delayed-pubkey`

* Fee - must be in range <br>
  `policy-htlc-fee-range`

## Mutual Closing Transaction

Before we sign a cooperative closing transaction, the following
controls are checked:

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
or justice sweep transaction, the following controls are checked:

* Format - version and sequence must be as specified in BOLT 3 <br>
  `policy-sweep-version`,
  `policy-sweep-sequence`
  
* Format - locktime must not be too far in the future <br>
  `policy-sweep-locktime`

* Destination - destination must be whitelisted <br>
  `policy-sweep-destination-allowlisted`

* Fee - must be in range <br>
  `policy-sweep-fee-range`

# Optional Policy Controls
## Funding Transaction

* Maximum - the amount funded in a channel must be under a certain amount <br>
  `policy-funding-max`

* Velocity - the amount funded must be under a certain amount per unit time <br>
  `policy-velocity-funding`

## Commitment Transaction

* Velocity - the amount transferred to peer must be under a certain
  amount per unit time <br>
  `policy-velocity-transferred`

# Use-case Specific Controls
## Merchant

* No sends - balances must only increase until closing or loop-out <br>
  `policy-merchant-no-sends`

## Routing Hub

* Balanced routing - ensure as much is claimed on input as can be claimed on output <br/>
  `policy-routing-balanced`

* No sends - balances must only change via HTLC settlement <br>
  `policy-routing-deltas-only-htlc`
