---
layout: layouts/docs.njk
title: Heartbeat and Operator Intervention
description: VLS heartbeat monitoring for operator alerts. Detect compromised nodes and ensure timely breach remediation with dead-man's switch.
eleventyNavigation:
  key: Heartbeat
  parent: Security
---

## Motivation

The security of the user's funds is dependent on timely on-chain response to certain events, such as nearing HTLC expiry
or remedying a breach.  The VLS security model assumes that the node may be compromised but the signer is not.  If the
node is compromised, the operator must intervene in a timely fashion.

There are two possible ways the signer can inform the operator of a problem:

- the signer can directly message the operator via an out-of-band channel
- the signer can send a message to the node, which in turn can send a message to the operator

In the first case, the signer can send a message with the details of the problem and the deadline directly to the
operator.

In the second case, the compromised node may censor the message from the signer, so another mechanism is needed to ensure that the
operator is informed.  We will focus on this case.

## Heartbeat

A heartbeat acts as a "dead-man's switch" to ensure that the operator is informed if the node is compromised.  If the
node is compromised, the heartbeat will not be sent, and the operator's admin device will raise an alert.  Once the operator
is alerted, they can proceed with remediation.

If the node does relay the heartbeat, the operator can notice any alerts communicated by the heartbeat message, so that
is not advantageous to an attacker.

## Deadlines

The following potential deadlines can occur during normal operation:

- breach remediation
- HTLC expiry

### Breach Remediation

Breach remediation must be performed within the time window specified by the `to_self_delay` of the channel.  This is
typically 144 blocks (24 hours) - `BREAKDOWN_TIMEOUT` in LDK.  We could use a 24-block deadline (4 hours) to ensure
we don't fail to meet the on-chain deadline.

Alternatively, a watch-tower can be used to monitor the chain for breaches and perform breach-remediation on the
operator's behalf, in which case this deadline is not relevant.

### HTLC Expiry

CTLV delta is at least 24 blocks (4 hours) in LDK - `MIN_FINAL_CLTV_EXPIRY`.  LDK nodes will force-close channels if the expiry
falls below 18 blocks (3 hours) - `CLTV_CLAIM_BUFFER`.  We can be somewhat more aggressive, and use a 12-block deadline, assuming
HTLCs are significantly less valuable than the overall channel value.


Alternatively, if `max_htlc_value_in_flight_msat` is set to a low value, we can accept the loss of such HTLCs and ignore this deadline.

### Composite Deadline

If we want to protect against both deadlines, we can allow at most 12 blocks (2 hours) of heartbeat downtime, since an
HTLC might have come in with a 4-hour expiry while the heartbeat was down and we want a 2-hour buffer for HTLC expiry.

If we want to just protect against breach, we can allow at most 120 blocks (20 hours) of heartbeat downtime.

## Remediation

The operator must take a disaster recovery action to close the channels and recover the funds.  The operator can do this
by connecting the signer to a special recovery node, which will force-close the channels and send the funds to the
layer-1 wallet.  The recovery node must ensure any time-sensitive transactions are confirmed within the required deadline.
