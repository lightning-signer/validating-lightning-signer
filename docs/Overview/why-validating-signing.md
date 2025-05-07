---
layout: layouts/docs.njk
title: Why Validating Signing?
description: Why blind signers fall short—and why VLS matters for secure Lightning
eleventyNavigation:
  key: Why Validating Signing
  parent: Overview
  order: 2
---

# Why Validating Signing?

Most Lightning setups today are dangerously insecure.

Hot wallets expose your private keys to every part of your system. Blind signers move keys off-node, but will still sign anything the node asks. It’s like putting your funds behind a locked door, then handing the keys to anyone who knocks.

A **validating signer** is the **only** architecture that enforces Lightning’s complex protocol rules and security policies before signing.

---

## 🔥 The Problem with Current Approaches

| Architecture       | Node Compromised = Funds Safe? | Summary                                |
|--------------------|-------------------------------|-------------------------------------------------|
| Hot Wallet         | ❌ No                         | All keys live in memory; any exploit = risk of total fund loss     |
| Blind Signer       | ❌ No                        | Signs anything the node asks, no safety checks   |
| Validating Signer  | ✅ Yes                         | Rejects malicious requests from a compromised node |

With a blind signer, **you've just added a second point of failure**: now either the node or the signer can leak funds. That’s not safer, it’s worse.

For deeper technical analysis, see [Why Blind Signing is Harmful](./blind-signing-deep-dive.md)

---

## 🧠 What Is a Validating Signer?

A validating signer doesn’t just hold keys, it understands the Lightning protocol. It ensures that every signing request:

- Follows the protocol (e.g. no revoked state, valid HTLC)
- Matches your security policy (e.g. allowed destinations, fee limits)
- Isn’t part of a known exploit path

If a request fails those checks, **it refuses to sign**. Your funds remain safe.

---

## 💡 Why It Matters for Builders

By separating signing from node logic, and adding real validation, you unlock:

- **Non-custodial services** without blind trust in the node
- **Resilience** against node compromise
- **Regulatory clarity**: users keep control of their funds
- **Growth**: safely increase channel balances without centralized custody

---

## 🌍 Enable Non-Custodial Services at Scale

Using a validating signer like VLS doesn’t just improve security—it unlocks entirely new business models.

With VLS, your infrastructure can:
- Manage Lightning operations on behalf of users
- Stay fully non-custodial (users control their funds)
- Avoid triggering custody-related compliance and licensing requirements

This means:
- You can offer **hosted node services** without holding keys
- You can **scale globally** without becoming a financial custodian
- Your users keep **full control of their Bitcoin**

This is how platforms like [Greenlight](https://vls.tech/posts/greenlight-case-study/) provide Lightning-as-a-Service while preserving self-custody.

👉 VLS is how you run Lightning without becoming a bank.


## 🛡️ Real-World Protection

A validating signer prevents known Lightning attack paths like:

- Signing revoked commitment transactions
- Losing HTLC funds by skipping protocol steps
- Approving mutual closes that send funds to an attacker
- Accepting malicious counterparty behavior without triggering remediation

For a deeper dive, see a list of [Potential Exploits that VLS Blocks](../Security/potential-exploits.md)

---

## ✅ Summary

- Blind signers are **not** secure
- Validating signers check every transaction before they sign
- VLS is the only validating signer, and the best security solution for protecting L2 Lightning funds

Ready to build with real Lightning security?

👉 [Start Here](../Get-Started/start-here.md)
