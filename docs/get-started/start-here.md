---
layout: layouts/docs.njk
title: Start Here
description: Get started with VLS. Choose between CLN, LDK, or hosted solutions like Greenlight. Find the right Lightning security setup for your needs.
eleventyNavigation:
  key: Start Here
  parent: Get Started
  order: 1
---

# Start Building with VLS

VLS is a Rust library for secure, self-custodial Lightning signers. It is the only solution that keeps private keys off your Lightning node and validates every transaction before signing, so funds stay safe even if the node is compromised. Protect your funds from node breaches while maintaining true self-custody. 

It’s designed to help you:

- Secure your **own Lightning funds** with stronger guarantees than standard Lightning nodes
- Provide **non-custodial Lightning services** to users, avoiding the risks of holding their keys

🧠 **New to VLS?** Learn why validation matters:  
- 👉 [Why Validating Signing?](../overview/why-validating-signing.md)
- Learn more about [what VLS does](../overview/intro.md)

---

## 🧭 Not Sure Where to Start?

You can start in two ways — by choosing based on **your goal**, or based on **your stack**.

---

### 👣 Start by Goal (Recommended)

**1. What kind of setup are you looking for?**

- ✅ **I’m a business or app developer who just wants a secure Lightning setup without deep infrastructure work**  
  → Use a **hosted non-custodial provider** powered by VLS:  
  👉 [Greenlight by Blockstream](https://blockstream.com/lightning/greenlight/) or [Breez SDK](https://breez.technology/)

- 🛠️ **I want to control my own Lightning node, but don’t want to build everything from scratch**  
  → Use [CLN + VLS](./cln-vls.md) — secure and flexible, without full custom integration.

- 🧪 **I want full control and deep integration flexibility**  
  → Use [LDK + VLS](./ldk-vls.md) — great for custom deployments.

---

### 🧠 Already Know Your Lightning Stack?

Choose your stack to get started:

- 👉 **[CLN + VLS](./cln-vls.md)**  
  Use our `vls-hsmd` plugin to forward signing requests from Core Lightning.

- 🛠️ **[LDK + VLS](./ldk-vls.md)**  
  Integrate via the `vls-proxy` crate inside your LDK-based node.

- 🐳 **[Docker Sandbox](./docker.md)**  
  Run CLN + VLS + Bitcoind locally using Docker. Great for testing.

- ❌ **LND or Eclair**  
  Not yet supported. Help move things forward by reaching out to LND or Eclair to encourage VLS support:  
  - [LND](https://lightning.engineering/)  
  - [Eclair](https://acinq.co/)

---

## 🧠 Learn From Other Builders

- ✅ [Greenlight Case Study](https://vls.tech/posts/greenlight-case-study/)  
  How Blockstream used VLS to build a hosted Lightning service without taking custody

- ✅ More case studies at [vls.tech/blog](https://vls.tech/blog/#case-studies)

---

## 👀 Want to Understand How Signing Works?

Check out our [Sequence Diagrams](../seq-diagrams/) for:

- [Channel Establishment](../seq-diagrams/channel-establishment.md)
- [Normal Operation](../seq-diagrams/normal-operation.md)
- [Lightning Transaction Signing Details](../seq-diagrams/transaction-diagrams.md)


## 🤝 Need Help?

- Join our [Matrix chat](https://matrix.to/#/#vls-general:matrix.org)
- Review our [Policy Engine & Security Rules](../security/policy-controls.md)
- Or message us directly—we’re happy to help!
