---
layout: layouts/docs.njk
title: Channel Establishment
description: Channel establishment sequence with VLS signing. BOLT 2 protocol flow showing remote signer API calls for Lightning channel setup.
eleventyNavigation:
  key: Channel Establishment
  parent: Sequence Diagrams
---

## Channel Establishment Sequence

[BOLT #2 - Channel Establishment](https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#channel-establishment)

<br>

   | State Notation  | Signer State                                                     |
   |-----------------|------------------------------------------------------------------|
   | `H[] C[]`       | no holder commitment, no counterparty commitment                 |
   | `H[0] C[0]`     | holder initial commitment, counterparty initial commitment       |
   | `H[n] C[m]`     | holder commitment n, counterparty commitment m                   |
   | `H[n,n+1] C[m]` | holder commitment n and n+1, counterparty commitment m           |
   | `H[n]*`         | holder base commitment, splice, and RBF candidates for n         |
   | `H[n,n+1]*`     | holder base commitment, splice, and RBF candidates for n and n+1 |

<br>

```mermaid
sequenceDiagram
    autonumber

    participant Signer-A
    participant Node-A
    participant Node-B
    participant Signer-B

    activate Node-A
    Note over Node-A: Fund New Channel
    Node-A->>+Signer-A: NewChannel
    Signer-A-->>-Node-A: 

    Node-A->>Node-B: open_channel
    activate Node-B

    Node-B->>+Signer-B: NewChannel
    Signer-B-->>-Node-B: 

    Node-B->>Node-A: accept_channel

    Node-A->>+Signer-A: SetupChannel
    Signer-A-->>-Node-A: 
    Note over Signer-A: H[] C[]

    Node-A->>+Signer-A: SignCounterpartyCommitment(0)
    Signer-A-->>-Node-A: 
    Note over Signer-A: H[] C[0]

    Node-A->>Node-B: funding_created

    Node-B->>+Signer-B: SetupChannel
    Signer-B-->>-Node-B: 
    Note over Signer-B: H[] C[]

    Node-B->>+Signer-B: ValidateHolderCommitment(0)
    Signer-B-->>-Node-B: 
    Note over Signer-B: H[0] C[]

    Node-B->>+Signer-B: SignCounterpartyCommitment(0)
    Signer-B-->>-Node-B: 
    Note over Signer-B: H[0] C[0]

    Node-B->>Node-A: funding_signed

    Node-A ->>+Signer-A : ValidateHolderCommitment(0)
    Signer-A -->>-Node-A : 
    Note over Signer-A : H[0] C[0]

    Node-A ->>+Signer-A : SignOnchainTx
    Signer-A -->>-Node-A : 

    Node-A ->>+Signer-A : CheckOutpoint
    Signer-A -->>-Node-A : 

    Node-A->>Node-B: channel_ready

    Node-B  ->>+Signer-B  : CheckOutpoint
    Signer-B  -->>-Node-B  : 

    Node-B  ->>+Signer-B  : LockOutpoint
    Signer-B  -->>-Node-B  : 

    Node-B->>Node-A: channel_ready
    deactivate Node-B

    Node-A  ->>+Signer-A  : LockOutpoint
    Signer-A  -->>-Node-A  : 

    deactivate Node-A
```
