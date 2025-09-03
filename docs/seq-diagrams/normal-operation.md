---
layout: layouts/docs.njk
title: Normal Operation
description: Normal Lightning operation with VLS - commitment updates, revocation, and HTLC management. Detailed signing sequence for channel operations.
eleventyNavigation:
  key: Normal Operation
  parent: Sequence Diagrams
---

[BOLT #2 - Normal Operation](https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#normal-operation)

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

    par
        %% Node-A initiated, nantucket red
        rect rgb(254, 126, 136)

            activate Node-A
            Note over Node-A: Update Node B's Commitment
            Note over Signer-A: H[n] C[m]
            Node-A->>+Signer-A: SignCounterpartyCommitment(m+1)
            Signer-A-->>-Node-A: 
            Note over Signer-A: H[n] C[m,m+1]

            Node-A->>+Node-B: commitment_signed(m+1)

            Note over Signer-B: H[m] C[n]
            Node-B->>+Signer-B: ValidateHolderCommitment(m+1)
            Signer-B-->>-Node-B: 
            Note over Signer-B: H[m,m+1] C[n]

            Note over Node-B: persist H[m+1]

            Node-B->>+Signer-B: RevokeHolderCommitment(m)
            Signer-B-->>-Node-B: 
            Note over Signer-B: H[m+1] C[n]

            Node-B->>Node-A: revoke_and_ack(m)

            deactivate Node-B
            Node-A->>+Signer-A: ValidateCounterpartyRevocation(m)
            Signer-A-->>-Node-A: 
            Note over Signer-A: H[n] C[m+1]
            deactivate Node-A

        end
    and
        %% Node-B initiated, soft teal
        rect rgb(143, 188, 187)

            activate Node-B
            Note over Node-B: Update Node A's Commitment
            Note over Signer-B: H[m] C[n]
            Node-B->>+Signer-B: SignCounterpartyCommitment(n+1)
            Signer-B-->>-Node-B: 
            Note over Signer-B: H[m] C[n,n+1]

            Node-B->>+Node-A: commitment_signed(n+1)

            Note over Signer-A: H[n] C[m]
            Node-A->>+Signer-A: ValidateHolderCommitment(n+1)
            Signer-A-->>-Node-A: 
            Note over Signer-A: H[n,n+1] C[m]

            Note over Node-A: persist H[n+1]

            Node-A->>+Signer-A: RevokeHolderCommitment(n)
            Signer-A-->>-Node-A: 
            Note over Signer-A: H[n+1] C[m]

            Node-A->>Node-B: revoke_and_ack(n)

            deactivate Node-A
            Node-B->>+Signer-B: ValidateCounterpartyRevocation(n)
            Signer-B-->>-Node-B: 
            Note over Signer-B: H[m] C[n+1]
            deactivate Node-B

        end
    end
```

<br>
