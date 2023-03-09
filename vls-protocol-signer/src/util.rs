use bit_vec::BitVec;
use lightning_signer::channel::CommitmentType;
use lightning_signer::prelude::*;
use vls_protocol::features::*;

/// Extract the commitment type from the CLN-style serialized channel features
pub fn channel_type_to_commitment_type(channel_type: &Vec<u8>) -> CommitmentType {
    // The byte/bit order from the wire is wrong in every way ...
    let features = BitVec::from_bytes(
        &channel_type.iter().rev().map(|bb| bb.reverse_bits()).collect::<Vec<u8>>(),
    );
    if features.get(OPT_ANCHORS_ZERO_FEE_HTLC_TX).unwrap_or_default() {
        assert_eq!(features.get(OPT_STATIC_REMOTEKEY).unwrap_or_default(), true);
        CommitmentType::AnchorsZeroFeeHtlc
    } else if features.get(OPT_ANCHOR_OUTPUTS).unwrap_or_default() {
        assert_eq!(features.get(OPT_STATIC_REMOTEKEY).unwrap_or_default(), true);
        CommitmentType::Anchors
    } else if features.get(OPT_STATIC_REMOTEKEY).unwrap_or_default() {
        CommitmentType::StaticRemoteKey
    } else {
        CommitmentType::Legacy
    }
}

/// Convert a commitment type to CLN-style serialized channel features
pub fn commitment_type_to_channel_type(commitment_type: CommitmentType) -> Vec<u8> {
    let mut channel_features = BitVec::from_elem(OPT_MAX, false);
    channel_features.set(OPT_STATIC_REMOTEKEY, true);
    if commitment_type == CommitmentType::Anchors
        || commitment_type == CommitmentType::AnchorsZeroFeeHtlc
    {
        channel_features.set(OPT_ANCHOR_OUTPUTS, true);
    }
    if commitment_type == CommitmentType::AnchorsZeroFeeHtlc {
        channel_features.set(OPT_ANCHORS_ZERO_FEE_HTLC_TX, true);
    }
    // The byte/bit order from the wire is wrong in every way ...
    channel_features.to_bytes().iter().rev().map(|bb| bb.reverse_bits()).collect::<Vec<u8>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn features_test() {
        for commitment_type in vec![
            CommitmentType::StaticRemoteKey,
            CommitmentType::Anchors,
            CommitmentType::AnchorsZeroFeeHtlc,
        ] {
            assert_eq!(
                channel_type_to_commitment_type(&commitment_type_to_channel_type(commitment_type)),
                commitment_type
            );
        }
    }
}
