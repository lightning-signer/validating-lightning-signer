use core::convert::TryInto;

use bitcoin::secp256k1::{ecdsa::Signature, PublicKey, SecretKey};
use lightning::chain::transaction::OutPoint;
use lightning::ln::chan_utils::{CommitmentTransaction, HTLCOutputInCommitment};

use lightning_signer::bitcoin;
use lightning_signer::channel::{ChannelId, TypedSignature};
use lightning_signer::lightning;
use lightning_signer::util::crypto_utils::signature_to_bitcoin_vec;
use lightning_signer::util::INITIAL_COMMITMENT_NUMBER;

use crate::grpc::remotesigner::{
    BitcoinSignature, ChannelNonce, CommitmentInfo, EcdsaSignature, HtlcInfo, NodeId, Outpoint,
    PubKey, Secret,
};

impl From<Signature> for BitcoinSignature {
    fn from(sig: Signature) -> Self {
        BitcoinSignature { data: signature_to_bitcoin_vec(sig) }
    }
}

impl From<TypedSignature> for BitcoinSignature {
    fn from(sig: TypedSignature) -> Self {
        BitcoinSignature { data: sig.serialize() }
    }
}

impl From<PublicKey> for PubKey {
    fn from(p: PublicKey) -> Self {
        PubKey { data: p.serialize().to_vec() }
    }
}

impl TryInto<PublicKey> for PubKey {
    type Error = ();

    fn try_into(self) -> Result<PublicKey, Self::Error> {
        PublicKey::from_slice(&self.data).map_err(|_| ())
    }
}

impl TryInto<Signature> for EcdsaSignature {
    type Error = ();

    fn try_into(self) -> Result<Signature, ()> {
        Signature::from_der(&self.data).map_err(|_| ())
    }
}

impl From<Signature> for EcdsaSignature {
    fn from(s: Signature) -> Self {
        EcdsaSignature { data: s.serialize_der().to_vec() }
    }
}

impl From<SecretKey> for Secret {
    fn from(s: SecretKey) -> Self {
        Secret { data: s[..].to_vec() }
    }
}

impl From<PublicKey> for NodeId {
    fn from(p: PublicKey) -> Self {
        NodeId { data: p.serialize().to_vec() }
    }
}

impl From<ChannelId> for ChannelNonce {
    fn from(c: ChannelId) -> Self {
        ChannelNonce { data: c.inner().clone() }
    }
}

impl From<OutPoint> for Outpoint {
    fn from(p: OutPoint) -> Self {
        Outpoint { txid: p.txid.to_vec(), index: p.index as u32 }
    }
}

impl From<(&CommitmentTransaction, bool)> for CommitmentInfo {
    fn from(p: (&CommitmentTransaction, bool)) -> Self {
        let (t, holder_is_broadcaster) = p;
        let (offered_htlcs, received_htlcs) = htlcs_to_proto(t.htlcs());
        let point = t.trust().keys().per_commitment_point;
        CommitmentInfo {
            feerate_sat_per_kw: t.feerate_per_kw(),
            n: INITIAL_COMMITMENT_NUMBER - t.commitment_number(),
            to_holder_value_sat: if holder_is_broadcaster {
                t.to_broadcaster_value_sat()
            } else {
                t.to_countersignatory_value_sat()
            },
            to_counterparty_value_sat: if holder_is_broadcaster {
                t.to_countersignatory_value_sat()
            } else {
                t.to_broadcaster_value_sat()
            },
            per_commitment_point: Some(point.into()),
            offered_htlcs,
            received_htlcs,
        }
    }
}

///
pub fn htlcs_to_proto(htlcs: &Vec<HTLCOutputInCommitment>) -> (Vec<HtlcInfo>, Vec<HtlcInfo>) {
    let mut offered_htlcs = Vec::new();
    let mut received_htlcs = Vec::new();
    for htlc in htlcs {
        let h = HtlcInfo {
            value_sat: htlc.amount_msat / 1000,
            payment_hash: htlc.payment_hash.0.to_vec(),
            cltv_expiry: htlc.cltv_expiry,
        };
        if htlc.offered {
            offered_htlcs.push(h);
        } else {
            received_htlcs.push(h);
        }
    }
    (offered_htlcs, received_htlcs)
}
