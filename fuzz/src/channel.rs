use arbitrary::{Arbitrary, Unstructured};
use bitcoin::secp256k1;
use lightning::ln::chan_utils::MAX_HTLCS;
use lightning::types::payment::PaymentHash;
use lightning_signer::bitcoin;
use lightning_signer::channel::ChannelId;
use lightning_signer::lightning;
use lightning_signer::node::Node;
use lightning_signer::policy::filter::PolicyFilter;
use lightning_signer::policy::simple_validator::{
    make_simple_policy, OptionizedSimplePolicy, SimpleValidatorFactory,
};
use lightning_signer::tx::tx::{CommitmentInfo2, HTLCInfo2};
use lightning_signer::util::status::Status;
use lightning_signer::util::test_utils::{
    init_node_and_channel, make_test_channel_setup, TEST_NODE_CONFIG, TEST_SEED,
};
use secp256k1::ecdsa::Signature;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Arbitrary)]
pub enum Action {
    AddHtlc {
        cltv_expiry: u8,
        is_offered: bool,
    },
    FulfillHtlc(
        #[arbitrary(with = |u: &mut Unstructured| u.int_in_range(0..=MAX_HTLCS))] u16,
        bool,
    ),

    ValidateHolder(),
    Revoke,
    RevokeOld(u8),

    SignCounterparty(),
    ValidateCounterpartyRevocation(),
    ValidateOldCounterpartyRevocation(u8),

    // Actions expected to error
    BadRevokeFuture(u8),
    BadValidateCounterpartyRevocationFuture(u8),
}

#[derive(Debug)]
pub struct ChannelFuzz {
    holder_commitment_number: u64,
    cp_commitment_number: u64,

    // the counterparty tx is just the mirror image of this one
    holder_tx: CommitmentInfo2,
    fee: u64,
    hash_counter: u64,
    node: Arc<Node>,
    channel_id: ChannelId,
    is_current_validated: bool,

    dummy_sig: Signature,
    dummy_point: secp256k1::PublicKey,
    dummy_secret: secp256k1::SecretKey,
}

impl ChannelFuzz {
    pub fn new() -> Self {
        let (node, channel_id) = init();
        let dummy_secret = secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
        let dummy_point = secp256k1::PublicKey::from_str(
            "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        )
        .unwrap();
        let dummy_sig = Signature::from_compact(&[0; 64]).unwrap();
        Self {
            holder_commitment_number: 0,
            cp_commitment_number: 0,
            holder_tx: CommitmentInfo2 {
                is_counterparty_broadcaster: false,
                feerate_per_kw: 2000,
                to_broadcaster_value_sat: 3_000_000,
                to_countersigner_value_sat: 0,
                offered_htlcs: vec![],
                received_htlcs: vec![],
            },
            fee: 10000,
            hash_counter: 0,
            node,
            channel_id,
            is_current_validated: false,
            dummy_sig,
            dummy_point,
            dummy_secret,
        }
    }

    pub fn run(&mut self, data: Vec<Action>) -> Result<(), Status> {
        for action in data {
            #[cfg(feature = "debug")]
            println!("{:?}", action);
            match action {
                Action::ValidateHolder() => {
                    self.validate_current_holder()?;
                    self.is_current_validated = true;
                }
                Action::Revoke => {
                    if !self.is_current_validated {
                        self.validate_current_holder()?;
                        self.is_current_validated = true;
                    }
                    self.revoke_previous(self.holder_commitment_number)?;
                    self.holder_commitment_number += 1;
                    self.is_current_validated = false;
                }
                Action::AddHtlc { cltv_expiry, is_offered } => {
                    // if we already validated, we have to move state forward before adding an HTLC
                    if self.is_current_validated {
                        self.revoke_previous(self.holder_commitment_number)?;
                        self.holder_commitment_number += 1;
                        self.is_current_validated = false;
                    }
                    self.hash_counter += 1;
                    let mut payment_hash = [0; 32];
                    payment_hash[0..8].copy_from_slice(&self.hash_counter.to_be_bytes());
                    let payment_hash = PaymentHash(payment_hash);

                    if is_offered {
                        if self.holder_tx.offered_htlcs.len() >= MAX_HTLCS as usize {
                            continue;
                        }
                        self.holder_tx.to_broadcaster_value_sat -= 2_000;
                        self.holder_tx.offered_htlcs.push(HTLCInfo2 {
                            value_sat: 2_000,
                            payment_hash,
                            cltv_expiry: cltv_expiry as u32,
                        });
                    } else if self.holder_tx.to_countersigner_value_sat >= 2_000 {
                        if self.holder_tx.received_htlcs.len() >= MAX_HTLCS as usize {
                            continue;
                        }
                        self.holder_tx.to_countersigner_value_sat -= 2_000;
                        self.holder_tx.received_htlcs.push(HTLCInfo2 {
                            value_sat: 2_000,
                            payment_hash,
                            cltv_expiry: cltv_expiry as u32,
                        });
                    }
                }
                Action::FulfillHtlc(htlc_idx, is_offered) => {
                    if !self.is_current_validated {
                        self.validate_current_holder()?;
                        self.is_current_validated = true;
                    }
                    if is_offered {
                        if self.holder_tx.offered_htlcs.is_empty() {
                            continue;
                        }
                        let idx = htlc_idx as usize % self.holder_tx.offered_htlcs.len();
                        let htlc = self.holder_tx.offered_htlcs.remove(idx);
                        self.holder_tx.to_countersigner_value_sat += htlc.value_sat;
                    } else {
                        if self.holder_tx.received_htlcs.is_empty() {
                            continue;
                        }
                        let idx = htlc_idx as usize % self.holder_tx.received_htlcs.len();
                        let htlc = self.holder_tx.received_htlcs.remove(idx);
                        self.holder_tx.to_broadcaster_value_sat += htlc.value_sat;
                    }
                }
                Action::RevokeOld(count) => {
                    if count >= 1 && self.holder_commitment_number > count as u64 {
                        self.revoke_previous(self.holder_commitment_number - count as u64)?;
                    }
                }
                Action::BadRevokeFuture(count) =>
                    if count > 0 {
                        self.revoke_previous(self.holder_commitment_number + count as u64)
                            .unwrap_err();
                    },
                Action::SignCounterparty() => {
                    self.sign_current_counterparty()?;
                }
                Action::ValidateCounterpartyRevocation() => {
                    self.validate_cp_revocation(self.cp_commitment_number)?;
                    self.cp_commitment_number += 1;
                }
                Action::ValidateOldCounterpartyRevocation(count) => {
                    if count >= 1 && self.cp_commitment_number > count as u64 {
                        self.validate_cp_revocation(self.cp_commitment_number - count as u64)?;
                    }
                }
                Action::BadValidateCounterpartyRevocationFuture(count) => {
                    if count > 0 {
                        // TODO this doesn't actually generate an error in permissive mode
                        self.validate_cp_revocation(self.cp_commitment_number + count as u64)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_cp_revocation(&mut self, commitment_number: u64) -> Result<(), Status> {
        self.node.with_channel(&self.channel_id, |chan| {
            chan.validate_counterparty_revocation(commitment_number, &self.dummy_secret)
        })?;
        Ok(())
    }

    fn revoke_previous(&mut self, commitment_number: u64) -> Result<(), Status> {
        self.node.with_channel(&self.channel_id, |chan| {
            chan.revoke_previous_holder_commitment(commitment_number)?;
            Ok(())
        })?;
        Ok(())
    }

    fn validate_current_holder(&mut self) -> Result<(), Status> {
        self.node.with_channel(&self.channel_id, |chan| {
            let tx = &self.holder_tx;
            let htlc_sigs = (0..tx.offered_htlcs.len() + tx.received_htlcs.len())
                .map(|_| self.dummy_sig.clone())
                .collect::<Vec<_>>();
            chan.validate_holder_commitment_tx_phase2(
                self.holder_commitment_number,
                tx.feerate_per_kw,
                tx.to_broadcaster_value_sat - self.fee,
                tx.to_countersigner_value_sat,
                tx.offered_htlcs.clone(),
                tx.received_htlcs.clone(),
                &self.dummy_sig,
                &htlc_sigs,
            )
            .unwrap();
            Ok(())
        })
    }

    fn sign_current_counterparty(&mut self) -> Result<(), Status> {
        self.node.with_channel(&self.channel_id, |chan| {
            let tx = &self.holder_tx;
            let remote_per_commitment_point = self.dummy_point;
            // like validate_current, but broadcaster is the counterparty, so swap the values
            chan.sign_counterparty_commitment_tx_phase2(
                &remote_per_commitment_point,
                self.cp_commitment_number + 1,
                tx.feerate_per_kw,
                tx.to_countersigner_value_sat,
                tx.to_broadcaster_value_sat - self.fee,
                tx.received_htlcs.clone(),
                tx.offered_htlcs.clone(),
            )?;
            Ok(())
        })
    }
}

fn init() -> (Arc<Node>, ChannelId) {
    let (node, channel_id) =
        init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
    let mut permissive_policy =
        make_simple_policy(bitcoin::Network::Testnet, OptionizedSimplePolicy::new());
    permissive_policy.filter = PolicyFilter::new_permissive();
    let permissive_factory = SimpleValidatorFactory::new_with_policy(permissive_policy);
    node.set_validator_factory(Arc::new(permissive_factory));
    (node, channel_id)
}

// these need `RUSTFLAGS=--cfg=fuzzing cargo test` to work
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run() {
        let mut channel_fuzz = ChannelFuzz::new();
        channel_fuzz
            .run(vec![
                Action::AddHtlc { cltv_expiry: 10, is_offered: true },
                Action::ValidateHolder(),
                Action::Revoke,
                Action::SignCounterparty(),
                Action::ValidateCounterpartyRevocation(),
            ])
            .unwrap();
        assert_eq!(channel_fuzz.holder_commitment_number, 1);
        assert_eq!(channel_fuzz.cp_commitment_number, 1);
    }

    #[test]
    fn test_reproduce_revoke_old_bug() {
        let mut channel_fuzz = ChannelFuzz::new();
        channel_fuzz
            .run(vec![
                Action::Revoke,
                Action::Revoke,
                Action::Revoke,
                // this will move the commitment number backwards without the fix in
                // https://gitlab.com/lightning-signer/validating-lightning-signer/-/merge_requests/686
                Action::ValidateHolder(),
                Action::RevokeOld(2),
                // crashes without the fix
                Action::Revoke,
            ])
            .unwrap();
    }
}
