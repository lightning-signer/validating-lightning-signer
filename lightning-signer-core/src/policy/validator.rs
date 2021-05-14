use bitcoin::util::address::Payload;
use bitcoin::{self, Network};

use crate::node::{Channel, ChannelSetup};
use crate::tx::tx::{CommitmentInfo, CommitmentInfo2};
use crate::util::enforcing_trait_impls::EnforcingSigner;

use super::error::ValidationError::{self, Policy, TransactionFormat};

pub trait Validator {
    /// Phase 1 CommitmentInfo
    fn make_info(
        &self,
        keys: &EnforcingSigner,
        setup: &ChannelSetup,
        is_counterparty: bool,
        tx: &bitcoin::Transaction,
        output_witscripts: &Vec<Vec<u8>>,
    ) -> Result<CommitmentInfo, ValidationError>;

    /// Phase 1 remote tx validation
    fn validate_remote_tx_phase1(
        &self,
        setup: &ChannelSetup,
        state: &ValidatorState,
        info: &CommitmentInfo,
        our_address: &Payload,
    ) -> Result<(), ValidationError>;
    /// Phase 2 remote tx validation
    fn validate_remote_tx(
        &self,
        setup: &ChannelSetup,
        state: &ValidatorState,
        info2: &CommitmentInfo2,
    ) -> Result<(), ValidationError>;
    /// Validate channel open
    fn validate_channel_open(&self) -> Result<(), ValidationError>;
}

// BEGIN NOT TESTED
#[derive(Debug)]
pub struct ValidatorState {
    pub current_height: u32,
}
// END NOT TESTED

pub trait ValidatorFactory: Send + Sync {
    fn make_validator(&self, channel: &Channel) -> Box<dyn Validator>;
    fn make_validator_phase1(
        &self,
        channel: &Channel,
        channel_value_sat: u64,
    ) -> Box<dyn Validator>;
}

pub struct SimpleValidatorFactory {}

fn simple_validator(network: Network, channel_value_sat: u64) -> SimpleValidator {
    SimpleValidator {
        policy: make_simple_policy(network),
        channel_value_sat,
    }
}

impl ValidatorFactory for SimpleValidatorFactory {
    fn make_validator(&self, channel: &Channel) -> Box<dyn Validator> {
        Box::new(simple_validator(
            channel.network(),
            channel.setup.channel_value_sat,
        ))
    }

    /// In phase 1 we don't have the channel value populated in the Channel object,
    /// so supply it separately
    fn make_validator_phase1(
        &self,
        channel: &Channel,
        channel_value_sat: u64,
    ) -> Box<dyn Validator> {
        Box::new(simple_validator(channel.network(), channel_value_sat))
    }
}

// BEGIN NOT TESTED
#[derive(Clone)]
pub struct SimplePolicy {
    /// Minimum delay in blocks
    pub min_delay: u16,
    /// Maximum delay in blocks
    pub max_delay: u16,
    /// Maximum channel value in satoshi
    pub max_channel_size_sat: u64,
    /// amounts below this number of satoshi are not considered important
    pub epsilon_sat: u64,
    /// Maximum number of in-flight HTLCs
    pub max_htlcs: usize,
    /// Maximum value of in-flight HTLCs
    pub max_htlc_value_sat: u64,
    /// Whether to use knowledge of chain state (e.g. current_height)
    pub use_chain_state: bool,
}
// END NOT TESTED

pub struct SimpleValidator {
    pub policy: SimplePolicy,
    pub channel_value_sat: u64,
}

impl SimpleValidator {
    fn validate_delay(&self, name: &str, delay: u32) -> Result<(), ValidationError> {
        let policy = &self.policy;

        if delay < policy.min_delay as u32 {
            return Err(Policy(format!("{} delay too small", name)));
        }
        if delay > policy.max_delay as u32 {
            return Err(Policy(format!("{} delay too large", name)));
        }

        Ok(())
    }

    fn validate_expiry(
        &self,
        name: &str,
        expiry: u32,
        current_height: u32,
    ) -> Result<(), ValidationError> {
        let policy = &self.policy;

        if policy.use_chain_state {
            if expiry < current_height + policy.min_delay as u32 {
                return Err(Policy(format!("{} expiry too early", name)));
            }
            if expiry > current_height + policy.max_delay as u32 {
                return Err(Policy(format!("{} expiry too late", name)));
            }
        }

        Ok(())
    }
}

// not yet implemented
// TODO - policy-v1-funding-output-scriptpubkey
// TODO - policy-v1-funding-output-match-commitment
// TODO - policy-v1-funding-fee-range
// TODO - policy-v1-funding-format-standard
// TODO - policy-v2-funding-change-to-wallet

// sign_commitment_tx has some, missing these
// TODO - policy-v1-commitment-input-single
// TODO - policy-v1-commitment-input-match-funding
// TODO - policy-v1-commitment-locktime
// TODO - policy-v1-commitment-nsequence
// TODO - policy-v2-commitment-initial-funding-value
// TODO - policy-v2-commitment-spends-active-utxo
// TODO - policy-v2-commitment-htlc-routing-balance
// TODO - policy-v2-commitment-htlc-received-spends-active-utxo
// TODO - policy-v1-commitment-revocation-pubkey
// TODO - policy-v1-commitment-htlc-delay-range
// TODO - policy-v1-commitment-payment-pubkey
// TODO - policy-v1-commitment-delayed-pubkey
// TODO - policy-v1-commitment-htlc-pubkey
// TODO - policy-v2-commitment-htlc-offered-hash-matches
// TODO - policy-v1-commitment-outputs-trimmed
// TODO - policy-v2-commitment-previous-revoked
// TODO - policy-v2-commitment-local-not-revoked
// TODO - policy-v1-commitment-anchor-static-remotekey

// not yet implemented
// TODO - policy-v2-revoke-new-commitment-signed
// TODO - policy-v2-revoke-new-commitment-valid
// TODO - policy-v2-revoke-not-closed

// not yet implemented
// TODO - policy-v1-htlc-revocation-pubkey
// TODO - policy-v1-htlc-payment-pubkey
// TODO - policy-v1-htlc-version
// TODO - policy-v1-htlc-locktime
// TODO - policy-v1-htlc-nsequence
// TODO - policy-v1-htlc-fee-range

// not yet implemented
// TODO - policy-v2-mutual-destination-whitelisted
// TODO - policy-v2-mutual-value-matches-commitment
// TODO - policy-v2-mutual-fee-range
// TODO - policy-v2-mutual-no-pending-htlcs

// not yet implemented
// TODO - policy-v2-forced-destination-whitelisted
// TODO - policy-v2-forced-fee-range

// not yet implemented
// TODO - policy-v3-velocity-transferred
// TODO - policy-v3-merchant-no-sends
// TODO - policy-v3-routing-deltas-only-htlc

impl Validator for SimpleValidator {
    fn make_info(
        &self,
        keys: &EnforcingSigner,
        setup: &ChannelSetup,
        is_counterparty: bool,
        tx: &bitcoin::Transaction,
        output_witscripts: &Vec<Vec<u8>>,
    ) -> Result<CommitmentInfo, ValidationError> {
        // policy-v1-commitment-version
        if tx.version != 2 {
            return Err(Policy(format!("bad commitment version: {}", tx.version)));
        }

        let mut info = CommitmentInfo::new(is_counterparty);
        for ind in 0..tx.output.len() {
            info.handle_output(
                keys,
                setup,
                &tx.output[ind],
                output_witscripts[ind].as_slice(),
            )
            .map_err(|ve| Policy(format!("tx output[{}]: {}", ind, ve)))?;
        }
        Ok(info)
    }

    fn validate_remote_tx_phase1(
        &self,
        setup: &ChannelSetup,
        state: &ValidatorState,
        info: &CommitmentInfo,
        our_address: &Payload,
    ) -> Result<(), ValidationError> {
        let policy = &self.policy;

        if info
            .to_countersigner_address
            .as_ref()
            .unwrap_or(our_address)
            != our_address
        {
            return Err(TransactionFormat(
                "to_countersigner address mismatch".to_string(),
            ));
        }

        // policy-v1-commitment-to-self-delay-range
        if info.to_broadcaster_delayed_pubkey.is_some() {
            self.validate_delay("to_broadcaster", info.to_self_delay as u32)?;
        }

        let num_htlc = info.offered_htlcs.len() + info.received_htlcs.len();

        // policy-v2-commitment-htlc-count-limit
        if num_htlc > policy.max_htlcs {
            return Err(Policy("too many HTLCs".to_string()));
        }

        let mut htlc_value_sat = 0;

        for htlc in &info.offered_htlcs {
            htlc_value_sat += htlc.value_sat;
        }

        // policy-v2-htlc-delay-range
        for htlc in &info.received_htlcs {
            self.validate_expiry("received HTLC", htlc.cltv_expiry, state.current_height)?;
            htlc_value_sat += htlc.value_sat;
        }

        if !setup.option_anchor_outputs() {
            // policy-v1-commitment-anchors-not-when-off
            if info.to_broadcaster_anchor_count > 0 {
                return Err(Policy(
                    "to_broadcaster anchor without option_anchor_outputs".to_string(),
                ));
            }
            // policy-v1-commitment-anchors-not-when-off
            if info.to_countersigner_anchor_count > 0 {
                return Err(Policy(
                    "to_countersigner anchor without option_anchor_outputs".to_string(),
                ));
            }
        } else {
            // FIXME - Does this need it's own policy tag?
            // policy-v1-commitment-anchor-to-local
            if info.to_broadcaster_anchor_count > 1 {
                return Err(Policy("more than one to_broadcaster anchors".to_string()));
            }
            // FIXME - Does this need it's own policy tag?
            // policy-v1-commitment-anchor-to-remote
            if info.to_countersigner_anchor_count > 1 {
                return Err(Policy("more than one to_countersigner anchors".to_string()));
            }
            // policy-v1-commitment-anchor-to-local
            if info.has_to_broadcaster() && info.to_broadcaster_anchor_count == 0 {
                return Err(Policy(
                    "to_broadcaster output without to_broadcaster anchor".to_string(),
                ));
            }
            // policy-v1-commitment-anchor-to-remote
            if info.has_to_countersigner() && info.to_countersigner_anchor_count == 0 {
                return Err(Policy(
                    "to_countersigner output without to_countersigner anchor".to_string(),
                ));
            }
            if num_htlc == 0 {
                // FIXME - Does this need it's own policy tag?
                // policy-v1-commitment-anchor-to-local
                if !info.has_to_broadcaster() && info.to_broadcaster_anchor_count == 1 {
                    return Err(Policy(
                        "to_broadcaster anchor without to_broadcaster output or HTLCs".to_string(),
                    ));
                }
                // FIXME - Does this need it's own policy tag?
                // policy-v1-commitment-anchor-to-remote
                if !info.has_to_countersigner() && info.to_countersigner_anchor_count == 1 {
                    return Err(Policy(
                        "to_countersigner anchor without to_countersigner output or HTLCs"
                            .to_string(),
                    ));
                }
            }
        }

        // policy-v2-commitment-htlc-inflight-limit
        if htlc_value_sat > policy.max_htlc_value_sat {
            return Err(Policy(format!(
                "sum of HTLC values {} too large",
                htlc_value_sat
            )));
        }

        let value_sat = info.to_broadcaster_value_sat
            + info.to_countersigner_value_sat
            + info.to_broadcaster_anchor_value_sat()
            + info.to_countersigner_anchor_value_sat()
            + htlc_value_sat;
        if self.channel_value_sat < value_sat {
            return Err(Policy(format!(
                "channel value greater than funding {} > {}",
                value_sat, self.channel_value_sat
            )));
        }

        // policy-v2-commitment-fee-range
        let shortage = self.channel_value_sat - value_sat;
        if shortage > policy.epsilon_sat {
            return Err(Policy(format!(
                "channel value short by {} > {}",
                shortage, policy.epsilon_sat
            )));
        }

        Ok(())
    }

    fn validate_remote_tx(
        &self,
        _setup: &ChannelSetup,
        state: &ValidatorState,
        info: &CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        let policy = &self.policy;

        // policy-v1-commitment-to-self-delay-range
        self.validate_delay("to_broadcaster", info.to_self_delay as u32)?;

        // policy-v2-commitment-htlc-count-limit
        if info.offered_htlcs.len() + info.received_htlcs.len() > policy.max_htlcs {
            return Err(Policy("too many HTLCs".to_string()));
        }

        let mut htlc_value_sat = 0;

        for htlc in &info.offered_htlcs {
            self.validate_expiry("offered HTLC", htlc.cltv_expiry, state.current_height)?;
            htlc_value_sat += htlc.value_sat;
        }

        for htlc in &info.received_htlcs {
            self.validate_expiry("received HTLC", htlc.cltv_expiry, state.current_height)?;
            htlc_value_sat += htlc.value_sat;
        }

        // policy-v2-commitment-htlc-inflight-limit
        if htlc_value_sat > policy.max_htlc_value_sat {
            return Err(Policy(format!(
                "sum of HTLC values {} too large",
                htlc_value_sat
            )));
        }

        // policy-v2-commitment-fee-range
        let shortage = self.channel_value_sat
            - (info.to_broadcaster_value_sat + info.to_countersigner_value_sat + htlc_value_sat);
        if shortage > policy.epsilon_sat {
            return Err(Policy(format!(
                "channel value short by {} > {}",
                shortage, policy.epsilon_sat
            )));
        }

        Ok(())
    }

    // TODO - policy-v3-velocity-funding
    // TODO - this implementation is incomplete
    fn validate_channel_open(&self) -> Result<(), ValidationError> {
        if self.channel_value_sat > self.policy.max_channel_size_sat {
            return Err(Policy(format!(
                "channel value {} too large",
                self.channel_value_sat
            )));
        }
        Ok(())
    }
}

pub fn make_simple_policy(network: Network) -> SimplePolicy {
    if network == Network::Bitcoin {
        // BEGIN NOT TESTED
        SimplePolicy {
            min_delay: 60,
            max_delay: 1440,
            max_channel_size_sat: 1_000_000_001,
            epsilon_sat: 1_600_000,
            max_htlcs: 1000,
            max_htlc_value_sat: 16_777_216,
            use_chain_state: false,
        }
    // END NOT TESTED
    } else {
        SimplePolicy {
            min_delay: 4,
            max_delay: 1440,
            max_channel_size_sat: 1_000_000_001, // lnd itest: wumbu default + 1
            epsilon_sat: 1_600_000, // lnd itest: async_bidirectional_payments (large amount of dust HTLCs)
            max_htlcs: 1000,
            max_htlc_value_sat: 16_777_216, // lnd itest: multi-hop_htlc_error_propagation
            use_chain_state: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use lightning::ln::PaymentHash;

    use crate::node::CommitmentType;
    use crate::tx::tx::{HTLCInfo, HTLCInfo2, ANCHOR_SAT};
    use crate::util::crypto_utils::payload_for_p2wpkh;
    use crate::util::test_utils::{
        make_reasonable_test_channel_setup, make_test_channel_keys, make_test_channel_setup,
        make_test_commitment_tx, make_test_pubkey,
    };

    use super::*;

    macro_rules! assert_policy_error {
        ($res: expr, $expected: expr) => {
            assert_eq!($res.unwrap_err(), Policy($expected.to_string()));
        };
    }

    macro_rules! assert_txfmt_error {
        ($res: expr, $expected: expr) => {
            assert_eq!($res.unwrap_err(), TransactionFormat($expected.to_string()));
        };
    }

    fn make_test_validator(channel_value_sat: u64) -> SimpleValidator {
        let policy = SimplePolicy {
            min_delay: 5,
            max_delay: 1440,
            max_channel_size_sat: 100_000_000,
            epsilon_sat: 100_000,
            max_htlcs: 1000,
            max_htlc_value_sat: 10_000_000,
            use_chain_state: true,
        };

        SimpleValidator {
            policy,
            channel_value_sat,
        }
    }

    #[test]
    fn make_info_test() {
        let validator = make_test_validator(100_000_000);
        let info = validator
            .make_info(
                &make_test_channel_keys(),
                &make_test_channel_setup(),
                true,
                &make_test_commitment_tx(),
                &vec![vec![]],
            )
            .unwrap();
        assert_eq!(info.is_counterparty_broadcaster, true);
    }

    #[test]
    fn validate_policy_commitment_version() {
        let validator = make_test_validator(100_000_000);
        let mut tx = make_test_commitment_tx();
        tx.version = 1;
        let res = validator.make_info(
            &make_test_channel_keys(),
            &make_test_channel_setup(),
            true,
            &tx,
            &vec![vec![]],
        ); // NOT TESTED
        assert_policy_error!(res, "bad commitment version: 1");
    }

    #[test]
    fn validate_channel_open_test() {
        let validator = make_test_validator(100_000_000);
        assert!(validator.validate_channel_open().is_ok());
        let validator_large = make_test_validator(100_000_001);
        assert!(validator_large.validate_channel_open().is_err());
    }

    fn make_counterparty_info(
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        to_self_delay: u16,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> CommitmentInfo2 {
        let to_counterparty_pubkey = make_test_pubkey(1);
        let revocation_pubkey = make_test_pubkey(2);
        let to_broadcaster_delayed_pubkey = make_test_pubkey(3);
        let to_counterparty_pubkey = to_counterparty_pubkey.clone();
        CommitmentInfo2 {
            is_counterparty_broadcaster: true,
            to_countersigner_pubkey: to_counterparty_pubkey,
            to_countersigner_value_sat: to_counterparty_value_sat,
            revocation_pubkey,
            to_broadcaster_delayed_pubkey: to_broadcaster_delayed_pubkey,
            to_broadcaster_value_sat: to_holder_value_sat,
            to_self_delay,
            offered_htlcs,
            received_htlcs,
        }
    }

    fn make_counterparty_info1(
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        to_self_delay: u16,
        offered_htlcs: Vec<HTLCInfo>,
        received_htlcs: Vec<HTLCInfo>,
    ) -> CommitmentInfo {
        let to_counterparty_pubkey = make_test_pubkey(1);
        let revocation_pubkey = Some(make_test_pubkey(2));
        let to_broadcaster_delayed_pubkey = Some(make_test_pubkey(3));
        let to_counterparty_pubkey = Some(to_counterparty_pubkey.clone());
        CommitmentInfo {
            is_counterparty_broadcaster: true,
            to_countersigner_address: None,
            to_countersigner_pubkey: to_counterparty_pubkey,
            to_countersigner_value_sat: to_counterparty_value_sat,
            to_countersigner_anchor_count: 0,
            revocation_pubkey,
            to_broadcaster_delayed_pubkey: to_broadcaster_delayed_pubkey,
            to_broadcaster_value_sat: to_holder_value_sat,
            to_self_delay,
            to_broadcaster_anchor_count: 0,
            offered_htlcs,
            received_htlcs,
        }
    }

    fn make_counterparty_info1_with_anchors(
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        to_self_delay: u16,
        offered_htlcs: Vec<HTLCInfo>,
        received_htlcs: Vec<HTLCInfo>,
    ) -> CommitmentInfo {
        let to_counterparty_pubkey = make_test_pubkey(1);
        let revocation_pubkey = Some(make_test_pubkey(2));
        let to_broadcaster_delayed_pubkey = Some(make_test_pubkey(3));
        let to_counterparty_pubkey = Some(to_counterparty_pubkey.clone());
        CommitmentInfo {
            is_counterparty_broadcaster: true,
            to_countersigner_address: None,
            to_countersigner_pubkey: to_counterparty_pubkey,
            to_countersigner_value_sat: to_counterparty_value_sat,
            to_countersigner_anchor_count: 1,
            revocation_pubkey,
            to_broadcaster_delayed_pubkey: to_broadcaster_delayed_pubkey,
            to_broadcaster_value_sat: to_holder_value_sat,
            to_self_delay,
            to_broadcaster_anchor_count: 1,
            offered_htlcs,
            received_htlcs,
        }
    }

    fn make_validator() -> SimpleValidator {
        make_test_validator(100_000_000)
    }

    fn make_validator_state() -> ValidatorState {
        ValidatorState {
            current_height: 1000,
        }
    }

    fn make_htlc_info(expiry: u32) -> HTLCInfo {
        HTLCInfo {
            value_sat: 10,
            payment_hash_hash: [0; 20],
            cltv_expiry: expiry,
        }
    }

    fn make_htlc_info2(expiry: u32) -> HTLCInfo2 {
        HTLCInfo2 {
            value_sat: 10,
            payment_hash: PaymentHash([0; 32]),
            cltv_expiry: expiry,
        }
    }

    #[test]
    fn validate_remote_tx_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let info = make_counterparty_info(99_000_000, 900_000, 6, vec![], vec![]);
        assert!(validator
            .validate_remote_tx(&make_test_channel_setup(), &state, &info)
            .is_ok());
    }

    #[test]
    fn validate_remote_tx_to_broadcaster_min_delay_test() {
        let validator = make_validator();
        let state = make_validator_state();
        // 5 is ok ...
        let info = make_counterparty_info(99_000_000, 900_000, 5, vec![], vec![]);
        assert!(validator
            .validate_remote_tx(&make_test_channel_setup(), &state, &info)
            .is_ok());
        // but 4 is right out
        let info_bad = make_counterparty_info(99_000_000, 900_000, 4, vec![], vec![]);
        assert_policy_error!(
            validator.validate_remote_tx(&make_test_channel_setup(), &state, &info_bad),
            "to_broadcaster delay too small"
        );
    }

    #[test]
    fn validate_remote_tx_to_broadcaster_max_delay_test() {
        let validator = make_validator();
        let state = make_validator_state();
        // 1440 is ok ...
        let info = make_counterparty_info(99_000_000, 900_000, 1440, vec![], vec![]);
        assert!(validator
            .validate_remote_tx(&make_test_channel_setup(), &state, &info)
            .is_ok());
        // but 1441 is right out
        let info_bad = make_counterparty_info(99_000_000, 900_000, 1441, vec![], vec![]);
        assert_policy_error!(
            validator.validate_remote_tx(&make_test_channel_setup(), &state, &info_bad),
            "to_broadcaster delay too large"
        );
    }

    #[test]
    fn validate_remote_tx_phase1_countersigner_addr_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let mut info = make_counterparty_info1(99_000_000, 900_000, 5, vec![], vec![]);
        info.to_countersigner_address = Some(payload_for_p2wpkh(&make_test_pubkey(1)));
        assert_txfmt_error!(
            validator.validate_remote_tx_phase1(
                &make_test_channel_setup(),
                &state,
                &info,
                &payload_for_p2wpkh(&make_test_pubkey(2)),
            ),
            "to_countersigner address mismatch"
        );
    }

    #[test]
    fn validate_remote_tx_phase1_htlc_count_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let htlcs = vec![make_htlc_info(1100); validator.policy.max_htlcs + 1];
        let info = make_counterparty_info1(99_000_000, 900_000, 5, htlcs.clone(), vec![]);
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &make_test_channel_setup(),
                &state,
                &info,
                &payload_for_p2wpkh(&make_test_pubkey(1)),
            ),
            "too many HTLCs"
        );
        let info2 = make_counterparty_info1(99_000_000, 900_000, 5, vec![], htlcs);
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &make_test_channel_setup(),
                &state,
                &info2,
                &payload_for_p2wpkh(&make_test_pubkey(1)),
            ),
            "too many HTLCs"
        );
    }

    #[test]
    fn validate_remote_tx_phase1_htlc_inflight_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let htlcs = vec![
            HTLCInfo {
                value_sat: 20_000,
                payment_hash_hash: [0; 20],
                cltv_expiry: 1100
            };
            validator.policy.max_htlcs
        ];
        let info = make_counterparty_info1(99_000_000, 900_000, 5, htlcs, vec![]);
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &make_test_channel_setup(),
                &state,
                &info,
                &payload_for_p2wpkh(&make_test_pubkey(1)),
            ),
            "sum of HTLC values 20000000 too large"
        );
    }

    #[test]
    fn validate_remote_tx_phase1_channel_value_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let htlcs = vec![
            HTLCInfo {
                value_sat: 10_000,
                payment_hash_hash: [0; 20],
                cltv_expiry: 1100
            };
            validator.policy.max_htlcs
        ];
        let info = make_counterparty_info1(99_000_000, 900_000, 5, htlcs, vec![]);
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &make_test_channel_setup(),
                &state,
                &info,
                &payload_for_p2wpkh(&make_test_pubkey(1)),
            ),
            "channel value greater than funding 109900000 > 100000000"
        );
    }

    #[test]
    fn validate_remote_tx_shortage_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let info_bad = make_counterparty_info(99_000_000, 900_000 - 1, 6, vec![], vec![]);
        assert_policy_error!(
            validator.validate_remote_tx(&make_test_channel_setup(), &state, &info_bad),
            "channel value short by 100001 > 100000"
        );
    }

    #[test]
    fn validate_remote_tx_phase1_shortage_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let info_bad = make_counterparty_info1(99_000_000, 900_000 - 1, 6, vec![], vec![]);
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &make_test_channel_setup(),
                &state,
                &info_bad,
                &payload_for_p2wpkh(&make_test_pubkey(1)),
            ),
            "channel value short by 100001 > 100000"
        );
    }

    #[test]
    fn validate_to_broadcaster_anchor_without_option_anchor_outputs_test() {
        let setup = make_reasonable_test_channel_setup();
        let validator = make_test_validator(setup.channel_value_sat);
        let state = make_validator_state();
        let remote_pubkey = make_test_pubkey(101);
        let mut info_bad = make_counterparty_info1(2_000_000, 1_000_000, 6, vec![], vec![]);
        info_bad.to_broadcaster_anchor_count = 1;
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &setup,
                &state,
                &info_bad,
                &payload_for_p2wpkh(&remote_pubkey),
            ),
            "to_broadcaster anchor without option_anchor_outputs"
        );
    }

    #[test]
    fn validate_to_countersigner_anchor_without_option_anchor_outputs_test() {
        let setup = make_reasonable_test_channel_setup();
        let validator = make_test_validator(setup.channel_value_sat);
        let state = make_validator_state();
        let remote_pubkey = make_test_pubkey(101);
        let mut info_bad = make_counterparty_info1(2_000_000, 1_000_000, 6, vec![], vec![]);
        info_bad.to_countersigner_anchor_count = 1;
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &setup,
                &state,
                &info_bad,
                &payload_for_p2wpkh(&remote_pubkey),
            ),
            "to_countersigner anchor without option_anchor_outputs"
        );
    }

    #[test]
    fn validate_more_than_one_to_broadcaster_anchors_test() {
        let mut setup = make_reasonable_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let validator = make_test_validator(setup.channel_value_sat);
        let state = make_validator_state();
        let remote_pubkey = make_test_pubkey(101);
        let mut info_bad = make_counterparty_info1_with_anchors(
            2_000_000,
            1_000_000 - (2 * ANCHOR_SAT),
            6,
            vec![],
            vec![],
        );
        info_bad.to_broadcaster_anchor_count = 2;
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &setup,
                &state,
                &info_bad,
                &payload_for_p2wpkh(&remote_pubkey),
            ),
            "more than one to_broadcaster anchors"
        );
    }

    #[test]
    fn validate_more_than_one_to_countersigner_anchors_test() {
        let mut setup = make_reasonable_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let validator = make_test_validator(setup.channel_value_sat);
        let state = make_validator_state();
        let remote_pubkey = make_test_pubkey(101);
        let mut info_bad = make_counterparty_info1_with_anchors(
            2_000_000,
            1_000_000 - (2 * ANCHOR_SAT),
            6,
            vec![],
            vec![],
        );
        info_bad.to_countersigner_anchor_count = 2;
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &setup,
                &state,
                &info_bad,
                &payload_for_p2wpkh(&remote_pubkey),
            ),
            "more than one to_countersigner anchors"
        );
    }

    #[test]
    fn validate_to_broadcaster_output_without_anchor_test() {
        let mut setup = make_reasonable_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let validator = make_test_validator(setup.channel_value_sat);
        let state = make_validator_state();
        let remote_pubkey = make_test_pubkey(101);
        let mut info_bad = make_counterparty_info1_with_anchors(
            2_000_000,
            1_000_000 - (2 * ANCHOR_SAT),
            6,
            vec![],
            vec![],
        );
        info_bad.to_broadcaster_anchor_count = 0;
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &setup,
                &state,
                &info_bad,
                &payload_for_p2wpkh(&remote_pubkey),
            ),
            "to_broadcaster output without to_broadcaster anchor"
        );
    }

    #[test]
    fn validate_to_countersigner_output_without_anchor_test() {
        let mut setup = make_reasonable_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let validator = make_test_validator(setup.channel_value_sat);
        let state = make_validator_state();
        let remote_pubkey = make_test_pubkey(101);
        let mut info_bad = make_counterparty_info1_with_anchors(
            2_000_000,
            1_000_000 - (2 * ANCHOR_SAT),
            6,
            vec![],
            vec![],
        );
        info_bad.to_countersigner_anchor_count = 0;
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &setup,
                &state,
                &info_bad,
                &payload_for_p2wpkh(&remote_pubkey),
            ),
            "to_countersigner output without to_countersigner anchor"
        );
    }

    #[test]
    fn validate_to_broadcaster_anchor_without_output_test() {
        let mut setup = make_reasonable_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let validator = make_test_validator(setup.channel_value_sat);
        let state = make_validator_state();
        let remote_pubkey = make_test_pubkey(101);
        let mut info_bad = make_counterparty_info1_with_anchors(
            0,
            3_000_000 - (2 * ANCHOR_SAT),
            6,
            vec![],
            vec![],
        );
        info_bad.to_broadcaster_delayed_pubkey = None;
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &setup,
                &state,
                &info_bad,
                &payload_for_p2wpkh(&remote_pubkey),
            ),
            "to_broadcaster anchor without to_broadcaster output or HTLCs"
        );
    }

    #[test]
    fn validate_to_broadcaster_anchor_without_output_test_with_htlc() {
        let mut setup = make_reasonable_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let validator = make_test_validator(setup.channel_value_sat);
        let state = make_validator_state();
        let remote_pubkey = make_test_pubkey(101);
        let htlcs = vec![make_htlc_info(1100)];
        let mut info = make_counterparty_info1_with_anchors(
            0,
            3_000_000 - (2 * ANCHOR_SAT) - 10,
            6,
            htlcs,
            vec![],
        );
        info.to_broadcaster_delayed_pubkey = None;
        assert!(validator
            .validate_remote_tx_phase1(&setup, &state, &info, &payload_for_p2wpkh(&remote_pubkey),)
            .is_ok());
    }

    #[test]
    fn validate_to_countersigner_anchor_without_output_test() {
        let mut setup = make_reasonable_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let validator = make_test_validator(setup.channel_value_sat);
        let state = make_validator_state();
        let remote_pubkey = make_test_pubkey(101);
        let mut info_bad = make_counterparty_info1_with_anchors(
            0,
            3_000_000 - (2 * ANCHOR_SAT),
            6,
            vec![],
            vec![],
        );
        info_bad.to_countersigner_pubkey = None;
        assert_policy_error!(
            validator.validate_remote_tx_phase1(
                &setup,
                &state,
                &info_bad,
                &payload_for_p2wpkh(&remote_pubkey),
            ),
            "to_countersigner anchor without to_countersigner output or HTLCs"
        );
    }

    #[test]
    fn validate_to_countersigner_anchor_without_output_test_with_htlc() {
        let mut setup = make_reasonable_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let validator = make_test_validator(setup.channel_value_sat);
        let state = make_validator_state();
        let remote_pubkey = make_test_pubkey(101);
        let htlcs = vec![make_htlc_info(1100)];
        let mut info = make_counterparty_info1_with_anchors(
            0,
            3_000_000 - (2 * ANCHOR_SAT) - 10,
            6,
            vec![],
            htlcs,
        );
        info.to_countersigner_pubkey = None;
        assert!(validator
            .validate_remote_tx_phase1(&setup, &state, &info, &payload_for_p2wpkh(&remote_pubkey),)
            .is_ok());
    }

    #[test]
    fn validate_remote_tx_htlc_shortage_test() {
        let validator = make_validator();
        let htlc = HTLCInfo2 {
            value_sat: 100_000,
            payment_hash: PaymentHash([0; 32]),
            cltv_expiry: 1005,
        };
        let state = make_validator_state();
        let info = make_counterparty_info(99_000_000, 800_000, 6, vec![htlc.clone()], vec![]);
        assert!(validator
            .validate_remote_tx(&make_test_channel_setup(), &state, &info)
            .is_ok());
        let info_bad =
            make_counterparty_info(99_000_000, 800_000 - 1, 6, vec![htlc.clone()], vec![]);
        assert_policy_error!(
            validator.validate_remote_tx(&make_test_channel_setup(), &state, &info_bad),
            "channel value short by 100001 > 100000"
        );
    }

    #[test]
    fn validate_remote_tx_htlc_count_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let htlcs = (0..1001).map(|_| make_htlc_info2(1100)).collect();
        let info_bad = make_counterparty_info(99_000_000, 900_000, 6, vec![], htlcs);
        assert_policy_error!(
            validator.validate_remote_tx(&make_test_channel_setup(), &state, &info_bad),
            "too many HTLCs"
        );
    }

    #[test]
    fn validate_remote_tx_htlc_value_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let htlcs = (0..1000)
            .map(|_| HTLCInfo2 {
                value_sat: 10001,
                payment_hash: PaymentHash([0; 32]),
                cltv_expiry: 1100,
            })
            .collect();
        let info_bad = make_counterparty_info(99_000_000, 900_000, 6, vec![], htlcs);
        assert_policy_error!(
            validator.validate_remote_tx(&make_test_channel_setup(), &state, &info_bad),
            "sum of HTLC values 10001000 too large"
        );
    }

    #[test]
    fn validate_remote_tx_htlc_delay_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let info_good =
            make_counterparty_info(99_000_000, 990_000, 6, vec![], vec![make_htlc_info2(1005)]);
        assert!(validator
            .validate_remote_tx(&make_test_channel_setup(), &state, &info_good)
            .is_ok());
        let info_good =
            make_counterparty_info(99_000_000, 990_000, 6, vec![], vec![make_htlc_info2(2440)]);
        assert!(validator
            .validate_remote_tx(&make_test_channel_setup(), &state, &info_good)
            .is_ok());
        let info_bad =
            make_counterparty_info(99_000_000, 990_000, 6, vec![], vec![make_htlc_info2(1004)]);
        assert_policy_error!(
            validator.validate_remote_tx(&make_test_channel_setup(), &state, &info_bad),
            "received HTLC expiry too early"
        );
        let info_bad =
            make_counterparty_info(99_000_000, 990_000, 6, vec![], vec![make_htlc_info2(2441)]);
        assert_policy_error!(
            validator.validate_remote_tx(&make_test_channel_setup(), &state, &info_bad),
            "received HTLC expiry too late"
        );
    }
}
