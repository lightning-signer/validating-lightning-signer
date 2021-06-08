use bitcoin::{self, Network};

use crate::node::{Channel, ChannelSetup};
use crate::tx::tx::{CommitmentInfo, CommitmentInfo2};
use crate::util::enforcing_trait_impls::EnforcingSigner;

use super::error::ValidationError::{self, Policy};

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

    /// Phase 2 remote tx validation
    fn validate_commitment_tx(
        &self,
        setup: &ChannelSetup,
        state: &ValidatorState,
        info2: &CommitmentInfo2,
        is_counterparty: bool,
    ) -> Result<(), ValidationError>;

    /// Validate channel open
    fn validate_channel_open(&self, setup: &ChannelSetup) -> Result<(), ValidationError>;
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
// TODO - policy-v2-commitment-initial-funding-value
// TODO - policy-v2-commitment-spends-active-utxo
// TODO - policy-v2-commitment-fee-range
// TODO - policy-v2-commitment-htlc-routing-balance
// TODO - policy-v2-commitment-htlc-received-spends-active-utxo
// TODO - policy-v1-commitment-htlc-delay-range
// TODO - policy-v2-commitment-htlc-count-limit
// TODO - policy-v1-commitment-payment-pubkey
// TODO - policy-v2-commitment-htlc-offered-hash-matches
// TODO - policy-v2-commitment-htlc-inflight-limit
// TODO - policy-v1-commitment-outputs-trimmed
// TODO - policy-v2-commitment-previous-revoked
// TODO - policy-v2-commitment-local-not-revoked
// TODO - policy-v1-commitment-anchor-static-remotekey
// TODO - policy-v1-commitment-anchor-to-local
// TODO - policy-v1-commitment-anchor-to-remote
// TODO - policy-v1-commitment-anchors-not-when-off

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
// TODO - policy-v2-htlc-delay-range

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

    fn validate_commitment_tx(
        &self,
        setup: &ChannelSetup,
        state: &ValidatorState,
        info: &CommitmentInfo2,
        is_counterparty: bool,
    ) -> Result<(), ValidationError> {
        let policy = &self.policy;

        // policy-v1-commitment-to-self-delay-range
        if is_counterparty {
            if info.to_self_delay != setup.counterparty_to_self_delay {
                return Err(Policy("counterparty to_self delay mismatch".to_string()));
            }
        } else {
            if info.to_self_delay != setup.holder_to_self_delay {
                return Err(Policy("holder to_self delay mismatch".to_string()));
            }
        }

        // policy-v2-commitment-htlc-count-limit
        if info.offered_htlcs.len() + info.received_htlcs.len() > policy.max_htlcs {
            return Err(Policy("too many HTLCs".to_string()));
        }

        let mut htlc_value_sat: u64 = 0;

        for htlc in &info.offered_htlcs {
            self.validate_expiry("offered HTLC", htlc.cltv_expiry, state.current_height)?;
            htlc_value_sat = htlc_value_sat
                .checked_add(htlc.value_sat)
                .ok_or_else(|| Policy("offered HTLC value overflow".to_string()))?;
        }

        for htlc in &info.received_htlcs {
            self.validate_expiry("received HTLC", htlc.cltv_expiry, state.current_height)?;
            htlc_value_sat = htlc_value_sat
                .checked_add(htlc.value_sat)
                .ok_or_else(|| Policy("received HTLC value overflow".to_string()))?;
        }

        // policy-v2-commitment-htlc-inflight-limit
        if htlc_value_sat > policy.max_htlc_value_sat {
            return Err(Policy(format!(
                "sum of HTLC values {} too large",
                htlc_value_sat
            )));
        }

        // policy-v2-commitment-fee-range
        let consumed = info
            .to_broadcaster_value_sat
            .checked_add(info.to_countersigner_value_sat)
            .ok_or_else(|| Policy("channel value overflow".to_string()))?
            .checked_add(htlc_value_sat)
            .ok_or_else(|| Policy("channel value overflow on HTLC".to_string()))?;
        let shortage = self
            .channel_value_sat
            .checked_sub(consumed)
            .ok_or_else(|| Policy("channel shortage underflow".to_string()))?;
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
    fn validate_channel_open(&self, setup: &ChannelSetup) -> Result<(), ValidationError> {
        if self.channel_value_sat > self.policy.max_channel_size_sat {
            return Err(Policy(format!(
                "channel value {} too large",
                self.channel_value_sat
            )));
        }
        // policy-v1-commitment-to-self-delay-range
        self.validate_delay(
            "counterparty_to_self_delay",
            setup.counterparty_to_self_delay as u32,
        )?;
        // policy-v1-commitment-to-self-delay-range
        self.validate_delay("holder_to_self_delay", setup.holder_to_self_delay as u32)?;
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

    use crate::tx::tx::HTLCInfo2;
    use crate::util::test_utils::{
        make_test_channel_keys, make_test_channel_setup, make_test_commitment_tx, make_test_pubkey,
    };

    use super::*;

    macro_rules! assert_policy_error {
        ($res: expr, $expected: expr) => {
            assert_eq!($res.unwrap_err(), Policy($expected.to_string()));
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
        let setup = make_test_channel_setup();
        let validator = make_test_validator(100_000_000);
        assert!(validator.validate_channel_open(&setup).is_ok());
        let validator_large = make_test_validator(100_000_001);
        assert!(validator_large.validate_channel_open(&setup).is_err());
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

    fn make_validator() -> SimpleValidator {
        make_test_validator(100_000_000)
    }

    fn make_validator_state() -> ValidatorState {
        ValidatorState {
            current_height: 1000,
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
    fn validate_commitment_tx_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let info = make_counterparty_info(99_000_000, 900_000, 6, vec![], vec![]);
        assert!(validator
            .validate_commitment_tx(&make_test_channel_setup(), &state, &info, true)
            .is_ok());
    }

    #[test]
    // policy-v1-commitment-to-self-delay-range
    fn validate_to_holder_min_delay_test() {
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator(1_000_000);
        setup.holder_to_self_delay = 5;
        assert!(validator.validate_channel_open(&setup).is_ok());
        setup.holder_to_self_delay = 4;
        assert_policy_error!(
            validator.validate_channel_open(&setup),
            "holder_to_self_delay delay too small"
        );
    }

    #[test]
    // policy-v1-commitment-to-self-delay-range
    fn validate_to_holder_max_delay_test() {
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator(1_000_000);
        setup.holder_to_self_delay = 1440;
        assert!(validator.validate_channel_open(&setup).is_ok());
        setup.holder_to_self_delay = 1441;
        assert_policy_error!(
            validator.validate_channel_open(&setup),
            "holder_to_self_delay delay too large"
        );
    }

    #[test]
    // policy-v1-commitment-to-self-delay-range
    fn validate_to_counterparty_min_delay_test() {
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator(1_000_000);
        setup.counterparty_to_self_delay = 5;
        assert!(validator.validate_channel_open(&setup).is_ok());
        setup.counterparty_to_self_delay = 4;
        assert_policy_error!(
            validator.validate_channel_open(&setup),
            "counterparty_to_self_delay delay too small"
        );
    }

    #[test]
    // policy-v1-commitment-to-self-delay-range
    fn validate_to_counterparty_max_delay_test() {
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator(1_000_000);
        setup.counterparty_to_self_delay = 1440;
        assert!(validator.validate_channel_open(&setup).is_ok());
        setup.counterparty_to_self_delay = 1441;
        assert_policy_error!(
            validator.validate_channel_open(&setup),
            "counterparty_to_self_delay delay too large"
        );
    }

    #[test]
    fn validate_commitment_tx_shortage_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let info_bad = make_counterparty_info(99_000_000, 900_000 - 1, 6, vec![], vec![]);
        assert_policy_error!(
            validator.validate_commitment_tx(&make_test_channel_setup(), &state, &info_bad, true),
            "channel value short by 100001 > 100000"
        );
    }

    #[test]
    fn validate_commitment_tx_htlc_shortage_test() {
        let validator = make_validator();
        let htlc = HTLCInfo2 {
            value_sat: 100_000,
            payment_hash: PaymentHash([0; 32]),
            cltv_expiry: 1005,
        };
        let state = make_validator_state();
        let info = make_counterparty_info(99_000_000, 800_000, 6, vec![htlc.clone()], vec![]);
        assert!(validator
            .validate_commitment_tx(&make_test_channel_setup(), &state, &info, true)
            .is_ok());
        let info_bad =
            make_counterparty_info(99_000_000, 800_000 - 1, 6, vec![htlc.clone()], vec![]);
        assert_policy_error!(
            validator.validate_commitment_tx(&make_test_channel_setup(), &state, &info_bad, true),
            "channel value short by 100001 > 100000"
        );
    }

    #[test]
    fn validate_commitment_tx_htlc_count_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let htlcs = (0..1001).map(|_| make_htlc_info2(1100)).collect();
        let info_bad = make_counterparty_info(99_000_000, 900_000, 6, vec![], htlcs);
        assert_policy_error!(
            validator.validate_commitment_tx(&make_test_channel_setup(), &state, &info_bad, true),
            "too many HTLCs"
        );
    }

    #[test]
    fn validate_commitment_tx_htlc_value_test() {
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
            validator.validate_commitment_tx(&make_test_channel_setup(), &state, &info_bad, true),
            "sum of HTLC values 10001000 too large"
        );
    }

    #[test]
    fn validate_commitment_tx_htlc_delay_test() {
        let validator = make_validator();
        let state = make_validator_state();
        let info_good =
            make_counterparty_info(99_000_000, 990_000, 6, vec![], vec![make_htlc_info2(1005)]);
        assert!(validator
            .validate_commitment_tx(&make_test_channel_setup(), &state, &info_good, true)
            .is_ok());
        let info_good =
            make_counterparty_info(99_000_000, 990_000, 6, vec![], vec![make_htlc_info2(2440)]);
        assert!(validator
            .validate_commitment_tx(&make_test_channel_setup(), &state, &info_good, true)
            .is_ok());
        let info_bad =
            make_counterparty_info(99_000_000, 990_000, 6, vec![], vec![make_htlc_info2(1004)]);
        assert_policy_error!(
            validator.validate_commitment_tx(&make_test_channel_setup(), &state, &info_bad, true),
            "received HTLC expiry too early"
        );
        let info_bad =
            make_counterparty_info(99_000_000, 990_000, 6, vec![], vec![make_htlc_info2(2441)]);
        assert_policy_error!(
            validator.validate_commitment_tx(&make_test_channel_setup(), &state, &info_bad, true),
            "received HTLC expiry too late"
        );
    }
}
