use std::sync::Arc;

use lightning_signer::util::velocity::VelocityControlSpec;
use lightning_signer::policy::DEFAULT_FEE_VELOCITY_CONTROL;
use lightning_signer::policy::validator::ValidatorFactory;
use lightning_signer::policy::simple_validator::{make_simple_policy, SimpleValidatorFactory};
use lightning_signer::policy::onchain_validator::OnchainValidatorFactory;
use lightning_signer::policy::filter::PolicyFilter;
use lightning_signer::bitcoin::Network;
use tracing::{info, warn};

use crate::util::compare_env_var;

/// Make a standard validation factory, allowing VLS_PERMISSIVE env var to override
pub fn make_validator_factory(network: Network) -> Arc<dyn ValidatorFactory> {
    make_validator_factory_with_filter(network, None)
}

/// Make a standard validation factory, with an optional filter specification,
/// allowing VLS_PERMISSIVE env var to override
pub fn make_validator_factory_with_filter(
    network: Network,
    filter_opt: Option<PolicyFilter>,
) -> Arc<dyn ValidatorFactory> {
    make_validator_factory_with_filter_and_velocity(
        network,
        filter_opt,
        VelocityControlSpec::UNLIMITED,
        DEFAULT_FEE_VELOCITY_CONTROL,
    )
}

/// Make a standard validation factory, with an optional filter specification,
/// allowing VLS_PERMISSIVE env var to override, and a global velocity control
pub fn make_validator_factory_with_filter_and_velocity(
    network: Network,
    filter_opt: Option<PolicyFilter>,
    velocity_spec: VelocityControlSpec,
    fee_velocity_control_spec: VelocityControlSpec,
) -> Arc<dyn ValidatorFactory> {
    let mut policy = make_simple_policy(network);
    policy.global_velocity_control = velocity_spec;
    policy.fee_velocity_control = fee_velocity_control_spec;

    if compare_env_var("VLS_PERMISSIVE", "1") {
        warn!("VLS_PERMISSIVE: ALL POLICY ERRORS ARE REPORTED AS WARNINGS");
        policy.filter = PolicyFilter::new_permissive();
    } else {
        if let Some(f) = filter_opt {
            policy.filter.merge(f);
        }
        info!("!VLS_PERMISSIVE: ALL POLICY ERRORS ARE ENFORCED");
    }
    // log out policy at startup
    info!("current policies: {:?}", policy);

    let simple_factory = SimpleValidatorFactory::new_with_policy(policy);

    if compare_env_var("VLS_ONCHAIN_VALIDATION_DISABLE", "1") {
        warn!("VLS_ONCHAIN_VALIDATION_DISABLE: onchain validation disabled");
        return Arc::new(simple_factory);
    }

    info!("VLS_ONCHAIN_VALIDATION: onchain validation enabled");
    Arc::new(OnchainValidatorFactory::new_with_simple_factory(simple_factory))
}
