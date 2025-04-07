use lightning::util::config::{
    ChannelConfig, ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig,
};
use lightning_signer::lightning;
use lightning_signer::lightning::util::config::MaxDustHTLCExposure;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Config {
    pub regtest: Option<bool>,
    pub signet: Option<bool>,
    pub ln_port: Option<u16>,
    pub rpc_port: Option<u16>,
    pub vls_port: Option<u16>,
    pub bitcoin_rpc: Option<String>,
    pub data_dir: Option<String>,
    pub log_level_console: Option<String>,
    pub log_level_disk: Option<String>,
    pub signer: Option<String>,
    pub tor: Option<bool>,
    pub name: Option<String>,

    pub channel: Option<ConfigChannel>,
}

impl Config {
    pub fn bitcoin_channel(&self) -> ConfigCoinChannel {
        self.channel.unwrap_or(Default::default()).bitcoin.unwrap_or(Default::default())
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Copy, Clone)]
pub struct ConfigChannel {
    pub bitcoin: Option<ConfigCoinChannel>,
}

#[derive(Serialize, Deserialize, Debug, Default, Copy, Clone)]
pub struct ConfigCoinChannel {
    propose: Option<ConfigProposeCoinChannel>,
    limit: Option<ConfigLimitCoinChannel>,
    default: Option<DefaultCoinChannelConfig>,
}

impl Into<UserConfig> for ConfigCoinChannel {
    fn into(self) -> UserConfig {
        UserConfig {
            channel_handshake_config: self.propose.unwrap_or(Default::default()).into(),
            channel_handshake_limits: self.limit.unwrap_or(Default::default()).into(),
            channel_config: self.default.unwrap_or(Default::default()).into(),
            accept_forwards_to_priv_channels: true,
            accept_inbound_channels: true,
            manually_accept_inbound_channels: false,
            accept_intercept_htlcs: false,
            manually_handle_bolt12_invoices: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Copy, Clone)]
pub struct ConfigProposeCoinChannel {
    pub minimum_depth: Option<u32>,
    pub our_to_self_delay: Option<u16>,
    pub our_htlc_minimum_msat: Option<u64>,
    pub announced_channel: Option<bool>,
    pub commit_upfront_shutdown_pubkey: Option<bool>,
}

impl Into<ChannelHandshakeConfig> for ConfigProposeCoinChannel {
    fn into(self) -> ChannelHandshakeConfig {
        ChannelHandshakeConfig {
            minimum_depth: self.minimum_depth.unwrap_or(6),
            our_to_self_delay: self.our_to_self_delay.unwrap_or(144),
            our_htlc_minimum_msat: self.our_htlc_minimum_msat.unwrap_or(1),
            max_inbound_htlc_value_in_flight_percent_of_channel: 100,
            negotiate_scid_privacy: false,
            announce_for_forwarding: self.announced_channel.unwrap_or(false),
            commit_upfront_shutdown_pubkey: self.commit_upfront_shutdown_pubkey.unwrap_or(true),
            their_channel_reserve_proportional_millionths: 0,
            negotiate_anchors_zero_fee_htlc_tx: true,
            our_max_accepted_htlcs: 100,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Copy, Clone)]
pub struct ConfigLimitCoinChannel {
    pub min_funding_sat: Option<u64>,
    pub max_htlc_minimum_msat: Option<u64>,
    pub min_max_htlc_value_in_flight_msat: Option<u64>,
    pub max_channel_reserve_sat: Option<u64>,
    pub min_max_accepted_htlcs: Option<u16>,
    pub min_dust_limit_satoshis: Option<u64>,
    pub max_dust_limit_satoshis: Option<u64>,
    pub max_minimum_depth: Option<u32>,
    pub force_announced_channel_preference: Option<bool>,
    pub their_to_self_delay: Option<u16>,
}

impl Into<ChannelHandshakeLimits> for ConfigLimitCoinChannel {
    fn into(self) -> ChannelHandshakeLimits {
        ChannelHandshakeLimits {
            min_funding_satoshis: self.min_funding_sat.unwrap_or(0),
            max_funding_satoshis: (1 << 24) - 1,
            max_htlc_minimum_msat: self.max_htlc_minimum_msat.unwrap_or(u64::max_value()),
            min_max_htlc_value_in_flight_msat: self.min_max_htlc_value_in_flight_msat.unwrap_or(0),
            max_channel_reserve_satoshis: self.max_channel_reserve_sat.unwrap_or(u64::max_value()),
            min_max_accepted_htlcs: self.min_max_accepted_htlcs.unwrap_or(0),
            max_minimum_depth: self.max_minimum_depth.unwrap_or(144),
            trust_own_funding_0conf: false,
            force_announced_channel_preference: self
                .force_announced_channel_preference
                .unwrap_or(false),
            their_to_self_delay: self.their_to_self_delay.unwrap_or(2016),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Copy, Clone)]
pub struct DefaultCoinChannelConfig {
    fee_proportional_millionths: Option<u32>,
    cltv_expiry_delta: Option<u16>,
}

impl Into<ChannelConfig> for DefaultCoinChannelConfig {
    fn into(self) -> ChannelConfig {
        ChannelConfig {
            forwarding_fee_proportional_millionths: self.fee_proportional_millionths.unwrap_or(0),
            forwarding_fee_base_msat: 0,
            cltv_expiry_delta: self.cltv_expiry_delta.unwrap_or(10),
            max_dust_htlc_exposure: MaxDustHTLCExposure::FixedLimitMsat(1000000), // FIXME
            force_close_avoidance_max_fee_satoshis: 1000000,                      // FIXME
            accept_underpaying_htlcs: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;
    use std::fs::read_to_string;

    #[test]
    fn test_url() {
        let url = Url::parse("http://user:pass@localhost:1234");
        println!("{:?}", url)
    }

    fn strip_comments(config_str: String) -> String {
        config_str.split("\n").filter(|l| !l.starts_with("#")).collect::<Vec<&str>>().join("\n")
    }

    fn strip_blank_lines(config_str: String) -> String {
        config_str.split("\n").filter(|l| *l != "").collect::<Vec<&str>>().join("\n")
    }

    #[test]
    fn load_sample_config() {
        let config_str = read_to_string("doc/sample-config.toml").unwrap();

        let config: Config = toml::from_str(config_str.as_str()).unwrap();
        let config_re_str = toml::to_string(&config).unwrap();
        let config_str_no_comments = strip_comments(config_str);
        assert_eq!(strip_blank_lines(config_str_no_comments), strip_blank_lines(config_re_str));

        let _user_config: UserConfig = config.bitcoin_channel().into();
    }

    #[test]
    fn load_empty_config() {
        let config: Config = toml::from_str("").unwrap();
        let config_re_str = toml::to_string(&config).unwrap();
        assert_eq!("", config_re_str)
    }
}
