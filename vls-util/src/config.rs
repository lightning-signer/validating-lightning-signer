/// Network names
pub const NETWORK_NAMES: [&'static str; 4] = ["testnet", "regtest", "signet", "bitcoin"];

/// Useful with clap's `Arg::default_value_ifs`
pub const CLAP_NETWORK_URL_MAPPING: [(&'static str, &'static str, Option<&'static str>); 4] = [
    ("network", "bitcoin", Some("http://user:pass@127.0.0.1:8332")),
    ("network", "testnet", Some("http://user:pass@127.0.0.1:18332")),
    ("network", "regtest", Some("http://user:pass@127.0.0.1:18443")),
    ("network", "signet", Some("http://user:pass@127.0.0.1:18443")),
];

pub const DEFAULT_DIR: &str = ".lightning-signer";
