use std::env;

pub fn bitcoind_rpc_url() -> String {
    env::var("BITCOIND_RPC_URL").expect("env var BITCOIND_RPC_URL")
}

pub fn vls_network() -> String {
    env::var("VLS_NETWORK").expect("env var VLS_NETWORK")
}

pub fn vls_cln_version() -> String {
    env::var("VLS_CLN_VERSION").expect("set VLS_CLN_VERSION to match c-lightning")
}

pub fn txoo_source_url() -> Option<String> {
    env::var("TXOO_SOURCE_URL").ok()
}

pub fn compare_env_var(key: &str, value: &str) -> bool {
    match env::var(key) {
        Ok(val) => val == value,
        Err(_) => false,
    }
}
