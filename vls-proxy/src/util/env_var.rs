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

pub fn deployment_environment() -> String {
    env::var("DEPLOYMENT_ENV").unwrap_or("DEVELOPMENT".to_string())
}

pub fn otlp_endpoint() -> String {
    env::var("OLTP_ENDPOINT").unwrap_or("http://localhost:4317".to_string())
}

pub fn otlp_timeout() -> u64 {
    env::var("OLTP_TIMEOUT")
        .unwrap_or("3".to_string())
        .parse()
        .expect("OLTP Exporter timeout value needs to be a positive number")
}

pub fn compare_env_var(key: &str, value: &str) -> bool {
    match env::var(key) {
        Ok(val) => val == value,
        Err(_) => false,
    }
}
