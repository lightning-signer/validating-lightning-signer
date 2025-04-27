use std::env;

pub fn deployment_environment() -> String {
    env::var("DEPLOYMENT_ENV").unwrap_or("DEVELOPMENT".to_string())
}

pub fn otlp_endpoint() -> Option<String> {
    env::var("OLTP_ENDPOINT").ok()
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
