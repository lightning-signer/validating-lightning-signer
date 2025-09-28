use std::env;

pub fn deployment_environment() -> String {
    env::var("DEPLOYMENT_ENV").unwrap_or("DEVELOPMENT".to_string())
}

pub fn otlp_endpoint() -> Option<String> {
    env::var("OTLP_ENDPOINT").ok()
}

pub fn otlp_timeout() -> u64 {
    env::var("OTLP_TIMEOUT")
        .unwrap_or("3".to_string())
        .parse()
        .expect("OTLP exporter timeout value needs to be a positive number")
}

pub fn compare_env_var(key: &str, value: &str) -> bool {
    match env::var(key) {
        Ok(val) => val == value,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_otlp_env_vars() {
        let orig_endpoint = env::var("OTLP_ENDPOINT").ok();
        let orig_timeout = env::var("OTLP_TIMEOUT").ok();

        env::remove_var("OTLP_ENDPOINT");
        env::remove_var("OTLP_TIMEOUT");
        assert_eq!(otlp_endpoint(), None);
        assert_eq!(otlp_timeout(), 3);

        env::set_var("OTLP_ENDPOINT", "http://localhost:4317");
        env::set_var("OTLP_TIMEOUT", "5");
        assert_eq!(otlp_endpoint(), Some("http://localhost:4317".to_string()));
        assert_eq!(otlp_timeout(), 5);

        match orig_endpoint {
            Some(v) => env::set_var("OTLP_ENDPOINT", v),
            None => env::remove_var("OTLP_ENDPOINT"),
        }
        match orig_timeout {
            Some(v) => env::set_var("OTLP_TIMEOUT", v),
            None => env::remove_var("OTLP_TIMEOUT"),
        }
    }
}
