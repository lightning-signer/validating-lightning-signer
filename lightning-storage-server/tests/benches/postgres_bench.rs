use lssd::database::postgres;
use std::sync::Arc;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
#[path = "./common.rs"]
mod common;

const PG_HOST: &'static str = "127.0.0.1";
const PG_PORT: u16 = 5432;
const PG_USER: &'static str = "dev";
const PG_PASSWORD: &'static str = "mysecretpassword";
const PG_DB: &'static str = "dev";

fn load_env_vars(port: u16) {
    std::env::set_var("PG_HOST", PG_HOST);
    std::env::set_var("PG_PORT", port.to_string());
    std::env::set_var("PG_USER", PG_USER);
    std::env::set_var("PG_PASS", PG_PASSWORD);
    std::env::set_var("PG_DB", PG_DB);
}

#[tokio::main]
async fn main() {
    let postgres_container = GenericImage::new("postgres", "latest")
        .with_exposed_port(PG_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr("database system is ready to accept connections"))
        .with_wait_for(WaitFor::message_on_stdout("database system is ready to accept connections"))
        .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
        .with_env_var("POSTGRES_USER", PG_USER)
        .start()
        .await
        .unwrap();

    load_env_vars(postgres_container.get_host_port_ipv4(PG_PORT).await.expect("expose db port"));
    let db = Arc::new(postgres::new_and_clear().await.unwrap());
    common::bench_test_db(db).await;
}
