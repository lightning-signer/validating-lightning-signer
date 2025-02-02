use lssd::database::etcd;
use std::sync::Arc;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
#[path = "./common.rs"]
mod common;

#[tokio::main]
async fn main() {
    let etcd_container = GenericImage::new("bitnami/etcd", "latest")
        .with_exposed_port(2379.tcp())
        .with_exposed_port(2380.tcp())
        .with_wait_for(WaitFor::seconds(10))
        .with_env_var("ETCD_NAME", "etcd-server")
        .with_env_var("ETCD_INITIAL_ADVERTISE_PEER_URLS", "http://etcd-server:2380")
        .with_env_var("ETCD_LISTEN_PEER_URLS", "http://0.0.0.0:2380")
        .with_env_var("ETCD_ADVERTISE_CLIENT_URLS", "http://localhost:2383")
        .with_env_var("ETCD_LISTEN_CLIENT_URLS", "http://0.0.0.0:2379")
        .with_env_var("ETCD_INITIAL_CLUSTER", "etcd-server=http://etcd-server:2380")
        .with_env_var("ETCD_INITIAL_CLUSTER_STATE", "new")
        .with_env_var("ETCD_ROOT_PASSWORD", "mysecretpassword")
        .with_container_name("etcd-server")
        .start()
        .await
        .expect("container didn't start");

    let host = std::env::var("DB_HOST").unwrap_or("127.0.0.1".to_string());
    let db = etcd::EtcdDatabase::new(
        vec![format!("http://{}:{}", host, etcd_container.get_host_port_ipv4(2379).await.unwrap())],
        Some(("root", "mysecretpassword")),
    )
    .await
    .unwrap();
    common::bench_test_db(Arc::new(db)).await;
}
