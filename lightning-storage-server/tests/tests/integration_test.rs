use lightning_storage_server::Value;
#[cfg(feature = "etcd")]
use lssd::database::etcd;
#[cfg(feature = "postgres")]
use lssd::database::postgres;
use lssd::database::redb::RedbDatabase;
use lssd::{Database, Error};
use std::sync::Arc;
use tempfile;
#[cfg(any(feature = "postgres", feature = "etcd"))]
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt as _,
};

fn make_value(v: u8) -> Value {
    Value { version: 0, value: vec![v] }
}

#[tokio::test]
async fn test_redb_database() {
    let dir = tempfile::tempdir().unwrap();
    let db = RedbDatabase::new(dir.path().to_str().unwrap()).await.unwrap();
    do_basic_with_db(Arc::new(db)).await;
}

const DB_HOST: &'static str = "127.0.0.1";
const PG_PORT: u16 = 5432;
const PG_USER: &'static str = "dev";
const PG_PASSWORD: &'static str = "mysecretpassword";
const PG_DB: &'static str = "dev";

fn load_env_vars(port: u16) {
    std::env::set_var("PG_HOST", std::env::var("DB_HOST").unwrap_or(DB_HOST.to_string()));
    std::env::set_var("PG_PORT", port.to_string());
    std::env::set_var("PG_USER", PG_USER);
    std::env::set_var("PG_PASS", PG_PASSWORD);
    std::env::set_var("PG_DB", PG_DB);
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn test_postgres_database() {
    let postgres_container = GenericImage::new("postgres", "latest")
        .with_exposed_port(PG_PORT.tcp())
        .with_wait_for(WaitFor::seconds(10))
        .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
        .with_env_var("POSTGRES_USER", PG_USER)
        .start()
        .await
        .unwrap();

    load_env_vars(postgres_container.get_host_port_ipv4(PG_PORT).await.expect("expose db port"));
    let db = postgres::new_and_clear().await.unwrap();
    do_basic_with_db(Arc::new(db)).await;
}

#[cfg(feature = "etcd")]
#[tokio::test]
async fn test_etcd_database() {
    let etcd_container = GenericImage::new("bitnamilegacy/etcd", "3.6.4")
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

    let host = std::env::var("DB_HOST").unwrap_or(DB_HOST.to_string());
    let db = etcd::EtcdDatabase::new(
        vec![format!("http://{}:{}", host, etcd_container.get_host_port_ipv4(2379).await.unwrap())],
        Some(("root", "mysecretpassword")),
    )
    .await
    .unwrap();

    db.clear().await.unwrap();
    do_basic_with_db(Arc::new(db)).await;
}

async fn do_basic_with_db(db: Arc<dyn Database>) {
    let client_id = vec![1];
    db.put(
        &client_id,
        &vec![
            ("x1a".to_string(), make_value(10)),
            ("x1b".to_string(), make_value(11)),
            ("x2b".to_string(), make_value(20)),
        ],
    )
    .await
    .unwrap();
    let values = db.get_with_prefix(&client_id, "x1".to_string()).await.unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].1.value, vec![10]);
    assert_eq!(values[0].1.version, 0);
    assert_eq!(values[1].1.value, vec![11]);
    assert_eq!(values[1].1.version, 0);
    let result = db
        .put(
            &client_id,
            &vec![
                ("x1b".to_string(), make_value(55)), // conflict with existing
                ("x1z".to_string(), Value { version: 22, value: vec![22] }), // non existent
            ],
        )
        .await
        .expect_err("expected conflict");
    match result {
        Error::Conflict(c) => {
            assert_eq!(c.len(), 2);
            assert_eq!(c[0].0, "x1b".to_string());
            let v0 = c[0].1.as_ref().unwrap();
            assert_eq!(v0.value, vec![11]);
            assert_eq!(v0.version, 0);
            assert_eq!(c[1].0, "x1z".to_string());
            assert!(c[1].1.is_none());
        }
        _ => panic!("expected conflict"),
    }
}
