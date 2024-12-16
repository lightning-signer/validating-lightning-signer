use lightning_storage_server::Value;
#[cfg(feature = "test-postgres")]
use lssd::database::postgres;
use lssd::database::redb::RedbDatabase;
use lssd::{Database, Error};
use std::sync::Arc;
use tempfile;

fn make_value(v: u8) -> Value {
    Value { version: 0, value: vec![v] }
}

#[tokio::test]
async fn test_redb_database() {
    let dir = tempfile::tempdir().unwrap();
    println!("tempdir: {}", dir.path().display());
    let db = RedbDatabase::new(dir.path().to_str().unwrap()).await.unwrap();
    do_basic_with_db(Arc::new(db)).await;
    dir.close().unwrap();
}

#[cfg(feature = "test-postgres")]
#[tokio::test]
async fn test_postgres_database() {
    let db = postgres::new_and_clear().await.unwrap();
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
    assert_eq!(values[1].1.value, vec![11]);
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
