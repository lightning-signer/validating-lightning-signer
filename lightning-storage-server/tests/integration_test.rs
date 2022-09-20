#[cfg(feature = "test_postgres")]
use lightning_storage_server::database::postgres;
use lightning_storage_server::database::sled::SledDatabase;
use lightning_storage_server::{Database, Error, Value};
use std::sync::Arc;
use tempfile;

#[test]
fn test_sled() {
    let dir = tempfile::tempdir().unwrap();
    let db = sled::open(&dir).unwrap();
    db.insert(b"yo!", b"v1").unwrap();
    assert_eq!(&db.get(b"yo!").unwrap().unwrap(), b"v1");
    dir.close().unwrap();
}

fn make_value(v: u8) -> Value {
    Value { version: 0, value: vec![v] }
}

#[tokio::test]
async fn test_sled_database() {
    let dir = tempfile::tempdir().unwrap();
    println!("tempdir: {}", dir.path().display());
    let db = SledDatabase::new(dir.path().to_str().unwrap()).await.unwrap();
    do_basic_with_db(Arc::new(db)).await;
    dir.close().unwrap();
}

#[cfg(feature = "test_postgres")]
#[tokio::test]
async fn test_postgres_database() {
    let db = postgres::new_and_clear().await.unwrap();
    do_basic_with_db(db).await;
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
            // at least one conflict should be reported
            // TODO: supply the full conflicts
            assert!(!c.is_empty());
        }
        _ => panic!("expected conflict"),
    }
}
