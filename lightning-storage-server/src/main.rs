use lightning_storage_server::{Database, Value};

use sled::transaction::TransactionResult;
use sled::Db;
use std::thread;
use std::thread::sleep;
use std::time::Duration;

#[derive(Debug, PartialEq)]
struct MyError;

fn make_value(v: u8) -> Value {
    Value { signature: vec![1, 2, 3], version: 0, value: vec![v] }
}

fn main() {
    let dir = "/tmp/x";
    let db = Database::new(dir).unwrap();
    db.put(vec![
        ("x1a".to_string(), make_value(10)),
        ("x1b".to_string(), make_value(11)),
        ("x2b".to_string(), make_value(20)),
    ])
    .unwrap();
    let values = db.get_prefix("x1".to_string()).unwrap();
    assert_eq!(values.len(), 2);
}

#[allow(unused)]
fn test_concurrent() {
    let db1 = sled::open("/tmp/x").unwrap();
    let db2 = db1.clone();
    let h1 = thread::spawn(|| transact(db1).unwrap());
    let h2 = thread::spawn(|| transact(db2).unwrap());
    h1.join().unwrap();
    h2.join().unwrap();
}

fn transact(db: Db) -> TransactionResult<(), MyError> {
    println!("start");
    db.transaction(|tx| {
        println!("get");
        let res_o = tx.get(b"yo!").unwrap();
        if let Some(res) = res_o {
            println!("res {}", res[0]);
            sleep(Duration::from_secs(1));
            println!("insert");
            tx.insert(b"yo!", vec![res[0] + 1]).unwrap();
        } else {
            tx.insert(b"yo!", vec![0u8]).unwrap();
        }
        println!("done");
        Ok(())
    })?;
    Ok(())
}
