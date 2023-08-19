#![allow(deprecated)]
use std::env::args;
use vls_persist::kvv::redb::RedbKVVStore;
use vls_persist::kvv::KVVStore;

fn main() {
    let path = args().nth(1).unwrap();
    let persister = RedbKVVStore::new(&path);

    for item in persister.get_prefix("").unwrap() {
        println!("{:?}", item);
    }
}
