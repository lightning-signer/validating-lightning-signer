use kv::Json;
use lightning_signer::bitcoin::hashes::hex::ToHex;
use std::env::args;
use vls_persist::kv_json::KVJsonPersister;
use vls_persist::model::NodeChannelId;

macro_rules! dump_items {
    ($obj:expr, $bucket:ident) => {
        println!("---------- {}", stringify!($bucket));
        for item_res in $obj.$bucket.iter() {
            let item = item_res.unwrap();
            let key: Vec<u8> = item.key().unwrap();
            let value: Json<_> = item.value().unwrap();
            println!("{}: {}", key.to_hex(), value);
        }
    };
}

macro_rules! dump_items_channel {
    ($obj:expr, $bucket:ident) => {
        println!("---------- {}", stringify!($bucket));
        for item_res in $obj.$bucket.iter() {
            let item = item_res.unwrap();
            let key: NodeChannelId = item.key().unwrap();
            let value: Json<_> = item.value().unwrap();
            println!("{}: {}", key, value);
        }
    };
}

fn main() {
    let path = args().nth(1).unwrap();
    let persister = KVJsonPersister::new(&path);

    // dump all buckets
    dump_items!(persister, node_bucket);
    dump_items!(persister, node_state_bucket);
    dump_items_channel!(persister, channel_bucket);
    dump_items!(persister, chain_tracker_bucket);
    dump_items!(persister, allowlist_bucket);
}
