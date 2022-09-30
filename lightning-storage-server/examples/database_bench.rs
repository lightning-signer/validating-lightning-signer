use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::{Hash, HashEngine};
use lightning_storage_server::database::postgres;
use lightning_storage_server::{Database, Value};
use std::sync::Arc;
use std::time::Instant;

const ITEMS_PER_TX: u32 = 64;
const CONCURRENT_TASKS: u32 = 32;
const ROUNDS: u32 = 128;

#[tokio::main]
async fn main() {
    let db = Arc::new(postgres::new_and_clear().await.unwrap());
    let start = Instant::now();
    let mut times = Vec::new();
    for o in 0..ROUNDS {
        let mut tasks = Vec::new();
        for i in 0..CONCURRENT_TASKS / 2 {
            tasks.push(tokio::spawn(do_insert(db.clone(), o * 100 + i, 0)));
            if o > 0 {
                tasks.push(tokio::spawn(do_insert(db.clone(), (o - 1) * 100 + i, 1)));
            }
        }

        for task in tasks {
            times.push(task.await.unwrap());
        }
    }
    let end = Instant::now();
    let elapsed_ms = (end - start).as_millis() as u32;
    println!("done in {} ms", elapsed_ms);
    println!("{}ms 90% percentile", percentile(&times, 0.9));
    println!("{}ms 95% percentile", percentile(&times, 0.95));
    println!("{}ms 99% percentile", percentile(&times, 0.99));
    println!(
        "{} items inserted/updated per second",
        ROUNDS as u64 * (CONCURRENT_TASKS as u64 - 1) * ITEMS_PER_TX as u64 * 1000
            / elapsed_ms as u64
    );
}

fn percentile(times: &Vec<f64>, percentile: f32) -> f64 {
    let mut times = times.clone();
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let index = (times.len() as f32 * percentile) as usize;
    times[index]
}

async fn do_insert(db: Arc<dyn Database>, i: u32, version: i64) -> f64 {
    let client_id = [0x01];
    let start = Instant::now();
    let mut engine = Sha256::engine();
    engine.input(&i.to_be_bytes());
    let kvs = (0..ITEMS_PER_TX)
        .map(|j| {
            let mut engine1 = engine.clone();
            engine1.input(&j.to_be_bytes());
            let key = hex::encode(Sha256::from_engine(engine1).into_inner());
            (key, Value { version, value: [(j % 256) as u8; 128].to_vec() })
        })
        .collect();
    db.put(&client_id, &kvs).await.unwrap();
    let end = Instant::now();
    println!("{} in {} ms", i, (end - start).as_millis());
    (end - start).as_millis() as f64
}
