use lssd::database::redb;
use std::sync::Arc;
use tempfile::TempDir;
#[path = "./common.rs"]
mod common;

#[tokio::main]
async fn main() {
    let temp_dir = TempDir::new().unwrap();
    let db = Arc::new(redb::RedbDatabase::new_and_clear(temp_dir.path()).await.unwrap());
    common::bench_test_db(db).await;
}
