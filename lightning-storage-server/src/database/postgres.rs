use super::{Database, Error};
use crate::Value;
use async_trait::async_trait;
use deadpool_postgres::RecyclingMethod;
use futures::TryFutureExt;
use tokio_postgres::types::{ToSql, Type};
pub use tokio_postgres::Error as PgError;
use tokio_postgres::{IsolationLevel, NoTls};

pub async fn new_and_clear() -> Result<PostgresDatabase, Error> {
    let db = new().await?;
    let client = db.pool.get().await.unwrap();
    client.batch_execute("TRUNCATE data").await?;
    Ok(db)
}

pub async fn new() -> Result<PostgresDatabase, Error> {
   let mut cfg = deadpool_postgres::Config::new();
    let host = std::env::var("PG_HOST").ok().unwrap_or("/var/run/postgresql".to_string());
    let user = std::env::var("PG_USER").ok().unwrap_or("dev".to_string());
    let pass = std::env::var("PG_PASS").ok();
    let db = std::env::var("PG_DB").ok().unwrap_or("dev".to_string());
    cfg.host = Some(host);
    cfg.dbname = Some(db);
    cfg.user = Some(user);
    cfg.password = pass;
    cfg.manager =
        Some(deadpool_postgres::ManagerConfig { recycling_method: RecyclingMethod::Fast });
    let pool = cfg.create_pool(Some(deadpool_postgres::Runtime::Tokio1), NoTls).unwrap();

    {
        let client = pool.get().await.unwrap();
        migrate_database(&client).await?;
    }
    Ok(PostgresDatabase { pool })
}

async fn migrate_database(client: &tokio_postgres::Client) -> Result<(), Error> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS data (client bytea, key varchar, version bigint, value bytea, primary key (client, key))",
        ).await?;
    Ok(())
}

pub struct PostgresDatabase {
    pool: deadpool_postgres::Pool,
}

#[async_trait]
impl Database for PostgresDatabase {
    async fn put(&self, client_id: &[u8], kvs: &Vec<(String, Value)>) -> Result<(), Error> {
        let mut client = self.pool.get().await.unwrap();
        let insert_statement = client
            .prepare("INSERT INTO data (client, key, version, value) VALUES ($1, $2, 0, $3) ON CONFLICT DO NOTHING RETURNING key")
            .await?;
        let update_statement = client
            .prepare_typed("UPDATE data SET version = $3, value = $4 WHERE client = $1 AND key = $2 AND version = $3 - 1 RETURNING key",
            &[Type::BYTEA, Type::VARCHAR, Type::INT8, Type::BYTEA]).await?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await?;
        let mut conflicts: Vec<(String, Option<Value>)> = Vec::new();
        let params = kvs
            .iter()
            .map(|(key, value)| {
                let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
                let is_new = value.version == 0;
                params.push(&client_id);
                params.push(key);
                if is_new {
                    params.push(&value.value);
                } else {
                    params.push(&value.version);
                    params.push(&value.value);
                }
                (is_new, params)
            })
            .collect::<Vec<_>>();
        let mut futs = Vec::new();
        for (is_new, param) in params.iter() {
            let fut = if *is_new {
                tx.query(&insert_statement, param)
            } else {
                tx.query(&update_statement, param)
            };
            // each query will return one row if successful, or zero if not
            futs.push(fut.map_ok(|res| !res.is_empty()));
        }

        for (idx, res) in futures::future::join_all(futs).await.into_iter().enumerate() {
            if !res? {
                let kv = kvs.get(idx).unwrap();
                conflicts.push(((*kv).0.clone(), None));
            }
        }
        if conflicts.len() > 0 {
            return Err(Error::Conflict(conflicts));
        }
        tx.commit().await?;
        Ok(())
    }

    async fn get_with_prefix(
        &self,
        client_id: &[u8],
        key_prefix: String,
    ) -> Result<Vec<(String, Value)>, Error> {
        let client = self.pool.get().await.unwrap();
        client
            .query(
                "SELECT key, version, value FROM data WHERE client = $1 AND key LIKE $2",
                &[&client_id, &format!("{}%", key_prefix)],
            )
            .await?
            .iter()
            .map(|row| {
                let key: String = row.get(0);
                let version: i64 = row.get(1);
                let value: Vec<u8> = row.get(2);
                Ok((key, Value { version, value }))
            })
            .collect()
    }
}
