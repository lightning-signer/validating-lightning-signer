pub mod driver;

use crate::proto::lightning_storage_server::{LightningStorage, LightningStorageServer};
use crate::proto::{self, GetReply, GetRequest, PingReply, PingRequest, PutReply, PutRequest};
use crate::{Database, Error, Value};
use tonic::{Request, Response, Status};

pub struct StorageServer {
    database: Database,
}

impl Into<(String, Value)> for proto::KeyValue {
    fn into(self) -> (String, Value) {
        (self.key, Value { signature: self.signature, version: self.version, value: self.value })
    }
}

// convert a conflict to proto
impl Into<proto::KeyValue> for (String, Option<Value>) {
    fn into(self) -> proto::KeyValue {
        let (key, v) = self;
        proto::KeyValue {
            key,
            signature: v.as_ref().map(|v| v.signature.clone()).unwrap_or_default(),
            version: v.as_ref().map(|v| v.version + 1).unwrap_or_default(),
            value: v.as_ref().map(|v| v.value.clone()).unwrap_or_default(),
        }
    }
}

// convert a conflict to proto
impl Into<proto::KeyValue> for (String, Value) {
    fn into(self) -> proto::KeyValue {
        let (key, v) = self;
        proto::KeyValue { key, signature: v.signature, version: v.version, value: v.value }
    }
}

fn into_status(s: Error) -> Status {
    match s {
        Error::Sled(_) => Status::internal("database error"),
        Error::Conflict(_) => unimplemented!("unexpected conflict error"),
    }
}

#[tonic::async_trait]
impl LightningStorage for StorageServer {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let request = request.into_inner();

        let response = PingReply { message: request.message };
        Ok(Response::new(response))
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetReply>, Status> {
        let request = request.into_inner();
        let client_id = request.client_id;
        let key_prefix = request.key_prefix;
        let kvs = self
            .database
            .get_with_prefix(&client_id, key_prefix)
            .map_err(into_status)?
            .into_iter()
            .map(|kv| kv.into())
            .collect();
        let response = GetReply { kvs };
        Ok(Response::new(response))
    }

    async fn put(&self, request: Request<PutRequest>) -> Result<Response<PutReply>, Status> {
        let request = request.into_inner();
        let kvs = request.kvs.into_iter().map(|kv| kv.into()).collect();
        let client_id = request.client_id;
        let response = match self.database.put(&client_id, kvs) {
            Ok(()) => PutReply { success: true, conflicts: vec![] },
            Err(Error::Sled(_)) => {
                return Err(Status::internal("database error"));
            }
            Err(Error::Conflict(conflicts)) => {
                let conflicts = conflicts.into_iter().map(|kv| kv.into()).collect();
                PutReply { success: false, conflicts }
            }
        };
        Ok(Response::new(response))
    }
}
