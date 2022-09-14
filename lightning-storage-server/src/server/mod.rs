pub mod driver;

use crate::client::auth::Auth;
use crate::proto::lightning_storage_server::{LightningStorage, LightningStorageServer};
use crate::proto::{
    self, GetReply, GetRequest, InfoReply, InfoRequest, PingReply, PingRequest, PutReply,
    PutRequest,
};
use crate::{Database, Error, Value};
use secp256k1::{PublicKey, SecretKey};
use tonic::{Request, Response, Status};

pub struct StorageServer {
    database: Database,
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl Into<(String, Value)> for proto::KeyValue {
    fn into(self) -> (String, Value) {
        (self.key, Value { version: self.version, value: self.value })
    }
}

// convert a conflict to proto
impl Into<proto::KeyValue> for (String, Option<Value>) {
    fn into(self) -> proto::KeyValue {
        let (key, v) = self;
        proto::KeyValue {
            key,
            version: v.as_ref().map(|v| v.version + 1).unwrap_or_default(),
            value: v.as_ref().map(|v| v.value.clone()).unwrap_or_default(),
        }
    }
}

// convert a conflict to proto
impl Into<proto::KeyValue> for (String, Value) {
    fn into(self) -> proto::KeyValue {
        let (key, v) = self;
        proto::KeyValue { key, version: v.version, value: v.value }
    }
}

fn into_status(s: Error) -> Status {
    match s {
        Error::Sled(_) => Status::internal("database error"),
        Error::Conflict(_) => unimplemented!("unexpected conflict error"),
    }
}

impl StorageServer {
    fn check_auth(&self, auth_proto: &proto::Auth) -> Result<(), Status> {
        let client_id = PublicKey::from_slice(&auth_proto.client_id)
            .map_err(|_| Status::unauthenticated("invalid client id"))?;
        let auth = Auth::new_for_server(self.secret_key.clone(), client_id);
        if auth_proto.token != auth.auth_token() {
            return Err(Status::invalid_argument("invalid auth token"));
        }
        Ok(())
    }
}
#[tonic::async_trait]
impl LightningStorage for StorageServer {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let request = request.into_inner();

        let response = PingReply { message: request.message };
        Ok(Response::new(response))
    }

    async fn info(&self, request: Request<InfoRequest>) -> Result<Response<InfoReply>, Status> {
        let _ = request.into_inner();

        let response = InfoReply {
            version: "0.1".to_string(),
            server_id: self.public_key.serialize().to_vec(),
        };
        Ok(Response::new(response))
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetReply>, Status> {
        let request = request.into_inner();
        let auth = request.auth.ok_or_else(|| Status::invalid_argument("missing auth"))?;
        self.check_auth(&auth)?;
        let client_id = auth.client_id;
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
        let auth = request.auth.ok_or_else(|| Status::invalid_argument("missing auth"))?;
        self.check_auth(&auth)?;
        let client_id = auth.client_id;
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
