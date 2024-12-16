pub mod database;
pub mod driver;
pub use database::{Database, Error};
pub mod util;

use itertools::Itertools;
use lightning_storage_server::client::PrivAuth;
use lightning_storage_server::proto::lightning_storage_server::{
    LightningStorage, LightningStorageServer,
};
use lightning_storage_server::proto::{
    self, GetReply, GetRequest, InfoReply, InfoRequest, PingReply, PingRequest, PutReply,
    PutRequest,
};
use lightning_storage_server::util::compute_shared_hmac;
use log::{debug, error};
use secp256k1::{PublicKey, SecretKey};
use tonic::{Request, Response, Status};

pub struct StorageServer {
    database: Box<dyn Database>,
    public_key: PublicKey,
    secret_key: SecretKey,
}

fn into_status(s: Error) -> Status {
    match s {
        Error::Conflict(_) => unimplemented!("unexpected conflict error"),
        e => {
            error!("database error: {:?}", e);
            Status::internal("unexpected error")
        }
    }
}

impl StorageServer {
    fn check_auth(&self, auth_proto: &proto::Auth) -> Result<PrivAuth, Status> {
        let client_id = PublicKey::from_slice(&auth_proto.client_id)
            .map_err(|_| Status::unauthenticated("invalid client id"))?;
        let auth = PrivAuth::new_for_server(&self.secret_key, &client_id);
        if auth_proto.token != auth.auth_token() {
            return Err(Status::invalid_argument("invalid auth token"));
        }
        Ok(auth)
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
        let auth_proto = request.auth.ok_or_else(|| Status::invalid_argument("missing auth"))?;
        let auth = self.check_auth(&auth_proto)?;
        let client_id = auth_proto.client_id;
        let key_prefix = request.key_prefix;
        debug!("get request({}) {}", hex::encode(&client_id), key_prefix);
        let kvs =
            self.database.get_with_prefix(&client_id, key_prefix).await.map_err(into_status)?;
        debug!("get result {:?}", kvs);
        let hmac = compute_shared_hmac(&auth.shared_secret, &request.nonce, &kvs);
        let kvs_proto = kvs.into_iter().map(|kv| kv.into()).collect();

        let response = GetReply { kvs: kvs_proto, hmac };
        Ok(Response::new(response))
    }

    async fn put(&self, request: Request<PutRequest>) -> Result<Response<PutReply>, Status> {
        let request = request.into_inner();
        let kvs: Vec<_> = request.kvs.into_iter().map(|kv| kv.into()).collect::<Vec<_>>();

        let auth_proto = request.auth.ok_or_else(|| Status::invalid_argument("missing auth"))?;
        let client_id = &auth_proto.client_id;

        debug!("put request({}) {:?}", hex::encode(client_id), kvs);

        for ((k1, _), (k2, _)) in kvs.iter().tuple_windows() {
            if k1 > k2 {
                return Err(Status::invalid_argument("keys are not sorted"));
            }
        }

        let auth = self.check_auth(&auth_proto)?;
        let client_hmac = compute_shared_hmac(&auth.shared_secret, &[0x01], &kvs);

        if client_hmac != request.hmac {
            return Err(Status::invalid_argument("invalid client HMAC"));
        }

        let response = match self.database.put(&client_id, &kvs).await {
            Ok(()) => {
                debug!("put result ok");
                let hmac = compute_shared_hmac(&auth.shared_secret, &[0x02], &kvs);

                PutReply { success: true, hmac, conflicts: vec![] }
            }
            Err(Error::Conflict(conflicts)) => {
                debug!("put result conflict {:?}", conflicts);
                let conflicts = conflicts.into_iter().map(|kv| kv.into()).collect();
                PutReply { success: false, hmac: Default::default(), conflicts }
            }
            Err(e) => {
                error!("database error: {:?}", e);
                return Err(Status::internal("unexpected error"));
            }
        };
        Ok(Response::new(response))
    }
}
