use lightning_signer::persist::{ExternalPersistHelper, SimpleEntropy};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;
use vls_frontend::external_persist::ExternalPersist;

/// Wraps an ExternalPersist with an ExternalPersistHelper.
/// For use with monolithic signers, such as the inplace signer mode.
/// WARNING: this does not ensure atomicity if mutated from different threads,
/// ensure that you lock the `persist_client` mutex to ensure mutual exclusion.
#[derive(Clone)]
pub struct ExternalPersistWithHelper {
    pub persist_client: Arc<AsyncMutex<Box<dyn ExternalPersist>>>,
    pub state: Arc<Mutex<BTreeMap<String, (u64, Vec<u8>)>>>,
    pub helper: ExternalPersistHelper,
}

impl ExternalPersistWithHelper {
    pub async fn init_state(&self) {
        let client = self.persist_client.lock().await;
        let entropy = SimpleEntropy::new();
        let mut helper = self.helper.clone();
        let nonce = helper.new_nonce(&entropy);
        let (muts, server_hmac) = client.get("".to_string(), &nonce).await.unwrap();
        let success = helper.check_hmac(&muts, server_hmac);
        assert!(success, "server hmac mismatch on get");
        let mut local = self.state.lock().unwrap();
        for (key, version_value) in muts.into_iter() {
            local.insert(key, version_value);
        }
    }
}
