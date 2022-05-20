use async_trait::async_trait;

use vls_protocol::Result;

#[async_trait]
pub trait SignerPort: Send + Sync {
    async fn handle_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>>;
}
