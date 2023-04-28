use async_trait::async_trait;

#[async_trait]
pub trait SignerPort: Send + Sync {
    async fn handle_message(&self, message: Vec<u8>) -> crate::ClientResult<Vec<u8>>;
    fn clone(&self) -> Box<dyn SignerPort>;
    fn is_ready(&self) -> bool;
}
