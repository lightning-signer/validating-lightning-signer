use async_trait::async_trait;
use bitcoind_client::BlockSource;
use lightning_signer::bitcoin::{Block, BlockHash};

/// A follower error
#[derive(Debug)]
pub enum Error {
    /// The block source is not available
    SourceError(String),
}

impl From<bitcoind_client::Error> for Error {
    fn from(e: bitcoind_client::Error) -> Error {
        Error::SourceError(e.to_string())
    }
}

/// The next action to take when following the chain
pub enum FollowAction {
    /// No action required, synced to chain tip
    None,
    /// A block has been added to the chain.
    /// Provides the new block.
    BlockAdded(Block),
    /// The current block has been reorganized out of the chain.
    /// Provides the block that was reorged out.
    BlockReorged(Block),
}

/// Follow the longest chain
#[async_trait]
pub trait Follower {
    async fn follow(&self, height: u32, hash: BlockHash) -> Result<FollowAction, Error>;
}

/// A follower for BlockSource
pub struct SourceFollower {
    source: Box<dyn BlockSource>,
}

impl SourceFollower {
    pub fn new(source: Box<dyn BlockSource>) -> Self {
        SourceFollower { source }
    }
}

#[async_trait]
impl Follower for SourceFollower {
    async fn follow(
        &self,
        current_height: u32,
        current_hash: BlockHash,
    ) -> Result<FollowAction, Error> {
        return match self.source.get_block_hash(current_height + 1).await? {
            None => {
                // No new block, but check if the current block has been reorged
                match self.source.get_block_hash(current_height).await? {
                    None => {
                        // The current block has been reorged out of the chain
                        Ok(FollowAction::BlockReorged(self.source.get_block(&current_hash).await?))
                    }
                    Some(check_hash) => {
                        if check_hash == current_hash {
                            // No action required, synced to chain tip
                            Ok(FollowAction::None)
                        } else {
                            // The current block has been reorged out of the chain
                            Ok(FollowAction::BlockReorged(
                                self.source.get_block(&current_hash).await?,
                            ))
                        }
                    }
                }
            }
            Some(new_hash) => {
                let block = self.source.get_block(&new_hash).await?;
                if block.header.prev_blockhash == current_hash {
                    // A block has been added to the chain
                    Ok(FollowAction::BlockAdded(block))
                } else {
                    // The new block actually extends a different chain
                    Ok(FollowAction::BlockReorged(self.source.get_block(&current_hash).await?))
                }
            }
        };
    }
}
