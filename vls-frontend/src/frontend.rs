use std::sync::Arc;

use url::Url;

use crate::{chain_follower::ChainFollower, ChainTrack, ChainTrackDirectory};

pub struct Frontend {
    pub signer: Arc<dyn ChainTrackDirectory>,
    pub rpc_url: Url,
}

impl Frontend {
    /// Create a new Frontend
    pub fn new(signer: Arc<dyn ChainTrackDirectory>, rpc_url: Url) -> Frontend {
        Frontend { signer, rpc_url }
    }

    /// Start a chain follower for each existing tracker
    pub async fn start(&self) {
        for tracker in self.signer.trackers().await {
            self.start_follower(tracker).await;
        }
    }

    /// Start a chain follower for a specific tracker
    pub async fn start_follower(&self, tracker: Arc<dyn ChainTrack>) {
        let cf_arc = ChainFollower::new(tracker, &self.rpc_url).await;
        ChainFollower::start(cf_arc).await;
    }
}
