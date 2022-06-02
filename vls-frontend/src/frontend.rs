use std::sync::Arc;

use tokio::task;

use url::Url;

use log::info;

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

    /// Start a task which creates a chain follower for each existing tracker
    pub fn start(&self) {
        let signer = Arc::clone(&self.signer);
        let rpc_url = self.rpc_url.clone();
        task::spawn(async move {
            for tracker in signer.trackers().await {
                let cf_arc = ChainFollower::new(tracker, &rpc_url).await;
                ChainFollower::start(cf_arc).await;
            }
        });
        info!("frontend started");
    }

    /// Start a chain follower for a specific tracker
    pub async fn start_follower(&self, tracker: Arc<dyn ChainTrack>) {
        let cf_arc = ChainFollower::new(tracker, &self.rpc_url).await;
        ChainFollower::start(cf_arc).await;
    }
}
