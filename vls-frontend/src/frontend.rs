use bitcoind_client::dummy::DummyPersistentTxooSource;
use lightning_signer::txoo::source::Source;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::{task, time};
use url::Url;

use lightning_signer::bitcoin::{Block, Network};
use log::info;

use crate::{chain_follower::ChainFollower, ChainTrack, ChainTrackDirectory};

pub struct SourceFactory {
    datadir: PathBuf,
    network: Network,
}

impl SourceFactory {
    /// Create a new SourceFactory
    pub fn new<P: Into<PathBuf>>(datadir: P, network: Network) -> Self {
        Self { datadir: datadir.into(), network }
    }

    /// Get a new TXOO source
    // TODO use real TxooSource
    pub fn get_source(&self, start_block: u32, block: &Block) -> Box<dyn Source> {
        Box::new(DummyPersistentTxooSource::new(
            self.datadir.clone(),
            self.network,
            start_block,
            block,
        ))
    }
}

#[derive(Clone)]
pub struct Frontend {
    directory: Arc<dyn ChainTrackDirectory>,
    rpc_url: Url,
    tracker_ids: Arc<Mutex<HashSet<Vec<u8>>>>,
    source_factory: Arc<SourceFactory>,
}

impl Frontend {
    /// Create a new Frontend
    pub fn new(
        signer: Arc<dyn ChainTrackDirectory>,
        source_factory: Arc<SourceFactory>,
        rpc_url: Url,
    ) -> Frontend {
        let tracker_ids = Arc::new(Mutex::new(HashSet::new()));
        Frontend { directory: signer, source_factory, rpc_url, tracker_ids }
    }

    pub fn directory(&self) -> Arc<dyn ChainTrackDirectory> {
        Arc::clone(&self.directory)
    }

    /// Start a task which creates a chain follower for each existing tracker
    pub fn start(&self) {
        let s = self.clone();
        task::spawn(async move {
            s.start_loop().await;
        });
        info!("frontend started");
    }

    async fn start_loop(&self) {
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            self.handle_new_trackers().await;
        }
    }

    async fn handle_new_trackers(&self) {
        for tracker in self.directory.trackers().await {
            let tracker_id = tracker.id().await;
            {
                let mut lock = self.tracker_ids.lock().unwrap();
                if lock.contains(&tracker_id) {
                    continue;
                }
                lock.insert(tracker_id);
            }
            self.start_follower(tracker).await;
        }
    }

    /// Start a chain follower for a specific tracker
    pub async fn start_follower(&self, tracker: Arc<dyn ChainTrack>) {
        let cf_arc = ChainFollower::new(tracker, &self.source_factory, &self.rpc_url).await;
        ChainFollower::start(cf_arc).await;
    }
}
