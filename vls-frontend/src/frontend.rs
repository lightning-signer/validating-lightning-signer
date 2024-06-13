use async_trait::async_trait;
use bitcoind_client::dummy::DummyPersistentTxooSource;
use lightning_signer::txoo::source::{FileSource, HttpSource, Source};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::{task, time};
use url::Url;

use lightning_signer::bitcoin::{BlockHash, FilterHeader, Network};
use log::info;

use triggered::Listener;

use crate::{chain_follower::ChainFollower, ChainTrack, ChainTrackDirectory};

#[async_trait]
pub trait SourceFactory: Send + Sync {
    /// Get a new TXOO Source
    async fn get_source(
        &self,
        start_block: u32,
        block_hash: BlockHash,
        filter_header: FilterHeader,
    ) -> Box<dyn Source>;

    fn get_network(&self) -> Network;
}

pub struct FileSourceFactory {
    datadir: PathBuf,
    network: Network,
}

impl FileSourceFactory {
    /// Create a new FileSourceFactory
    pub fn new<P: Into<PathBuf>>(datadir: P, network: Network) -> Self {
        Self { datadir: datadir.into(), network }
    }
}

#[async_trait]
impl SourceFactory for FileSourceFactory {
    async fn get_source(
        &self,
        _start_block: u32,
        _block_hash: BlockHash,
        _filter_header: FilterHeader,
    ) -> Box<dyn Source> {
        let file_source = FileSource::new(self.datadir.clone());
        let source_network = file_source.oracle_setup().await.network;
        assert_eq!(source_network, self.network);
        Box::new(file_source)
    }

    fn get_network(&self) -> Network {
        self.network
    }
}

pub struct HTTPSourceFactory {
    url: Url,
    network: Network,
}

impl HTTPSourceFactory {
    /// Create a new HTTPSourceFactory
    pub fn new(url: Url, network: Network) -> Self {
        Self { url: url, network }
    }
}

#[async_trait]
impl SourceFactory for HTTPSourceFactory {
    async fn get_source(
        &self,
        _start_block: u32,
        _block_hash: BlockHash,
        _filter_header: FilterHeader,
    ) -> Box<dyn Source> {
        let http_source =
            HttpSource::new(self.url.clone()).await.expect("couldn't connect to http source");
        let source_network = http_source.oracle_setup().await.network;
        assert_eq!(source_network, self.network);
        Box::new(http_source)
    }

    fn get_network(&self) -> Network {
        self.network
    }
}

pub struct DummySourceFactory {
    datadir: PathBuf,
    network: Network,
}

impl DummySourceFactory {
    /// Create a new DummySourceFactory
    pub fn new<P: Into<PathBuf>>(datadir: P, network: Network) -> Self {
        Self { datadir: datadir.into(), network }
    }
}

#[async_trait]
impl SourceFactory for DummySourceFactory {
    async fn get_source(
        &self,
        start_block: u32,
        block_hash: BlockHash,
        filter_header: FilterHeader,
    ) -> Box<dyn Source> {
        Box::new(DummyPersistentTxooSource::from_checkpoint(
            self.datadir.clone(),
            self.network,
            start_block,
            block_hash,
            filter_header.clone(),
        ))
    }

    fn get_network(&self) -> Network {
        self.network
    }
}

#[derive(Clone)]
pub struct Frontend {
    directory: Arc<dyn ChainTrackDirectory>,
    rpc_url: Url,
    tracker_ids: Arc<Mutex<HashSet<Vec<u8>>>>,
    source_factory: Arc<dyn SourceFactory>,
    shutdown_signal: Listener,
}

impl Frontend {
    /// Create a new Frontend
    pub fn new(
        signer: Arc<dyn ChainTrackDirectory>,
        source_factory: Arc<dyn SourceFactory>,
        rpc_url: Url,
        shutdown_signal: Listener,
    ) -> Frontend {
        let tracker_ids = Arc::new(Mutex::new(HashSet::new()));
        Frontend { directory: signer, source_factory, rpc_url, tracker_ids, shutdown_signal }
    }

    pub fn directory(&self) -> Arc<dyn ChainTrackDirectory> {
        Arc::clone(&self.directory)
    }

    /// Start a task which creates a chain follower for each existing tracker
    pub fn start(&self) {
        let s = self.clone();
        let shutdown_signal = self.shutdown_signal.clone();
        task::spawn(async move {
            s.start_loop(shutdown_signal).await;
        });
        info!("frontend started");
    }

    async fn start_loop(&self, shutdown_signal: Listener) {
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            let shutdown_signal_clone = shutdown_signal.clone();
            tokio::select! {
                _ = interval.tick() => self.handle_new_trackers().await,
                _ = shutdown_signal_clone => break,
            }
        }
        info!("frontend stopped");
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
        assert_eq!(tracker.network(), self.source_factory.get_network());
        let cf_arc = ChainFollower::new(tracker, self.source_factory.as_ref(), &self.rpc_url).await;
        ChainFollower::start(cf_arc).await;
    }
}
