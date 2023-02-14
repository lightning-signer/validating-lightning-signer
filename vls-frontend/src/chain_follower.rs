use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{Mutex, OnceCell};
use tokio::{task, time};
use url::Url;

use bitcoin::{Block, Network, OutPoint, Transaction, TxOut, Txid};
use lightning_signer::bitcoin;

use bitcoind_client::follower::{Error, Tracker};
use bitcoind_client::txoo_follower::{FollowWithProofAction, SourceWithTxooProofFollower};
use bitcoind_client::{BitcoindClient, BlockSource};

#[allow(unused_imports)]
use lightning_signer::{debug_vals, short_function, vals_str};
#[allow(unused_imports)]
use log::{debug, error, info, trace};

use crate::frontend::SourceFactory;
use crate::{ChainTrack, HeartbeatMonitor};

/// Follows the longest chain and feeds proofs of watched changes to ChainTracker.
pub struct ChainFollower {
    tracker: Arc<dyn ChainTrack>,
    heartbeat_monitor: OnceCell<HeartbeatMonitor>,
    follower: SourceWithTxooProofFollower,
    state: Mutex<State>,
    update_interval: u64,
}

#[derive(Debug, PartialEq)]
enum State {
    Scanning,
    Synced,
}

impl Display for State {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            State::Scanning => write!(f, "scanning"),
            State::Synced => write!(f, "synced"),
        }
    }
}

#[derive(PartialEq)]
enum ScheduleNext {
    Pause,
    Immediate,
    // Terminate,
}

macro_rules! abbrev {
    ($str: expr, $sz: expr) => {{
        format!("{}...", $str.to_string()[0..$sz].to_string())
    }};
}

impl ChainFollower {
    pub async fn new(
        tracker: Arc<dyn ChainTrack>,
        txoo_source_factory: &SourceFactory,
        rpc_url: &Url,
    ) -> Arc<ChainFollower> {
        let client = BitcoindClient::new(rpc_url.clone()).await;
        let genesis_hash = client.get_block_hash(0).await.unwrap().unwrap();
        let genesis = client.get_block(&genesis_hash).await.unwrap();
        let txoo_source = txoo_source_factory.get_source(0, &genesis);
        let update_interval = match tracker.network() {
            Network::Regtest => 1000, // poll rapidly, automated testing
            _ => 60 * 1000,
        };
        info!(
            "follower {} rpc_url: {}, network: {}, update_interval: {}",
            tracker.log_prefix(),
            rpc_url,
            tracker.network(),
            update_interval
        );
        let follower = SourceWithTxooProofFollower::new(Box::new(client), txoo_source);
        Arc::new(ChainFollower {
            tracker,
            heartbeat_monitor: OnceCell::new(),
            follower,
            state: Mutex::new(State::Scanning),
            update_interval,
        })
    }

    pub async fn start(cf_arc: Arc<ChainFollower>) {
        use std::env;
        let enable = env::var("VLS_CHAINFOLLOWER_ENABLE")
            .map(|s| s.parse().expect("VLS_CHAINFOLLOWER_ENABLE parse"))
            .unwrap_or(0);
        if enable != 1 {
            info!("follower not enabled - VLS_CHAINFOLLOWER_ENABLE");
            return;
        }
        info!("follower starting");
        let cf_arc_clone = Arc::clone(&cf_arc);
        task::spawn(async move {
            cf_arc_clone.run().await;
        });
    }

    async fn run(&self) {
        let mut interval = time::interval(Duration::from_millis(self.update_interval));
        loop {
            interval.tick().await;
            loop {
                match self.update().await {
                    Ok(next) => {
                        if next == ScheduleNext::Pause {
                            break;
                        }
                        // otherwise loop immediately
                    }
                    Err(err) => {
                        error!("{}: {:?}", self.tracker.log_prefix(), err);
                        break; // Would a shorter pause be better here?
                    }
                }
            }
        }
    }

    async fn heartbeat_monitor(&self) -> &HeartbeatMonitor {
        self.heartbeat_monitor
            .get_or_init(|| async {
                let pubkey = self.tracker.heartbeat_pubkey().await;
                HeartbeatMonitor::new(self.tracker.network(), pubkey, self.tracker.log_prefix())
            })
            .await
    }

    async fn update(&self) -> Result<ScheduleNext, Error> {
        let heartbeat_monitor = self.heartbeat_monitor().await;
        heartbeat_monitor.on_tick();

        let mut state = self.state.lock().await;

        // Fetch the current tip from the tracker
        let (height0, hash0) = self.tracker.tip_info().await;

        match self.follower.follow_with_proof(height0, hash0, self).await? {
            FollowWithProofAction::None => {
                // Current top block matches
                if *state != State::Synced {
                    info!("{} synced at height {}", self.tracker.log_prefix(), height0);
                    *state = State::Synced;
                }

                self.do_heartbeat().await;
                return Ok(ScheduleNext::Pause);
            }
            FollowWithProofAction::BlockAdded(block, proof) => {
                *state = State::Scanning;
                let height = height0 + 1;
                if height % 2016 == 0 {
                    info!("{} at height {}", self.tracker.log_prefix(), height);
                }

                // debug!("node {} at height {} adding {}", self.tracker.log_prefix(), height, hash);
                self.tracker.add_block(block.header, proof).await;

                Ok(ScheduleNext::Immediate)
            }
            FollowWithProofAction::BlockReorged(_block, proof) => {
                debug!(
                    "{} reorg at height {}, removing hash {}",
                    self.tracker.log_prefix(),
                    height0,
                    abbrev!(hash0, 12),
                );
                self.tracker.remove_block(proof).await;
                Ok(ScheduleNext::Immediate)
            }
        }
    }

    async fn do_heartbeat(&self) {
        let heartbeat = self.tracker.beat().await;
        self.heartbeat_monitor().await.on_heartbeat(heartbeat)
    }
}

#[async_trait]
impl Tracker for ChainFollower {
    async fn forward_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.tracker.forward_watches().await
    }

    async fn reverse_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.tracker.reverse_watches().await
    }
}

// A transaction summary suitable for debugging follower activities
#[derive(Debug)]
#[allow(dead_code)]
struct DebugTransactionSummary {
    txid: Txid,
    inputs: Vec<OutPoint>,
    outputs: Vec<TxOut>,
}

#[allow(dead_code)]
fn debug_block_txs(block: &Block) -> Vec<DebugTransactionSummary> {
    block.txdata.iter().map(|tx| debug_transaction_summary(&tx)).collect::<Vec<_>>()
}

#[allow(dead_code)]
fn debug_transaction_summary(tx: &Transaction) -> DebugTransactionSummary {
    DebugTransactionSummary {
        txid: tx.txid(),
        inputs: tx.input.iter().map(|inp| inp.previous_output).collect(),
        outputs: tx.output.clone(),
    }
}
