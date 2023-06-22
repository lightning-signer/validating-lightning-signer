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
use bitcoind_client::{bitcoind_client_from_url, BlockSource};

use lightning_signer::bitcoin::hashes::Hash;
use lightning_signer::bitcoin::FilterHeader;
use lightning_signer::txoo::filter::BlockSpendFilter;
use lightning_signer::txoo::get_latest_checkpoint;
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
    // sleep before performing an update, to test race conditions
    debug_update_sleep: u32,
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
        let client = bitcoind_client_from_url(rpc_url.clone(), tracker.network()).await;
        let genesis_hash = client.get_block_hash(0).await.unwrap().unwrap();
        let genesis = client.get_block(&genesis_hash).await.unwrap();
        let txoo_source = if let Some((ckp_height, ckp_hash, ckp_filter_header, _)) =
            get_latest_checkpoint(tracker.network())
        {
            // current code can't supply tracker with blocks before or at the checkpoint
            // so the tip must be at the checkpoint or higher
            assert!(
                tracker.tip_info().await.0 >= ckp_height,
                "tracker at height {} is < checkpoint at height {}",
                tracker.tip_info().await.0,
                ckp_height
            );
            txoo_source_factory.get_source(ckp_height, ckp_hash, ckp_filter_header)
        } else {
            let filter = BlockSpendFilter::from_block(&genesis);
            let filter_header = filter.filter_header(&FilterHeader::all_zeros());

            txoo_source_factory.get_source(0, genesis.block_hash(), filter_header)
        };
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
        let debug_update_sleep = std::env::var("VLS_CHAINFOLLOWER_DEBUG_UPDATE_SLEEP")
            .map(|s| s.parse().expect("VLS_CHAINFOLLOWER_DEBUG_UPDATE_SLEEP parse"))
            .unwrap_or(0);
        Arc::new(ChainFollower {
            tracker,
            heartbeat_monitor: OnceCell::new(),
            follower,
            state: Mutex::new(State::Scanning),
            update_interval,
            debug_update_sleep,
        })
    }

    pub async fn start(cf_arc: Arc<ChainFollower>) {
        use std::env;
        let disable = env::var("VLS_FRONTEND_DISABLE")
            .map(|s| s.parse().expect("VLS_FRONTEND_DISABLE parse"))
            .unwrap_or(0);
        if disable != 0 {
            info!("follower not enabled - VLS_FRONTEND_DISABLE");
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

        if self.debug_update_sleep > 0 && height0 > 100 {
            info!(
                "{} at {} before sleep {}s",
                self.tracker.log_prefix(),
                height0,
                self.debug_update_sleep
            );
            time::sleep(Duration::from_secs(self.debug_update_sleep.into())).await;
            info!("{} after sleep", self.tracker.log_prefix());
        }

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

                trace!(
                    "node {} at height {} adding {}",
                    self.tracker.log_prefix(),
                    height,
                    abbrev!(block.block_hash(), 12)
                );
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
