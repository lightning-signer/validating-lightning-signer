use bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use bitcoin::Network;
use lightning_signer::bitcoin;
use lightning_signer::node::SignedHeartbeat;
use log::*;
use std::sync::Mutex;
use std::time::SystemTime;

struct State {
    // seconds since the epoch of the last notification
    last_timestamp: u64,
    // the last heartbeat we received
    last_heartbeat: Option<SignedHeartbeat>,
}

pub struct HeartbeatMonitor {
    pubkey: PublicKey,
    secp: Secp256k1<All>,
    log_prefix: String,
    // number of seconds between notifications
    notify_interval: u64,
    // number of seconds until a heartbeat is considered stale
    stale_interval: u64,
    state: Mutex<State>,
}

#[cfg_attr(test, derive(PartialEq, Debug))]
enum HeartbeatStatus {
    // heartbeat is fresh
    Fresh,
    // heartbeat is stale
    Stale,
    // heartbeat is missing
    Missing,
    // heartbeat timestamp is in the future
    Future,
}

impl HeartbeatMonitor {
    pub fn new(network: Network, pubkey: PublicKey, log_prefix: String) -> Self {
        let (notify_interval, stale_interval) = match network {
            Network::Bitcoin => (60, 3600),
            Network::Testnet => (60, 3600),
            Network::Regtest => (5, 5),
            Network::Signet => (5, 5),
            _ => unreachable!(),
        };
        Self {
            pubkey,
            secp: Secp256k1::new(),
            log_prefix,
            notify_interval,
            stale_interval,
            state: Mutex::new(State { last_timestamp: 0, last_heartbeat: None }),
        }
    }

    pub fn on_heartbeat(&self, heartbeat: SignedHeartbeat) {
        let ok = heartbeat.verify(&self.pubkey, &self.secp);
        if ok {
            let mut state = self.state.lock().unwrap();
            debug!("{} heartbeat: height {:?}", self.log_prefix, heartbeat.heartbeat.chain_height);
            state.last_heartbeat = Some(heartbeat);
            state.last_timestamp = Self::now();
        } else {
            error!(
                "{} heartbeat signature verify failed: {:?} pubkey {}",
                self.log_prefix, heartbeat, self.pubkey
            );
        }
    }

    pub fn on_tick(&self) {
        let now = Self::now();
        let mut state = self.state.lock().unwrap();
        match status(state.last_heartbeat.as_ref(), now, self.stale_interval) {
            HeartbeatStatus::Fresh => {}
            HeartbeatStatus::Stale =>
                if now > state.last_timestamp + self.notify_interval {
                    error!(
                        "{} heartbeat stale: {:?}",
                        self.log_prefix,
                        state.last_heartbeat.as_ref()
                    );
                    state.last_timestamp = now;
                },
            HeartbeatStatus::Missing =>
                if now > state.last_timestamp + self.notify_interval {
                    error!("{} no heartbeat", self.log_prefix);
                    state.last_timestamp = now;
                },
            HeartbeatStatus::Future => {
                error!(
                    "{} heartbeat timestamp in the future: {:?} now {}",
                    self.log_prefix,
                    state.last_heartbeat.as_ref(),
                    now
                );
            }
        }
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }
}

fn status(
    heartbeat_opt: Option<&SignedHeartbeat>,
    now: u64,
    stale_interval: u64,
) -> HeartbeatStatus {
    if let Some(heartbeat) = heartbeat_opt.as_ref() {
        let heartbeat_ts = heartbeat.heartbeat.current_timestamp as u64;
        if now < heartbeat_ts {
            HeartbeatStatus::Future
        } else if now > heartbeat_ts + stale_interval {
            HeartbeatStatus::Stale
        } else {
            HeartbeatStatus::Fresh
        }
    } else {
        HeartbeatStatus::Missing
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;
    use lightning_signer::bitcoin;
    use lightning_signer::node::Heartbeat;

    #[test]
    fn status_test() {
        let heartbeat = super::SignedHeartbeat {
            heartbeat: Heartbeat {
                chain_tip: BlockHash::all_zeros(),
                chain_height: 0,
                chain_timestamp: 0,
                current_timestamp: 1000,
            },
            signature: [0; 64].to_vec(),
        };
        assert_eq!(super::status(Some(&heartbeat), 999, 100), super::HeartbeatStatus::Future);
        assert_eq!(super::status(None, 1000, 100), super::HeartbeatStatus::Missing);
        assert_eq!(super::status(Some(&heartbeat), 1000, 100), super::HeartbeatStatus::Fresh);
        assert_eq!(super::status(Some(&heartbeat), 1100, 100), super::HeartbeatStatus::Fresh);
        assert_eq!(super::status(Some(&heartbeat), 1101, 100), super::HeartbeatStatus::Stale);
    }
}
