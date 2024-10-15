use crate::recovery::{Iter, RecoveryKeys, RecoverySign};
use lightning_signer::bitcoin::secp256k1::{PublicKey, SecretKey};
use lightning_signer::bitcoin::{Address, ScriptBuf, Transaction, TxOut};
use lightning_signer::channel::{Channel, ChannelBase, ChannelSlot};
use lightning_signer::lightning::chain::transaction::OutPoint;
use lightning_signer::node::Node;
use lightning_signer::util::status::Status;
use lightning_signer::wallet::Wallet;
use std::sync::{Arc, Mutex, MutexGuard};

/// Recovery keys for an in-process Node
pub struct DirectRecoveryKeys {
    pub node: Arc<Node>,
}

impl RecoveryKeys for DirectRecoveryKeys {
    type Signer = DirectRecoverySigner;

    fn iter(&self) -> Iter<Self::Signer> {
        let signers: Vec<_> = self
            .node
            .get_channels()
            .iter()
            .map(|(_id, channel)| Arc::clone(channel))
            .filter_map(|channel| {
                let channel1 = Arc::clone(&channel);
                let lock = channel1.lock().unwrap();
                match *lock {
                    ChannelSlot::Stub(ref c) => {
                        println!("# channel {} is a stub", c.id0);
                        None
                    }
                    ChannelSlot::Ready(_) => Some(DirectRecoverySigner { channel }),
                }
            })
            .collect();
        Iter { signers }
    }

    fn sign_onchain_tx(
        &self,
        tx: &Transaction,
        segwit_flags: &[bool],
        ipaths: &Vec<Vec<u32>>,
        prev_outs: &Vec<TxOut>,
        uniclosekeys: Vec<Option<(SecretKey, Vec<Vec<u8>>)>>,
        opaths: &Vec<Vec<u32>>,
    ) -> Result<Vec<Vec<Vec<u8>>>, Status> {
        self.node.check_onchain_tx(tx, segwit_flags, prev_outs, &uniclosekeys, opaths)?;
        self.node.unchecked_sign_onchain_tx(tx, ipaths, prev_outs, uniclosekeys)
    }

    fn wallet_address_native(&self, index: u32) -> Result<Address, Status> {
        self.node.get_native_address(&[index])
    }

    fn wallet_address_taproot(&self, index: u32) -> Result<Address, Status> {
        self.node.get_taproot_address(&[index])
    }
}

/// Recovery signer for an in-process Channel
pub struct DirectRecoverySigner {
    channel: Arc<Mutex<ChannelSlot>>,
}

impl RecoverySign for DirectRecoverySigner {
    fn sign_holder_commitment_tx_for_recovery(
        &self,
    ) -> Result<
        (Transaction, Vec<Transaction>, ScriptBuf, (SecretKey, Vec<Vec<u8>>), PublicKey),
        Status,
    > {
        let mut lock = self.lock();
        Self::channel(&mut lock).sign_holder_commitment_tx_for_recovery()
    }

    fn funding_outpoint(&self) -> OutPoint {
        let mut lock = self.lock();
        Self::channel(&mut lock).keys.funding_outpoint().unwrap().clone()
    }

    fn counterparty_selected_contest_delay(&self) -> u16 {
        let mut lock = self.lock();
        Self::channel(&mut lock).setup.counterparty_selected_contest_delay
    }

    fn get_per_commitment_point(&self) -> Result<PublicKey, Status> {
        let mut lock = self.lock();
        let channel = Self::channel(&mut lock);
        channel.get_per_commitment_point(channel.enforcement_state.next_holder_commit_num - 1)
    }
}

impl DirectRecoverySigner {
    fn channel(lock: &mut ChannelSlot) -> &mut Channel {
        match *lock {
            ChannelSlot::Stub(_) => {
                panic!("already checked");
            }
            ChannelSlot::Ready(ref mut c) => c,
        }
    }

    fn lock(&self) -> MutexGuard<ChannelSlot> {
        self.channel.lock().unwrap()
    }
}
