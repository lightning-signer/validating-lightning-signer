use crate::Map;
use core::convert::TryFrom;
use crate::{Arc, Mutex};

use bitcoin::secp256k1::SignOnly;

#[cfg(feature = "backtrace")]
use backtrace::Backtrace;
use bitcoin;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::bip32::ChildNumber;
use bitcoin::{Address, Network, OutPoint, SigHashType};
use lightning::chain::keysinterface::KeysInterface;
use lightning::util::logger::Logger;

use super::my_keys_manager::KeyDerivationStyle;
use crate::node::node::{
    Channel, ChannelBase, ChannelId, ChannelSlot, Node, NodeConfig,
};
use crate::persist::{DummyPersister, Persist};
use crate::util::crypto_utils::signature_to_bitcoin_vec;
use crate::util::status::Status;
use crate::SendSync;
use bitcoin::hashes::Hash;
use rand::{OsRng, Rng};
use core::str::FromStr;
use crate::util::test_logger::TestLogger;

#[derive(PartialEq, Clone, Copy)]
#[repr(i32)]
pub enum SpendType {
    Invalid = 0,
    P2pkh = 1,
    P2wpkh = 3,
    P2shP2wpkh = 4,
}

impl TryFrom<i32> for SpendType {
    type Error = ();

    // BEGIN NOT TESTED
    fn try_from(i: i32) -> Result<Self, Self::Error> {
        let res = match i {
            x if x == SpendType::Invalid as i32 => SpendType::Invalid,
            x if x == SpendType::P2pkh as i32 => SpendType::P2pkh,
            x if x == SpendType::P2wpkh as i32 => SpendType::P2wpkh,
            x if x == SpendType::P2shP2wpkh as i32 => SpendType::P2shP2wpkh,
            _ => return Err(()),
        };
        Ok(res)
    }
    // END NOT TESTED
}

pub trait SyncLogger: Logger + SendSync {}

pub struct MySigner {
    pub logger: Arc<dyn SyncLogger>,
    pub(crate) nodes: Mutex<Map<PublicKey, Arc<Node>>>,
    pub(crate) persister: Box<dyn Persist>,
    pub(crate) test_mode: bool,
}

impl MySigner {
    pub(super) fn invalid_argument(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INVALID ARGUMENT: {}", &s);
        #[cfg(feature = "backtrace")]
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::invalid_argument(s)
    }

    // BEGIN NOT TESTED
    #[allow(dead_code)]
    pub(super) fn internal_error(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INTERNAL ERROR: {}", &s);
        #[cfg(feature = "backtrace")]
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::internal(s)
    }
    // END NOT TESTED

    pub fn new() -> MySigner {
        let signer = MySigner::new_with_persister(Box::new(DummyPersister), true);
        log_info!(signer, "new MySigner");
        signer
    }

    pub fn new_with_persister(persister: Box<dyn Persist>, test_mode: bool) -> MySigner {
        let test_logger: Arc<dyn SyncLogger> = Arc::new(TestLogger::with_id("server".to_owned()));
        let mut nodes = Map::new();
        println!("Start restore");
        for (node_id, node_entry) in persister.get_nodes() {
            // BEGIN NOT TESTED
            let config = NodeConfig {
                key_derivation_style: KeyDerivationStyle::try_from(node_entry.key_derivation_style)
                    .unwrap(),
            };
            let network = Network::from_str(node_entry.network.as_str()).expect("bad network");
            let node = Arc::new(Node::new(
                &test_logger,
                config,
                node_entry.seed.as_slice(),
                network,
            ));
            println!("Restore node {}", node_id);
            for (channel_id0, channel_entry) in persister.get_node_channels(&node_id) {
                println!("  Restore channel {}", channel_id0);
                node.restore_channel(
                    channel_id0,
                    channel_entry.id,
                    channel_entry.nonce,
                    channel_entry.channel_value_satoshis,
                    channel_entry.channel_setup,
                    channel_entry.enforcement_state,
                    &node,
                )
                .expect("restore channel");
            }
            nodes.insert(node_id, node);
            // END NOT TESTED
        }
        MySigner {
            logger: test_logger,
            nodes: Mutex::new(nodes),
            persister,
            test_mode,
        }
    }

    pub fn new_node(&self, node_config: NodeConfig) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        let network = Network::Testnet;
        let mut rng = OsRng::new().unwrap();

        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);

        let node = Node::new(&self.logger, node_config, &seed, network);
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node.keys_manager.get_node_secret());
        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(node_id, Arc::new(node));
        self.persister
            .new_node(&node_id, &node_config, &seed, network);
        node_id
    }

    pub fn new_node_from_seed(
        &self,
        node_config: NodeConfig,
        seed: &[u8],
    ) -> Result<PublicKey, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let network = Network::Testnet;

        let node = Node::new(&self.logger, node_config, seed, network);
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node.keys_manager.get_node_secret());
        let mut nodes = self.nodes.lock().unwrap();
        if self.test_mode {
            // In test mode we allow overwriting the node (thereby resetting all of its channels)
            self.persister.delete_node(&node_id);
        } else {
            // In production, the node must not have existed
            // BEGIN NOT TESTED
            if nodes.contains_key(&node_id) {
                return Err(self.invalid_argument("node_exists"));
            }
            // END NOT TESTED
        }
        nodes.insert(node_id, Arc::new(node));
        self.persister
            .new_node(&node_id, &node_config, seed, network);
        Ok(node_id)
    }

    pub fn get_node_ids(&self) -> Vec<PublicKey> {
        let nodes = self.nodes.lock().unwrap();
        nodes.keys().map(|k| k.clone()).collect()
    }

    /// opt_channel_nonce0 should be unique if specified, or a unique one
    /// will be generated for you.
    pub fn new_channel(
        &self,
        node_id: &PublicKey,
        opt_channel_nonce0: Option<Vec<u8>>,
        opt_channel_id: Option<ChannelId>,
    ) -> Result<ChannelId, Status> {
        log_info!(self, "new channel {}/{:?}", node_id, opt_channel_id);
        let node = self.get_node(node_id)?;
        let keys_manager = &node.keys_manager;
        let channel_id = opt_channel_id.unwrap_or_else(|| ChannelId(keys_manager.get_channel_id()));
        let channel_nonce0 = opt_channel_nonce0.unwrap_or_else(|| channel_id.0.to_vec());
        let stub = node.new_channel(channel_id, channel_nonce0, &node)?;
        stub.map(|s| {
            self.persister
                .new_channel(&node_id, &s)
                .expect("channel was in storage but not in memory")
        });
        Ok(channel_id)
    }

    pub fn warmstart_with_seed(
        &self,
        node_config: NodeConfig,
        seed: &[u8],
    ) -> Result<PublicKey, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let network = Network::Testnet;

        let node = Node::new(&self.logger, node_config, seed, network);
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node.keys_manager.get_node_secret());
        let nodes = self.nodes.lock().unwrap();
        nodes.get(&node_id).ok_or_else(|| {
            self.invalid_argument(format!("warmstart failed: no such node: {}", node_id))
        })?;
        Ok(node_id)
    }

    /// Temporary, until phase 2 is fully implemented
    // BEGIN NOT TESTED
    pub fn additional_setup(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        outpoint: OutPoint,
    ) -> Result<(), Status> {
        self.with_ready_channel(node_id, channel_id, |chan| {
            if chan.setup.funding_outpoint.is_null() {
                chan.setup.funding_outpoint = outpoint;
            } else if chan.setup.funding_outpoint != outpoint {
                panic!("funding outpoint changed");
            }
            self.persist_channel(node_id, chan);
            Ok(())
        })
    }
    // END NOT TESTED

    pub fn with_channel_base<F: Sized, T>(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        f: F,
    ) -> Result<T, Status>
    where
        F: Fn(&mut ChannelBase) -> Result<T, Status>,
    {
        let slot_arc = self.get_channel_slot(&node_id, &channel_id)?;
        let mut slot = slot_arc.lock().unwrap();
        let base = match &mut *slot {
            ChannelSlot::Stub(stub) => stub as &mut ChannelBase,
            ChannelSlot::Ready(chan) => chan as &mut ChannelBase,
        };
        f(base)
    }

    fn get_channel_slot(&self, node_id: &PublicKey, channel_id: &ChannelId) -> Result<Arc<Mutex<ChannelSlot>>, Status> {
        let node = self.get_node(node_id)?;
        // Grab a reference to the channel slot and release the channels mutex
        let mut guard = node.channels();
        let elem = guard.get_mut(channel_id);
        let slot_arc = elem.ok_or_else(|| {
            // BEGIN NOT TESTED
            self.invalid_argument(format!("no such channel: {}", &channel_id))
            // END NOT TESTED
        })?;
        Ok(Arc::clone(slot_arc))
    }

    pub fn get_node(&self, node_id: &PublicKey) -> Result<Arc<Node>, Status> {
        // Grab a reference to the node and release the nodes mutex
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id)
            .ok_or_else(|| self.invalid_argument("no such node"))?;
        Ok(Arc::clone(node))
    }

    pub fn with_ready_channel<F: Sized, T>(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        f: F,
    ) -> Result<T, Status>
    where
        F: Fn(&mut Channel) -> Result<T, Status>,
    {
        let slot_arc = self.get_channel_slot(&node_id, &channel_id)?;
        let mut slot = slot_arc.lock().unwrap();
        match &mut *slot {
            ChannelSlot::Stub(_) => {
                Err(self.invalid_argument(format!("channel not ready: {}", &channel_id)))
            }
            ChannelSlot::Ready(chan) => f(chan),
        }
    }

    // TODO this seems to be used only in tests?
    pub(crate) fn get_wallet_key(
        &self,
        secp_ctx: &Secp256k1<SignOnly>,
        node_id: &PublicKey,
        child_path: &Vec<u32>,
    ) -> Result<bitcoin::PrivateKey, Status> {
        let node = self.get_node(node_id)?;
        if child_path.len() != node.node_config.key_derivation_style.get_key_path_len() {
            // BEGIN NOT TESTED
            self.invalid_argument(format!(
                "get_wallet_key: bad child_path len : {}",
                child_path.len()
            ));
            // END NOT TESTED
        }
        // Start with the base xpriv for this wallet.
        let mut xkey = node.get_account_extended_key().clone();

        // Derive the rest of the child_path.
        for elem in child_path {
            xkey = xkey
                .ckd_priv(&secp_ctx, ChildNumber::from_normal_idx(*elem).unwrap())
                .map_err(|err| {
                    // BEGIN NOT TESTED
                    self.internal_error(format!("derive child_path failed: {}", err))
                    // END NOT TESTED
                })?;
        }
        Ok(xkey.private_key)
    }

    // TODO(devrandom) move into Node
    pub fn persist_channel(&self, node_id: &PublicKey, chan: &Channel) {
        self.persister
            .update_channel(&node_id, &chan)
            .expect("channel was in storage but not in memory");
    }

    // TODO(devrandom) does this go in Node or Channel?
    pub fn sign_funding_tx(
        &self,
        node_id: &PublicKey,
        _channel_id: &ChannelId,
        tx: &bitcoin::Transaction,
        paths: &Vec<Vec<u32>>,
        values_sat: &Vec<u64>,
        spendtypes: &Vec<SpendType>,
        uniclosekeys: &Vec<Option<SecretKey>>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Status> {
        let secp_ctx = Secp256k1::signing_only();

        let mut witvec: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for idx in 0..tx.input.len() {
            if spendtypes[idx] == SpendType::Invalid {
                // If we are signing a PSBT some of the inputs may be
                // marked as SpendType::Invalid (we skip these), push
                // an empty witness element instead.
                witvec.push((vec![], vec![]));
            } else {
                let value_sat = values_sat[idx];
                let privkey = match uniclosekeys[idx] {
                    // There was a unilateral_close_key.
                    Some(sk) => bitcoin::PrivateKey {
                        compressed: true,
                        network: Network::Testnet,
                        key: sk,
                    },
                    // Derive the HD key.
                    None => {
                        let child_path = &paths[idx];
                        self.get_wallet_key(&secp_ctx, node_id, child_path)
                            .map_err(|err| {
                                // BEGIN NOT TESTED
                                self.internal_error(format!("get_wallet_key failed: {}", err))
                                // END NOT TESTED
                            })?
                    }
                };
                let pubkey = privkey.public_key(&secp_ctx);
                let script_code = Address::p2pkh(&pubkey, privkey.network).script_pubkey();
                let sighash = match spendtypes[idx] {
                    SpendType::P2pkh => Message::from_slice(
                        &tx.signature_hash(0, &script_code, 0x01)[..],
                    )
                    .map_err(|err| self.internal_error(format!("p2pkh sighash failed: {}", err))),
                    SpendType::P2wpkh | SpendType::P2shP2wpkh => Message::from_slice(
                        &SigHashCache::new(tx).signature_hash(
                            idx,
                            &script_code,
                            value_sat,
                            SigHashType::All,
                        )[..],
                    )
                    .map_err(|err| self.internal_error(format!("p2wpkh sighash failed: {}", err))),
                    // BEGIN NOT TESTED
                    _ => Err(self.invalid_argument(format!(
                        "unsupported spend_type: {}",
                        spendtypes[idx] as i32
                    ))),
                    // END NOT TESTED
                }?;
                let sig = secp_ctx.sign(&sighash, &privkey.key);
                let sigvec = signature_to_bitcoin_vec(sig);

                witvec.push((sigvec, pubkey.key.serialize().to_vec()));
            }
        }
        // TODO(devrandom) self.persist_channel(node_id, chan);
        Ok(witvec)
    }
}

pub fn channel_nonce_to_id(nonce: &Vec<u8>) -> ChannelId {
    // Impedance mismatch - we want a 32 byte channel ID for internal use
    // Hash the client supplied channel nonce
    let hash = Sha256Hash::hash(nonce);
    ChannelId(hash.into_inner())
}

#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::sha256d::Hash as Sha256dHash;
    use bitcoin::hashes::hash160::Hash as Hash160;
    use bitcoin::hashes::ripemd160::Hash as Ripemd160Hash;
    use bitcoin::secp256k1::recovery::{RecoverableSignature, RecoveryId};
    use bitcoin::secp256k1::Signature;
    use bitcoin::secp256k1;
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::{OutPoint, TxIn, TxOut, Script};
    use lightning::ln::chan_utils::{build_htlc_transaction, get_htlc_redeemscript, get_revokeable_redeemscript, make_funding_redeemscript, HTLCOutputInCommitment, TxCreationKeys, ChannelPublicKeys};
    use lightning::ln::PaymentHash;

    use crate::node::node::{CommitmentType, ChannelSetup};
    use crate::policy::error::ValidationError;
    use crate::tx::tx::{ANCHOR_SAT, HTLCInfo2, build_close_tx};
    use crate::util::crypto_utils::{derive_public_key, derive_revocation_pubkey, payload_for_p2wpkh, derive_private_revocation_key};
    use crate::util::test_utils::*;
    use crate::util::test_utils::{
        make_test_channel_setup, make_test_counterparty_points, TEST_SEED,
    };

    use super::*;
    use crate::util::status::{Code, Status};
    use bitcoin::hashes::Hash;
    use lightning::chain::keysinterface::BaseSign;

    fn init_node(signer: &MySigner, node_config: NodeConfig, seedstr: &str) -> PublicKey {
        let mut seed = [0; 32];
        seed.copy_from_slice(hex::decode(seedstr).unwrap().as_slice());
        signer.new_node_from_seed(node_config, &seed).unwrap()
    }

    fn init_node_and_channel(
        signer: &MySigner,
        node_config: NodeConfig,
        seedstr: &str,
        setup: ChannelSetup,
    ) -> (PublicKey, ChannelId) {
        let node_id = init_node(signer, node_config, seedstr);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);
        let node = signer.get_node(&node_id).expect("node does not exist");
        signer
            .new_channel(&node_id, Some(channel_nonce), Some(channel_id))
            .expect("new_channel");
        node.ready_channel(channel_id, None, setup)
            .expect("ready channel");
        (node_id, channel_id)
    }

    #[test]
    fn channel_debug_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );
        let _status: Result<(), Status> =
            signer.with_ready_channel(&node_id, &channel_id, |chan| {
                assert_eq!(format!("{:?}", chan), "channel");
                Ok(())
            });
    }

    #[test]
    fn ready_channel_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );
        signer
            .with_ready_channel(&node_id, &channel_id, |c| {
                let signer = &c.keys.inner();
                let params = signer.get_channel_parameters();
                assert!(params.is_outbound_from_holder);
                assert_eq!(params.holder_selected_contest_delay, 6);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn ready_channel_not_exist_test() {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_nonce_x = "nonceX".as_bytes().to_vec();
        let channel_id_x = channel_nonce_to_id(&channel_nonce_x);
        let node = signer.get_node(&node_id).unwrap();
        let status: Result<_, Status> =
            node.ready_channel(channel_id_x, None, make_test_channel_setup());
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.message(),
            format!("channel does not exist: {}", &channel_id_x)
        );
    }

    #[test]
    fn ready_channel_dual_channelid_test() {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);
        signer
            .new_channel(&node_id, Some(channel_nonce), Some(channel_id))
            .expect("new_channel");

        // Issue ready_channel w/ an alternate id.
        let channel_nonce_x = "nonceX".as_bytes().to_vec();
        let channel_id_x = channel_nonce_to_id(&channel_nonce_x);
        let node = signer.get_node(&node_id).unwrap();
        node.ready_channel(
            channel_id,
            Some(channel_id_x),
            make_test_channel_setup(),
        ).expect("ready_channel");

        // Original channel_id should work with_ready_channel.
        let val = signer
            .with_ready_channel(&node_id, &channel_id, |_chan| Ok(42))
            .expect("u32");
        assert_eq!(val, 42);

        // Alternate channel_id should work with_ready_channel.
        let val_x = signer
            .with_ready_channel(&node_id, &channel_id_x, |_chan| Ok(43))
            .expect("u32");
        assert_eq!(val_x, 43);
    }

    #[test]
    fn with_ready_channel_not_exist_test() {
        let signer = MySigner::new();
        let (node_id, _channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );
        let channel_nonce_x = "nonceX".as_bytes().to_vec();
        let channel_id_x = channel_nonce_to_id(&channel_nonce_x);

        let status: Result<(), Status> =
            signer.with_ready_channel(&node_id, &channel_id_x, |_chan| Ok(()));
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), format!("no such channel: {}", &channel_id_x));
    }

    #[test]
    fn channel_invalid_argument_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );
        let status: Result<(), Status> = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            Err(chan.invalid_argument("testing invalid_argument"))
        });
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "testing invalid_argument");
    }

    #[test]
    fn channel_internal_error_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );
        let status: Result<(), Status> = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            Err(chan.internal_error("testing internal_error"))
        });
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::Internal);
        assert_eq!(err.message(), "testing internal_error");
    }

    #[test]
    fn channel_validation_error_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );
        let status: Result<(), Status> = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            Err(chan.validation_error(ValidationError::Policy("testing".to_string())))
        });
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.message(), "policy failure: testing");
    }

    #[test]
    fn node_debug_test() {
        let signer = MySigner::new();
        let (node_id, _channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );
        let node = signer.get_node(&node_id).unwrap();
        assert_eq!(format!("{:?}", node), "node");
    }

    #[test]
    fn node_invalid_argument_test() {
        let signer = MySigner::new();
        let (node_id, _channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );
        let node = signer.get_node(&node_id).unwrap();
        let err = node.invalid_argument("testing invalid_argument");

        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "testing invalid_argument");
    }

    #[test]
    fn node_internal_error_test() {
        let signer = MySigner::new();
        let (node_id, _channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );
        let node = signer.get_node(&node_id).unwrap();
        let err = node.internal_error("testing internal_error");

        assert_eq!(err.code(), Code::Internal);
        assert_eq!(err.message(), "testing internal_error");
    }

    #[test]
    fn channel_stub_test() {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);
        signer
            .new_channel(&node_id, Some(channel_nonce), Some(channel_id))
            .expect("new_channel");

        // with_ready_channel should return not ready.
        let result: Result<(), Status> =
            signer.with_ready_channel(&node_id, &channel_id, |_chan| {
                // BEGIN NOT TESTED
                assert!(false); // shouldn't get here
                Ok(())
                // END NOT TESTED
            });
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.message(),
            format!("channel not ready: {}", TEST_CHANNEL_ID[0]),
        );

        // get_per_commitment_{point,secret} should work.
        let _: Result<(), Status> = signer.with_channel_base(&node_id, &channel_id, |base| {
            let point = base.get_per_commitment_point(1);
            let secret = base.get_per_commitment_secret(1);
            let derived_point = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
            assert_eq!(point, derived_point);
            Ok(())
        });

        let basepoints = signer.with_channel_base(&node_id, &channel_id, |base| {
            Ok(base.get_channel_basepoints())
        }).unwrap();
        // get_channel_basepoints should work.
        check_basepoints(&basepoints);

        // check_future_secret should work.
        let n: u64 = 10;
        let suggested = SecretKey::from_slice(
            hex::decode("4220531d6c8b15d66953c46b5c4d67c921943431452d5543d8805b9903c6b858")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let correct = signer.with_channel_base(&node_id, &channel_id, |base| {
            let secret = base.get_per_commitment_secret(n);
            Ok(suggested[..] == secret[..])
        }).unwrap();
        assert_eq!(correct, true);

        let notcorrect = signer.with_channel_base(&node_id, &channel_id, |base| {
            let secret = base.get_per_commitment_secret(n+1);
            Ok(suggested[..] == secret[..])
        }).unwrap();
        assert_eq!(notcorrect, false);
    }

    #[ignore] // Ignore this test while we allow extra NewChannel calls.
    // BEGIN NOT TESTED
    #[test]
    fn node_new_channel_already_exists_test() {
        let signer = MySigner::new();
        let (node_id, _channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        // Try and create the channel again.
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);
        let result = signer.new_channel(&node_id, Some(channel_nonce), Some(channel_id));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.message(),
            format!("channel already exists: {}", TEST_CHANNEL_ID[0])
        );
    }
    // END NOT TESTED

    #[test]
    fn ready_channel_already_ready_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        let node = signer.get_node(&node_id).unwrap();
        // Trying to ready it again should fail.
        let result = node.ready_channel(channel_id, None, make_test_channel_setup());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.message(),
            format!("channel already ready: {}", TEST_CHANNEL_ID[0])
        );
    }

    #[test]
    fn warmstart_with_seed_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(hex::decode(TEST_SEED[1]).unwrap().as_slice());

        // First try a warmstart w/ no existing node.
        let result = signer.warmstart_with_seed(TEST_NODE_CONFIG, &seed);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "warmstart failed: no such node: 022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59");

        // Then a "coldstart" from seed should succeed.
        let node_id = signer.new_node_from_seed(TEST_NODE_CONFIG, &seed).unwrap();

        // Now a warmstart will work, should get the same node_id.
        let result = signer.warmstart_with_seed(TEST_NODE_CONFIG, &seed);
        assert!(!result.is_err());
        assert_eq!(result.unwrap(), node_id);
    }

    #[test]
    fn sign_counterparty_commitment_tx_test() {
        let signer = MySigner::new();
        let setup = make_static_test_channel_setup();
        let (node_id, channel_id) =
            init_node_and_channel(&signer, TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());
        let remote_percommitment_point = make_test_pubkey(10);
        let counterparty_points = make_test_counterparty_points();
        let (ser_signature, tx) = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let channel_parameters = chan.make_channel_parameters();
                let parameters = channel_parameters.as_counterparty_broadcastable();
                let mut htlcs = vec![];
                let keys = chan
                    .make_counterparty_tx_keys(&remote_percommitment_point)
                    .unwrap();
                let redeem_scripts =
                    build_tx_scripts(&keys, 100, 197, &mut htlcs, &parameters).expect("scripts");
                let commit_num = 23;
                let feerate_per_kw = 0;
                let commitment_tx = chan.make_counterparty_commitment_tx(
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    200,
                    100,
                    htlcs,
                );
                // rebuild to get the scripts
                let trusted_tx = commitment_tx.trust();
                let tx = trusted_tx.built_transaction();
                let output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();
                let payment_hashmap = Map::new();
                let ser_signature = chan
                    .sign_counterparty_commitment_tx(
                        &tx.transaction,
                        &output_witscripts,
                        &remote_percommitment_point,
                        setup.channel_value_sat,
                        &payment_hashmap,
                        commit_num,
                    )
                    .expect("sign");
                Ok((ser_signature, tx.transaction.clone()))
            })
            .expect("build_commitment_tx");

        assert_eq!(
            hex::encode(tx.txid()),
            "af218d148bec83f7091c18898718bfe3553f158178b869347a3b41e4b9be34e2"
        );

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }

    #[test]
    #[ignore] // we don't support anchors yet
              // BEGIN NOT TESTED
    fn sign_counterparty_commitment_tx_with_anchors_test() {
        let signer = MySigner::new();
        let mut setup = make_reasonable_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let (node_id, channel_id) =
            init_node_and_channel(&signer, TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());
        let remote_percommitment_point = make_test_pubkey(10);
        let counterparty_points = make_test_counterparty_points();
        let to_counterparty_value_sat = 2_000_000;
        let to_holder_value_sat =
            setup.channel_value_sat - to_counterparty_value_sat - (2 * ANCHOR_SAT);
        let (ser_signature, tx) = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let info = chan.build_counterparty_commitment_info(
                    &remote_percommitment_point,
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    vec![],
                    vec![],
                )?;
                let commit_num = 23;
                let (tx, output_scripts, _) =
                    chan.build_commitment_tx(&remote_percommitment_point, commit_num, &info)?;
                let output_witscripts = output_scripts.iter().map(|s| s.serialize()).collect();
                let payment_hashmap = Map::new();
                let ser_signature = chan
                    .sign_counterparty_commitment_tx(
                        &tx,
                        &output_witscripts,
                        &remote_percommitment_point,
                        setup.channel_value_sat,
                        &payment_hashmap,
                        commit_num,
                    )
                    .expect("sign");
                Ok((ser_signature, tx))
            })
            .expect("build_commitment_tx");

        assert_eq!(
            hex::encode(tx.txid()),
            "68a0916cea22e66438f0cd2c50f667866ebd16f59ba395352602bd817d6c0fd9"
        );

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }
    // END NOT TESTED

    #[test]
    fn sign_counterparty_commitment_tx_with_htlc_test() {
        let signer = MySigner::new();
        let setup = make_static_test_channel_setup();
        let (node_id, channel_id) =
            init_node_and_channel(&signer, TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let remote_percommitment_point = make_test_pubkey(10);
        let counterparty_points = make_test_counterparty_points();

        let htlc1 = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1000,
            payment_hash: PaymentHash([1; 32]),
            cltv_expiry: 2 << 16,
            transaction_output_index: None,
        };

        let htlc2 = HTLCOutputInCommitment {
            offered: false,
            amount_msat: 1000,
            payment_hash: PaymentHash([3; 32]),
            cltv_expiry: 3 << 16,
            transaction_output_index: None,
        };

        let htlc3 = HTLCOutputInCommitment {
            offered: false,
            amount_msat: 1000,
            payment_hash: PaymentHash([5; 32]),
            cltv_expiry: 4 << 16,
            transaction_output_index: None,
        };

        let (ser_signature, tx) = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let channel_parameters = chan.make_channel_parameters();
                let parameters = channel_parameters.as_counterparty_broadcastable();
                let mut htlcs = vec![htlc1.clone(), htlc2.clone(), htlc3.clone()];
                let mut payment_hashmap = Map::new();
                for htlc in &htlcs {
                    payment_hashmap.insert(
                        Ripemd160Hash::hash(&htlc.payment_hash.0).into_inner(),
                        htlc.payment_hash,
                    );
                }
                let keys = chan
                    .make_counterparty_tx_keys(&remote_percommitment_point)
                    .unwrap();
                let redeem_scripts =
                    build_tx_scripts(&keys, 100, 197, &mut htlcs, &parameters).expect("scripts");
                let commit_num = 23;
                let feerate_per_kw = 0;
                let commitment_tx = chan.make_counterparty_commitment_tx(
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    197,
                    100,
                    htlcs,
                );
                // rebuild to get the scripts
                let trusted_tx = commitment_tx.trust();
                let tx = trusted_tx.built_transaction();
                let output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();
                let ser_signature = chan
                    .sign_counterparty_commitment_tx(
                        &tx.transaction,
                        &output_witscripts,
                        &remote_percommitment_point,
                        setup.channel_value_sat,
                        &payment_hashmap,
                        commit_num,
                    )
                    .expect("sign");
                Ok((ser_signature, tx.transaction.clone()))
            })
            .expect("build_commitment_tx");

        assert_eq!(
            hex::encode(tx.txid()),
            "433e14a7560ffe7d724267c2c0068c2e183e06057004407dda1bd863160ae5b6"
        );

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }

    #[test]
    #[ignore] // we don't support anchors yet
              // BEGIN NOT TESTED
    fn sign_counterparty_commitment_tx_with_htlc_and_anchors_test() {
        let signer = MySigner::new();
        let mut setup = make_reasonable_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let (node_id, channel_id) =
            init_node_and_channel(&signer, TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let remote_percommitment_point = make_test_pubkey(10);
        let counterparty_points = make_test_counterparty_points();

        let htlc1 = HTLCInfo2 {
            value_sat: 1,
            payment_hash: PaymentHash([1; 32]),
            cltv_expiry: 2 << 16,
        };

        let htlc2 = HTLCInfo2 {
            value_sat: 1,
            payment_hash: PaymentHash([3; 32]),
            cltv_expiry: 3 << 16,
        };

        let htlc3 = HTLCInfo2 {
            value_sat: 1,
            payment_hash: PaymentHash([5; 32]),
            cltv_expiry: 4 << 16,
        };

        let to_counterparty_value_sat = 2_000_000;
        let to_holder_value_sat =
            setup.channel_value_sat - to_counterparty_value_sat - 3 - (2 * ANCHOR_SAT);

        let mut payment_hashmap = Map::new();
        for htlc in &vec![htlc1.clone(), htlc2.clone(), htlc3.clone()] {
            payment_hashmap.insert(
                Ripemd160Hash::hash(&htlc.payment_hash.0).into_inner(),
                htlc.payment_hash,
            );
        }

        let (ser_signature, tx) = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let info = chan.build_counterparty_commitment_info(
                    &remote_percommitment_point,
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    vec![htlc1.clone()],
                    vec![htlc2.clone(), htlc3.clone()],
                )?;
                let commit_num = 23;
                let (tx, output_scripts, _) =
                    chan.build_commitment_tx(&remote_percommitment_point, commit_num, &info)?;
                let output_witscripts = output_scripts.iter().map(|s| s.serialize()).collect();
                let ser_signature = chan
                    .sign_counterparty_commitment_tx(
                        &tx,
                        &output_witscripts,
                        &remote_percommitment_point,
                        setup.channel_value_sat,
                        &payment_hashmap,
                        commit_num,
                    )
                    .expect("sign");
                Ok((ser_signature, tx))
            })
            .expect("build_commitment_tx");

        assert_eq!(
            hex::encode(tx.txid()),
            "52aa09518edbdbd77ca56790efbb9392710c3bed10d7d27b04d98f6f6d8a207d"
        );

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }
    // END NOT TESTED

    #[test]
    fn sign_counterparty_commitment_tx_phase2_test() {
        let signer = MySigner::new();
        let setup = make_static_test_channel_setup();
        let (node_id, channel_id) =
            init_node_and_channel(&signer, TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let remote_percommitment_point = make_test_pubkey(10);
        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);

        let tx = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let commitment_tx = chan.make_counterparty_commitment_tx(
                    &remote_percommitment_point,
                    23,
                    0,
                    100,
                    200,
                    vec![],
                );
                let trusted_tx = commitment_tx.trust();
                let tx = trusted_tx.built_transaction();
                assert_eq!(
                    hex::encode(tx.txid),
                    "eca4bec8c50a4498c5fa5cb34ec4aaafc3b46e879a3cdad6ab4954922e08cabd"
                );
                Ok(tx.transaction.clone())
            })
            .expect("build");
        let (ser_signature, _) = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            chan.sign_counterparty_commitment_tx_phase2(
                &remote_percommitment_point,
                23,
                0, // we are not looking at HTLCs yet
                100,
                200,
                vec![],
                vec![],
            )
        }).expect("sign");
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &setup.counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }

    #[test]
    fn sign_holder_commitment_tx_phase2_test() {
        let signer = MySigner::new();
        let setup = make_static_test_channel_setup();
        let (node_id, channel_id) =
            init_node_and_channel(&signer, TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let tx = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let commitment_tx = chan.make_holder_commitment_tx(23, 0, 100, 200, vec![]);
                Ok(commitment_tx
                    .trust()
                    .built_transaction()
                    .transaction
                    .clone())
            })
            .expect("build");
        let (ser_signature, _) = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            chan.sign_holder_commitment_tx_phase2(
                23,
                0, // feerate not used
                100,
                200,
                vec![],
                vec![],
            )})
            .expect("sign");
        assert_eq!(
            hex::encode(tx.txid()),
            "57ac467fdcf17d64c6c6a4d37e6b4b618cc688f69dc56698bc9ac0a874a5ae1c"
        );

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &setup.counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }

    #[test]
    fn sign_mutual_close_tx_phase2_test() {
        // We can't use init_node_and_channel here because we need the node_id to construct
        // the ChannelSetup.
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = signer
            .new_channel(&node_id, Some(channel_nonce), None)
            .expect("new_channel");

        let mut setup = make_test_channel_setup();
        setup.counterparty_shutdown_script =
            payload_for_p2wpkh(&make_test_pubkey(11)).script_pubkey();

        let node = signer.get_node(&node_id).unwrap();
        let local_shutdown_script =
            payload_for_p2wpkh(&node.get_shutdown_pubkey())
                .script_pubkey();

        let node = signer.get_node(&node_id).unwrap();
        node.ready_channel(channel_id, None, setup.clone())
            .expect("ready channel");

        let tx = {
            build_close_tx(
                100,
                200,
                &local_shutdown_script,
                &setup.counterparty_shutdown_script,
                setup.funding_outpoint,
            )
        };
        let ser_signature =
            signer.with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_mutual_close_tx_phase2(
                    100,
                    200,
                    Some(setup.counterparty_shutdown_script.clone())
                ).unwrap();
                Ok(signature_to_bitcoin_vec(sig))
            }).expect("sign");
        assert_eq!(
            hex::encode(tx.txid()),
            "7d1618688e8a9a4cc09c94f5385a05c92a8b6662ac6e7e77eeb19a0e19070a56"
        );

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &setup.counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }

    fn get_channel_funding_pubkey(
        signer: &MySigner,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> PublicKey {
        let res: Result<PublicKey, Status> =
            signer.with_ready_channel(&node_id, &channel_id, |chan| {
                Ok(chan.keys.pubkeys().funding_pubkey)
            });
        res.unwrap()
    }

    fn get_channel_htlc_pubkey(
        signer: &MySigner,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        remote_per_commitment_point: &PublicKey,
    ) -> PublicKey {
        let res: Result<PublicKey, Status> =
            signer.with_ready_channel(&node_id, &channel_id, |chan| {
                let secp_ctx = &chan.secp_ctx;
                let pubkey = derive_public_key(
                    &secp_ctx,
                    &remote_per_commitment_point,
                    &chan.keys.pubkeys().htlc_basepoint,
                )
                .unwrap();
                Ok(pubkey)
            });
        res.unwrap()
    }

    fn get_channel_delayed_payment_pubkey(
        signer: MySigner,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        remote_per_commitment_point: &PublicKey,
    ) -> PublicKey {
        let res: Result<PublicKey, Status> =
            signer.with_ready_channel(&node_id, &channel_id, |chan| {
                let secp_ctx = &chan.secp_ctx;
                let pubkey = derive_public_key(
                    &secp_ctx,
                    &remote_per_commitment_point,
                    &chan.keys.pubkeys().delayed_payment_basepoint,
                )
                .unwrap();
                Ok(pubkey)
            });
        res.unwrap()
    }

    fn get_channel_revocation_pubkey(
        signer: MySigner,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        revocation_point: &PublicKey,
    ) -> PublicKey {
        let res: Result<PublicKey, Status> =
            signer.with_ready_channel(&node_id, &channel_id, |chan| {
                let secp_ctx = &chan.secp_ctx;
                let pubkey = derive_revocation_pubkey(
                    secp_ctx,
                    revocation_point, // matches revocation_secret
                    &chan.keys.pubkeys().revocation_basepoint,
                )
                .unwrap();
                Ok(pubkey)
            });
        res.unwrap()
    }

    fn check_signature(
        tx: &bitcoin::Transaction,
        input: usize,
        ser_signature: Vec<u8>,
        pubkey: &PublicKey,
        input_value_sat: u64,
        redeemscript: &Script,
    ) {
        check_signature_with_setup(
            tx,
            input,
            ser_signature,
            pubkey,
            input_value_sat,
            redeemscript,
            &make_test_channel_setup(),
        ) // NOT TESTED
    }

    fn check_signature_with_setup(
        tx: &bitcoin::Transaction,
        input: usize,
        ser_signature: Vec<u8>,
        pubkey: &PublicKey,
        input_value_sat: u64,
        redeemscript: &Script,
        setup: &ChannelSetup,
    ) {
        let sig_hash_type = if setup.option_anchor_outputs() {
            SigHashType::SinglePlusAnyoneCanPay
        } else {
            SigHashType::All
        };

        let sighash = Message::from_slice(
            &SigHashCache::new(tx).signature_hash(
                input,
                &redeemscript,
                input_value_sat,
                sig_hash_type,
            )[..],
        )
        .expect("sighash");
        let mut der_signature = ser_signature.clone();
        der_signature.pop(); // Pop the sighash type byte
        let signature = Signature::from_der(&der_signature).expect("from_der");
        let secp_ctx = Secp256k1::new();
        secp_ctx
            .verify(&sighash, &signature, &pubkey)
            .expect("verify");
    }

    #[test]
    fn new_channel_test() {
        let signer = MySigner::new();
        let node_id = signer.new_node(TEST_NODE_CONFIG);
        let channel_id = signer.new_channel(&node_id, None, None).unwrap();
        assert!(signer.get_node(&node_id).is_ok());
        assert!(signer.get_channel_slot(&node_id, &channel_id).is_ok());
    }

    #[test]
    fn bad_channel_lookup_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = signer.new_node(TEST_NODE_CONFIG);
        let channel_id = ChannelId([1; 32]);
        assert!(signer.get_channel_slot(&node_id, &channel_id).is_err());
        Ok(())
    }

    #[test]
    fn bad_node_lookup_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = pubkey_from_secret_hex(
            "0101010101010101010101010101010101010101010101010101010101010101",
            &secp_ctx,
        );

        let channel_id = ChannelId([1; 32]);
        assert!(signer.get_channel_slot(&node_id, &channel_id).is_err());
        assert!(signer.get_node(&node_id).is_err());

        Ok(())
    }

    #[test]
    fn new_channel_bad_node_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = pubkey_from_secret_hex(
            "0101010101010101010101010101010101010101010101010101010101010101",
            &secp_ctx,
        );
        assert!(signer.new_channel(&node_id, None, None).is_err());
        Ok(())
    }

    fn check_basepoints(basepoints: &ChannelPublicKeys) {
        assert_eq!(
            hex::encode(basepoints.funding_pubkey.serialize().to_vec()),
            "02868b7bc9b6d307509ed97758636d2d3628970bbd3bd36d279f8d3cde8ccd45ae"
        );
        assert_eq!(
            hex::encode(basepoints.revocation_basepoint.serialize().to_vec()),
            "02982b69bb2d70b083921cbc862c0bcf7761b55d7485769ddf81c2947155b1afe4"
        );
        assert_eq!(
            hex::encode(basepoints.payment_point.serialize().to_vec()),
            "026bb6655b5e0b5ff80d078d548819f57796013b09de8085ddc04b49854ae1e483"
        );
        assert_eq!(
            hex::encode(basepoints.delayed_payment_basepoint.serialize().to_vec()),
            "0291dfb201bc87a2da8c7ffe0a7cf9691962170896535a7fd00d8ee4406a405e98"
        );
        assert_eq!(
            hex::encode(basepoints.htlc_basepoint.serialize().to_vec()),
            "02c0c8ff7278e50bd07d7b80c109621d44f895e216400a7e95b09f544eb3fafee2"
        );
    }

    #[test]
    fn get_channel_basepoints_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        let basepoints = signer.with_channel_base(&node_id, &channel_id, |base| {
            Ok(base.get_channel_basepoints())
        }).unwrap();

        check_basepoints(&basepoints);
    }

    #[test]
    fn get_per_commitment_point_and_secret_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        let (point, secret) = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                Ok((
                    chan.get_per_commitment_point(1),
                    chan.get_per_commitment_secret(1),
                ))
            })
            .expect("point");

        let derived_point = PublicKey::from_secret_key(&Secp256k1::new(), &secret);

        assert_eq!(point, derived_point);
    }

    #[test]
    fn get_check_future_secret_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        let n: u64 = 10;

        let suggested = SecretKey::from_slice(
            hex::decode("4220531d6c8b15d66953c46b5c4d67c921943431452d5543d8805b9903c6b858")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let correct = signer.with_channel_base(&node_id, &channel_id, |base| {
            let secret = base.get_per_commitment_secret(n);
            Ok(suggested[..] == secret[..])
        }).unwrap();
        assert_eq!(correct, true);

        let notcorrect = signer.with_channel_base(&node_id, &channel_id, |base| {
            let secret = base.get_per_commitment_secret(n+1);
            Ok(suggested[..] == secret[..])
        }).unwrap();
        assert_eq!(notcorrect, false);
    }

    #[test]
    fn sign_funding_tx_p2wpkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node(TEST_NODE_CONFIG);
        let channel_id = ChannelId([1; 32]);
        let indices = vec![vec![0u32], vec![1u32]];
        let values_sat = vec![100u64, 200u64];

        let input1 = TxIn {
            previous_output: OutPoint {
                txid: Default::default(),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let input2 = TxIn {
            previous_output: OutPoint {
                txid: Default::default(),
                vout: 1,
            },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };
        let mut tx = make_test_funding_tx(vec![input1, input2], 300);
        let spendtypes = vec![SpendType::P2wpkh, SpendType::P2wpkh];
        let uniclosekeys = vec![None, None];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 2);

        let address = |n: u32| {
            Address::p2wpkh(
                &signer
                    .get_wallet_key(&secp_ctx, &node_id, &vec![n])
                    .unwrap()
                    .public_key(&secp_ctx),
                Network::Testnet,
            )
            .unwrap()
        };

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];
        tx.input[1].witness = vec![witvec[1].0.clone(), witvec[1].1.clone()];

        let outs = vec![
            TxOut {
                value: 100,
                script_pubkey: address(0).script_pubkey(),
            },
            TxOut {
                value: 200,
                script_pubkey: address(1).script_pubkey(),
            },
        ];
        println!("{:?}", address(0).script_pubkey());
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2wpkh_test1() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node(TEST_NODE_CONFIG);
        let channel_id = ChannelId([1; 32]);
        let txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let indices = vec![vec![0u32]];
        let values_sat = vec![100u64];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let mut tx = make_test_funding_tx(vec![input1], 100);
        let spendtypes = vec![SpendType::P2wpkh];
        let uniclosekeys = vec![None];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        let address = |n: u32| {
            Address::p2wpkh(
                &signer
                    .get_wallet_key(&secp_ctx, &node_id, &vec![n])
                    .unwrap()
                    .public_key(&secp_ctx),
                Network::Testnet,
            )
            .unwrap()
        };

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];

        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: 100,
            script_pubkey: address(0).script_pubkey(),
        }]; // NOT TESTED
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_unilateral_close_info_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node(TEST_NODE_CONFIG);
        let channel_id = ChannelId([1; 32]);
        let txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let indices = vec![vec![0u32]];
        let values_sat = vec![100u64];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let mut tx = make_test_funding_tx(vec![input1], 200);
        let spendtypes = vec![SpendType::P2wpkh];

        let uniclosekey = SecretKey::from_slice(
            hex::decode("4220531d6c8b15d66953c46b5c4d67c921943431452d5543d8805b9903c6b858")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let uniclosepubkey = bitcoin::PublicKey::from_slice(
            &PublicKey::from_secret_key(&secp_ctx, &uniclosekey).serialize()[..],
        )
        .unwrap();
        let uniclosekeys = vec![Some(uniclosekey)];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        assert_eq!(witvec[0].1, uniclosepubkey.serialize());

        let address = Address::p2wpkh(&uniclosepubkey, Network::Testnet).unwrap();

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];
        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: 100,
            script_pubkey: address.script_pubkey(),
        }];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2pkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node(TEST_NODE_CONFIG);
        let channel_id = ChannelId([1; 32]);
        let txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let indices = vec![vec![0u32]];
        let values_sat = vec![100u64];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let mut tx = make_test_funding_tx(vec![input1], 100);
        let spendtypes = vec![SpendType::P2pkh];
        let uniclosekeys = vec![None];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        let address = |n: u32| {
            Address::p2pkh(
                &signer
                    .get_wallet_key(&secp_ctx, &node_id, &vec![n])
                    .unwrap()
                    .public_key(&secp_ctx),
                Network::Testnet,
            )
        };

        tx.input[0].script_sig = Builder::new()
            .push_slice(witvec[0].0.as_slice())
            .push_slice(witvec[0].1.as_slice())
            .into_script();
        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: 100,
            script_pubkey: address(0).script_pubkey(),
        }]; // NOT TESTED
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));
        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2sh_p2wpkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node(TEST_NODE_CONFIG);
        let channel_id = ChannelId([1; 32]);
        let txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let indices = vec![vec![0u32]];
        let values_sat = vec![100u64];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let mut tx = make_test_funding_tx(vec![input1], 100);
        let spendtypes = vec![SpendType::P2shP2wpkh];
        let uniclosekeys = vec![None];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        let address = |n: u32| {
            Address::p2shwpkh(
                &signer
                    .get_wallet_key(&secp_ctx, &node_id, &vec![n])
                    .unwrap()
                    .public_key(&secp_ctx),
                Network::Testnet,
            )
            .unwrap()
        };

        let pubkey = &signer
            .get_wallet_key(&secp_ctx, &node_id, &indices[0])
            .unwrap()
            .public_key(&secp_ctx);

        let keyhash = Hash160::hash(&pubkey.serialize()[..]);

        tx.input[0].script_sig = Builder::new()
            .push_slice(
                Builder::new()
                    .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                    .push_slice(&keyhash.into_inner())
                    .into_script()
                    .as_bytes(),
            )
            .into_script();

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];

        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: 100,
            script_pubkey: address(0).script_pubkey(),
        }]; // NOT TESTED
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_psbt_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = signer.new_node(TEST_NODE_CONFIG);
        let channel_id = ChannelId([1; 32]);
        let txids = vec![
            bitcoin::Txid::from_slice(&[2u8; 32]).unwrap(),
            bitcoin::Txid::from_slice(&[4u8; 32]).unwrap(),
            bitcoin::Txid::from_slice(&[6u8; 32]).unwrap(),
        ];

        let inputs = vec![
            TxIn {
                previous_output: OutPoint {
                    txid: txids[0],
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }, // NOT TESTED
            TxIn {
                previous_output: OutPoint {
                    txid: txids[1],
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }, // NOT TESTED
            TxIn {
                previous_output: OutPoint {
                    txid: txids[2],
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }, // NOT TESTED
        ];

        let tx = make_test_funding_tx(inputs, 100);
        let indices = vec![vec![0u32], vec![1u32], vec![2u32]];
        let values_sat = vec![100u64, 101u64, 102u64];
        let spendtypes = vec![
            SpendType::Invalid,
            SpendType::P2shP2wpkh,
            SpendType::Invalid,
        ];
        let uniclosekeys = vec![None, None, None];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        // Should have three witness stack items.
        assert_eq!(witvec.len(), 3);

        // First item should be empty sig/pubkey.
        assert_eq!(witvec[0].0.len(), 0);
        assert_eq!(witvec[0].1.len(), 0);

        // Second should have values.
        assert!(witvec[1].0.len() > 0);
        assert!(witvec[1].1.len() > 0);

        // Third should be empty.
        assert_eq!(witvec[2].0.len(), 0);
        assert_eq!(witvec[2].1.len(), 0);

        // Doesn't verify, not fully signed.
        Ok(())
    }

    #[test]
    fn sign_local_htlc_tx_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let secp_ctx_all = Secp256k1::new();

        let n: u64 = 1;

        let per_commitment_point = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                Ok(chan.get_per_commitment_point(n))
            })
            .expect("point");

        let a_delayed_payment_base = make_test_pubkey(2);
        let b_revocation_base = make_test_pubkey(3);

        let keys = TxCreationKeys::derive_new(
            &secp_ctx_all,
            &per_commitment_point,
            &a_delayed_payment_base,
            &make_test_pubkey(4), // a_htlc_base
            &b_revocation_base,
            &make_test_pubkey(6),
        ) // b_htlc_base
        .expect("new TxCreationKeys");

        let a_delayed_payment_key = derive_public_key(
            &secp_ctx_all,
            &per_commitment_point,
            &a_delayed_payment_base,
        )
        .expect("a_delayed_payment_key");

        let revocation_key =
            derive_revocation_pubkey(&secp_ctx_all, &per_commitment_point, &b_revocation_base)
                .expect("revocation_key");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);

        let htlc_amount_sat = 10 * 1000;

        let htlc_pubkey =
            get_channel_htlc_pubkey(&signer, &node_id, &channel_id, &per_commitment_point);

        let sigvec = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            let sig = chan.sign_holder_htlc_tx(
                &htlc_tx,
                n,
                None,
                &htlc_redeemscript,
                htlc_amount_sat,
            ).unwrap();
            Ok(signature_to_bitcoin_vec(sig))
        }).unwrap();

        check_signature(
            &htlc_tx,
            0,
            sigvec,
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
        );

        let sigvec1 = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            let sig = chan.sign_holder_htlc_tx(
                &htlc_tx,
                999,
                Some(per_commitment_point),
                &htlc_redeemscript,
                htlc_amount_sat,
            ).unwrap();
            Ok(signature_to_bitcoin_vec(sig))
        }).unwrap();

        check_signature(
            &htlc_tx,
            0,
            sigvec1,
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
        );
    }

    #[test]
    fn sign_delayed_sweep_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let secp_ctx_all = Secp256k1::new();

        let n: u64 = 1;

        let per_commitment_point = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                Ok(chan.get_per_commitment_point(n))
            })
            .expect("point");

        let a_delayed_payment_base = make_test_pubkey(2);
        let b_revocation_base = make_test_pubkey(3);

        let a_delayed_payment_key = derive_public_key(
            &secp_ctx_all,
            &per_commitment_point,
            &a_delayed_payment_base,
        )
        .expect("a_delayed_payment_key");

        let revocation_pubkey =
            derive_revocation_pubkey(&secp_ctx_all, &per_commitment_point, &b_revocation_base)
                .expect("revocation_pubkey");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_pubkey,
        );

        let redeemscript =
            get_revokeable_redeemscript(&revocation_pubkey, to_self_delay, &a_delayed_payment_key);

        let htlc_amount_sat = 10 * 1000;

        let sigvec =
            signer.with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_delayed_sweep(
                    &htlc_tx,
                    0,
                    n,
                    &redeemscript,
                    htlc_amount_sat)
                    .unwrap();
                Ok(signature_to_bitcoin_vec(sig))
            }).unwrap();

        let htlc_pubkey = get_channel_delayed_payment_pubkey(
            signer,
            &node_id,
            &channel_id,
            &per_commitment_point,
        );

        check_signature(
            &htlc_tx,
            0,
            sigvec,
            &htlc_pubkey,
            htlc_amount_sat,
            &redeemscript,
        );
    }

    #[test]
    fn sign_remote_htlc_tx_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let remote_per_commitment_point = make_test_pubkey(10);

        let per_commitment_point = make_test_pubkey(1);
        let a_delayed_payment_base = make_test_pubkey(2);
        let b_revocation_base = make_test_pubkey(3);

        let secp_ctx = Secp256k1::new();

        let keys = TxCreationKeys::derive_new(
            &secp_ctx,
            &per_commitment_point,
            &a_delayed_payment_base,
            &make_test_pubkey(4), // a_htlc_base
            &b_revocation_base,
            &make_test_pubkey(6),
        ) // b_htlc_base
        .expect("new TxCreationKeys");

        let a_delayed_payment_key =
            derive_public_key(&secp_ctx, &per_commitment_point, &a_delayed_payment_base)
                .expect("a_delayed_payment_key");

        let revocation_key =
            derive_revocation_pubkey(&secp_ctx, &per_commitment_point, &b_revocation_base)
                .expect("revocation_key");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);

        let htlc_amount_sat = 10 * 1000;

        let ser_signature = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            let sig = chan.sign_counterparty_htlc_tx(
                &htlc_tx,
                &remote_per_commitment_point,
                &htlc_redeemscript,
                htlc_amount_sat
            ).unwrap();
            Ok(signature_to_bitcoin_vec(sig))
        }).unwrap();

        let htlc_pubkey =
            get_channel_htlc_pubkey(&signer, &node_id, &channel_id, &remote_per_commitment_point);

        check_signature(
            &htlc_tx,
            0,
            ser_signature,
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
        );
    }

    #[test]
    fn sign_remote_htlc_tx_with_anchors_test() {
        let signer = MySigner::new();
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let (node_id, channel_id) =
            init_node_and_channel(&signer, TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let remote_per_commitment_point = make_test_pubkey(10);

        let per_commitment_point = make_test_pubkey(1);
        let a_delayed_payment_base = make_test_pubkey(2);
        let b_revocation_base = make_test_pubkey(3);

        let secp_ctx = Secp256k1::new();

        let keys = TxCreationKeys::derive_new(
            &secp_ctx,
            &per_commitment_point,
            &a_delayed_payment_base,
            &make_test_pubkey(4), // a_htlc_base
            &b_revocation_base,
            &make_test_pubkey(6),
        ) // b_htlc_base
        .expect("new TxCreationKeys");

        let a_delayed_payment_key =
            derive_public_key(&secp_ctx, &per_commitment_point, &a_delayed_payment_base)
                .expect("a_delayed_payment_key");

        let revocation_key =
            derive_revocation_pubkey(&secp_ctx, &per_commitment_point, &b_revocation_base)
                .expect("revocation_key");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);

        let htlc_amount_sat = 10 * 1000;

        let ser_signature = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            let sig = chan.sign_counterparty_htlc_tx(
                &htlc_tx,
                &remote_per_commitment_point,
                &htlc_redeemscript,
                htlc_amount_sat
            ).unwrap();
            Ok(signature_to_bitcoin_vec(sig))
        }).unwrap();

        let htlc_pubkey =
            get_channel_htlc_pubkey(&signer, &node_id, &channel_id, &remote_per_commitment_point);

        check_signature_with_setup(
            &htlc_tx,
            0,
            ser_signature,
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
            &setup,
        );
    }

    #[test]
    fn sign_counterparty_htlc_sweep_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let remote_per_commitment_point = make_test_pubkey(10);

        let per_commitment_point = make_test_pubkey(1);
        let a_delayed_payment_base = make_test_pubkey(2);
        let b_revocation_base = make_test_pubkey(3);

        let secp_ctx = Secp256k1::new();

        let keys = TxCreationKeys::derive_new(
            &secp_ctx,
            &per_commitment_point,
            &a_delayed_payment_base,
            &make_test_pubkey(4), // a_htlc_base
            &b_revocation_base,
            &make_test_pubkey(6),
        ) // b_htlc_base
        .expect("new TxCreationKeys");

        let a_delayed_payment_key =
            derive_public_key(&secp_ctx, &per_commitment_point, &a_delayed_payment_base)
                .expect("a_delayed_payment_key");

        let revocation_key =
            derive_revocation_pubkey(&secp_ctx, &per_commitment_point, &b_revocation_base)
                .expect("revocation_key");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);

        let htlc_amount_sat = 10 * 1000;

        let ser_signature =
            signer.with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_counterparty_htlc_sweep(
                    &htlc_tx,
                    0,
                    &remote_per_commitment_point,
                    &htlc_redeemscript,
                    htlc_amount_sat).unwrap();
                Ok(signature_to_bitcoin_vec(sig))
            }).unwrap();

        let htlc_pubkey =
            get_channel_htlc_pubkey(&signer, &node_id, &channel_id, &remote_per_commitment_point);

        check_signature(
            &htlc_tx,
            0,
            ser_signature,
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
        );
    }

    #[test]
    // TODO - same as sign_mutual_close_tx_test
    fn sign_holder_commitment_tx_test() {
        let signer = MySigner::new();
        let setup = make_static_test_channel_setup();
        let (node_id, channel_id) =
            init_node_and_channel(&signer, TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let tx = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let commitment_tx = chan.make_holder_commitment_tx(23, 0, 200, 100, vec![]);
                Ok(commitment_tx
                    .trust()
                    .built_transaction()
                    .transaction
                    .clone())
            })
            .expect("tx");

        let sigvec = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            let sig = chan.sign_holder_commitment_tx(
                &tx,
                setup.channel_value_sat,
            ).unwrap();
            Ok(signature_to_bitcoin_vec(sig))
        }).unwrap();

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);

        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &setup.counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            sigvec,
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }

    #[test]
    // TODO - same as sign_commitment_tx_test
    fn sign_mutual_close_tx_test() {
        let signer = MySigner::new();
        let setup = make_static_test_channel_setup();
        let (node_id, channel_id) =
            init_node_and_channel(&signer, TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let counterparty_points = make_test_counterparty_points();

        let tx = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let commitment_tx = chan.make_holder_commitment_tx(23, 0, 200, 100, vec![]);
                Ok(commitment_tx
                    .trust()
                    .built_transaction()
                    .transaction
                    .clone())
            })
            .expect("tx");

        let sigvec =
            signer.with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_mutual_close_tx(
                    &tx,
                    setup.channel_value_sat,
                ).unwrap();

                Ok(signature_to_bitcoin_vec(sig))
            }).unwrap();

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);

        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            sigvec,
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }

    #[test]
    fn sign_justice_sweep_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let secp_ctx = Secp256k1::new();

        let n: u64 = 1;

        let (per_commitment_point, per_commitment_secret) = signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                Ok((
                    chan.get_per_commitment_point(n),
                    chan.get_per_commitment_secret(n),
                ))
            })
            .expect("point");

        let a_delayed_payment_base = make_test_pubkey(2);

        let a_delayed_payment_pubkey =
            derive_public_key(&secp_ctx, &per_commitment_point, &a_delayed_payment_base)
                .expect("a_delayed_payment_pubkey");

        let (b_revocation_base_point, b_revocation_base_secret) = make_test_key(42);

        let revocation_pubkey =
            derive_revocation_pubkey(&secp_ctx, &per_commitment_point, &b_revocation_base_point)
                .expect("revocation_pubkey");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_pubkey,
            &revocation_pubkey,
        );

        let redeemscript = get_revokeable_redeemscript(
            &revocation_pubkey,
            to_self_delay,
            &a_delayed_payment_pubkey,
        );

        let htlc_amount_sat = 10 * 1000;

        let revocation_secret = derive_private_revocation_key(
            &secp_ctx,
            &per_commitment_secret,
            &b_revocation_base_secret,
        )
        .expect("revocation_secret");

        let revocation_point = PublicKey::from_secret_key(&secp_ctx, &revocation_secret);

        let sigvec =
            signer.with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_justice_sweep(
                    &htlc_tx,
                    0,
                    &revocation_secret,
                    &redeemscript,
                    htlc_amount_sat).unwrap();
                Ok(signature_to_bitcoin_vec(sig))
            }).unwrap();

        let pubkey =
            get_channel_revocation_pubkey(signer, &node_id, &channel_id, &revocation_point);

        check_signature(&htlc_tx, 0, sigvec, &pubkey, htlc_amount_sat, &redeemscript);
    }

    #[test]
    fn sign_channel_announcement_test() {
        let signer = MySigner::new();
        let (node_id, channel_id) = init_node_and_channel(
            &signer,
            TEST_NODE_CONFIG,
            TEST_SEED[1],
            make_test_channel_setup(),
        );

        let ann = hex::decode("0123456789abcdef").unwrap();
        let (nsig, bsig) = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            Ok(chan.sign_channel_announcement(&ann))
        }).unwrap();

        let ca_hash = Sha256dHash::hash(&ann);
        let encmsg = secp256k1::Message::from_slice(&ca_hash[..]).expect("encmsg");
        let secp_ctx = Secp256k1::new();
        secp_ctx
            .verify(&encmsg, &nsig, &node_id)
            .expect("verify nsig");
        let _res: Result<(), Status> = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            let funding_pubkey = PublicKey::from_secret_key(&secp_ctx, &chan.keys.funding_key());
            Ok(secp_ctx
                .verify(&encmsg, &bsig, &funding_pubkey)
                .expect("verify bsig"))
        });
    }

    #[test]
    fn sign_node_announcement_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let ann = hex::decode("000302aaa25e445fef0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b65180265b64c4f554450484f544f2d2e302d3139392d67613237336639642d6d6f646465640000").unwrap();
        let sigvec = signer.get_node(&node_id).unwrap().sign_node_announcement(&ann).unwrap();
        assert_eq!(sigvec, hex::decode("30450221008ef1109b95f127a7deec63b190b72180f0c2692984eaf501c44b6bfc5c4e915502207a6fa2f250c5327694967be95ff42a94a9c3d00b7fa0fbf7daa854ceb872e439").unwrap());
        Ok(())
    }

    #[test]
    fn sign_channel_update_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let cu = hex::decode("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015e42ddc6010000060000000000000000000000010000000a000000003b023380").unwrap();
        let sigvec = signer.get_node(&node_id).unwrap().sign_channel_update(&cu).unwrap();
        assert_eq!(sigvec, hex::decode("3045022100be9840696c868b161aaa997f9fa91a899e921ea06c8083b2e1ea32b8b511948d0220352eec7a74554f97c2aed26950b8538ca7d7d7568b42fd8c6f195bd749763fa5").unwrap());
        Ok(())
    }

    #[test]
    fn sign_invoice_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let human_readable_part = String::from("lnbcrt1230n");
        let data_part = hex::decode("010f0418090a010101141917110f01040e050f06100003021e1b0e13161c150301011415060204130c0018190d07070a18070a1c1101111e111f130306000d00120c11121706181b120d051807081a0b0f0d18060004120e140018000105100114000b130b01110c001a05041a181716020007130c091d11170d10100d0b1a1b00030e05190208171e16080d00121a00110719021005000405001000").unwrap();
        let rsig = signer.get_node(&node_id).unwrap()
            .sign_invoice_in_parts(&data_part, &human_readable_part)
            .unwrap();
        assert_eq!(rsig, hex::decode("739ffb91aa7c0b3d3c92de1600f7a9afccedc5597977095228232ee4458685531516451b84deb35efad27a311ea99175d10c6cdb458cd27ce2ed104eb6cf806400").unwrap());
        Ok(())
    }

    #[test]
    fn sign_invoice_with_overhang_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let human_readable_part = String::from("lnbcrt2m");
        let data_part = hex::decode("010f0a001d051e0101140c0c000006140009160c09051a0d1a190708020d17141106171f0f07131616111f1910070b0d0e150c0c0c0d010d1a01181c15100d010009181a06101a0a0309181b040a111a0a06111705100c0b18091909030e151b14060004120e14001800010510011419080f1307000a0a0517021c171410101a1e101605050a08180d0d110e13150409051d02091d181502020f050e1a1f161a09130005000405001000").unwrap();
        // The data_part is 170 bytes.
        // overhang = (data_part.len() * 5) % 8 = 2
        // looking for a verified invoice where overhang is in 1..3
        let rsig = signer.get_node(&node_id).unwrap()
            .sign_invoice_in_parts(&data_part, &human_readable_part)
            .unwrap();
        assert_eq!(rsig, hex::decode("f278cdba3fd4a37abf982cee5a66f52e142090631ef57763226f1232eead78b43da7962fcfe29ffae9bd918c588df71d6d7b92a4787de72801594b22f0e7e62a00").unwrap());
        Ok(())
    }

    #[test]
    fn ecdh_test() {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let pointvec =
            hex::decode("0330febba06ba074378dec994669cf5ebf6b15e24a04ec190fb93a9482e841a0ca")
                .unwrap();
        let other_key = PublicKey::from_slice(pointvec.as_slice()).unwrap();

        let ssvec = signer.get_node(&node_id).unwrap().ecdh(&other_key);
        assert_eq!(
            ssvec,
            hex::decode("48db1582f4b42a0068b5727fd37090a65fbf1f9bd842f4393afc2e794719ae47")
                .unwrap()
        );
    }

    #[test]
    fn get_unilateral_close_key_test() {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[0]);
        let channel_nonce = hex::decode(
            "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d590100000000000000",
        )
        .unwrap();
        let channel_id = signer
            .new_channel(&node_id, Some(channel_nonce), None)
            .unwrap();

        let node = signer.get_node(&node_id).unwrap();
        node.ready_channel(channel_id, None, make_test_channel_setup())
            .expect("ready channel");

        let uck = signer.with_ready_channel(&node_id, &channel_id, |chan| {
            chan.get_unilateral_close_key(&None)
        }).unwrap();

        assert_eq!(
            uck,
            SecretKey::from_slice(
                &hex::decode("d5f8a9fdd0e4be18c33656944b91dc1f6f2c38ce2a4bbd0ef330ffe4e106127c")
                    .unwrap()[..]
            )
            .unwrap()
        );
    }

    #[test]
    fn get_account_ext_pub_key_test() {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let node = signer.get_node(&node_id).unwrap();
        let xpub = node.get_account_extended_pubkey();
        assert_eq!(format!("{}", xpub), "tpubDAu312RD7nE6R9qyB4xJk9QAMyi3ppq3UJ4MMUGpB9frr6eNDd8FJVPw27zTVvWAfYFVUtJamgfh5ZLwT23EcymYgLx7MHsU8zZxc9L3GKk");
    }

    #[test]
    fn sign_message_test() {
        let signer = MySigner::new();
        let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
        let message = String::from("Testing 1 2 3").into_bytes();
        let mut rsigvec = signer.get_node(&node_id).unwrap()
            .sign_message(&message).unwrap();
        let rid = rsigvec.pop().unwrap() as i32;
        let rsig =
            RecoverableSignature::from_compact(&rsigvec[..], RecoveryId::from_i32(rid).unwrap())
                .unwrap();
        let secp_ctx = secp256k1::Secp256k1::new();
        let mut buffer = String::from("Lightning Signed Message:").into_bytes();
        buffer.extend(message);
        let hash = Sha256dHash::hash(&buffer);
        let encmsg = secp256k1::Message::from_slice(&hash[..]).unwrap();
        let sig =
            secp256k1::Signature::from_compact(&rsig.to_standard().serialize_compact()).unwrap();
        let pubkey = secp_ctx.recover(&encmsg, &rsig).unwrap();
        assert!(secp_ctx.verify(&encmsg, &sig, &pubkey).is_ok());
        assert_eq!(pubkey.serialize().to_vec(), node_id.serialize().to_vec());
    }

    // TODO move this elsewhere
    #[test]
    fn transaction_verify_test() {
        use hex::decode as hex_decode;
        // a random recent segwit transaction from blockchain using both old and segwit inputs
        let spending: bitcoin::Transaction = deserialize(hex_decode("020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c91000000006a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a8022013959632492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffffffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d04cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5ab979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c588ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b00000000001976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d4757de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10da6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322a18b920a4dfa887d30700")
            .unwrap().as_slice()).unwrap();
        let spent1: bitcoin::Transaction = deserialize(hex_decode("020000000001040aacd2c49f5f3c0968cfa8caf9d5761436d95385252e3abb4de8f5dcf8a582f20000000017160014bcadb2baea98af0d9a902e53a7e9adff43b191e9feffffff96cd3c93cac3db114aafe753122bd7d1afa5aa4155ae04b3256344ecca69d72001000000171600141d9984579ceb5c67ebfbfb47124f056662fe7adbfeffffffc878dd74d3a44072eae6178bb94b9253177db1a5aaa6d068eb0e4db7631762e20000000017160014df2a48cdc53dae1aba7aa71cb1f9de089d75aac3feffffffe49f99275bc8363f5f593f4eec371c51f62c34ff11cc6d8d778787d340d6896c0100000017160014229b3b297a0587e03375ab4174ef56eeb0968735feffffff03360d0f00000000001976a9149f44b06f6ee92ddbc4686f71afe528c09727a5c788ac24281b00000000001976a9140277b4f68ff20307a2a9f9b4487a38b501eb955888ac227c0000000000001976a9148020cd422f55eef8747a9d418f5441030f7c9c7788ac0247304402204aa3bd9682f9a8e101505f6358aacd1749ecf53a62b8370b97d59243b3d6984f02200384ad449870b0e6e89c92505880411285ecd41cf11e7439b973f13bad97e53901210205b392ffcb83124b1c7ce6dd594688198ef600d34500a7f3552d67947bbe392802473044022033dfd8d190a4ae36b9f60999b217c775b96eb10dee3a1ff50fb6a75325719106022005872e4e36d194e49ced2ebcf8bb9d843d842e7b7e0eb042f4028396088d292f012103c9d7cbf369410b090480de2aa15c6c73d91b9ffa7d88b90724614b70be41e98e0247304402207d952de9e59e4684efed069797e3e2d993e9f98ec8a9ccd599de43005fe3f713022076d190cc93d9513fc061b1ba565afac574e02027c9efbfa1d7b71ab8dbb21e0501210313ad44bc030cc6cb111798c2bf3d2139418d751c1e79ec4e837ce360cc03b97a024730440220029e75edb5e9413eb98d684d62a077b17fa5b7cc19349c1e8cc6c4733b7b7452022048d4b9cae594f03741029ff841e35996ef233701c1ea9aa55c301362ea2e2f68012103590657108a72feb8dc1dec022cf6a230bb23dc7aaa52f4032384853b9f8388baf9d20700")
            .unwrap().as_slice()).unwrap();
        let spent2: bitcoin::Transaction = deserialize(hex_decode("0200000000010166c3d39490dc827a2594c7b17b7d37445e1f4b372179649cd2ce4475e3641bbb0100000017160014e69aa750e9bff1aca1e32e57328b641b611fc817fdffffff01e87c5d010000000017a914f3890da1b99e44cd3d52f7bcea6a1351658ea7be87024830450221009eb97597953dc288de30060ba02d4e91b2bde1af2ecf679c7f5ab5989549aa8002202a98f8c3bd1a5a31c0d72950dd6e2e3870c6c5819a6c3db740e91ebbbc5ef4800121023f3d3b8e74b807e32217dea2c75c8d0bd46b8665b3a2d9b3cb310959de52a09bc9d20700")
            .unwrap().as_slice()).unwrap();
        let spent3: bitcoin::Transaction = deserialize(hex_decode("01000000027a1120a30cef95422638e8dab9dedf720ec614b1b21e451a4957a5969afb869d000000006a47304402200ecc318a829a6cad4aa9db152adbf09b0cd2de36f47b53f5dade3bc7ef086ca702205722cda7404edd6012eedd79b2d6f24c0a0c657df1a442d0a2166614fb164a4701210372f4b97b34e9c408741cd1fc97bcc7ffdda6941213ccfde1cb4075c0f17aab06ffffffffc23b43e5a18e5a66087c0d5e64d58e8e21fcf83ce3f5e4f7ecb902b0e80a7fb6010000006b483045022100f10076a0ea4b4cf8816ed27a1065883efca230933bf2ff81d5db6258691ff75202206b001ef87624e76244377f57f0c84bc5127d0dd3f6e0ef28b276f176badb223a01210309a3a61776afd39de4ed29b622cd399d99ecd942909c36a8696cfd22fc5b5a1affffffff0200127a000000000017a914f895e1dd9b29cb228e9b06a15204e3b57feaf7cc8769311d09000000001976a9144d00da12aaa51849d2583ae64525d4a06cd70fde88ac00000000")
            .unwrap().as_slice()).unwrap();

        println!("{:?}", &spending.txid());
        println!("{:?}", &spent1.txid());
        println!("{:?}", &spent2.txid());
        println!("{:?}", &spent3.txid());
        println!("{:?}", &spent1.output[0].script_pubkey);
        println!("{:?}", &spent2.output[0].script_pubkey);
        println!("{:?}", &spent3.output[0].script_pubkey);

        let mut spent = Map::new();
        spent.insert(spent1.txid(), spent1);
        spent.insert(spent2.txid(), spent2);
        spent.insert(spent3.txid(), spent3);
        spending
            .verify(|point: &OutPoint| {
                if let Some(tx) = spent.remove(&point.txid) {
                    return tx.output.get(point.vout as usize).cloned();
                }
                None // NOT TESTED
            })
            .unwrap();
    }

    // TODO move this elsewhere
    #[test]
    fn bip143_p2wpkh_test() {
        let tx: bitcoin::Transaction = deserialize(hex::decode("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
            .unwrap().as_slice()).unwrap();
        let secp_ctx = Secp256k1::signing_only();
        let priv2 = SecretKey::from_slice(
            hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let pub2 = bitcoin::PublicKey::from_slice(
            &PublicKey::from_secret_key(&secp_ctx, &priv2).serialize(),
        )
        .unwrap();

        let script_code = Address::p2pkh(&pub2, Network::Testnet).script_pubkey();
        assert_eq!(
            hex::encode(script_code.as_bytes()),
            "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
        );
        let value = 600_000_000;

        let sighash =
            &SigHashCache::new(&tx).signature_hash(1, &script_code, value, SigHashType::All)[..];
        assert_eq!(
            hex::encode(sighash),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
        );
    }
}
