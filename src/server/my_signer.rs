use core::fmt;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::{Address, Network, Script, SigHashType, Transaction};
use bitcoin::util::bip143::SighashComponents;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin_hashes::core::fmt::{Error, Formatter};
use lightning::chain::keysinterface::{ChannelKeys, KeysInterface};
use lightning::ln::chan_utils::{ChannelPublicKeys, HTLCOutputInCommitment, make_funding_redeemscript, TxCreationKeys};
use lightning::ln::msgs::UnsignedChannelAnnouncement;
use lightning::util::logger::Logger;
use rand::{Rng, thread_rng};
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Signature, SignOnly};
use secp256k1::ecdh::SharedSecret;
use tonic::Status;

use crate::server::my_keys_manager::MyKeysManager;
use crate::util::enforcing_trait_impls::EnforcingChannelKeys;
use crate::util::test_utils::TestLogger;

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct ChannelId(pub [u8; 32]);

impl Debug for ChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(hex::encode(self.0).as_str())
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(hex::encode(self.0).as_str())
    }
}


pub struct Channel {
    pub keys: EnforcingChannelKeys,
    pub secp_ctx: Secp256k1<All>,
}

impl Debug for Channel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("channel")
    }
}

impl Channel {
    fn make_tx_keys(&self, per_commitment_point: &PublicKey) -> TxCreationKeys {
        let keys = &self.keys.inner;
        let pubkeys = keys.pubkeys();

        let remote_points = keys.remote_pubkeys().as_ref().unwrap();

        TxCreationKeys::new(&self.secp_ctx,
                            &per_commitment_point,
                            &remote_points.delayed_payment_basepoint,
                            &remote_points.htlc_basepoint,
                            &pubkeys.revocation_basepoint,
                            &pubkeys.payment_basepoint,
                            &pubkeys.htlc_basepoint).unwrap()
    }

    pub fn sign_remote_commitment(&self, feerate_per_kw: u64, commitment_tx: &Transaction,
                                  per_commitment_point: &PublicKey, htlcs: &[&HTLCOutputInCommitment],
                                  to_self_delay: u16) -> Result<(Signature, Vec<Signature>), ()> {
        let tx_keys = self.make_tx_keys(per_commitment_point);
        self.keys.sign_remote_commitment(feerate_per_kw, commitment_tx, &tx_keys, htlcs, to_self_delay, &self.secp_ctx)
    }

    pub fn sign_channel_announcement(&self, msg: &UnsignedChannelAnnouncement) -> Result<Signature, ()> {
        self.keys.sign_channel_announcement(msg, &self.secp_ctx)
    }

    pub fn accept(&mut self, channel_points: &ChannelPublicKeys) {
        self.keys.set_remote_channel_pubkeys(channel_points);
    }
}

pub struct Node {
    keys_manager: MyKeysManager,
    channels: Mutex<HashMap<ChannelId, Channel>>,
}

impl Node {
    /// TODO leaking secret
    pub fn get_node_secret(&self) -> SecretKey {
        self.keys_manager.get_node_secret()
    }

    /// TODO leaking secret
    pub fn get_onion_rand(&self) -> (SecretKey, [u8; 32]) {
        self.keys_manager.get_onion_rand()
    }

    /// Get destination redeemScript to encumber static protocol exit points.
    pub fn get_destination_script(&self) -> Script {
        self.keys_manager.get_destination_script()
    }

    /// Get shutdown_pubkey to use as PublicKey at channel closure
    pub fn get_shutdown_pubkey(&self) -> PublicKey {
        self.keys_manager.get_shutdown_pubkey()
    }

    /// Get a unique temporary channel id. Channels will be referred to by this until the funding
    /// transaction is created, at which point they will use the outpoint in the funding
    /// transaction.
    pub fn get_channel_id(&self) -> [u8; 32] {
        self.keys_manager.get_channel_id()
    }

    pub fn get_bip32_key(&self) -> &ExtendedPrivKey {
        self.keys_manager.get_bip32_key()
    }
}

impl Debug for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("node")
    }
}

pub struct MySigner {
    pub logger: Arc<Logger>,
    nodes: Mutex<HashMap<PublicKey, Node>>,
}

impl MySigner {
    pub fn new() -> MySigner {
        let test_logger = Arc::new(TestLogger::with_id("server".to_owned()));
        let signer = MySigner {
            logger: test_logger,
            nodes: Mutex::new(HashMap::new()),
        };
        log_info!(signer, "new MySigner");
        signer
    }

    pub fn new_node(&self) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        let network = Network::Testnet;
        let mut rng = thread_rng();

        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);

        let logger = Arc::clone(&self.logger);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
        let node = Node {
            keys_manager: MyKeysManager::new(&seed, network, logger, now.as_secs(), now.subsec_nanos()),
            channels: Mutex::new(HashMap::new()),
        };
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node.keys_manager.get_node_secret());
        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(node_id, node);
        node_id
    }

    pub fn new_node_from_seed(&self, seed: &[u8; 32]) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        let network = Network::Testnet;

        let logger = Arc::clone(&self.logger);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");

        let node = Node {
            keys_manager: MyKeysManager::new(seed, network, logger, now.as_secs(), now.subsec_nanos()),
            channels: Mutex::new(HashMap::new()),
        };
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node.keys_manager.get_node_secret());
        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(node_id, node);
        node_id
    }

    pub fn new_channel(&self, node_id: &PublicKey, channel_value_satoshi: u64, opt_channel_id: Option<ChannelId>) -> Result<ChannelId, ()> {
        log_info!(self, "new channel {}/{:?}", node_id, opt_channel_id);
        let nodes = self.nodes.lock().unwrap();
        let node = match nodes.get(node_id) {
            Some(n) => n,
            None => {
                log_error!(self, "no such node {}", node_id);
                return Err(());
            }
        };
        let mut channels = node.channels.lock().unwrap();
        let keys_manager = &node.keys_manager;
        let channel_id = opt_channel_id.unwrap_or_else(|| ChannelId(keys_manager.get_channel_id()));
        if channels.contains_key(&channel_id) {
            log_info!(self, "already have channel ID {}", channel_id);
            return Ok(channel_id);
        }
        let unused_inbound_flag = false;
        let chan_keys =
            EnforcingChannelKeys::new(keys_manager.get_channel_keys(channel_id.0, unused_inbound_flag, channel_value_satoshi));
        let channel = Channel {
            keys: chan_keys,
            secp_ctx: Secp256k1::new(),
        };
        channels.insert(channel_id, channel);
        Ok(channel_id)
    }

    pub fn with_node<F: Sized, T, E>(&self, node_id: &PublicKey, f: F) -> Result<T, E>
        where F: Fn(Option<&Node>) -> Result<T, E> {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id);
        f(node)
    }

    pub fn with_channel<F: Sized, T, E>(&self, node_id: &PublicKey,
                                        channel_id: &ChannelId,
                                        f: F) -> Result<T, E>
        where F: Fn(Option<&mut Channel>) -> Result<T, E> {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id);
        node.map_or_else(|| f(None), |n| {
            f(n.channels.lock().unwrap().get_mut(channel_id))
        })
    }

    pub fn with_channel_do<F: Sized, T>(&self, node_id: &PublicKey,
                                        channel_id: &ChannelId,
                                        f: F) -> T
        where F: Fn(Option<&mut Channel>) -> T {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id);
        node.map_or_else(|| f(None), |n| {
            f(n.channels.lock().unwrap().get_mut(channel_id))
        })
    }

    pub fn get_per_commitment_point(&self, node_id: &PublicKey, channel_id: &ChannelId, secp_ctx: &Secp256k1<SignOnly>, commitment_number: u64) -> Result<PublicKey, Status> {
        let point: Result<PublicKey, Status> = self.with_channel(&node_id, &channel_id, |opt_chan| {
            let chan = opt_chan.ok_or(Status::invalid_argument("no such channel"))?;
            let seed = chan.keys.commitment_seed();
            Ok(MyKeysManager::per_commitment_point(&secp_ctx, seed, commitment_number))
        });
        point
    }

    pub fn xkey(&self, node_id: &PublicKey) -> Result<ExtendedPrivKey, Status> {
        self.with_node(&node_id, |opt_node| {
            let node = opt_node.ok_or(Status::invalid_argument("no such node"))?;
            Ok(node.get_bip32_key().clone())
        })
    }
    pub fn sign_remote_commitment_tx(&self, node_id: &PublicKey, channel_id: &ChannelId,
                                     tx: &Transaction,
                                     remote_per_commitment_point: &PublicKey) -> Result<Vec<u8>, Status> {
        let sig: Result<Vec<u8>, Status> =
            self.with_channel(node_id, channel_id, |opt_chan| {
            let chan = opt_chan.ok_or(Status::invalid_argument("no such node/channel"))?;
            let to_self_delay = 0;
            let feerate = 0;
            let htlcs = vec![];
            let chan_keys = &chan.keys;
            let pubkeys = chan_keys.pubkeys();
            let remote_points =
                chan_keys.remote_pubkeys().as_ref().ok_or(Status::aborted("channel not accepted yet"))?;
            let secp_ctx = &chan.secp_ctx;
            let tx_keys = TxCreationKeys::new(secp_ctx,
                                              &remote_per_commitment_point,
                                              &remote_points.delayed_payment_basepoint,
                                              &remote_points.htlc_basepoint,
                                              &pubkeys.revocation_basepoint,
                                              &pubkeys.payment_basepoint,
                                              &pubkeys.htlc_basepoint).unwrap();

            let sig = chan_keys.sign_remote_commitment(feerate, tx, &tx_keys,
                                                  &htlcs, to_self_delay, secp_ctx);
            let sigs = sig.map_err(|_| Status::aborted("could not sign"))?;
            let mut sig = sigs.0.serialize_der().to_vec();
            Ok(sig)
        });
        sig
    }

    pub fn sign_funding_tx(&self, node_id: &PublicKey, _channel_id: &ChannelId, tx: &Transaction,
                           indices: &Vec<u32>, values: &Vec<u64>, iswit: &Vec<bool>) -> Result<Vec<Vec<Vec<u8>>>, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let xkey = self.xkey(node_id)?;

        let mut sigs: Vec<Vec<Vec<u8>>> = Vec::new();
        for idx in 0..tx.input.len() {
            let child_index = indices[idx];
            let value = values[idx];
            let privkey = xkey.ckd_priv(&secp_ctx, ChildNumber::from(child_index)).unwrap().private_key;
            let pubkey = privkey.public_key(&secp_ctx);
            let script_code = Address::p2pkh(&pubkey, privkey.network).script_pubkey();
            let sighash = if iswit[idx] {
                Message::from_slice(&SighashComponents::new(&tx).sighash_all(&tx.input[idx], &script_code, value)[..])
                    .unwrap()
            } else {
                Message::from_slice(&tx.signature_hash(0, &script_code, 0x01)[..]).unwrap()
            };
            let mut sig = secp_ctx.sign(&sighash, &privkey.key).serialize_der().to_vec();
            sig.push(SigHashType::All as u8);
            let stack = vec![sig, pubkey.serialize()];
            sigs.push(stack);
        }
        Ok(sigs)
    }

    pub fn ecdh(&self, node_id: &PublicKey, other_key: &PublicKey) -> Result<Vec<u8>, Status> {
        self.with_node(&node_id, |opt_node| {
            let node = opt_node.ok_or(Status::invalid_argument("no such node"))?;
            let our_key = node.keys_manager.get_node_secret();
    		let ss = SharedSecret::new(&other_key, &our_key);
            let res = ss[..].to_vec();
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{OutPoint, TxIn, TxOut};
    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::{Hash, sha256d};

    use crate::util::crypto_utils::public_key_from_raw;
    use crate::util::test_utils::*;

    use super::*;

    #[test]
    fn new_channel_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let channel_id = signer.new_channel(&node_id, 1000, None)?;
        signer.with_node(&node_id, |node| {
            assert!(node.is_some());
            Ok(())
        })?;
        signer.with_channel(&node_id, &channel_id, |chan| {
            assert!(chan.is_some());
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn bad_channel_lookup_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let channel_id = ChannelId([1; 32]);
        signer.with_channel(&node_id, &channel_id, |chan| {
            assert!(chan.is_none());
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn bad_node_lookup_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = pubkey_from_secret_hex("0101010101010101010101010101010101010101010101010101010101010101", &secp_ctx);

        let channel_id = ChannelId([1; 32]);
        signer.with_channel(&node_id, &channel_id, |chan| {
            assert!(chan.is_none());
            Ok(())
        })?;

        signer.with_node(&node_id, |node| {
            assert!(node.is_none());
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn new_channel_bad_node_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = pubkey_from_secret_hex("0101010101010101010101010101010101010101010101010101010101010101", &secp_ctx);
        assert!(signer.new_channel(&node_id, 1000, None).is_err());
        Ok(())
    }

    #[test]
    fn sign_funding_tx_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let xkey = signer.xkey(&node_id).expect("xkey");
        let channel_id = ChannelId([1; 32]);
        let indices = vec![0u32, 1u32];
        let values = vec![100u64, 200u64];
        let input1 = TxIn {
            previous_output: OutPoint { txid: Default::default(), vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![]
        };

        let input2 = TxIn {
            previous_output: OutPoint { txid: Default::default(), vout: 1 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![]
        };
        let mut tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input1, input2],
            output: vec![TxOut {
                script_pubkey: Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(),
                value: 300,
            }]
        };
        let iswits = vec! [true, true];

        let sigs = signer.sign_funding_tx(&node_id, &channel_id, &tx, &indices, &values, &iswits)
            .expect("good sigs");
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].len(), 2);
        assert_eq!(sigs[1].len(), 2);

        let address = |n: u32| {
            Address::p2wpkh(&xkey.ckd_priv(&secp_ctx, ChildNumber::from(n)).unwrap().private_key.public_key(&secp_ctx),
                            Network::Testnet)
        };

        tx.input[0].witness = sigs[0].clone();
        tx.input[1].witness = sigs[1].clone();
        let outs = vec! [
            TxOut { value: 100, script_pubkey: address(0).script_pubkey() },
            TxOut { value: 200, script_pubkey: address(1).script_pubkey() },
        ];
        print!("{:?}", address(0).script_pubkey());
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_test1() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let xkey = signer.xkey(&node_id).expect("xkey");
        let channel_id = ChannelId([1; 32]);
        let txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let indices = vec![0u32];
        let values = vec![100u64];
        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![]
        };

        let mut tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input1],
            output: vec![TxOut {
                script_pubkey: Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(),
                value: 100,
            }]
        };
        let sigs = signer.sign_funding_tx(&node_id, &channel_id, &tx, &indices, &values, &vec![true])
            .expect("good sigs");
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].len(), 2);

        let address = |n: u32| {
            Address::p2wpkh(&xkey.ckd_priv(&secp_ctx, ChildNumber::from(n)).unwrap().private_key.public_key(&secp_ctx),
                            Network::Testnet)
        };

        tx.input[0].witness = sigs[0].clone();

        println!("{:?}", tx.input[0].script_sig);
        let outs = vec! [
            TxOut { value: 100, script_pubkey: address(0).script_pubkey() },
        ];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_test1_nonwit() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let xkey = signer.xkey(&node_id).expect("xkey");
        let channel_id = ChannelId([1; 32]);
        let txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let indices = vec![0u32];
        let values = vec![100u64];
        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![]
        };

        let mut tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input1],
            output: vec![TxOut {
                script_pubkey: Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(),
                value: 100,
            }]
        };
        let sigs = signer.sign_funding_tx(&node_id, &channel_id, &tx, &indices, &values, &vec![false])
            .expect("good sigs");
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].len(), 2);

        let address = |n: u32| {
            Address::p2pkh(&xkey.ckd_priv(&secp_ctx, ChildNumber::from(n)).unwrap().private_key.public_key(&secp_ctx),
                            Network::Testnet)
        };

        tx.input[0].script_sig = Builder::new().push_slice(sigs[0][0].as_slice()).push_slice(sigs[0][1].as_slice()).into_script();
        println!("{:?}", tx.input[0].script_sig);
        let outs = vec! [
            TxOut { value: 100, script_pubkey: address(0).script_pubkey() },
        ];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));
        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn test_transaction_verify () {
        use hex::decode as hex_decode;
        // a random recent segwit transaction from blockchain using both old and segwit inputs
        let spending: Transaction = deserialize(hex_decode("020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c91000000006a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a8022013959632492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffffffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d04cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5ab979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c588ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b00000000001976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d4757de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10da6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322a18b920a4dfa887d30700")
            .unwrap().as_slice()).unwrap();
        let spent1: Transaction = deserialize(hex_decode("020000000001040aacd2c49f5f3c0968cfa8caf9d5761436d95385252e3abb4de8f5dcf8a582f20000000017160014bcadb2baea98af0d9a902e53a7e9adff43b191e9feffffff96cd3c93cac3db114aafe753122bd7d1afa5aa4155ae04b3256344ecca69d72001000000171600141d9984579ceb5c67ebfbfb47124f056662fe7adbfeffffffc878dd74d3a44072eae6178bb94b9253177db1a5aaa6d068eb0e4db7631762e20000000017160014df2a48cdc53dae1aba7aa71cb1f9de089d75aac3feffffffe49f99275bc8363f5f593f4eec371c51f62c34ff11cc6d8d778787d340d6896c0100000017160014229b3b297a0587e03375ab4174ef56eeb0968735feffffff03360d0f00000000001976a9149f44b06f6ee92ddbc4686f71afe528c09727a5c788ac24281b00000000001976a9140277b4f68ff20307a2a9f9b4487a38b501eb955888ac227c0000000000001976a9148020cd422f55eef8747a9d418f5441030f7c9c7788ac0247304402204aa3bd9682f9a8e101505f6358aacd1749ecf53a62b8370b97d59243b3d6984f02200384ad449870b0e6e89c92505880411285ecd41cf11e7439b973f13bad97e53901210205b392ffcb83124b1c7ce6dd594688198ef600d34500a7f3552d67947bbe392802473044022033dfd8d190a4ae36b9f60999b217c775b96eb10dee3a1ff50fb6a75325719106022005872e4e36d194e49ced2ebcf8bb9d843d842e7b7e0eb042f4028396088d292f012103c9d7cbf369410b090480de2aa15c6c73d91b9ffa7d88b90724614b70be41e98e0247304402207d952de9e59e4684efed069797e3e2d993e9f98ec8a9ccd599de43005fe3f713022076d190cc93d9513fc061b1ba565afac574e02027c9efbfa1d7b71ab8dbb21e0501210313ad44bc030cc6cb111798c2bf3d2139418d751c1e79ec4e837ce360cc03b97a024730440220029e75edb5e9413eb98d684d62a077b17fa5b7cc19349c1e8cc6c4733b7b7452022048d4b9cae594f03741029ff841e35996ef233701c1ea9aa55c301362ea2e2f68012103590657108a72feb8dc1dec022cf6a230bb23dc7aaa52f4032384853b9f8388baf9d20700")
            .unwrap().as_slice()).unwrap();
        let spent2: Transaction = deserialize(hex_decode("0200000000010166c3d39490dc827a2594c7b17b7d37445e1f4b372179649cd2ce4475e3641bbb0100000017160014e69aa750e9bff1aca1e32e57328b641b611fc817fdffffff01e87c5d010000000017a914f3890da1b99e44cd3d52f7bcea6a1351658ea7be87024830450221009eb97597953dc288de30060ba02d4e91b2bde1af2ecf679c7f5ab5989549aa8002202a98f8c3bd1a5a31c0d72950dd6e2e3870c6c5819a6c3db740e91ebbbc5ef4800121023f3d3b8e74b807e32217dea2c75c8d0bd46b8665b3a2d9b3cb310959de52a09bc9d20700")
            .unwrap().as_slice()).unwrap();
        let spent3: Transaction = deserialize(hex_decode("01000000027a1120a30cef95422638e8dab9dedf720ec614b1b21e451a4957a5969afb869d000000006a47304402200ecc318a829a6cad4aa9db152adbf09b0cd2de36f47b53f5dade3bc7ef086ca702205722cda7404edd6012eedd79b2d6f24c0a0c657df1a442d0a2166614fb164a4701210372f4b97b34e9c408741cd1fc97bcc7ffdda6941213ccfde1cb4075c0f17aab06ffffffffc23b43e5a18e5a66087c0d5e64d58e8e21fcf83ce3f5e4f7ecb902b0e80a7fb6010000006b483045022100f10076a0ea4b4cf8816ed27a1065883efca230933bf2ff81d5db6258691ff75202206b001ef87624e76244377f57f0c84bc5127d0dd3f6e0ef28b276f176badb223a01210309a3a61776afd39de4ed29b622cd399d99ecd942909c36a8696cfd22fc5b5a1affffffff0200127a000000000017a914f895e1dd9b29cb228e9b06a15204e3b57feaf7cc8769311d09000000001976a9144d00da12aaa51849d2583ae64525d4a06cd70fde88ac00000000")
            .unwrap().as_slice()).unwrap();

        println!("{:?}", &spending.txid());
        println!("{:?}", &spent1.txid());
        println!("{:?}", &spent2.txid());
        println!("{:?}", &spent3.txid());
        println!("{:?}", &spent1.output[0].script_pubkey);
        println!("{:?}", &spent2.output[0].script_pubkey);
        println!("{:?}", &spent3.output[0].script_pubkey);

        let mut spent = HashMap::new();
        spent.insert(spent1.txid(), spent1);
        spent.insert(spent2.txid(), spent2);
        spent.insert(spent3.txid(), spent3);
        spending.verify(|point: &OutPoint| {
            if let Some(tx) = spent.remove(&point.txid) {
                return tx.output.get(point.vout as usize).cloned();
            }
            None
        }).unwrap();
    }

    #[test]
    fn test_bip143_p2wpkh() {
        let tx: Transaction = deserialize(hex::decode("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
            .unwrap().as_slice()).unwrap();
        let secp_ctx = Secp256k1::signing_only();
        let priv2 = SecretKey::from_slice(hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
            .unwrap().as_slice()).unwrap();
        let pub2 = bitcoin::PublicKey::from_slice(&PublicKey::from_secret_key(&secp_ctx, &priv2).serialize()).unwrap();

        let script_code = Address::p2pkh(&pub2, Network::Testnet).script_pubkey();
        assert_eq!(hex::encode(script_code.as_bytes()), "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
        let value = 600_000_000;

        let sighash = &SighashComponents::new(&tx).sighash_all(&tx.input[1], &script_code, value)[..];
        assert_eq!(hex::encode(sighash), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
    }

    #[test]
    fn test_deser_raw() {
        let raw: [u8; 64] = [158, 156, 70, 5, 38, 221, 32, 73, 180, 87, 57, 36, 5, 47, 168, 160, 245, 209, 189, 150, 120, 71, 89, 121, 242, 226, 118, 91, 240, 36, 16, 253, 43, 220, 178, 191, 181, 152, 246, 154, 176, 43, 194, 95, 165, 0, 61, 9, 214, 95, 90, 144, 62, 135, 181, 82, 32, 196, 138, 80, 167, 249, 29, 143];
        let point = public_key_from_raw(&raw).unwrap();
        let secret = SecretKey::from_slice(hex::decode("7f4fa93708cb666f507f35ae9967c23f75976ab721cbcf5352bb49c50c8b7458")
            .unwrap().as_slice()).unwrap();
        let ss = SharedSecret::new(&point, &secret);
        assert_eq!(hex::encode(ss[..].to_vec()), "08e9c2ce6d882fd3c8166c9c26e748ff3def2c75b717b7709556ec9688515dc9");
        assert_eq!(hex::encode(point.serialize().to_vec()), "03fd1024f05b76e2f27959477896bdd1f5a0a82f05243957b44920dd2605469c9e");
    }
}
