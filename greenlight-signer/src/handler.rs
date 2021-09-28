use std::convert::TryInto;

use secp256k1::{PublicKey, Secp256k1};
use secp256k1::rand::rngs::OsRng;

use greenlight_protocol::{msgs, msgs::Message};
use greenlight_protocol::model::{Basepoints, ExtKey, PubKey, PubKey32, Secret};
use lightning_signer::Arc;
use lightning_signer::bitcoin::Network;
use lightning_signer::node::{Node, NodeConfig};
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::signer::my_keys_manager::KeyDerivationStyle;

use crate::client::Client;

/// Protocol handler
pub(crate) struct Handler<C: Client> {
    pub(crate) client: C,
    pub(crate) node: Arc<Node>
}

impl<C: Client> Handler<C> {
    pub(crate) fn new(client: C) -> Self {
        let config = NodeConfig {
            network: Network::Testnet,
            key_derivation_style: KeyDerivationStyle::Native
        };
        let seed = [0; 32];
        let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
        Self {
            client,
            node: Arc::new(Node::new(config, &seed, &persister, vec![]))
        }
    }

    pub(crate) fn with_new_client(&mut self, client: C) -> Self {
        Self {
            client,
            node: Arc::clone(&self.node)
        }
    }

    pub(crate) fn handle(&mut self, msg: Message) {
        match msg {
            Message::Memleak(m) => {
                self.client.write(msgs::MemleakReply { result: false }).unwrap();
            }
            Message::HsmdInit(_) => {
                let bip32 = self.node.get_account_extended_pubkey().encode();
                let node_id = self.node.get_id().serialize();
                let secp = Secp256k1::new();
                let mut rng = OsRng::new().unwrap();
                let (_, bolt12_pubkey) = secp.generate_schnorrsig_keypair(&mut rng);
                let bolt12_xonly = bolt12_pubkey.serialize();
                self.client.write(msgs::HsmdInitReply {
                    node_id: PubKey(node_id),
                    bip32: ExtKey(bip32),
                    bolt12: PubKey32(bolt12_xonly),
                }).unwrap();
            }
            Message::Ecdh(m) => {
                let pubkey =
                    PublicKey::from_slice(&m.point.0).expect("pubkey");
                let secret = self.node.ecdh(&pubkey).as_slice().try_into().unwrap();
                self.client.write(msgs::EcdhReply { secret: Secret(secret) }).unwrap();
            }
            Message::GetChannelBasepoints(_) => {
                let basepoints = Basepoints {
                    revocation: PubKey([0; 33]),
                    payment: PubKey([0; 33]),
                    htlc: PubKey([0; 33]),
                    delayed_payment: PubKey([0; 33]),
                };
                self.client.write(msgs::GetChannelBasepointsReply { basepoints, node_id: PubKey([0; 33]) }).unwrap();
            }
            Message::Unknown(u) => unimplemented!("loop {}: unknown message type {}", self.client.id(), u.message_type),
            m => unimplemented!("loop {}: unimplemented message {:?}", self.client.id(), m),
        }
    }
}
