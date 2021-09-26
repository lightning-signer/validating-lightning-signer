use greenlight_protocol::{msgs, msgs::Message};
use greenlight_protocol::model::{Basepoints, ExtKey, PubKey, PubKey32, Secret};

use crate::client::Client;

/// Protocol handler
pub(crate) struct Handler<C: Client> {
    pub(crate) client: C
}

impl<C: Client> Handler<C> {
    pub(crate) fn handle(&mut self, msg: Message) {
        match msg {
            Message::Memleak(m) => {
                self.client.write(msgs::MemleakReply { result: false }).unwrap();
            }
            Message::HsmdInit(_) => {
                self.client.write(msgs::HsmdInitReply {
                    node_id: PubKey([0; 33]),
                    bip32: ExtKey([0; 78]),
                    bolt12: PubKey32([0; 32]),
                    onion_reply_secret: Secret([0; 32])
                }).unwrap();
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
