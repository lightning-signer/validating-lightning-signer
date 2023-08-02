use std::env::args;
use vls_protocol::msgs::SignMutualCloseTx;
use vls_protocol::msgs::{self, Message};

pub fn main() {
    let msg_hex = args().nth(1).expect("usage: decode-vls <message-hex>");
    let msg = msgs::from_vec(hex::decode(msg_hex).unwrap()).unwrap();
    match msg {
        Message::SignMutualCloseTx(SignMutualCloseTx { tx, psbt, .. }) => {
            println!("SignMutualCloseTxRequest {:?} {:?}", tx, psbt.0);
        }
        msg => {
            println!("{:?}", msg);
        }
    }
}
