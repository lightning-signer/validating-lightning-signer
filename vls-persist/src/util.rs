use lightning_signer::channel::{ChannelId, ChannelSlot, ChannelStub};
use lightning_signer::node::Node;

pub fn do_with_channel_stub<F: Fn(&ChannelStub) -> ()>(node: &Node, channel_id: &ChannelId, f: F) {
    let guard = node.channels();
    let slot = guard.get(&channel_id).unwrap().lock().unwrap();
    match &*slot {
        ChannelSlot::Stub(s) => f(&s),
        ChannelSlot::Ready(_) => panic!("expected channel stub"),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use lightning_signer::bitcoin::secp256k1::{self, Secp256k1, SecretKey};
    use lightning_signer::bitcoin::PublicKey;

    fn make_key() -> PublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let sec_key = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        PublicKey::from_slice(&sec_key.serialize()).unwrap()
    }

    #[test]
    fn public_key_json_test() {
        let key = make_key();
        let key_json = json!(&key);
        assert_eq!(key_json, json!("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"));
    }

    #[test]
    fn public_key_cbor_test() {
        let mut buf = Vec::new();
        let key = make_key();
        ciborium::ser::into_writer(&key, &mut buf).unwrap();
        let key_str = hex::encode(buf);
        assert_eq!(key_str, "5821031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
    }
}
