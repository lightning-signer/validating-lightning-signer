use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{CompressedPublicKey, NetworkKind};
use lightning::ln::chan_utils::ChannelPublicKeys;
use lightning::ln::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint};

/// Make a bitcoin test key
pub fn make_test_bitcoin_key(i: u8) -> (bitcoin::PublicKey, bitcoin::PrivateKey) {
    let secp_ctx = Secp256k1::signing_only();
    let secret_key = SecretKey::from_slice(&[i; 32]).unwrap();
    let private_key =
        bitcoin::PrivateKey { compressed: true, network: NetworkKind::Test, inner: secret_key };
    (private_key.public_key(&secp_ctx), private_key)
}

/// Make a bitcoin test pubkey
pub fn make_test_bitcoin_pubkey(i: u8) -> CompressedPublicKey {
    CompressedPublicKey(make_test_bitcoin_key(i).0.inner)
}

/// Make a secp256k1 test key
pub fn make_test_key(i: u8) -> (PublicKey, SecretKey) {
    let secp_ctx = Secp256k1::signing_only();
    let secret_key = SecretKey::from_slice(&[i; 32]).unwrap();
    (PublicKey::from_secret_key(&secp_ctx, &secret_key), secret_key)
}

/// Make a secp256k1 test pubkey
pub fn make_test_pubkey(i: u8) -> PublicKey {
    make_test_key(i).0
}

/// Make a secp256k1 test privkey
pub fn make_test_privkey(i: u8) -> SecretKey {
    make_test_key(i).1
}

/// Make a test ChannelPublicKeys
pub fn make_test_counterparty_points() -> ChannelPublicKeys {
    ChannelPublicKeys {
        funding_pubkey: make_test_pubkey(104),
        revocation_basepoint: RevocationBasepoint(make_test_pubkey(100)),
        payment_point: make_test_pubkey(101),
        delayed_payment_basepoint: DelayedPaymentBasepoint(make_test_pubkey(102)),
        htlc_basepoint: HtlcBasepoint(make_test_pubkey(103)),
    }
}
