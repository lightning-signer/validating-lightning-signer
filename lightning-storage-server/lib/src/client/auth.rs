use bitcoin_hashes::sha256::Hash as Sha256Hash;
use bitcoin_hashes::Hash;
use secp256k1::ecdh::SharedSecret;
use secp256k1::{PublicKey, SecretKey};

/// A non-priviledged authentication token.
/// This token cannot be used for HMAC operations, so is suitable
/// for an untrusted proxy.
pub struct Auth {
    /// Client pubkey
    pub client_id: PublicKey,
    /// SHA256 of ECDH of client and server keys
    pub token: Vec<u8>,
}

impl Auth {
    pub fn auth_token(&self) -> Vec<u8> {
        self.token.clone()
    }
}

/// A priviledged authentication token.
/// This allows authentication to the server and also performing HMAC operations.
/// For non-privileged access, use [`Auth`].
#[derive(Clone)]
pub struct PrivAuth {
    /// Client pubkey
    pub client_id: PublicKey,
    /// ECDH of client and server keys
    pub shared_secret: Vec<u8>,
}

impl PrivAuth {
    pub fn new_for_client(client_key: &SecretKey, server_id: &PublicKey) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let shared_secret = SharedSecret::new(server_id, client_key).secret_bytes().to_vec();
        let client_id = PublicKey::from_secret_key(&secp, client_key);
        Self { client_id, shared_secret }
    }

    pub fn new_for_server(server_key: &SecretKey, client_id: &PublicKey) -> Self {
        let shared_secret = SharedSecret::new(client_id, server_key).secret_bytes().to_vec();
        Self { client_id: client_id.clone(), shared_secret }
    }

    /// Unpriviledged authentication token
    pub fn auth(&self) -> Auth {
        let token = self.auth_token();
        Auth { client_id: self.client_id.clone(), token }
    }

    /// SHA256 of shared_secret
    pub fn auth_token(&self) -> Vec<u8> {
        Sha256Hash::hash(&self.shared_secret).to_byte_array().to_vec()
    }
}
