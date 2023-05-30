use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, Script};

use crate::util::status::Status;

/// A layer-1 wallet used by Validator
pub trait Wallet {
    /// True if the wallet can spend the given output with a derived key
    fn can_spend(&self, child_path: &[u32], script_pubkey: &Script) -> Result<bool, Status>;

    /// Returns true if the given destination Lightning payee is in the node's allowlist
    fn allowlist_contains_payee(&self, payee: PublicKey) -> bool;

    /// True if the script_pubkey is in the node's allowlist
    fn allowlist_contains(&self, script_pubkey: &Script, path: &[u32]) -> bool;

    /// Returns the network
    fn network(&self) -> Network;

    /// Returns the native segwit address at path
    fn get_native_address(&self, child_path: &[u32]) -> Result<Address, Status>;

    /// Returns the wrapped segwit address at path
    #[deprecated(since = "0.9.0", note = "Use native addresses instead")]
    fn get_wrapped_address(&self, child_path: &[u32]) -> Result<Address, Status>;
}
