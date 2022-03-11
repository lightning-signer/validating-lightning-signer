use bitcoin::{Address, Network, Script};

use crate::util::status::Status;

use crate::prelude::*;

/// A layer-1 wallet used by Validator
pub trait Wallet {
    /// True if the wallet can spend the given output with a derived key
    fn can_spend(&self, child_path: &Vec<u32>, script_pubkey: &Script) -> Result<bool, Status>;

    /// True if the script_pubkey is in the node's allowlist
    fn allowlist_contains(&self, script_pubkey: &Script) -> bool;

    /// Returns the network
    fn network(&self) -> Network;

    /// Returns the native segwit address at path
    fn get_native_address(&self, child_path: &Vec<u32>) -> Result<Address, Status>;

    /// Returns the wrapped segwit address at path
    fn get_wrapped_address(&self, child_path: &Vec<u32>) -> Result<Address, Status>;
}
