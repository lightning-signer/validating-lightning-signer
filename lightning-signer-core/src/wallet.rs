use bitcoin::TxOut;

use crate::prelude::*;
use crate::util::status::Status;

/// A layer-1 wallet used by Validator
pub trait Wallet {
    /// True if the wallet can spend the given output with a derived key
    fn wallet_can_spend(&self, child_path: &Vec<u32>, output: &TxOut) -> Result<bool, Status>;
}
