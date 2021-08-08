use bitcoin::TxOut;

use crate::prelude::*;
use crate::util::status::Status;

pub trait Wallet {
    fn wallet_can_spend(&self, child_path: &Vec<u32>, output: &TxOut) -> Result<bool, Status>;
}
