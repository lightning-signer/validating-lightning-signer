#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use bitcoin::bip32::{ChildNumber, DerivationPath};

#[macro_use]
pub mod macros;

pub trait HexEncode {
    fn to_hex(&self) -> String;
}

impl<T: hex::ToHex> HexEncode for T {
    fn to_hex(&self) -> String {
        self.encode_hex()
    }
}

pub fn to_derivation_path<T: Into<u32> + Copy>(child_index: &[T]) -> DerivationPath {
    child_index
        .iter()
        .map(|index| ChildNumber::from((*index).into()))
        .collect::<Vec<ChildNumber>>()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_index_derivation_path() {
        let path: Vec<u32> = vec![1, 11 | (1 << 31), 3, 4];

        let derivation_path = to_derivation_path(&path);
        assert_eq!("1/11'/3/4", derivation_path.to_string());
    }
}
