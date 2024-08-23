#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

use alloc::string::String;

pub trait HexEncode {
	fn to_hex(&self) -> String;
}

impl<T: hex::ToHex> HexEncode for T {
	fn to_hex(&self) -> String {
		self.encode_hex()
	}
}
