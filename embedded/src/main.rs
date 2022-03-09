#![cfg_attr(feature = "device", feature(alloc_error_handler, panic_info_message))]
#![cfg_attr(feature = "device", no_std)]
#![cfg_attr(feature = "device", no_main)]

extern crate alloc;

mod tests;

#[cfg(feature = "device")]
mod entry;

#[cfg(not(feature = "device"))]
fn main() {}
