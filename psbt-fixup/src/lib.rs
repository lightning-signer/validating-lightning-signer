#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::consensus::Decodable;
use bitcoin::util::bip32::{ChildNumber, KeySource};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::PublicKey;
use bitcoin::Script;

pub fn decode_and_extract_witscripts(ser: &[u8]) -> Vec<Vec<u8>> {
    let psbt = PartiallySignedTransaction::consensus_decode(ser).unwrap();
    extract_witscripts(&psbt)
}

fn extract_output_path(x: &BTreeMap<PublicKey, KeySource>) -> Vec<u32> {
    if x.is_empty() {
        return Vec::new();
    }
    if x.len() > 1 {
        panic!("len > 1");
    }
    let (_fingerprint, path) = x.iter().next().unwrap().1;
    let segments: Vec<ChildNumber> = path.clone().into();
    segments.into_iter().map(|c| u32::from(c)).collect()
}

pub fn decode_and_extract_output_paths(ser: &[u8]) -> Vec<Vec<u32>> {
    let psbt = PartiallySignedTransaction::consensus_decode(ser).unwrap();
    psbt.outputs.iter().map(|o| extract_output_path(&o.bip32_derivation)).collect()
}

pub fn extract_witscripts(psbt: &PartiallySignedTransaction) -> Vec<Vec<u8>> {
    psbt.outputs
        .iter()
        .map(|o| o.witness_script.clone().unwrap_or(Script::new()))
        .map(|s| s[..].to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::extract_witscripts;
    use bitcoin::consensus::Decodable;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::util::psbt::PartiallySignedTransaction;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    #[test]
    fn test_decode_psbt() {
        let ser = Vec::from_hex("70736274ff0100890200000001c447bec5bd00c02e8db7d725f48767c6e19cd8a2046acc921238d8d52ec1a50e0100000000073bbc80024a01000000000000220020708aae81941aed00dd778008ce5e200ca00b732639d21176324d0de965982938e50e0f0000000000220020e2f341c4c55194e29832b3903d393213dbd5483a850c2fad556dc0ae1c1e26317f693f200001012b40420f0000000000220020e3d09d42ab5170dc9bd6f89027e3a5010ea6dc6ddb89705bb83f145db89e2c5c220202e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e574007fc3f44b61d10f8b26863c739082d75bc56ce99b3506f97d6180ccbb87a3d2bf4358f8bb85f7cc0cc50661e7fc49fd49d3f66a16a10cd3f3c614a98a5c6581e01030401000000010547522102d6cf12d636160228c003a20cacdb80c2e0669ec30792b6627667b80c7b46a2c02102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae220602d6cf12d636160228c003a20cacdb80c2e0669ec30792b6627667b80c7b46a2c0082a7a952200000000220602e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e57081abcc1d000000000000101282102d6cf12d636160228c003a20cacdb80c2e0669ec30792b6627667b80c7b46a2c0ac736460b2680001014b6321038e4becfc742f862e0c88c8763fa5fd92beb1aa4f1880ae95083eda5b2092d3286755b2752102dd6877efdb9cac37654aaf7ef3fcf8db24cb88c5ac3277ca5f93ed31315e1be268ac00").unwrap();
        let psbt = PartiallySignedTransaction::consensus_decode(ser.as_slice()).unwrap();
        let _ = extract_witscripts(&psbt);
    }
}
