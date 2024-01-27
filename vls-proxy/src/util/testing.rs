use std::{
    fs,
    path::{Path, PathBuf},
};

use lightning_signer::util::crypto_utils::generate_seed;
use tracing::warn;

pub fn read_integration_test_seed<P: AsRef<Path>>(datadir: P) -> Option<[u8; 32]> {
    let path = PathBuf::from(datadir.as_ref()).join("hsm_secret");
    warn!("reading integration hsm_secret from {:?}", path);
    let result = fs::read(path);
    if let Ok(data) = result {
        Some(
            data.as_slice().try_into().unwrap_or_else(|_| {
                panic!("Expected hsm_secret to be 32 bytes, got {}", data.len())
            }),
        )
    } else {
        None
    }
}

/// Read integration test seed, and generate/persist it if it's missing
pub fn integration_test_seed_or_generate(seeddir: Option<PathBuf>) -> [u8; 32] {
    let seeddir = seeddir.unwrap_or(PathBuf::from("."));
    match read_integration_test_seed(&seeddir) {
        None => {
            let seed = generate_seed();
            write_integration_test_seed(&seeddir, &seed);
            seed
        }
        Some(seed) => seed,
    }
}

fn write_integration_test_seed<P: AsRef<Path>>(datadir: P, seed: &[u8; 32]) {
    let path = PathBuf::from(datadir.as_ref()).join("hsm_secret");
    warn!("writing integration hsm_secret to {:?}", path);
    fs::write(path, seed).expect("writing hsm_secret");
}
