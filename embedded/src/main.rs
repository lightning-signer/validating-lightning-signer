#![feature(alloc_error_handler)]
#![feature(panic_info_message)]
#![no_std]
#![no_main]

extern crate alloc;
extern crate bitcoin;
extern crate lightning;

use alloc::string::ToString;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::panic::PanicInfo;

use alloc_cortex_m::CortexMHeap;
// use panic_halt as _;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, Network, OutPoint, PrivateKey, Script, Txid};
use cortex_m::asm;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use lightning::ln::chan_utils::ChannelPublicKeys;

use lightning_signer::channel::{ChannelSetup, CommitmentType};
use lightning_signer::node::{Node, NodeConfig};
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::signer::my_keys_manager::KeyDerivationStyle;
use lightning_signer::Arc;

// this is the allocator the application will use
#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

const HEAP_SIZE: usize = 1024 * 512; // 512 KB

#[entry]
fn main() -> ! {
    hprintln!("heap size {}", HEAP_SIZE).unwrap();

    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }

    let size = Secp256k1::preallocate_size();
    hprintln!("secp buf size {}", size * 16).unwrap();

    test_bitcoin();
    test_lightning_signer();

    // exit QEMU
    // NOTE do not run this on hardware; it can corrupt OpenOCD state
    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

pub fn make_test_key(i: u8) -> (PublicKey, SecretKey) {
    let secp_ctx = Secp256k1::signing_only();
    let secret_key = SecretKey::from_slice(&[i; 32]).unwrap();
    return (
        PublicKey::from_secret_key(&secp_ctx, &secret_key),
        secret_key,
    );
}

pub fn make_test_pubkey(i: u8) -> PublicKey {
    make_test_key(i).0
}

pub fn make_test_privkey(i: u8) -> SecretKey {
    make_test_key(i).1
}

pub fn make_test_counterparty_points() -> ChannelPublicKeys {
    ChannelPublicKeys {
        funding_pubkey: make_test_pubkey(104),
        revocation_basepoint: make_test_pubkey(100),
        payment_point: make_test_pubkey(101),
        delayed_payment_basepoint: make_test_pubkey(102),
        htlc_basepoint: make_test_pubkey(103),
    }
}

pub fn make_test_channel_setup() -> ChannelSetup {
    ChannelSetup {
        is_outbound: true,
        channel_value_sat: 3_000_000,
        push_value_msat: 0,
        funding_outpoint: OutPoint {
            txid: Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        },
        holder_selected_contest_delay: 6,
        holder_shutdown_script: None,
        counterparty_points: make_test_counterparty_points(),
        counterparty_selected_contest_delay: 7,
        counterparty_shutdown_script: Script::new(),
        commitment_type: CommitmentType::StaticRemoteKey,
    }
}

fn test_lightning_signer() {
    let config = NodeConfig {
        key_derivation_style: KeyDerivationStyle::Native,
    };
    let network = bitcoin::Network::Signet;
    let seed = [0u8; 32];
    let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
    let node = Arc::new(Node::new(config, &seed, network, &persister, Vec::new()));
    let (channel_id, _) = node.new_channel(None, None, &node).unwrap();
    hprintln!("stub channel ID: {}", channel_id).unwrap();
    let channel = node
        .ready_channel(channel_id, None, make_test_channel_setup())
        .expect("ready_channel");
    hprintln!("channel ID: {}", channel.id0).unwrap();
    hprintln!("used memory {}", ALLOCATOR.used()).unwrap();
}

fn test_bitcoin() {
    // Load a private key
    let raw = "L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D";
    let pk = PrivateKey::from_wif(raw).unwrap();
    hprintln!("Seed WIF: {}", pk).unwrap();

    let secp = Secp256k1::new();

    // Derive address
    let pubkey = pk.public_key(&secp);
    let address = Address::p2wpkh(&pubkey, Network::Bitcoin).unwrap();
    hprintln!("Address: {}", address).unwrap();

    assert_eq!(
        address.to_string(),
        "bc1qpx9t9pzzl4qsydmhyt6ctrxxjd4ep549np9993".to_string()
    );
}

// define what happens in an Out Of Memory (OOM) condition
#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    hprintln!("alloc error").unwrap();
    debug::exit(debug::EXIT_FAILURE);
    asm::bkpt();

    loop {}
}

#[inline(never)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    hprintln!("panic {:?}", info.message()).unwrap();
    debug::exit(debug::EXIT_FAILURE);
    loop {}
}
