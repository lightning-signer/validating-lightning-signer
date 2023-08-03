//! Exercise hardware components.  See README.md for details.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;
mod device;
mod logger;
mod timer;
mod usbserial;

use cortex_m_rt::entry;
use device::DeviceContext;
use lightning_signer::bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
};
use log::info;
use vls_protocol_signer::lightning_signer;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

struct Bencher<'a>(u32, &'a mut DeviceContext);

impl Bencher<'_> {
    fn iter<F>(&mut self, mut f: F, name: &'static str)
    where
        F: FnMut(),
    {
        // warmup
        for _ in 0..self.0 / 2 {
            f();
        }

        let start = self.1.timer1.now();
        for _ in 0..self.0 {
            f();
        }
        let end = self.1.timer1.now();
        let duration =
            end.checked_duration_since(start).map(|d| d.to_millis()).expect("failed timer");
        info!(
            "Bench: {}, {} iterations in {}ms, each {}ms",
            name,
            self.0,
            duration,
            duration as f32 / self.0 as f32
        );
    }
}

fn sign_bench(b: &mut Bencher, name: &'static str) {
    let secp = Secp256k1::new();
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    let secret = SecretKey::from_slice(&[0x22; 32]).unwrap();
    b.iter(
        || {
            secp.sign_ecdsa(&msg, &secret);
        },
        name,
    );
}

fn verify_bench(b: &mut Bencher, name: &'static str) {
    let secp = Secp256k1::new();
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    let secret = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &secret);
    let sig = secp.sign_ecdsa(&msg, &secret);
    b.iter(
        || {
            secp.verify_ecdsa(&msg, &sig, &pubkey).unwrap();
        },
        name,
    );
}

fn hash_bench(b: &mut Bencher, name: &'static str) {
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    b.iter(
        || {
            sha256::Hash::hash(&msg[..]);
        },
        name,
    );
}

fn secp_create_bench(b: &mut Bencher, name: &'static str) {
    b.iter(
        || {
            Secp256k1::new();
        },
        name,
    );
}

#[entry]
fn main() -> ! {
    logger::init("test").expect("logger");
    info!("{}", GIT_DESC);
    for part in GIT_DESC.split("-g") {
        info!("{}", part);
    }
    device::init_allocator();

    let mut devctx = device::make_devices();
    logger::set_timer(devctx.timer1.clone());

    let mut bencher = Bencher(200, &mut devctx);
    sign_bench(&mut bencher, "Sign ECDSA");
    verify_bench(&mut bencher, "Verify ECDSA");
    hash_bench(&mut bencher, "SHA256");
    secp_create_bench(&mut bencher, "Secp256k1 Create");

    loop {}
}
