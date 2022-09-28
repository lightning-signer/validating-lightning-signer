//! Run the signer, listening to the serial port

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use core::cell::RefCell;
use core::time::Duration;

use cortex_m::interrupt::Mutex;
use cortex_m_rt::entry;

#[allow(unused_imports)]
use log::{debug, info, trace};

use crate::lightning_signer::util::clock::ManualClock;
use device::heap_bytes_used;
use lightning_signer::bitcoin::Network;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::Arc;
use random_starting_time::RandomStartingTimeFactory;
use vls_protocol::model::PubKey;
use vls_protocol::msgs::{self, read_serial_request_header, write_serial_response_header, Message};
use vls_protocol::serde_bolt::WireString;
use vls_protocol_signer::approver::PositiveApprover;
use vls_protocol_signer::handler::{Handler, RootHandlerBuilder};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::vls_protocol;

mod device;
mod logger;
mod random_starting_time;
#[cfg(feature = "sdio")]
mod sdcard;
mod timer;
mod usbserial;

#[entry]
fn main() -> ! {
    logger::init().expect("logger");

    device::init_allocator();

    #[allow(unused)]
    let (mut delay, timer1, timer2, mut serial, mut sdio, mut disp, mut rng) =
        device::make_devices();

    logger::set_timer(timer1.clone());

    #[cfg(feature = "sdio")]
    {
        sdcard::init_sdio(&mut sdio, &mut delay);

        let mut block = [0u8; 512];

        let res = sdio.read_block(0, &mut block);
        info!("sdcard read result {:?}", res);

        sdcard::test(sdio);
    }

    timer::start_tim2_interrupt(timer2);

    disp.clear_screen();
    disp.show_text("init");

    let starting_time_factory = RandomStartingTimeFactory::new(Mutex::new(RefCell::new(rng)));

    let persister: Arc<dyn Persist> = Arc::new(DummyPersister);
    let validator_factory = Arc::new(SimpleValidatorFactory::new());
    let clock = Arc::new(ManualClock::new(Duration::ZERO));

    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };

    let (sequence, dbid) = read_serial_request_header(&mut serial).expect("read init header");
    assert_eq!(dbid, 0);
    assert_eq!(sequence, 0);
    let init: msgs::HsmdInit2 =
        msgs::read_message(&mut serial).expect("failed to read init message");
    info!("init {:?}", init);
    let allowlist = init.dev_allowlist.iter().map(|s| from_wire_string(s)).collect::<Vec<_>>();
    let seed_opt = init.dev_seed.as_ref().map(|s| s.0);
    let network = Network::Regtest; // TODO - get from config/args/env somehow
    let approver = Arc::new(PositiveApprover()); // TODO - switch to invoice GUI
    let root_handler = RootHandlerBuilder::new(network, 0, services)
        .seed_opt(seed_opt)
        .allowlist(allowlist)
        .approver(approver)
        .build();
    let init_reply = root_handler.handle(Message::HsmdInit2(init)).expect("handle init");
    write_serial_response_header(&mut serial, sequence).expect("write init header");
    msgs::write_vec(&mut serial, init_reply.as_vec()).expect("write init reply");

    info!("used {} bytes", heap_bytes_used());

    // HACK - use a dummy peer_id until it is plumbed
    let dummy_peer = PubKey([0; 33]);
    loop {
        let (sequence, dbid) =
            read_serial_request_header(&mut serial).expect("read request header");
        let mut message = msgs::read(&mut serial).expect("message read failed");

        // Override the peerid when it is passed in certain messages
        match message {
            Message::NewChannel(ref mut m) => m.node_id = dummy_peer.clone(),
            Message::ClientHsmFd(ref mut m) => m.peer_id = dummy_peer.clone(),
            Message::GetChannelBasepoints(ref mut m) => m.node_id = dummy_peer.clone(),
            Message::SignCommitmentTx(ref mut m) => m.peer_id = dummy_peer.clone(),
            _ => {}
        };

        disp.clear_screen();
        let mut message_d = format!("{:?}", message);
        message_d.truncate(20);
        let balance = root_handler.channel_balance();
        disp.show_texts(&[
            format!("req # {}", sequence),
            message_d.clone(),
            format!("{:>+11}", balance.received_htlc),
            format!("{:>11}", balance.claimable),
            if balance.offered_htlc > 0 {
                format!("{:>+11}", 0 - balance.offered_htlc as i64)
            } else {
                format!("         -0")
            },
            format!("The height is {}", root_handler.get_chain_height()),
        ]);
        let start = timer1.now();
        let reply = if dbid > 0 {
            let handler = root_handler.for_new_client(0, dummy_peer.clone(), dbid);
            handler.handle(message).expect("handle")
        } else {
            root_handler.handle(message).expect("handle")
        };
        let end = timer1.now();
        let duration = end.checked_duration_since(start).map(|d| d.to_millis()).unwrap_or(0);
        info!("handled {} in {} ms", message_d, duration);
        write_serial_response_header(&mut serial, sequence).expect("write reply header");
        msgs::write_vec(&mut serial, reply.as_vec()).expect("write reply");
    }
}

fn from_wire_string(s: &WireString) -> String {
    String::from_utf8(s.0.to_vec()).expect("malformed string")
}
