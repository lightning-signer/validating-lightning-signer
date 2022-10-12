//! Run the signer, listening to the serial port

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::cell::RefCell;
use core::cmp::max;
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
mod sdcard;
mod timer;
mod tracks;
mod usbserial;

#[entry]
fn main() -> ! {
    logger::init("demo_signer").expect("logger");
    info!("{}", env!("GIT_DESC"));

    device::init_allocator();

    #[allow(unused)]
    let (
        mut delay,
        timer1,
        timer2,
        mut serial,
        mut sdio,
        mut disp,
        mut rng,
        mut touchscreen,
        mut i2c,
        _button,
    ) = device::make_devices();
    logger::set_timer(timer1.clone());
    timer::start_tim2_interrupt(timer2);

    // Probe the sdcard
    disp.clear_screen();
    disp.show_texts(&[format!("probing sdcard ...")]);
    let has_sdcard = sdcard::init_sdio(&mut sdio, &mut delay);
    if has_sdcard {
        let mut block = [0u8; 512];
        let res = sdio.read_block(0, &mut block);
        info!("sdcard read result {:?}", res);
        sdcard::test(sdio);
    }

    // Display the intro screen
    let mut intro = Vec::new();
    intro.push(format!("{: ^19}", "VLS"));
    intro.push("".to_string());
    for verpart in env!("GIT_DESC").split("-g") {
        intro.push(format!("{: ^19}", verpart));
    }
    intro.push("".to_string());
    intro.push("".to_string());
    intro.push(format!("{: ^19}", "waiting for node"));
    disp.clear_screen();
    disp.show_texts(&intro);

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
    let seed = init.dev_seed.as_ref().map(|s| s.0).expect("no seed");
    let network = Network::Regtest; // TODO - get from config/args/env somehow
    let approver = Arc::new(PositiveApprover()); // TODO - switch to invoice GUI
    let (root_handler, _muts) = RootHandlerBuilder::new(network, 0, services, seed)
        .allowlist(allowlist)
        .approver(approver)
        .build();
    let (init_reply, _muts) = root_handler.handle(Message::HsmdInit2(init)).expect("handle init");
    write_serial_response_header(&mut serial, sequence).expect("write init header");
    msgs::write_vec(&mut serial, init_reply.as_vec()).expect("write init reply");

    info!("used {} bytes", heap_bytes_used());

    let mut tracks = tracks::Tracks::new();
    let mut numreq = 0_u64;

    let mut maxkb = heap_bytes_used() / 1024;

    // HACK - use a dummy peer_id until it is plumbed
    let dummy_peer = PubKey([0; 33]);
    loop {
        numreq += 1;
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

        const NUM_TRACKS: usize = 5;
        let top_tracks = tracks.add_message(dbid, numreq, &message, NUM_TRACKS);

        let mut message_d = format!("{:?}", message);
        message_d.truncate(20);

        let start = timer1.now();
        let reply = if dbid > 0 {
            let handler = root_handler.for_new_client(0, dummy_peer.clone(), dbid);
            handler.handle(message).expect("handle").0
        } else {
            root_handler.handle(message).expect("handle").0
        };
        let end = timer1.now();
        let duration = end.checked_duration_since(start).map(|d| d.to_millis()).unwrap_or(0);
        info!("handled {} in {} ms", message_d.clone(), duration);

        let kb = heap_bytes_used() / 1024;
        maxkb = max(kb, maxkb);

        disp.clear_screen();
        let balance = root_handler.channel_balance();
        disp.show_texts(&[
            format!("#:{:>3} h:{:>6} {:>3}K", sequence, root_handler.get_chain_height(), kb),
            format!("r:{:>3} {:>+13}", balance.received_htlc_count, balance.received_htlc),
            format!("c:{:>3} {:>13}", balance.channel_count, balance.claimable),
            if balance.offered_htlc > 0 {
                format!(
                    "o:{:>3} {:>+13}",
                    balance.offered_htlc_count,
                    0 - balance.offered_htlc as i64
                )
            } else {
                format!("o:{:>3} {:>13}", balance.offered_htlc_count, "-0")
            },
            format!(""),
            top_tracks[0].clone(),
            top_tracks[1].clone(),
            top_tracks[2].clone(),
            top_tracks[3].clone(),
            top_tracks[4].clone(),
        ]);

        write_serial_response_header(&mut serial, sequence).expect("write reply header");
        msgs::write_vec(&mut serial, reply.as_vec()).expect("write reply");
    }
}

fn from_wire_string(s: &WireString) -> String {
    String::from_utf8(s.0.to_vec()).expect("malformed string")
}
