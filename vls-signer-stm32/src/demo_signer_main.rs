//! Run the signer, listening to the serial port

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use core::cell::RefCell;
use core::cmp::max;
use core::time::Duration;

use cortex_m_rt::entry;

#[allow(unused_imports)]
use log::{debug, info, trace};

use device::{heap_bytes_used, DeviceContext};
use lightning_signer::node::NodeServices;
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::util::clock::ManualClock;
use lightning_signer::Arc;
use random_starting_time::RandomStartingTimeFactory;
use vls_protocol::model::PubKey;
use vls_protocol::msgs::{self, read_serial_request_header, write_serial_response_header, Message};
use vls_protocol::serde_bolt::WireString;
use vls_protocol_signer::handler::{Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::bitcoin::Network;
use vls_protocol_signer::vls_protocol;

mod approver;
mod device;
mod fat_json_persist;
mod logger;
mod random_starting_time;
mod sdcard;
mod setup;
mod timer;
mod tracks;
mod usbserial;

use approver::ScreenApprover;
use fat_json_persist::FatJsonPersister;
use setup::{get_run_context, setup_mode, NormalContext, RunContext, TestingContext};

#[entry]
fn main() -> ! {
    logger::init("demo_signer").expect("logger");
    info!("{}", env!("GIT_DESC"));

    device::init_allocator();
    let mut devctx = device::make_devices();

    logger::set_timer(devctx.timer1.clone());
    timer::start_tim2_interrupt(devctx.timer2.take().unwrap());

    let runctx = if devctx.button.is_high() { setup_mode(devctx) } else { get_run_context(devctx) };
    match runctx {
        RunContext::Testing(testctx) => start_test_mode(testctx),
        RunContext::Normal(normctx) => start_normal_mode(normctx),
    }
}

fn display_intro(devctx: &mut DeviceContext, network: Network, path: &str) {
    // we have limited horizontal display room
    let mut abbrev_path = path.to_string();
    abbrev_path.truncate(9);

    // Display the intro screen
    let mut intro = Vec::new();
    intro.push(format!("{: ^19}", "VLS"));
    intro.push("".to_string());
    for verpart in env!("GIT_DESC").split("-g") {
        intro.push(format!("{: ^19}", verpart));
    }
    intro.push("".to_string());
    intro.push(format!("{: ^19}", "waiting for node"));
    intro.push(format!(" {: >7}:{: <9}", network.to_string(), abbrev_path));
    intro.push("".to_string());
    intro.push(format!("{: ^19}", "blue+reset to setup"));

    devctx.disp.clear_screen();
    devctx.disp.show_texts(&intro);
}

// Start the signer in normal mode, use the persisted seed
fn start_normal_mode(runctx: NormalContext) -> ! {
    info!("start_normal_mode {:?}", runctx);

    let root_handler = {
        let mut devctx = runctx.cmn.devctx.borrow_mut();

        devctx.disp.clear_screen();
        devctx.disp.show_texts(&[
            format!("starting"),
            format!(
                " {: >7}:{: <9}",
                runctx.cmn.network.to_string(),
                runctx.cmn.setupfs.as_ref().unwrap().borrow().abbrev_path()
            ),
        ]);

        // The seed and network come from the rundir (via NormalContext)
        let validator_factory = Arc::new(SimpleValidatorFactory::new());
        let starting_time_factory =
            RandomStartingTimeFactory::new(RefCell::new(devctx.rng.take().unwrap()));
        let persister: Arc<dyn Persist> =
            Arc::new(FatJsonPersister::new(Arc::clone(&runctx.cmn.setupfs.as_ref().unwrap())));
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
        let allowlist = vec![]; // TODO - add to NormalContext
        let seed = runctx.seed;
        let approver = Arc::new(ScreenApprover::new(Arc::clone(&runctx.cmn.devctx)));
        let (root_handler, _muts) = RootHandlerBuilder::new(runctx.cmn.network, 0, services, seed)
            .allowlist(allowlist)
            .approver(approver)
            .build();
        info!("used {} bytes", heap_bytes_used());

        display_intro(
            &mut devctx,
            runctx.cmn.network,
            &runctx.cmn.setupfs.unwrap().borrow().runpath().as_str(),
        );
        root_handler
    };

    handle_requests(runctx.cmn.devctx, root_handler);
}

// Start the signer in test mode, use the seed from the initial HsmdInit2 message.
fn start_test_mode(runctx: TestingContext) -> ! {
    info!("start_test_mode {:?}", runctx);

    let root_handler = {
        let mut devctx = runctx.cmn.devctx.borrow_mut();

        display_intro(&mut devctx, runctx.cmn.network, "test-mode");

        // Receive the HsmdInit2 message to learn the dev_seed (and allowlist)
        let (sequence, dbid) =
            read_serial_request_header(&mut devctx.serial).expect("read init header");
        assert_eq!(dbid, 0);
        assert_eq!(sequence, 0);
        let init: msgs::HsmdInit2 =
            msgs::read_message(&mut devctx.serial).expect("failed to read init message");
        info!("init {:?}", init);

        // Create the test-mode handler
        let validator_factory = Arc::new(SimpleValidatorFactory::new());
        let starting_time_factory =
            RandomStartingTimeFactory::new(RefCell::new(devctx.rng.take().unwrap()));
        let persister: Arc<dyn Persist> = Arc::new(DummyPersister);
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
        let allowlist = init.dev_allowlist.iter().map(|s| from_wire_string(s)).collect::<Vec<_>>();
        let seed = init.dev_seed.as_ref().map(|s| s.0).expect("no seed");
        let approver = Arc::new(ScreenApprover::new(Arc::clone(&runctx.cmn.devctx)));
        let (root_handler, _muts) = RootHandlerBuilder::new(runctx.cmn.network, 0, services, seed)
            .allowlist(allowlist)
            .approver(approver)
            .build();
        let (init_reply, _muts) =
            root_handler.handle(Message::HsmdInit2(init)).expect("handle init");
        write_serial_response_header(&mut devctx.serial, sequence).expect("write init header");
        msgs::write_vec(&mut devctx.serial, init_reply.as_vec()).expect("write init reply");

        info!("used {} bytes", heap_bytes_used());
        root_handler
    };

    handle_requests(runctx.cmn.devctx, root_handler);
}

fn handle_requests(arc_devctx: Arc<RefCell<DeviceContext>>, root_handler: RootHandler) -> ! {
    // HACK - use a dummy peer_id until it is plumbed
    let dummy_peer = PubKey([0; 33]);

    let mut tracks = tracks::Tracks::new();
    let mut numreq = 0_u64;
    let mut maxkb = heap_bytes_used() / 1024;
    loop {
        let mut devctx = arc_devctx.borrow_mut();

        numreq += 1;
        let (sequence, dbid) =
            read_serial_request_header(&mut devctx.serial).expect("read request header");
        let mut message = msgs::read(&mut devctx.serial).expect("message read failed");

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

        let start = devctx.timer1.now();
        drop(devctx); // Release the DeviceContext during the handler call (Approver needs)
        let reply = if dbid > 0 {
            let handler = root_handler.for_new_client(0, dummy_peer.clone(), dbid);
            handler.handle(message).expect("handle").0
        } else {
            root_handler.handle(message).expect("handle").0
        };
        devctx = arc_devctx.borrow_mut(); // Reacquire the DeviceContext
        let end = devctx.timer1.now();
        let duration = end.checked_duration_since(start).map(|d| d.to_millis()).unwrap_or(0);
        info!("handled {} in {} ms", message_d.clone(), duration);

        let kb = heap_bytes_used() / 1024;
        maxkb = max(kb, maxkb);

        devctx.disp.clear_screen();
        let balance = root_handler.channel_balance();
        devctx.disp.show_texts(&[
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

        write_serial_response_header(&mut devctx.serial, sequence).expect("write reply header");
        msgs::write_vec(&mut devctx.serial, reply.as_vec()).expect("write reply");
    }
}

fn from_wire_string(s: &WireString) -> String {
    String::from_utf8(s.0.to_vec()).expect("malformed string")
}
