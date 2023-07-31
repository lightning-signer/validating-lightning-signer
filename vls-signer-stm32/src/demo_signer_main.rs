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
use core::time::Duration;

use cortex_m_rt::entry;

#[allow(unused_imports)]
use log::*;

use device::{heap_bytes_used, DeviceContext, HEAP_SIZE};
use lightning_signer::node::NodeServices;
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::policy::filter::{FilterRule, PolicyFilter};
use lightning_signer::policy::simple_validator::{make_simple_policy, SimpleValidatorFactory};
use lightning_signer::prelude::Box;
use lightning_signer::util::clock::ManualClock;
use lightning_signer::util::velocity::VelocityControlSpec;
use lightning_signer::Arc;
use random_starting_time::RandomStartingTimeFactory;
use vls_protocol::model::PubKey;
use vls_protocol::msgs::{self, read_serial_request_header, write_serial_response_header, Message};
use vls_protocol::serde_bolt::WireString;
use vls_protocol_signer::approver::{Approve, WarningPositiveApprover};
use vls_protocol_signer::handler::{Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::bitcoin::Network;
use vls_protocol_signer::vls_protocol;

mod approver;
mod device;
mod fat_json_persist;
mod fat_logger;
mod logger;
mod random_starting_time;
mod sdcard;
mod setup;
mod timer;
mod tracks;
mod usbserial;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

use approver::ScreenApprover;
use fat_json_persist::FatJsonPersister;
use fat_logger::FatLogger;
use setup::{get_run_context, setup_mode, NormalContext, RunContext, TestingContext};

const DEMO_SIGNER_LOG: &str = "demo_signer.log";

#[entry]
fn main() -> ! {
    logger::init("demo_signer").expect("logger");
    info!("{}", GIT_DESC);

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

fn display_intro(devctx: &mut DeviceContext, network: Network, permissive: bool, path: &str) {
    // we have limited horizontal display room
    let mut abbrev_path = path.to_string();
    abbrev_path.truncate(9);

    // Display the intro screen
    let mut intro = Vec::new();
    intro.push(format!("{: ^19}", "VLS"));
    for verpart in GIT_DESC.split("-g") {
        intro.push(format!("{: ^19}", verpart));
    }
    intro.push(format!("{: ^19}", if permissive { "PERMISSIVE" } else { "ENFORCING" }));
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
    if let Some(setupfs) = runctx.cmn.setupfs.as_ref() {
        logger::add_also(Box::new(FatLogger::new(
            DEMO_SIGNER_LOG.to_string(),
            Arc::clone(&setupfs),
        )));
    }

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
        let validator_factory = make_validator_factory(runctx.cmn.network, runctx.cmn.permissive);
        let starting_time_factory =
            RandomStartingTimeFactory::new(RefCell::new(devctx.rng.take().unwrap()));
        let persister: Arc<dyn Persist> =
            Arc::new(FatJsonPersister::new(Arc::clone(&runctx.cmn.setupfs.as_ref().unwrap())));
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
        let allowlist = vec![]; // TODO - add to NormalContext
        let seed = runctx.seed;
        let approver = make_approver(&runctx.cmn.devctx, runctx.cmn.permissive);
        let (root_handler, _muts) =
            RootHandlerBuilder::new(runctx.cmn.network, 0, services, seed.0)
                .allowlist(allowlist)
                .approver(approver)
                .build()
                .expect("handler build");
        info!("used {} bytes", heap_bytes_used());

        display_intro(
            &mut devctx,
            runctx.cmn.network,
            runctx.cmn.permissive,
            &runctx.cmn.setupfs.unwrap().borrow().runpath().as_str(),
        );
        root_handler
    };

    handle_requests(runctx.cmn.devctx, root_handler);
}

// Start the signer in test mode, use the seed from the initial HsmdInit2 message.
fn start_test_mode(runctx: TestingContext) -> ! {
    if let Some(setupfs) = runctx.cmn.setupfs.as_ref() {
        // remove any pre-existing log
        let sfs = setupfs.borrow();
        let rundir = sfs.rundir();
        sfs.remove_possible_file(&rundir, DEMO_SIGNER_LOG);

        logger::add_also(Box::new(FatLogger::new(
            DEMO_SIGNER_LOG.to_string(),
            Arc::clone(&setupfs),
        )));
    }

    info!("start_test_mode {:?}", runctx);

    let root_handler = {
        let mut devctx = runctx.cmn.devctx.borrow_mut();

        display_intro(&mut devctx, runctx.cmn.network, runctx.cmn.permissive, "test-mode");

        // Receive the HsmdInit2 message to learn the dev_seed (and allowlist)
        let reqhdr = read_serial_request_header(&mut devctx.serial).expect("read init header");
        assert_eq!(reqhdr.sequence, 0);
        assert_eq!(reqhdr.peer_id, [0u8; 33]);
        assert_eq!(reqhdr.dbid, 0);
        let init: msgs::HsmdInit2 =
            msgs::read_message(&mut devctx.serial).expect("failed to read init message");
        info!("init {:?}", init);

        // Create the test-mode handler
        let validator_factory = make_validator_factory(runctx.cmn.network, runctx.cmn.permissive);
        let starting_time_factory =
            RandomStartingTimeFactory::new(RefCell::new(devctx.rng.take().unwrap()));
        let persister: Arc<dyn Persist> = Arc::new(DummyPersister);
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
        let allowlist = init.dev_allowlist.iter().map(|s| from_wire_string(s)).collect::<Vec<_>>();
        let seed = init.dev_seed.as_ref().map(|s| s.0).expect("no seed");
        let approver = make_approver(&runctx.cmn.devctx, runctx.cmn.permissive);
        let (root_handler, _muts) = RootHandlerBuilder::new(runctx.cmn.network, 0, services, seed)
            .allowlist(allowlist)
            .approver(approver)
            .build()
            .expect("handler build");
        let (init_reply, _muts) =
            root_handler.handle(Message::HsmdInit2(init)).expect("handle init");
        write_serial_response_header(&mut devctx.serial, reqhdr.sequence)
            .expect("write init header");
        msgs::write_vec(&mut devctx.serial, init_reply.as_vec()).expect("write init reply");

        info!("used {} bytes", heap_bytes_used());
        root_handler
    };

    handle_requests(runctx.cmn.devctx, root_handler);
}

fn handle_requests(arc_devctx: Arc<RefCell<DeviceContext>>, root_handler: RootHandler) -> ! {
    let mut tracks = tracks::Tracks::new();
    let mut numreq = 0_u64;
    loop {
        let mut devctx = arc_devctx.borrow_mut();

        numreq += 1;
        let reqhdr = read_serial_request_header(&mut devctx.serial).expect("read request header");

        let message = msgs::read(&mut devctx.serial).expect("message read failed");

        let peer_id = PubKey(reqhdr.peer_id);

        const NUM_TRACKS: usize = 5;
        let top_tracks = tracks.add_message(reqhdr.dbid, numreq, &message, NUM_TRACKS);

        let mut message_d = format!("dbid: {:>3}, {:<24}", reqhdr.dbid, message.inner().name());
        message_d.truncate(35);

        let heap_free_kb = (HEAP_SIZE - heap_bytes_used()) / 1024;
        info!("starting {}, {}KB heap free", message_d.clone(), heap_free_kb);

        let start = devctx.timer1.now();
        drop(devctx); // Release the DeviceContext during the handler call (Approver needs)
        let reply = if reqhdr.dbid > 0 {
            let handler = root_handler.for_new_client(0, peer_id, reqhdr.dbid);
            handler.handle(message).expect("handle").0
        } else {
            root_handler.handle(message).expect("handle").0
        };
        devctx = arc_devctx.borrow_mut(); // Reacquire the DeviceContext
        let end = devctx.timer1.now();
        let duration = end.checked_duration_since(start).map(|d| d.to_millis()).unwrap_or(0);
        let heap_free_kb = (HEAP_SIZE - heap_bytes_used()) / 1024;
        info!(" handled {}, {}KB heap free, in {} ms, ", message_d.clone(), heap_free_kb, duration);

        devctx.disp.clear_screen();
        let balance = root_handler.channel_balance();
        devctx.disp.show_texts(&[
            format!(
                "h:  {:<9}{:>4}KB",
                pretty_thousands(root_handler.get_chain_height() as i64),
                heap_free_kb
            ),
            format!(
                "r:{:>3} {:>+13}",
                balance.received_htlc_count,
                pretty_thousands(balance.received_htlc as i64)
            ),
            format!(
                "c:{:>3} {:>13}",
                balance.channel_count,
                pretty_thousands(balance.claimable as i64)
            ),
            if balance.offered_htlc > 0 {
                format!(
                    "o:{:>3} {:>+13}",
                    balance.offered_htlc_count,
                    pretty_thousands(0 - balance.offered_htlc as i64),
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

        write_serial_response_header(&mut devctx.serial, reqhdr.sequence)
            .expect("write reply header");
        msgs::write_vec(&mut devctx.serial, reply.as_vec()).expect("write reply");
    }
}

fn from_wire_string(s: &WireString) -> String {
    String::from_utf8(s.0.to_vec()).expect("malformed string")
}

pub fn pretty_thousands(i: i64) -> String {
    let mut s = String::new();
    let i_str = i.to_string();
    let a = i_str.chars().rev().enumerate();
    for (idx, val) in a {
        if idx != 0 && idx % 3 == 0 && val != '-' {
            s.insert(0, '_');
        }
        s.insert(0, val);
    }
    s
}

fn make_validator_factory(network: Network, permissive: bool) -> Arc<SimpleValidatorFactory> {
    let velocity_spec = VelocityControlSpec::UNLIMITED; // TODO - from config

    let mut policy = make_simple_policy(network);
    policy.global_velocity_control = velocity_spec;

    if permissive {
        warn!("VLS_PERMISSIVE: ALL POLICY ERRORS ARE REPORTED AS WARNINGS");
        policy.filter = PolicyFilter::new_permissive();
    } else {
        // TODO - from config
        let filter_opt = Some(PolicyFilter {
            rules: vec![FilterRule::new_warn("policy-channel-safe-type-anchors")],
        }); // TODO(236)

        if let Some(f) = filter_opt {
            policy.filter.merge(f);
        }
        info!("VLS_ENFORCING: ALL POLICY ERRORS ARE ENFORCED");
    }

    Arc::new(SimpleValidatorFactory::new_with_policy(policy))
}

fn make_approver(devctx: &Arc<RefCell<DeviceContext>>, permissive: bool) -> Arc<dyn Approve> {
    if permissive {
        info!("VLS_PERMISSIVE: ALL INVOICES AND KEYSENDS AUTOMATICALLY APPROVED");
        Arc::new(WarningPositiveApprover())
    } else {
        info!("VLS_ENFORCING: INVOICES AND KEYSENDS REQUIRE APPROVAL");
        Arc::new(ScreenApprover::new(Arc::clone(devctx)))
    }
}
