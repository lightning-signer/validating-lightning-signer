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

use bitcoin::Network;
use device::{heap_bytes_used, DeviceContext, HEAP_SIZE};
use lightning_signer::node::NodeServices;
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::policy::filter::{FilterRule, PolicyFilter};
use lightning_signer::policy::simple_validator::{make_simple_policy, SimpleValidatorFactory};
use lightning_signer::prelude::Box;
use lightning_signer::util::clock::ManualClock;
use lightning_signer::util::velocity::VelocityControlSpec;
use lightning_signer::Arc;
use rand_core::RngCore;
use random_starting_time::RandomStartingTimeFactory;
use vls_protocol::model::DevSecret;
use vls_protocol::model::PubKey;
use vls_protocol::msgs::{self, read_serial_request_header, write_serial_response_header, Message};
use vls_protocol::serde_bolt::WireString;
use vls_protocol_signer::approver::{Approve, WarningPositiveApprover};
use vls_protocol_signer::handler::{Handler, HandlerBuilder, InitHandler, RootHandler};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::bitcoin;
use vls_protocol_signer::lightning_signer::channel::ChannelBalance;

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

fn heap_free_kb() -> usize {
    (HEAP_SIZE - heap_bytes_used()) / 1024
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
    intro.push(format!(" {: >7}:{: <9}", network.to_string(), abbrev_path));
    intro.push(format!("{: ^19}", format!("{}KB heap avail", heap_free_kb())));
    intro.push(format!("{: ^19}", "waiting for node"));
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

    let mut init_handler = {
        let mut devctx = runctx.cmn.devctx.borrow_mut();

        devctx.disp.clear_screen();
        let setupfs = runctx.cmn.setupfs.clone().unwrap();
        devctx.disp.show_texts(&[
            format!("starting"),
            format!(
                " {: >7}:{: <9}",
                runctx.cmn.network.to_string(),
                setupfs.borrow().abbrev_path()
            ),
        ]);

        // The seed and network come from the rundir (via NormalContext)
        let validator_factory = make_validator_factory(runctx.cmn.network, runctx.cmn.permissive);
        let mut rng = devctx.rng.take().unwrap();
        let mut signer_id = [0u8; 16];
        rng.fill_bytes(&mut signer_id);
        let starting_time_factory = RandomStartingTimeFactory::new(RefCell::new(rng));
        let persister: Arc<dyn Persist> = Arc::new(FatJsonPersister::new(setupfs, signer_id));
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        // TODO(king-11) pass trusted oracle public keys
        let services = NodeServices { validator_factory, starting_time_factory, persister, clock, trusted_oracle_pubkeys: vec![] };
        let allowlist = vec![]; // TODO - add to NormalContext
        let seed = runctx.seed;
        let approver = make_approver(&runctx.cmn.devctx, runctx.cmn.permissive, runctx.cmn.network);
        let (root_handler, _muts) = HandlerBuilder::new(runctx.cmn.network, 0, services, seed.0)
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

    init_handler.log_chaninfo();

    info!("ready for requests");
    handle_init_requests(&*runctx.cmn.devctx, &mut init_handler);
    let root_handler = init_handler.root_handler();
    handle_requests(&*runctx.cmn.devctx, root_handler);
}

fn handle_init_requests(arc_devctx: &RefCell<DeviceContext>, init_handler: &mut InitHandler) {
    loop {
        let mut devctx = arc_devctx.borrow_mut();

        let reqhdr = read_serial_request_header(&mut devctx.serial).expect("read request header");

        let message = msgs::read(&mut devctx.serial).expect("message read failed");

        if reqhdr.dbid > 0 {
            panic!("dbid > 0 not supported during init");
        }

        drop(devctx); // Release the DeviceContext during the handler call (Approver needs)
        let (is_done, maybe_reply) = init_handler.handle(message).expect("handle");
        let mut devctx = arc_devctx.borrow_mut(); // Reacquire the DeviceContext

        if let Some(reply) = maybe_reply {
            write_serial_response_header(&mut devctx.serial, reqhdr.sequence)
                .expect("write reply header");
            msgs::write_vec(&mut devctx.serial, reply.as_vec()).expect("write reply");
        }
        if is_done {
            break;
        }
    }
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

    let mut init_handler = {
        let mut devctx = runctx.cmn.devctx.borrow_mut();

        display_intro(&mut devctx, runctx.cmn.network, runctx.cmn.permissive, "test-mode");

        // Receive the HsmdDevPreinit message to learn the test seed (and allowlist)
        let reqhdr = read_serial_request_header(&mut devctx.serial).expect("read preinit header");
        assert_eq!(reqhdr.sequence, 0);
        assert_eq!(reqhdr.peer_id, [0u8; 33]);
        assert_eq!(reqhdr.dbid, 0);
        let preinit: msgs::HsmdDevPreinit2 =
            msgs::read_message(&mut devctx.serial).expect("failed to read preinit message");
        info!("preinit {:?}", preinit);

        // Get the seed from preinit. If it's not available, generate a new one.
        // This needs to be done before the RandomStartingTimeFactory below
        // takes the rng for itself ...
        let seed = preinit
            .options
            .seed
            .as_ref()
            .map(|s| {
                info!("using forced seed from HsmdDevPreinit2Options: {:?}", s);
                s.0
            })
            .or_else(|| {
                let mut seed = [0u8; 32];
                let rng = devctx.rng.as_mut().unwrap();
                rng.fill_bytes(&mut seed);
                info!("generated new random seed: {:?}", DevSecret(seed));
                Some(seed)
            })
            .expect("no seed");

        // Create the test-mode handler
        let validator_factory = make_validator_factory(runctx.cmn.network, runctx.cmn.permissive);
        let starting_time_factory =
            RandomStartingTimeFactory::new(RefCell::new(devctx.rng.take().unwrap()));
        let persister: Arc<dyn Persist> = Arc::new(DummyPersister);
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        // TODO(king-11) pass trusted oracle public keys
        let services = NodeServices { validator_factory, starting_time_factory, persister, clock, trusted_oracle_pubkeys: vec![] };
        let allowlist = if let Some(ref alist) = preinit.options.allowlist {
            alist.iter().map(|s| from_wire_string(s)).collect::<Vec<_>>()
        } else {
            vec![]
        };

        let approver = make_approver(&runctx.cmn.devctx, runctx.cmn.permissive, runctx.cmn.network);
        let (mut init_handler, _muts) = HandlerBuilder::new(runctx.cmn.network, 0, services, seed)
            .allowlist(allowlist)
            .approver(approver)
            .build()
            .expect("handler build");
        let (is_done, _init_reply) =
            init_handler.handle(Message::HsmdDevPreinit2(preinit)).expect("handle HsmdDevPreinit2");
        assert!(!is_done, "init handler done");

        // HsmdDevPreinit2 does not send a response, ignore the placeholder init_reply ...

        info!("used {} bytes", heap_bytes_used());
        init_handler
    };

    init_handler.log_chaninfo();

    handle_init_requests(&*runctx.cmn.devctx, &mut init_handler);
    let root_handler = init_handler.root_handler();
    handle_requests(&*runctx.cmn.devctx, root_handler);
}

fn handle_requests(arc_devctx: &RefCell<DeviceContext>, root_handler: RootHandler) -> ! {
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

        info!("starting {}, {}KB heap free", message_d.clone(), heap_free_kb());

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

        // write the response before updating the display
        write_serial_response_header(&mut devctx.serial, reqhdr.sequence)
            .expect("write reply header");
        msgs::write_vec(&mut devctx.serial, reply.as_vec()).expect("write reply");

        // update the display before the next request
        devctx.disp.clear_screen();
        let balance = root_handler.channel_balance();
        let chan_count_str = channel_count_string(&balance);
        let chan_bal_str = pretty_thousands(balance.claimable as i64);
        let chan_field_len = chan_count_str.len() + chan_bal_str.len();
        let chan_pad =
            if chan_field_len < 17 { " ".repeat(17 - chan_field_len) } else { "".to_string() };
        devctx.disp.show_texts(&[
            format!(
                "h:  {:<9}{:>4}KB",
                pretty_thousands(root_handler.get_chain_height() as i64),
                heap_free_kb
            ),
            format!(
                "r:{:>4} {:>+12}",
                balance.received_htlc_count,
                pretty_thousands(balance.received_htlc as i64)
            ),
            format!("c:{}{}{}", chan_count_str, chan_pad, chan_bal_str),
            if balance.offered_htlc > 0 {
                format!(
                    "o:{:>4} {:>+12}",
                    balance.offered_htlc_count,
                    pretty_thousands(0 - balance.offered_htlc as i64),
                )
            } else {
                format!("o:{:>4} {:>12}", balance.offered_htlc_count, "-0")
            },
            format!(""),
            top_tracks[0].clone(),
            top_tracks[1].clone(),
            top_tracks[2].clone(),
            top_tracks[3].clone(),
            top_tracks[4].clone(),
        ]);
    }
}

fn channel_count_string(balance: &ChannelBalance) -> String {
    // NOTE - there is not a lot of room on the display, this is contrived ...
    //
    // Examples, alignment is designed to match adjacent lines
    // " 1a5z2" - 1 prep, 5 active, 2 eol
    // "3a17"
    // " 1a8"   - 1 prep, 8 active
    // "  16"   - 16 active
    // "  16z2" - 16 active, 2 eol
    //
    // To save room combine the stub count with the unconfirmed count.
    let npre = balance.stub_count + balance.unconfirmed_count;
    let nact = balance.channel_count;
    let ncls = balance.closing_count;

    // Format the string components
    let pre_str = if npre > 0 { format!("{}a", npre) } else { "".to_string() };
    let act_str = format!("{}", nact);
    let cls_str = if ncls > 0 { format!("z{}", ncls) } else { "".to_string() };

    // Pad to line up the nact field w/ the surrounding lines
    let align = 4;
    let len = pre_str.len() + act_str.len();
    let pad_str = if len < align { " ".repeat(align - len) } else { "".to_string() };

    format!("{}{}{}{}", &pad_str, &pre_str, &act_str, &cls_str)
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
            rules: vec![
                FilterRule::new_warn("policy-channel-safe-type-anchors"), // TODO(236)
                FilterRule::new_warn("policy-commitment-retry-same"),     // TODO(491)
                FilterRule::new_warn("policy-commitment-htlc-routing-balance"), // TODO(313)
                FilterRule::new_warn("policy-commitment-fee-range"),      // TODO(313)
            ],
        });

        if let Some(f) = filter_opt {
            policy.filter.merge(f);
        }
        info!("VLS_ENFORCING: ALL POLICY ERRORS ARE ENFORCED");
    }

    Arc::new(SimpleValidatorFactory::new_with_policy(policy))
}

fn make_approver(
    devctx: &Arc<RefCell<DeviceContext>>,
    permissive: bool,
    network: Network,
) -> Arc<dyn Approve> {
    if permissive {
        info!("VLS_PERMISSIVE: ALL INVOICES AND KEYSENDS AUTOMATICALLY APPROVED");
        Arc::new(WarningPositiveApprover())
    } else {
        info!("VLS_ENFORCING: INVOICES AND KEYSENDS REQUIRE APPROVAL");
        Arc::new(ScreenApprover::new(Arc::clone(devctx), network))
    }
}
