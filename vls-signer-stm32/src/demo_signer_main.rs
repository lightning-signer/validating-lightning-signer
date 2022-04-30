//! Run the signer, listening to the serial port

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use cortex_m_rt::entry;

#[allow(unused_imports)]
use log::{debug, info, trace};

use device::heap_bytes_used;
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::Arc;
use vls_protocol::msgs::{self, Message};
use vls_protocol::serde_bolt::WireString;
use vls_protocol_signer::handler::{Handler, RootHandler};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::vls_protocol;

mod device;
mod logger;
#[cfg(feature = "sdio")]
mod sdcard;
mod timer;
mod usbserial;

#[entry]
fn main() -> ! {
    logger::init().expect("logger");

    device::init_allocator();

    #[allow(unused)]
    let (mut delay, timer, mut serial, mut sdio, mut disp) = device::make_devices();

    let mut counter = 0;

    #[cfg(feature = "sdio")]
    {
        sdcard::init_sdio(&mut sdio, &mut delay);

        let mut block = [0u8; 512];

        let res = sdio.read_block(0, &mut block);
        info!("sdcard read result {:?}", res);

        sdcard::test(sdio);
    }

    timer::start(timer);

    disp.clear_screen();
    disp.show_text("init");

    let persister: Arc<dyn Persist> = Arc::new(DummyPersister);
    let init: msgs::HsmdInit2 =
        msgs::read_message(&mut serial).expect("failed to read init message");
    info!("init {:?}", init);
    let allowlist = init.dev_allowlist.iter().map(|s| from_wire_string(s)).collect::<Vec<_>>();
    let seed_opt = init.dev_seed.as_ref().map(|s| s.0);
    let root_handler = RootHandler::new(0, seed_opt, persister, allowlist);
    let init_reply = root_handler.handle(Message::HsmdInit2(init)).expect("handle init");
    msgs::write_vec(&mut serial, init_reply.as_vec()).expect("write init reply");

    info!("used {} bytes", heap_bytes_used());

    loop {
        disp.clear_screen();
        disp.show_text(format!("{}", counter));
        let message = msgs::read(&mut serial).expect("message read failed");
        match message {
            Message::Ping(p) => {
                info!("got ping with {} {}", p.id, String::from_utf8(p.message.0).unwrap());
                let reply =
                    msgs::Pong { id: p.id, message: WireString("pong".as_bytes().to_vec()) };
                msgs::write(&mut serial, reply).expect("message write failed");
            }
            Message::Unknown(u) => {
                panic!("Unknown message type {}", u.message_type);
            }
            _ => {
                panic!("Unhandled message");
            }
        }
        // delay.delay_ms(100u16);
        counter += 1;
    }
}

fn from_wire_string(s: &WireString) -> String {
    String::from_utf8(s.0.to_vec()).expect("malformed string")
}
