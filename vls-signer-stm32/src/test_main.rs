//! Exercise hardware components.  See README.md for details.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::string::ToString;
use alloc::{format, vec};

use cortex_m_rt::entry;

use stm32f4xx_hal::prelude::*;

#[allow(unused_imports)]
use log::{debug, info, trace};

use lightning_signer::persist::Persist;
use lightning_signer::prelude::Box;
use lightning_signer::Arc;
use vls_protocol_signer::lightning_signer;

mod device;
mod fat_json_persist;
mod fat_logger;
mod logger;
mod sdcard;
mod setup;
mod timer;
mod usbserial;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

const TEST_LOG: &str = "test.log";

use rand_core::RngCore;

use device::DeviceContext;
use fat_json_persist::FatJsonPersister;
use fat_logger::FatLogger;
use setup::{get_run_context, setup_mode, RunContext};

#[entry]
fn main() -> ! {
    logger::init("test").expect("logger");
    info!("{}", GIT_DESC);
    for part in GIT_DESC.split("-g") {
        info!("{}", part);
    }

    device::init_allocator();

    let bare_devctx = device::make_devices();
    let runctx = if bare_devctx.button.is_high() {
        setup_mode(bare_devctx)
    } else {
        get_run_context(bare_devctx)
    };

    let arc_devctx = match runctx {
        RunContext::Testing(testctx) => {
            info!("RunContext::Testing {:?}", testctx);
            if let Some(setupfs) = testctx.cmn.setupfs.as_ref() {
                // remove any pre-existing log
                let sfs = setupfs.borrow();
                let rundir = sfs.rundir();
                sfs.remove_possible_file(&rundir, TEST_LOG);

                logger::add_also(Box::new(FatLogger::new(
                    TEST_LOG.to_string(),
                    Arc::clone(&setupfs),
                )));
            }
            testctx.cmn.devctx
        }
        RunContext::Normal(normctx) => {
            info!("RunContext::Normal {:?}", normctx);
            let _persister: Arc<dyn Persist> =
                Arc::new(FatJsonPersister::new(Arc::clone(&normctx.cmn.setupfs.as_ref().unwrap())));
            if let Some(setupfs) = normctx.cmn.setupfs.as_ref() {
                logger::add_also(Box::new(FatLogger::new(
                    TEST_LOG.to_string(),
                    Arc::clone(&setupfs),
                )));
            }
            normctx.cmn.devctx
        }
    };
    timer::start_tim2_interrupt(arc_devctx.borrow_mut().timer2.take().unwrap());
    let mut rng = arc_devctx.borrow_mut().rng.take().unwrap();

    // Create and log a 16KB random buffer (in hex) to ensure we can write large values
    info!("logging random data starting");
    let mut buff = [0u8; 16];
    rng.fill_bytes(&mut buff);
    info!("buff: {}", hex::encode(buff));
    let mut buff = [0u8; 16 * 1024];
    rng.fill_bytes(&mut buff);
    info!("buff: {}", hex::encode(buff));
    info!("logging random data finished");

    let mut counter = 1; // so we don't start with a check
    const TS_CHECK_PERIOD: usize = 50;
    loop {
        let mut devctx = arc_devctx.borrow_mut();

        if counter % TS_CHECK_PERIOD != 0 {
            let button_is_high = devctx.button.is_high();
            devctx.disp.clear_screen();
            devctx.disp.show_texts(&vec![
                format!("{}", counter),
                format!("{}", rng.next_u32()),
                format!("{}", button_is_high),
                // format!("1234567890123456789"),
                // format!("4  4567890123456789"),
                // format!("5  4567890123456789"),
                // format!("6  4567890123456789"),
                // format!("7  4567890123456789"),
                // format!("8  4567890123456789"),
                // format!("9  4567890123456789"),
            ]);
        } else {
            devctx.disp.clear_screen();
            devctx.disp.show_choice();
            loop {
                let ans = device::check_choice(&mut devctx);
                match ans {
                    Err(e) => {
                        info!("Err: {}. Try again.", e);
                        continue;
                    }
                    Ok(n) => {
                        info!("{}", n);
                        break;
                    }
                }
            }
            devctx.disp.clear_screen();
            devctx.disp.show_texts(&vec![format!("{}", counter), format!("{}", rng.next_u32())]);
        }

        // Echo any usbserial characters
        let mut data = [0; 1024];
        let n = devctx.serial.do_read(&mut data);
        devctx.serial.do_write(&data[0..n]);

        devctx.delay.delay_ms(100u16);
        counter += 1;
        info!("counter {}", counter);
    }
}
