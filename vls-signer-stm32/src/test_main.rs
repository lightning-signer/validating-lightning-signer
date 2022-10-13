//! Exercise hardware components.  See README.md for details.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::{format, vec};

use cortex_m_rt::entry;

use stm32f4xx_hal::prelude::*;

#[allow(unused_imports)]
use log::{debug, info, trace};

mod device;
mod logger;
mod sdcard;
mod timer;
mod usbserial;

use rand_core::RngCore;

#[entry]
fn main() -> ! {
    logger::init("test").expect("logger");
    info!("{}", env!("GIT_DESC"));
    for part in env!("GIT_DESC").split("-g") {
        info!("{}", part);
    }

    device::init_allocator();

    #[allow(unused)]
    let mut devctx = device::make_devices();

    if sdcard::init_sdio(&mut devctx.sdio, &mut devctx.delay) {
        let mut block = [0u8; 512];
        let res = devctx.sdio.read_block(0, &mut block);
        info!("sdcard read result {:?}", res);
        sdcard::test(devctx.sdio);
    }

    timer::start_tim2_interrupt(devctx.timer2);

    let mut counter = 1; // so we don't start with a check
    const TS_CHECK_PERIOD: usize = 50;
    loop {
        if counter % TS_CHECK_PERIOD != 0 {
            devctx.disp.clear_screen();
            devctx.disp.show_texts(&vec![
                format!("{}", counter),
                format!("{}", devctx.rng.next_u32()),
                format!("{}", devctx.button.is_high()),
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
                let ans = devctx.disp.check_choice(&mut devctx.touchscreen.inner, &mut devctx.i2c);
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
            devctx
                .disp
                .show_texts(&vec![format!("{}", counter), format!("{}", devctx.rng.next_u32())]);
        }

        // Echo any usbserial characters
        let mut data = [0; 1024];
        let n = devctx.serial.do_read(&mut data);
        devctx.serial.do_write(&data[0..n]);

        devctx.delay.delay_ms(100u16);
        counter += 1;
    }
}
