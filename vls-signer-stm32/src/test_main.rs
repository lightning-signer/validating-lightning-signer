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
#[cfg(feature = "sdio")]
mod sdcard;
mod timer;
mod usbserial;

use rand_core::RngCore;

#[entry]
fn main() -> ! {
    logger::init("test").expect("logger");

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
    ) = device::make_devices();

    #[cfg(feature = "sdio")]
    {
        sdcard::init_sdio(&mut sdio, &mut delay);

        let mut block = [0u8; 512];

        let res = sdio.read_block(0, &mut block);
        info!("sdcard read result {:?}", res);

        sdcard::test(sdio);
    }

    timer::start_tim2_interrupt(timer2);

    let mut counter = 1; // so we don't start with a check
    const TS_CHECK_PERIOD: usize = 50;
    loop {
        if counter % TS_CHECK_PERIOD != 0 {
            disp.clear_screen();
            disp.show_texts(&vec![format!("{}", counter), format!("{}", rng.next_u32())]);
        } else {
            disp.clear_screen();
            disp.show_choice();
            loop {
                let ans = disp.check_choice(&mut touchscreen.inner, &mut i2c);
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
            disp.clear_screen();
            disp.show_texts(&vec![format!("{}", counter), format!("{}", rng.next_u32())]);
        }

        // Echo any usbserial characters
        let mut data = [0; 1024];
        let n = serial.do_read(&mut data);
        serial.do_write(&data[0..n]);

        delay.delay_ms(100u16);
        counter += 1;
    }
}
