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
    logger::init().expect("logger");

    device::init_allocator();

    #[allow(unused)]
    let (mut delay, timer1, timer2, mut serial, mut sdio, mut disp, mut rng) =
        device::make_devices();

    let mut counter = 0;

    #[cfg(feature = "sdio")]
    {
        sdcard::init_sdio(&mut sdio, &mut delay);

        let mut block = [0u8; 512];

        let res = sdio.read_block(0, &mut block);
        info!("sdcard read result {:?}", res);

        sdcard::test(sdio);
    }

    timer::start_tim2_interrupt(timer2);

    loop {
        if counter % 100 == 0 || counter < 100 {
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
