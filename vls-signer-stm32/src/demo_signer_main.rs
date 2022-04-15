#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
extern crate alloc;

use alloc::string::String;
use core::fmt;
use alloc_cortex_m::CortexMHeap;

use cortex_m_rt::entry;
use panic_probe as _;

use rtt_target::{self, rprintln, rtt_init_print};

use embedded_graphics::{
    mono_font::MonoTextStyleBuilder, pixelcolor::Rgb565, prelude::*, text::Text,
};

use st7789::{Orientation, ST7789};

#[allow(unused_imports)]
use stm32f4xx_hal::{
    fsmc_lcd::{ChipSelect1, ChipSelect3, FsmcLcd, LcdPins, Timing},
    gpio::Speed,
    pac::{CorePeripherals, Peripherals},
    prelude::*,
    sdio::{ClockFreq, SdCard, Sdio},
};

use profont::PROFONT_24_POINT;

mod sdcard;

#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();
const HEAP_SIZE: usize = 1024 * 256;

pub const SCREEN_WIDTH: i32 = 240;
pub const SCREEN_HEIGHT: i32 = 240;
pub const FONT_HEIGHT: i32 = 18;
#[cfg(feature = "stm32f412")]
pub const VCENTER_PIX: i32 = (SCREEN_HEIGHT - FONT_HEIGHT) / 2;
#[cfg(feature = "stm32f413")] // FIXME - why is this needed?  bug w/ PortraitSwapped?
pub const VCENTER_PIX: i32 = 80 + (SCREEN_HEIGHT - FONT_HEIGHT) / 2;
pub const HINSET_PIX: i32 = 100;

#[entry]
fn main() -> ! {
    rtt_init_print!(BlockIfFull);
    rprintln!("demo_signer starting");

    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }

    let p = Peripherals::take().unwrap();
    let cp = CorePeripherals::take().unwrap();
    let rcc = p.RCC.constrain();

    let clocks = rcc
        .cfgr
        .use_hse(8.MHz())
        .require_pll48clk()
        .sysclk(100.MHz())
        .hclk(100.MHz())
        .pclk1(50.MHz())
        .pclk2(100.MHz())
        .freeze();

    let mut delay = cp.SYST.delay(&clocks);

    #[cfg(feature = "stm32f413")]
    let gpiob = p.GPIOB.split();

    // both
    let gpioa = p.GPIOA.split();
    let gpioc = p.GPIOC.split();
    let gpiod = p.GPIOD.split();
    let gpioe = p.GPIOE.split();
    let gpiof = p.GPIOF.split();

    #[cfg(feature = "stm32f413")]
    let gpiog = p.GPIOG.split();

    let lcd_pins = LcdPins {
        data: (
            gpiod.pd14.into_alternate(),
            gpiod.pd15.into_alternate(),
            gpiod.pd0.into_alternate(),
            gpiod.pd1.into_alternate(),
            gpioe.pe7.into_alternate(),
            gpioe.pe8.into_alternate(),
            gpioe.pe9.into_alternate(),
            gpioe.pe10.into_alternate(),
            gpioe.pe11.into_alternate(),
            gpioe.pe12.into_alternate(),
            gpioe.pe13.into_alternate(),
            gpioe.pe14.into_alternate(),
            gpioe.pe15.into_alternate(),
            gpiod.pd8.into_alternate(),
            gpiod.pd9.into_alternate(),
            gpiod.pd10.into_alternate(),
        ),
        address: gpiof.pf0.into_alternate(),
        read_enable: gpiod.pd4.into_alternate(),
        write_enable: gpiod.pd5.into_alternate(),

        #[cfg(feature = "stm32f412")]
        chip_select: ChipSelect1(gpiod.pd7.into_alternate()),
        #[cfg(feature = "stm32f413")]
        chip_select: ChipSelect3(gpiog.pg10.into_alternate()),
    };

    rprintln!("SDIO setup");

    let d0 = gpioc.pc8.into_alternate().internal_pull_up(true);
    let d1 = gpioc.pc9.into_alternate().internal_pull_up(true);
    let d2 = gpioc.pc10.into_alternate().internal_pull_up(true);
    let d3 = gpioc.pc11.into_alternate().internal_pull_up(true);
    let clk = gpioc.pc12.into_alternate().internal_pull_up(false);
    let cmd = gpioa.pa6.into_alternate().internal_pull_up(true);
    let mut sdio: Sdio<SdCard> = Sdio::new(p.SDIO, (clk, cmd, d0, d1, d2, d3), &clocks);

    #[cfg(feature = "stm32f412")]
    let lcd_reset = gpiod.pd11.into_push_pull_output().speed(Speed::VeryHigh);
    #[cfg(feature = "stm32f413")]
    let lcd_reset = gpiob.pb13.into_push_pull_output().speed(Speed::VeryHigh);

    #[cfg(feature = "stm32f412")]
    let mut backlight_control = gpiof.pf5.into_push_pull_output();
    #[cfg(feature = "stm32f413")]
    let mut backlight_control = gpioe.pe5.into_push_pull_output();

    let write_timing = Timing::default().data(3).address_setup(3).bus_turnaround(0);
    let read_timing = Timing::default().data(8).address_setup(8).bus_turnaround(0);

    let (_fsmc, interface) = FsmcLcd::new(p.FSMC, lcd_pins, &read_timing, &write_timing);

    let mut disp = ST7789::new(interface, lcd_reset, 240, 240);

    disp.init(&mut delay).unwrap();

    #[cfg(feature = "stm32f412")]
    disp.set_orientation(Orientation::Portrait).unwrap();
    #[cfg(feature = "stm32f413")]
    disp.set_orientation(Orientation::PortraitSwapped).unwrap();

    // Turn on backlight
    backlight_control.set_high();

    let mut format_buf = String::new();
    let mut counter = 0;
    let text_style =
        MonoTextStyleBuilder::new().font(&PROFONT_24_POINT).text_color(Rgb565::WHITE).build();

    rprintln!("detecting sdcard");
    loop {
        match sdio.init(ClockFreq::F24Mhz) {
            Ok(_) => break,
            Err(e) => rprintln!("waiting for sdio - {:?}", e),
        }

        delay.delay_ms(1000u32);
    }

    let nblocks = sdio.card().map(|c| c.block_count());
    rprintln!("sdcard detected: nbr of blocks: {:?}", nblocks);

    let mut block = [0u8; 512];

    let res = sdio.read_block(0, &mut block);
    rprintln!("sdcard read result {:?}", res);

    sdcard::test(sdio);

    loop {
        disp.clear(Rgb565::BLACK).unwrap();

        format_buf.clear();
        if fmt::write(&mut format_buf, format_args!("{}", counter)).is_ok() {
            Text::new(&format_buf, Point::new(HINSET_PIX, VCENTER_PIX), text_style)
                .draw(&mut disp)
                .unwrap();
        }

        delay.delay_ms(100u16);
        counter += 1;
    }
}

// define what happens in an Out Of Memory (OOM) condition
#[alloc_error_handler]
fn alloc_error(_layout: core::alloc::Layout) -> ! {
    rprintln!("alloc error");
    cortex_m::asm::bkpt();

    loop {}
}
