use alloc::string::ToString;
use alloc::sync::Arc;
use alloc_cortex_m::CortexMHeap;
use core::convert::Infallible;
use cortex_m::interrupt::{free, Mutex};
use cortex_m::peripheral::SYST;
use embedded_hal::digital::v2::OutputPin;
use log::info;
use panic_probe as _;
use rtt_target::{self, rprintln};
use st7789::{Orientation, ST7789};
#[allow(unused_imports)]
use stm32f4xx_hal::{
    fsmc_lcd::{self, ChipSelect1, ChipSelect3, FsmcLcd, Lcd, LcdPins, SubBank, Timing},
    gpio::Speed,
    otg_fs::{UsbBus, USB},
    pac::{CorePeripherals, Peripherals},
    pac::{Interrupt, NVIC, TIM2, TIM5},
    prelude::*,
    rcc::{Clocks, Rcc},
    rng::Rng,
    sdio::{ClockFreq, SdCard, Sdio},
    timer::{Counter, SysDelay},
    timer::{Event, FTimerMs, FTimerUs},
};

use embedded_graphics::{
    mono_font::MonoTextStyleBuilder, pixelcolor::Rgb565, prelude::*, text::Text,
};

use profont::{PROFONT_18_POINT, PROFONT_24_POINT};

use crate::usbserial::SerialDriver;

const TEXT_COLOR: Rgb565 = Rgb565::new(255, 255, 255);

#[cfg(feature = "stm32f412")]
mod device_specific {
    use stm32f4xx_hal::{
        fsmc_lcd::SubBank1,
        gpio::{Output, Pin},
    };

    pub type LcdSubBank = SubBank1;
    pub type LcdResetPin = Pin<'D', 11_u8, Output>;
    pub use stm32f4::stm32f412::FSMC;
}

#[cfg(feature = "stm32f413")]
mod device_specific {
    use stm32f4xx_hal::{
        fsmc_lcd::SubBank3,
        gpio::{Output, Pin},
    };

    pub type LcdSubBank = SubBank3;
    pub type LcdResetPin = Pin<'B', 13_u8, Output>;
    pub use stm32f4::stm32f413::FSMC;
}

use device_specific::*;

pub const SCREEN_WIDTH: u16 = 240;
pub const SCREEN_HEIGHT: u16 = 240;
pub const FONT_HEIGHT: u16 = 24;
#[cfg(feature = "stm32f412")]
pub const VCENTER_PIX: u16 = (SCREEN_HEIGHT - FONT_HEIGHT) / 2;
#[cfg(feature = "stm32f413")] // FIXME - why is this needed?  bug w/ PortraitSwapped?
pub const VCENTER_PIX: u16 = 80 + (SCREEN_HEIGHT - FONT_HEIGHT) / 2;
pub const HINSET_PIX: u16 = 100;

#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();
// 128K heap, leaving 128K for stack (which is overkill)
const HEAP_SIZE: usize = 1024 * 128;

pub fn make_timer(clocks: &Clocks, tim2: TIM2) -> Counter<TIM2, 1000000> {
    let mut timer = FTimerUs::<TIM2>::new(tim2, &clocks).counter();
    timer.start(5.millis()).unwrap();
    timer.listen(Event::Update);
    timer
}

pub fn init_allocator() {
    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }
}

pub fn heap_bytes_used() -> usize {
    ALLOCATOR.used()
}

pub fn make_lcd<PINS: fsmc_lcd::Pins<Lcds = Lcd<B>>, B: SubBank>(
    fsmc: FSMC,
    lcd_pins: PINS,
) -> Lcd<B> {
    let write_timing = Timing::default().data(3).address_setup(3).bus_turnaround(0);
    let read_timing = Timing::default().data(8).address_setup(8).bus_turnaround(0);

    let (_fsmc, interface) = FsmcLcd::new(fsmc, lcd_pins, &read_timing, &write_timing);
    interface
}

pub fn make_display<
    PINS: fsmc_lcd::Pins<Lcds = Lcd<LcdSubBank>>,
    BC: OutputPin<Error = Infallible>,
>(
    fsmc: FSMC,
    lcd_pins: PINS,
    lcd_reset: LcdResetPin,
    delay: &mut SysDelay,
    mut backlight_control: BC,
) -> ST7789<Lcd<LcdSubBank>, LcdResetPin> {
    let interface = make_lcd(fsmc, lcd_pins);
    let mut disp = ST7789::new(interface, lcd_reset, SCREEN_WIDTH, SCREEN_HEIGHT);
    disp.init(delay).unwrap();
    #[cfg(feature = "stm32f412")]
    disp.set_orientation(Orientation::Portrait).unwrap();
    #[cfg(feature = "stm32f413")]
    disp.set_orientation(Orientation::PortraitSwapped).unwrap();
    // Turn on backlight
    backlight_control.set_high().expect("failed to set backlight");

    disp
}

pub fn make_clocks(rcc: Rcc, syst: SYST) -> (Clocks, SysDelay) {
    let clocks = rcc
        .cfgr
        .use_hse(8.MHz())
        .require_pll48clk()
        .sysclk(100.MHz())
        .hclk(100.MHz())
        .pclk1(50.MHz())
        .pclk2(100.MHz())
        .freeze();
    let delay = syst.delay(&clocks);

    (clocks, delay)
}

pub struct Display {
    inner: ST7789<Lcd<LcdSubBank>, LcdResetPin>,
}

impl Display {
    pub fn clear_screen(&mut self) {
        self.inner.clear(Rgb565::BLACK).unwrap();
    }

    pub fn show_text<S: ToString>(&mut self, text: S) {
        let text_style =
            MonoTextStyleBuilder::new().font(&PROFONT_24_POINT).text_color(TEXT_COLOR).build();
        Text::new(&text.to_string(), Point::new(HINSET_PIX as i32, VCENTER_PIX as i32), text_style)
            .draw(&mut self.inner)
            .unwrap();
    }

    pub fn show_texts<S: ToString>(&mut self, texts: &[S]) {
        let text_style =
            MonoTextStyleBuilder::new().font(&PROFONT_18_POINT).text_color(TEXT_COLOR).build();

        let mut y = VCENTER_PIX as i32 - texts.len() as i32 * (FONT_HEIGHT as i32 + 2) / 2;
        for text in texts {
            info!("show {} {}.", text.to_string(), y);
            Text::new(&text.to_string(), Point::new(10, y), text_style)
                .draw(&mut self.inner)
                .unwrap();
            y += FONT_HEIGHT as i32 + 2;
        }
    }
}

/// A timer that can be cloned
#[derive(Clone)]
pub struct FreeTimer {
    inner: Arc<Mutex<Counter<TIM5, 1000000>>>,
}

impl FreeTimer {
    pub fn new(inner: Counter<TIM5, 1000000>) -> Self {
        Self { inner: Arc::new(Mutex::new(inner)) }
    }
    pub fn now(&self) -> fugit::TimerInstantU32<1000000> {
        free(|cs| self.inner.borrow(&cs).now())
    }
}

pub fn make_devices(
) -> (SysDelay, FreeTimer, Counter<TIM2, 1000000>, SerialDriver, Sdio<SdCard>, Display, Rng) {
    let p = Peripherals::take().unwrap();
    let cp = CorePeripherals::take().unwrap();
    let rcc = p.RCC.constrain();

    let (clocks, mut delay) = make_clocks(rcc, cp.SYST);

    let gpioa = p.GPIOA.split();
    #[cfg(feature = "stm32f413")]
    let gpiob = p.GPIOB.split();
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

    // Create a free timer from TIM5
    let mut timer1 = FTimerUs::<_>::new(p.TIM5, &clocks).counter();
    // wraps around every 1000 seconds
    timer1.start(1000.secs()).expect("start TIM5");
    // Create a periodic interrupt from TIM2
    let timer2 = make_timer(&clocks, p.TIM2);
    let serial = SerialDriver::new(USB {
        usb_global: p.OTG_FS_GLOBAL,
        usb_device: p.OTG_FS_DEVICE,
        usb_pwrclk: p.OTG_FS_PWRCLK,
        pin_dm: gpioa.pa11.into_alternate(),
        pin_dp: gpioa.pa12.into_alternate(),
        hclk: clocks.hclk(),
    });

    let sdio: Sdio<SdCard> = {
        info!("SDIO setup");
        let d0 = gpioc.pc8.into_alternate().internal_pull_up(true);
        let d1 = gpioc.pc9.into_alternate().internal_pull_up(true);
        let d2 = gpioc.pc10.into_alternate().internal_pull_up(true);
        let d3 = gpioc.pc11.into_alternate().internal_pull_up(true);
        let clk = gpioc.pc12.into_alternate().internal_pull_up(false);

        #[cfg(feature = "stm32f412")]
        let cmd = gpiod.pd2.into_alternate().internal_pull_up(true);
        #[cfg(feature = "stm32f413")]
        let cmd = gpioa.pa6.into_alternate().internal_pull_up(true);

        Sdio::new(p.SDIO, (clk, cmd, d0, d1, d2, d3), &clocks)
    };

    #[cfg(feature = "stm32f412")]
    let lcd_reset = gpiod.pd11.into_push_pull_output().speed(Speed::VeryHigh);
    #[cfg(feature = "stm32f413")]
    let lcd_reset = gpiob.pb13.into_push_pull_output().speed(Speed::VeryHigh);

    #[cfg(feature = "stm32f412")]
    let backlight_control = gpiof.pf5.into_push_pull_output();
    #[cfg(feature = "stm32f413")]
    let backlight_control = gpioe.pe5.into_push_pull_output();

    let disp =
        Display { inner: make_display(p.FSMC, lcd_pins, lcd_reset, &mut delay, backlight_control) };

    let rng = p.RNG.constrain(&clocks);

    (delay, FreeTimer::new(timer1), timer2, serial, sdio, disp, rng)
}

// define what happens in an Out Of Memory (OOM) condition
#[alloc_error_handler]
fn alloc_error(_layout: core::alloc::Layout) -> ! {
    rprintln!("alloc error");
    cortex_m::asm::udf();
    // cortex_m::asm::bkpt();
    // loop {}
}
