use alloc::{collections::VecDeque, vec::Vec};
use core::cell::{RefCell, RefMut};
use core::ops::DerefMut;
use cortex_m::interrupt::{free, Mutex};
use stm32f4xx_hal::{
    interrupt,
    otg_fs::{UsbBus, USB},
    pac::{Interrupt, NVIC, TIM2},
    timer::{CounterUs, Event},
};
use usb_device::{bus::UsbBusAllocator, device::UsbDevice, prelude::*};
use usbd_serial::SerialPort;

#[allow(unused_imports)]
use log::{debug, error};

static mut EP_MEMORY: [u32; 1024] = [0; 1024];

static mut USB_BUS: Option<UsbBusAllocator<stm32f4xx_hal::otg_fs::UsbBus<USB>>> = None;
static mut SERIAL: Option<SerialPort<UsbBus<USB>>> = None;
static mut USB_DEV: Option<UsbDevice<UsbBus<USB>>> = None;

static TIMER_TIM2: Mutex<RefCell<Option<CounterUs<TIM2>>>> = Mutex::new(RefCell::new(None));

const READ_BUFSZ: usize = 1024;

struct InputBuffer {
    data: [u8; READ_BUFSZ],
    size: usize,
}

impl InputBuffer {
    pub fn harvest(&mut self) -> Option<Vec<u8>> {
        let sz = self.size;
        if sz == 0 {
            None
        } else {
            self.size = 0;
            Some(self.data[..sz].to_vec())
        }
    }
}

static INBUF: Mutex<RefCell<InputBuffer>> =
    Mutex::new(RefCell::new(InputBuffer { data: [0; READ_BUFSZ], size: 0 }));

struct OutputBuffer {
    data: Option<VecDeque<u8>>,
}

static OUTBUF: Mutex<RefCell<OutputBuffer>> = Mutex::new(RefCell::new(OutputBuffer { data: None }));

pub fn init(usb: USB, timer: CounterUs<TIM2>) {
    // This is called once on startup
    unsafe {
        USB_BUS = Some(UsbBus::new(usb, &mut EP_MEMORY));

        SERIAL = Some(SerialPort::new(USB_BUS.as_mut().unwrap()));

        USB_DEV = Some(
            UsbDeviceBuilder::new(USB_BUS.as_mut().unwrap(), UsbVidPid(0x16c0, 0x27dd))
                .manufacturer("VLS")
                .product("signer")
                .serial_number("TEST")
                .device_class(usbd_serial::USB_CLASS_CDC)
                .build(),
        );
    }

    free(|cs| {
        TIMER_TIM2.borrow(cs).replace(Some(timer));
        OUTBUF.borrow(cs).borrow_mut().data = Some(VecDeque::new());
    });

    // Enable interrupts
    NVIC::unpend(Interrupt::TIM2);
    unsafe {
        NVIC::unmask(Interrupt::TIM2);
    };
}

#[interrupt]
fn TIM2() {
    free(|cs| {
        if let Some(ref mut tim2) = TIMER_TIM2.borrow(cs).borrow_mut().deref_mut() {
            tim2.clear_interrupt(Event::Update);
        }

        let mut inbuf = INBUF.borrow(cs).borrow_mut();
        append_inbuf(&mut inbuf);

        let mut outbuf = OUTBUF.borrow(cs).borrow_mut();
        drain_outbuf(&mut outbuf);
    });
}

pub fn read() -> Option<Vec<u8>> {
    free(|cs| {
        let mut inbuf = INBUF.borrow(cs).borrow_mut();
        append_inbuf(&mut inbuf);
        inbuf.harvest()
    })
}

pub fn write(outgoing: &[u8]) {
    free(|cs| {
        let mut outbuf = OUTBUF.borrow(cs).borrow_mut();
        outbuf.data.as_mut().unwrap().extend(outgoing);
        drain_outbuf(&mut outbuf);
    })
}

fn append_inbuf(inbuf: &mut RefMut<'_, InputBuffer>) {
    // These are not modified after init
    let (usb_dev, serial) = unsafe { (USB_DEV.as_mut().unwrap(), SERIAL.as_mut().unwrap()) };

    let size = inbuf.size;
    if size < inbuf.data.len() {
        if usb_dev.poll(&mut [serial]) {
            match serial.read(&mut inbuf.data[size..]) {
                Ok(count) => inbuf.size += count,
                Err(UsbError::WouldBlock) => {}
                Err(err) => error!("append_inbuf: serial.read error: {:?}", err),
            }
        }
    }
}

fn drain_outbuf(outbuf: &mut RefMut<'_, OutputBuffer>) {
    // These are not modified after init
    let serial = unsafe { SERIAL.as_mut().unwrap() };

    let ovd = &mut outbuf.data.as_mut().unwrap();
    if !ovd.is_empty() {
        match serial.write(ovd.make_contiguous()) {
            Ok(count) => {
                ovd.drain(0..count);
            }
            Err(UsbError::WouldBlock) => {}
            Err(err) => error!("drain_outbuf: serial.write error: {:?}", err),
        }
    }
}
