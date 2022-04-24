use alloc::{collections::VecDeque, vec::Vec};
use core::cell::RefCell;
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
pub static SERIAL: Mutex<RefCell<Option<SerialDriver>>> = Mutex::new(RefCell::new(None));
static mut USB_BUS: Option<UsbBusAllocator<UsbBus<USB>>> = None;

pub struct SerialDriver {
    serial: SerialPort<'static, UsbBus<USB>>,
    usb_dev: UsbDevice<'static, UsbBus<USB>>,
    timer_tim2: CounterUs<TIM2>,
    inbuf: InputBuffer,
    outbuf: OutputBuffer,
}

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

struct OutputBuffer {
    data: VecDeque<u8>,
}

impl SerialDriver {
    pub(crate) fn init(usb: USB, timer: CounterUs<TIM2>) {
        let inbuf = InputBuffer { data: [0; READ_BUFSZ], size: 0 };
        let outbuf = OutputBuffer { data: VecDeque::new() };

        // This is called once on startup
        unsafe {
            assert!(USB_BUS.is_none());
            USB_BUS = Some(UsbBus::new(usb, &mut EP_MEMORY));
        };

        let serial = unsafe { SerialPort::new(USB_BUS.as_ref().unwrap()) };

        let usb_dev = unsafe {
            UsbDeviceBuilder::new(USB_BUS.as_ref().unwrap(), UsbVidPid(0x16c0, 0x27dd))
                .manufacturer("VLS")
                .product("signer")
                .serial_number("TEST")
                .device_class(usbd_serial::USB_CLASS_CDC)
                .build()
        };

        // Enable interrupts
        NVIC::unpend(Interrupt::TIM2);
        unsafe {
            NVIC::unmask(Interrupt::TIM2);
        };
        let serial_driver =
            SerialDriver { serial: serial, usb_dev, timer_tim2: timer, inbuf, outbuf };
        free(|cs| SERIAL.borrow(cs).replace(Some(serial_driver)));
    }
}

#[interrupt]
fn TIM2() {
    free(|cs| {
        let mut serial_lock = SERIAL.borrow(cs).borrow_mut();
        let serial = serial_lock.as_mut().unwrap();
        serial.timer_tim2.clear_interrupt(Event::Update);

        serial.append_inbuf();

        serial.drain_outbuf();
    });
}

impl SerialDriver {
    pub fn read(&mut self) -> Option<Vec<u8>> {
        self.append_inbuf();
        self.inbuf.harvest()
    }

    pub fn write(&mut self, outgoing: &[u8]) {
        self.outbuf.data.extend(outgoing);
        self.drain_outbuf();
    }

    fn append_inbuf(&mut self) {
        let size = self.inbuf.size;
        if size < self.inbuf.data.len() {
            if self.usb_dev.poll(&mut [&mut self.serial]) {
                match self.serial.read(&mut self.inbuf.data[size..]) {
                    Ok(count) => self.inbuf.size += count,
                    Err(UsbError::WouldBlock) => {}
                    Err(err) => error!("append_inbuf: serial.read error: {:?}", err),
                }
            }
        }
    }

    fn drain_outbuf(&mut self) {
        let ovd = &mut self.outbuf.data;
        if !ovd.is_empty() {
            match self.serial.write(ovd.make_contiguous()) {
                Ok(count) => {
                    ovd.drain(0..count);
                }
                Err(UsbError::WouldBlock) => {}
                Err(err) => error!("drain_outbuf: serial.write error: {:?}", err),
            }
        }
    }
}
