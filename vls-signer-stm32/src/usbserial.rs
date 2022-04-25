use alloc::{collections::VecDeque, vec::Vec};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::borrow::{Borrow, BorrowMut};
use core::cell::RefCell;
use core::ops::Deref;
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
static mut USB_BUS: Option<UsbBusAllocator<UsbBus<USB>>> = None;
static mut TIMER_LISTENERS: Vec<Box<dyn TimerListener>> = Vec::new();
static mut TIMER_TIM2: Option<CounterUs<TIM2>> = None;

trait TimerListener {
    fn on_tick(&self);
}

pub struct SerialDriverImpl {
    serial: SerialPort<'static, UsbBus<USB>>,
    usb_dev: UsbDevice<'static, UsbBus<USB>>,
    inbuf: InputBuffer,
    outbuf: OutputBuffer,
}

#[derive(Clone)]
pub struct SerialDriver {
    inner: Arc<Mutex<RefCell<SerialDriverImpl>>>,
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
    pub(crate) fn new(usb: USB, timer: CounterUs<TIM2>) -> Self {
        let inbuf = InputBuffer { data: [0; READ_BUFSZ], size: 0 };
        let outbuf = OutputBuffer { data: VecDeque::new() };

        // This is called once on startup
        unsafe {
            assert!(USB_BUS.is_none());
            USB_BUS = Some(UsbBus::new(usb, &mut EP_MEMORY));
            TIMER_TIM2 = Some(timer);
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
        let serial_driver_impl =
            SerialDriverImpl { serial: serial, usb_dev, inbuf, outbuf };
        let serial_driver = SerialDriver {
            inner: Arc::new(Mutex::new(RefCell::new(serial_driver_impl)))
        };
        unsafe { TIMER_LISTENERS.push(Box::new(serial_driver.clone())); }

        serial_driver
    }

    pub fn read(&self) -> Option<Vec<u8>> {
        free(|cs| {
            let mut inner = self.inner.deref().borrow(cs).borrow_mut();
            inner.read()
        })
    }

    pub fn write(&self, data: &[u8]) {
        free(|cs| {
            let mut inner = self.inner.deref().borrow(cs).borrow_mut();
            inner.write(data)
        })
    }
}

impl TimerListener for SerialDriver {
    fn on_tick(&self) {
        free(|cs| {
            let mut serial = self.inner.deref().borrow(cs).borrow_mut();
            serial.append_inbuf();
            serial.drain_outbuf();
        });
    }
}

#[interrupt]
fn TIM2() {
    unsafe {
        for listener in &TIMER_LISTENERS {
            listener.on_tick();
        }
        TIMER_TIM2.as_mut().unwrap().clear_interrupt(Event::Update);
    }
}

impl SerialDriverImpl {
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
