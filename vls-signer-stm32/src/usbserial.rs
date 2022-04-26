use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::{collections::VecDeque, vec::Vec};
use core::cell::RefCell;
use core::ops::Deref;
use cortex_m::interrupt::{free, CriticalSection, Mutex};
use stm32f4xx_hal::otg_fs::{UsbBus, USB};
use usb_device::{bus::UsbBusAllocator, device::UsbDevice, prelude::*};
use usbd_serial::SerialPort;

use crate::timer::{self, TimerListener};
#[allow(unused_imports)]
use log::{debug, error};

static mut USB_BUS: Option<UsbBusAllocator<UsbBus<USB>>> = None;

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
    pub(crate) fn new(usb: USB) -> Self {
        let inbuf = InputBuffer { data: [0; READ_BUFSZ], size: 0 };
        let outbuf = OutputBuffer { data: VecDeque::new() };

        // This works at most once for now
        unsafe {
            if USB_BUS.is_none() {
                // Allocate memory for the USB driver that lasts to the end of the program ('static)
                let ep_memory = Box::leak(Box::new([0u32; 1024]));
                USB_BUS = Some(UsbBus::new(usb, ep_memory));
            }
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

        let serial_driver_impl = SerialDriverImpl { serial: serial, usb_dev, inbuf, outbuf };
        let serial_driver =
            SerialDriver { inner: Arc::new(Mutex::new(RefCell::new(serial_driver_impl))) };

        timer::add_listener(Box::new(serial_driver.clone()));
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
    fn on_tick(&self, cs: &CriticalSection) {
        let mut serial = self.inner.deref().borrow(cs).borrow_mut();
        serial.append_inbuf();
        serial.drain_outbuf();
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
