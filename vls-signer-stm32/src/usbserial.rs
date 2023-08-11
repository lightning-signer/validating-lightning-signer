use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::RefCell;
use core::ops::Deref;
use cortex_m::interrupt::{free, CriticalSection, Mutex};
use stm32f4xx_hal::otg_fs::{UsbBus, USB};
use usb_device::{bus::UsbBusAllocator, device::UsbDevice, prelude::*};
use usbd_serial::SerialPort;
use vls_protocol::serde_bolt::io;
use vls_protocol_signer::vls_protocol;

use crate::timer::{self, TimerListener};
#[allow(unused_imports)]
use log::{debug, error, info, trace};

static mut USB_BUS: Option<UsbBusAllocator<UsbBus<USB>>> = None;

pub struct SerialDriverImpl {
    serial: SerialPort<'static, UsbBus<USB>>,
    usb_dev: UsbDevice<'static, UsbBus<USB>>,
    poll_count: u64,
    trace_count: u64,
}

#[derive(Clone)]
pub struct SerialDriver {
    inner: Arc<Mutex<RefCell<SerialDriverImpl>>>,
}

impl SerialDriver {
    pub(crate) fn new(usb: USB) -> Self {
        // This works at most once for now
        info!("serial: allocate usb driver memory");
        unsafe {
            if USB_BUS.is_none() {
                // Allocate memory for the USB driver that lasts to the end of the program ('static)
                let ep_memory = Box::leak(Box::new([0u32; 1024]));
                USB_BUS = Some(UsbBus::new(usb, ep_memory));
            }
        };

        info!("serial: new serial port");
        let serial = unsafe { SerialPort::new(USB_BUS.as_ref().unwrap()) };

        info!("serial: usb device builder");
        let usb_dev = unsafe {
            UsbDeviceBuilder::new(USB_BUS.as_ref().unwrap(), UsbVidPid(0x16c0, 0x27dd))
                .manufacturer("VLS")
                .product("signer")
                .serial_number("TEST")
                .device_class(usbd_serial::USB_CLASS_CDC)
                .build()
        };
        trace!("state {:?}", usb_dev.state());

        info!("serial: create serial driver impl");
        let serial_driver_impl =
            SerialDriverImpl { serial, usb_dev, poll_count: 0, trace_count: 0 };

        info!("serial: create serial driver");
        let serial_driver =
            SerialDriver { inner: Arc::new(Mutex::new(RefCell::new(serial_driver_impl))) };

        info!("serial: adding listener");
        timer::add_listener(Box::new(serial_driver.clone()));
        serial_driver
    }

    /// Return Some() if there are bytes available, otherwise None
    pub fn do_read(&self, dest: &mut [u8]) -> usize {
        free(|cs| {
            let mut inner = self.inner.deref().borrow(cs).borrow_mut();
            inner.read(dest)
        })
    }

    pub fn do_write(&self, data: &[u8]) -> usize {
        free(|cs| {
            let mut inner = self.inner.deref().borrow(cs).borrow_mut();
            inner.write(data)
        })
    }
}

impl TimerListener for SerialDriver {
    fn on_tick(&self, cs: &CriticalSection) {
        let mut serial = self.inner.deref().borrow(cs).borrow_mut();
        serial.poll_count = serial.poll_count.wrapping_add(1);
        serial.poll();
    }
}

impl SerialDriverImpl {
    pub fn read(&mut self, dest: &mut [u8]) -> usize {
        match self.serial.read(dest) {
            Ok(count) => count,
            Err(UsbError::WouldBlock) => {
                self.poll();
                if log::log_enabled!(log::Level::Trace) {
                    self.trace_count = self.trace_count.wrapping_add(1);
                    if self.trace_count % 100000 == 0 {
                        trace!("SERIAL read wait, poll_count {}", self.poll_count);
                    }
                }
                0
            }
            Err(err) => {
                error!("serial.read error: {:?}", err);
                0
            }
        }
    }

    pub fn write(&mut self, outgoing: &[u8]) -> usize {
        match self.serial.write(outgoing) {
            Ok(count) => count,
            Err(UsbError::WouldBlock) => {
                self.poll();
                if log::log_enabled!(log::Level::Trace) {
                    self.trace_count = self.trace_count.wrapping_add(1);
                    if self.trace_count % 100000 == 0 {
                        trace!("SERIAL write wait, poll_count {}", self.poll_count);
                    }
                }
                0
            }
            Err(err) => {
                error!("serial.write error: {:?}", err);
                0
            }
        }
    }

    fn poll(&mut self) -> bool {
        self.usb_dev.poll(&mut [&mut self.serial])
    }
}

impl io::Read for SerialDriver {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // We must not return Ok(0), because that signals EOF to the caller.
        // Block until at least 1 byte is available.
        // If the caller wants to block until the buffer is full, they can call read_exact().
        loop {
            let n = self.do_read(buf);
            if n > 0 {
                trace!("SERIAL read {}", hex::encode(&buf[0..n]));
                return Ok(n);
            }
        }
    }
}

impl io::Write for SerialDriver {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let c = self.do_write(buf);
            if c > 0 {
                trace!("SERIAL write {}", hex::encode(&buf[0..c]));
                return Ok(c);
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let c = self.do_write(buf);
            buf = &buf[c..];
        }
        Ok(())
    }
}
