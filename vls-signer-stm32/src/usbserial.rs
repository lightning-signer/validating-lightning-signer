use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::RefCell;
use core::cmp::min;
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
    pub fn read(&mut self, dest: &mut [u8]) -> usize {
        let sz = min(self.size, dest.len());
        if sz == 0 {
            return sz;
        }
        dest[0..sz].copy_from_slice(&self.data[0..sz]);
        self.data.copy_within(sz..self.size, 0);
        self.size -= sz;
        sz
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
        let serial_driver_impl = SerialDriverImpl { serial, usb_dev, inbuf, outbuf };

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

    pub fn do_write(&self, data: &[u8]) {
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
    pub fn read(&mut self, dest: &mut [u8]) -> usize {
        self.append_inbuf();
        self.inbuf.read(dest)
    }

    pub fn write(&mut self, outgoing: &[u8]) {
        self.outbuf.data.extend(outgoing);
        self.drain_outbuf();
    }

    fn append_inbuf(&mut self) {
        let size = self.inbuf.size;
        if size < self.inbuf.data.len() {
            if self.usb_dev.poll(&mut [&mut self.serial]) {
                trace!("state {:?}", self.usb_dev.state());
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

impl io::Read for SerialDriver {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut nread = 0;

        // Not well documented in serde_bolt, but we are expected to block
        // until we can read the whole buf or until we get to EOF.
        while !buf.is_empty() {
            let n = self.do_read(buf);
            if n == 0 {
                // TODO delay
                continue;
            }
            nread += n;
            let len = buf.len();
            buf = &mut buf[n..len];
        }
        Ok(nread)
    }
}

impl io::Write for SerialDriver {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        trace!("write {:x?}", buf);
        self.do_write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        trace!("write {:x?}", buf);
        self.do_write(buf);
        Ok(())
    }
}
