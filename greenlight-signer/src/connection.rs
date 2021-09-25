use std::os::unix::net::UnixStream;
use std::os::unix::io::{RawFd, FromRawFd};

use std::io::{Read as _, Write as _};
use std::io;

use serde_bolt::{Error as SError, Read, Result as SResult, Write};

use greenlight_protocol::serde_bolt;

pub(crate) struct Connection {
    fd: RawFd,
    stream: UnixStream,
}

impl Connection {
    pub(crate) fn new(fd: RawFd) -> Self {
        Connection {
            fd,
            stream: unsafe { UnixStream::from_raw_fd(fd) }
        }
    }
}

impl Read for Connection {
    type Error = SError;

    fn read(&mut self, dest: &mut [u8]) -> SResult<usize> {
        let res: io::Result<()> = self.stream.read_exact(dest);
        match res {
            Ok(()) => Ok(dest.len()),
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    Err(SError::Eof)
                } else {
                    Err(SError::Message(format!("{}", e)))
                }
            }
        }
    }
}

impl Write for Connection {
    type Error = SError;

    fn write_all(&mut self, buf: &[u8]) -> SResult<()> {
        self.stream.write_all(buf).map_err(|e| SError::Message(format!("{}", e)))?;
        Ok(())
    }
}
