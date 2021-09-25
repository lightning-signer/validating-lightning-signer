use std::io::{Read as _, Write as _};
use std::io;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use log::{info, error};
use nix::cmsg_space;
use nix::sys::socket::{ControlMessage, MsgFlags, recvmsg, sendmsg, ControlMessageOwned};
use serde_bolt::{Error as SError, Read, Result as SResult, Write};

use greenlight_protocol::serde_bolt;
use nix::sys::uio::IoVec;
use nix::unistd::close;

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

    pub(crate) fn send_fd(&self, fd: RawFd) {
        info!("sending fd {}", fd);
        let fds = [fd];
        let fd_msg = ControlMessage::ScmRights(&fds);
        let mut c = [0xff];
        let x = IoVec::from_slice(&mut c);
        sendmsg(self.fd, &[x], &[fd_msg], MsgFlags::empty(), None).unwrap();
        close(fd).unwrap();
    }

    pub(crate) fn recv_fd(&self) -> Result<RawFd, ()> {
        let mut cmsgs = cmsg_space!(RawFd);
        let mut c = [0];
        let x = IoVec::from_mut_slice(&mut c);
        let result = recvmsg(self.fd, &[x], Some(&mut cmsgs), MsgFlags::empty()).unwrap();
        let mut iter = result.cmsgs();
        if c[0] != 0xff {
            error!("expected a 0xff byte, got {}", c[0]);
            return Err(())
        }
        let cmsg = iter.next()
            .ok_or_else(|| {
                error!("expected a control message");
            })?;
        if iter.next().is_some() {
            error!("expected exactly one control message");
            return Err(());
        }
        match cmsg {
            ControlMessageOwned::ScmRights(r) => {
                if r.len() != 1 {
                    error!("expected exactly one fd");
                    Err(())
                } else {
                    Ok(r[0])
                }
            },
            m => {
                error!("unexpected cmsg {:?}", m);
                Err(())
            }
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
