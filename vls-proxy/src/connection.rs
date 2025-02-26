use std::io::{IoSlice, IoSliceMut, Read, Result as SResult, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::{fs, io};

use log::{error, info, trace};
use nix::cmsg_space;
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};

use nix::libc;
use nix::unistd::close;

const PARENT_FD: u16 = 3;

pub struct UnixConnection {
    fd: RawFd,
    stream: UnixStream,
}

impl UnixConnection {
    pub fn new(fd: RawFd) -> Self {
        UnixConnection { fd, stream: unsafe { UnixStream::from_raw_fd(fd) } }
    }

    pub fn try_clone(&self) -> SResult<Self> {
        Ok(UnixConnection { fd: self.fd, stream: self.stream.try_clone()? })
    }

    pub(crate) fn id(&self) -> u64 {
        self.fd as u64
    }

    pub(crate) fn send_fd(&self, fd: RawFd) {
        info!("sending fd {}", fd);
        let fds = [fd];
        let fd_msg = ControlMessage::ScmRights(&fds);
        let c = [0xff];
        let x = IoSlice::new(&c);
        sendmsg::<()>(self.fd, &[x], &[fd_msg], MsgFlags::empty(), None).unwrap();
        close(fd).unwrap();
    }

    pub(crate) fn recv_fd(&self) -> Result<RawFd, ()> {
        let mut cmsgs = cmsg_space!(RawFd);
        let mut c = [0];
        let mut io_slice = [IoSliceMut::new(&mut c)];
        let result =
            recvmsg::<()>(self.fd, &mut io_slice, Some(&mut cmsgs), MsgFlags::empty()).unwrap();
        let mut iter = result.cmsgs().map_err(|_| ())?;
        let cmsg = iter.next().ok_or_else(|| {
            error!("expected a control message");
        })?;
        if iter.next().is_some() {
            error!("expected exactly one control message");
            return Err(());
        }
        match cmsg {
            ControlMessageOwned::ScmRights(r) =>
                if r.len() != 1 {
                    error!("expected exactly one fd");
                    Err(())
                } else {
                    if c[0] != 0xff {
                        error!("expected a 0xff byte ancillary byte, got {}", c[0]);
                        return Err(());
                    }
                    Ok(r[0])
                },
            m => {
                error!("unexpected cmsg {:?}", m);
                Err(())
            }
        }
    }
}

impl Read for UnixConnection {
    fn read(&mut self, dest: &mut [u8]) -> SResult<usize> {
        let mut cursor = 0;
        if dest.is_empty() {
            return Ok(0);
        }
        while cursor < dest.len() {
            let res: io::Result<usize> = self.stream.read(&mut dest[cursor..]);
            trace!("read {}: {:?} cursor={} expected={}", self.id(), res, cursor, dest.len());
            match res {
                Ok(n) => {
                    if n == 0 {
                        return Ok(cursor);
                    }
                    cursor = cursor + n;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(cursor)
    }
}

impl Write for UnixConnection {
    fn write(&mut self, buf: &[u8]) -> SResult<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> SResult<()> {
        self.stream.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> SResult<()> {
        self.stream.write_all(buf)
    }
}

pub fn open_parent_fd() -> RawFd {
    // Only use fd 3 if we are really running with a lightningd parent, so we don't conflict with future fd allocation
    // Check this before opening any files or sockets!
    let have_parent = unsafe { libc::fcntl(PARENT_FD as libc::c_int, libc::F_GETFD) } != -1;

    let dummy_file = fs::File::open("/dev/null").unwrap().into_raw_fd();

    let parent_fd = if have_parent {
        close(dummy_file).expect("close dummy");
        RawFd::from(PARENT_FD)
    } else {
        error!("no parent on {}, using /dev/null", PARENT_FD);
        dummy_file
    };
    parent_fd
}
