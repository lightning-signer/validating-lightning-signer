use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpListener;
use tonic::codegen::futures_core::Stream;

/// A copy of the tonic TcpIncoming, but initialized from either an address or an std listener
pub struct TcpIncoming {
    inner: AddrIncoming,
}

impl TcpIncoming {
    pub fn new(addr: SocketAddr, nodelay: bool, keepalive: Option<Duration>) -> Result<Self, ()> {
        let mut inner = AddrIncoming::bind(&addr).expect("");
        inner.set_nodelay(nodelay);
        inner.set_keepalive(keepalive);
        Ok(TcpIncoming { inner })
    }

    pub fn new_from_std(
        std_listener: StdTcpListener,
        nodelay: bool,
        keepalive: Option<Duration>,
    ) -> Result<Self, ()> {
        std_listener.set_nonblocking(true).expect("set_nonblocking"); // should be infallible on a new socket
        let listener = TcpListener::from_std(std_listener).expect("tokio TcpListener"); // should only fail due to a fatal error in tokio runtime

        let mut inner = AddrIncoming::from_listener(listener).expect("from_listener"); // should be infallible
        inner.set_nodelay(nodelay);
        inner.set_keepalive(keepalive);
        Ok(TcpIncoming { inner })
    }
}

impl Stream for TcpIncoming {
    type Item = Result<AddrStream, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_accept(cx)
    }
}
