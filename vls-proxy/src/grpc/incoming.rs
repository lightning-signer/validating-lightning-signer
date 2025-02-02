use futures::Stream;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::net::{TcpListener, TcpStream};

/// TcpIncoming encapsulates a TcpListener and holds the TCP configuration
/// for nodelay so that every accepted connection is configured.
pub struct TcpIncoming {
    listener: TcpListener,
    nodelay: bool,
}

impl TcpIncoming {
    /// Binds a TcpListener to the given address and constructs a TcpIncoming
    /// with the provided socket options.
    pub async fn new(addr: SocketAddr, nodelay: bool) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(TcpIncoming { listener, nodelay })
    }
}

impl Stream for TcpIncoming {
    type Item = io::Result<TcpStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&self.listener).poll_accept(cx) {
            Poll::Ready(Ok((stream, _peer_addr))) => {
                stream.set_nodelay(self.nodelay)?;
                return Poll::Ready(Some(Ok(stream)));
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}
