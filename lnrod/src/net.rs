use std::sync::Arc;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use lightning_net_tokio::setup_outbound;
use lightning_signer::bitcoin;
use log::warn;
use tokio::net::TcpStream;

use crate::disk::HostAndPort;
use crate::PeerManager;

pub struct Connector {}

impl Connector {
    pub(crate) async fn do_connect_peer(
        &self,
        pubkey: PublicKey,
        peer_addr: HostAndPort,
        peer_manager: Arc<PeerManager>,
    ) -> Result<(), ()> {
        match self.connect_outbound(Arc::clone(&peer_manager), pubkey, peer_addr.to_string()).await
        {
            Some(connection_closed_future) => {
                let mut connection_closed_future = Box::pin(connection_closed_future);
                loop {
                    match futures::poll!(&mut connection_closed_future) {
                        std::task::Poll::Ready(_) => {
                            println!("ERROR: Peer disconnected before we finished the handshake");
                            return Err(());
                        }
                        std::task::Poll::Pending => {}
                    }
                    // Avoid blocking the tokio context by sleeping a bit
                    match peer_manager
                        .list_peers()
                        .iter()
                        .find(|peer| peer.counterparty_node_id == pubkey)
                    {
                        Some(_) => break,
                        None => tokio::time::sleep(Duration::from_millis(10)).await,
                    }
                }
            }
            None => {
                return Err(());
            }
        }
        Ok(())
    }

    async fn connect_outbound(
        &self,
        peer_manager: Arc<PeerManager>,
        their_node_id: PublicKey,
        address: String,
    ) -> Option<impl std::future::Future<Output = ()>> {
        let connection_result: Result<Result<std::net::TcpStream, _>, _> =
            tokio::time::timeout(Duration::from_secs(10), async {
                TcpStream::connect(address.clone()).await.map(|s| s.into_std().unwrap())
            })
            .await;
        if let Ok(Ok(stream)) = connection_result {
            Some(setup_outbound(peer_manager, their_node_id, stream))
        } else {
            warn!("connection failed to {} - {:?}", address, connection_result);
            None
        }
    }
}
