#![crate_name = "bitcoind_client"]

//! A bitcoind RPC client.

#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]
#![warn(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]

/// Bitcoind RPC client
pub mod bitcoind_client;
mod convert;

pub use self::bitcoind_client::{BitcoindClient, BlockSource, Error};
use lightning_signer::bitcoin::Network;
use log::info;
use std::env;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use url::Url;

fn bitcoin_network_path(base_path: PathBuf, network: Network) -> PathBuf {
    match network {
        Network::Bitcoin => base_path,
        Network::Testnet => base_path.join("testnet3"),
        Network::Signet => base_path.join("signet"),
        Network::Regtest => base_path.join("regtest"),
    }
}

fn bitcoin_rpc_cookie(network: Network) -> (String, String) {
    let home = env::var("HOME").expect("cannot get cookie file if HOME is not set");
    let bitcoin_path = Path::new(&home).join(".bitcoin");
    let bitcoin_net_path = bitcoin_network_path(bitcoin_path, network);
    let cookie_path = bitcoin_net_path.join("cookie");
    info!("auth to bitcoind via cookie {}", cookie_path.to_string_lossy());
    let cookie_contents = read_to_string(cookie_path).expect("cookie file read");
    let mut iter = cookie_contents.splitn(2, ":");
    (iter.next().expect("cookie user").to_string(), iter.next().expect("cookie pass").to_string())
}

/// Construct a client from an RPC URL and a network
pub async fn bitcoind_client_from_url(url: Url, network: Network) -> BitcoindClient {
    let host = url.host_str().expect("host");
    let port = url.port().expect("port");
    // Initialize our bitcoind client.
    let (user, pass) = if url.username().is_empty() {
        // try to get from cookie file
        bitcoin_rpc_cookie(network)
    } else {
        (url.username().to_string(), url.password().unwrap_or("").to_string())
    };
    BitcoindClient::new(host.to_string(), port, user, pass).await
}
