use crate::{hex_utils, DynKeysInterface, DynSigner, LoggerAdapter, MyEntropySource, NetworkGraph};
use anyhow::Result;
use bitcoin::hashes::sha256d;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, Txid};
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::transaction::OutPoint;
use lightning::util::ser::{ReadableArgs, Writeable};
use lightning_signer::bitcoin;
use lightning_signer::bitcoin::Network;
use lightning_signer::lightning;
use log::error;
use regex::Regex;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Cursor, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const MAX_CHANNEL_MONITOR_FILENAME_LENGTH: usize = 65;

pub(crate) fn read_channelmonitors(
    path: String,
    entropy_source: Arc<MyEntropySource>,
    keys_manager: Arc<DynKeysInterface>,
) -> Result<HashMap<OutPoint, (BlockHash, ChannelMonitor<DynSigner>)>, std::io::Error> {
    if !Path::new(&path).exists() {
        return Ok(HashMap::new());
    }
    let mut outpoint_to_channelmonitor = HashMap::new();
    for file_option in fs::read_dir(path)? {
        let file = file_option?;
        let owned_file_name = file.file_name();
        let filename = owned_file_name.to_str().ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Invalid ChannelMonitor file name: Not valid Unicode",
        ))?;

        if !filename.is_ascii() || filename.len() < MAX_CHANNEL_MONITOR_FILENAME_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Invalid ChannelMonitor file name: Must be ASCII with more than {} characters",
                    MAX_CHANNEL_MONITOR_FILENAME_LENGTH
                ),
            ));
        }

        let txid = Txid::from_raw_hash(sha256d::Hash::from_str(filename.split_at(64).0).map_err(
            |_| std::io::Error::new(std::io::ErrorKind::Other, "Invalid tx ID in filename"),
        )?);

        let index = filename
            .split_at(MAX_CHANNEL_MONITOR_FILENAME_LENGTH)
            .1
            .split('.')
            .next()
            .unwrap()
            .parse()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "Invalid tx index in filename")
            })?;

        let contents = fs::read(&file.path())?;

        if let Ok((blockhash, channel_monitor)) = <(BlockHash, ChannelMonitor<DynSigner>)>::read(
            &mut Cursor::new(&contents),
            (&*entropy_source, &*keys_manager),
        ) {
            outpoint_to_channelmonitor
                .insert(OutPoint { txid, index }, (blockhash, channel_monitor));
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to deserialize ChannelMonitor",
            ));
        }
    }
    Ok(outpoint_to_channelmonitor)
}

pub(crate) fn read_network(
    path: &Path,
    network: Network,
    logger: Arc<LoggerAdapter>,
) -> NetworkGraph<Arc<LoggerAdapter>> {
    if let Ok(file) = File::open(path) {
        if let Ok(graph) = NetworkGraph::read(&mut BufReader::new(file), logger.clone()) {
            return graph;
        }
    }
    NetworkGraph::new(network, logger)
}

pub(crate) fn persist_network(
    path: &Path,
    network_graph: &NetworkGraph<Arc<LoggerAdapter>>,
) -> std::io::Result<()> {
    let mut tmp_path = path.to_path_buf().into_os_string();
    tmp_path.push(".tmp");
    let file = fs::OpenOptions::new().write(true).create(true).open(&tmp_path)?;
    network_graph.write(&mut BufWriter::new(file))?;
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        Err(e)
    } else {
        Ok(())
    }
}

pub(crate) fn start_network_graph_persister(
    network_graph_path: String,
    network_graph: &Arc<NetworkGraph<Arc<LoggerAdapter>>>,
) {
    let network_graph_persist = Arc::clone(&network_graph);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        loop {
            interval.tick().await;
            if persist_network(Path::new(&network_graph_path), &network_graph_persist).is_err() {
                error!("Warning: Failed to persist network graph, check your disk and permissions");
            }
        }
    });
}

pub(crate) fn parse_peer_info(
    peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, HostAndPort), std::io::Error> {
    let regex = Regex::new(r"^(.*)@(.*):(.*)$").expect("regex");
    let caps = regex.captures(&peer_pubkey_and_ip_addr).ok_or(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ERROR: incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`",
    ))?;
    let pubkey_str = caps.get(1).expect("capture 1").as_str();
    let host = caps.get(2).expect("capture 2").as_str();
    let port = caps.get(3).expect("capture 3").as_str().parse().expect("port integer");
    let pubkey = hex_utils::to_compressed_pubkey(pubkey_str);
    if pubkey.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ERROR: unable to parse given pubkey for node",
        ));
    }

    Ok((pubkey.unwrap(), HostAndPort(host.to_string(), port)))
}

pub(crate) fn persist_channel_peer(
    path: &Path,
    pubkey: PublicKey,
    addr: HostAndPort,
) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(format!("{}@{}:{}\n", pubkey, addr.0, addr.1).as_bytes())
}

#[derive(Clone)]
pub struct HostAndPort(pub String, pub u16);

impl Display for HostAndPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)?;
        f.write_str(":")?;
        f.write_str(&self.1.to_string())?;
        Ok(())
    }
}

impl FromStr for HostAndPort {
    type Err = std::io::Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let regex = Regex::new(r"^(.*):(.*)$").expect("regex");
        let captures = regex
            .captures(s)
            .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "invalid host:port"))?;

        let host = captures.get(1).unwrap().as_str().to_string();
        let port = captures.get(2).unwrap().as_str().parse().expect("port numeric");
        Ok(HostAndPort(host, port))
    }
}

impl TryInto<SocketAddr> for HostAndPort {
    type Error = std::io::Error;

    fn try_into(self) -> core::result::Result<SocketAddr, Self::Error> {
        let ip: IpAddr =
            self.0.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(SocketAddr::from((ip, self.1)))
    }
}

pub(crate) fn read_channel_peer_data(
    path: &Path,
) -> Result<HashMap<PublicKey, HostAndPort>, std::io::Error> {
    let mut peer_data = HashMap::new();
    if !Path::new(&path).exists() {
        return Ok(HashMap::new());
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        match parse_peer_info(line.unwrap()) {
            Ok((pubkey, socket_addr)) => {
                peer_data.insert(pubkey, socket_addr);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(peer_data)
}
