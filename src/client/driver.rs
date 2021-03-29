use tonic::{transport, Request};

use remotesigner::signer_client::SignerClient;

use crate::server::remotesigner;
use crate::server::remotesigner::node_config::KeyDerivationStyle;
use crate::server::remotesigner::{
    Bip32Seed, ChannelNonce, GetPerCommitmentPointRequest, InitRequest, ListChannelsRequest,
    ListNodesRequest, NewChannelRequest, NodeConfig, NodeId, PingRequest,
};

use rand::{OsRng, Rng};
use bip39::{Mnemonic, Language};

// BEGIN NOT TESTED

pub async fn connect() -> Result<SignerClient<transport::Channel>, Box<dyn std::error::Error>> {
    Ok(SignerClient::connect("http://[::1]:50051").await?)
}

pub async fn ping(
    client: &mut SignerClient<transport::Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ping_request = Request::new(PingRequest {
        message: "hello".into(),
    });

    let response = client.ping(ping_request).await?;

    println!("ping response={:?}", response);
    Ok(())
}

pub async fn new_node(
    client: &mut SignerClient<transport::Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = Mnemonic::generate_in(Language::English, 12).unwrap();
    let secret = mnemonic.to_seed("");
    let init_request = Request::new(InitRequest {
        node_config: Some(NodeConfig {
            key_derivation_style: KeyDerivationStyle::Native as i32,
        }),
        chainparams: None,
        coldstart: true,
        hsm_secret: Some(Bip32Seed { data: secret.to_vec() }),
    });

    let response = client.init(init_request).await?;
    let node_id = response.into_inner().node_id.expect("missing node_id").data;

    eprintln!("mnemonic: {}", mnemonic);
    println!("{}", hex::encode(&node_id));
    Ok(())
}

pub async fn list_nodes(
    client: &mut SignerClient<transport::Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let list_request = Request::new(ListNodesRequest {});

    let response = client.list_nodes(list_request).await?.into_inner();
    let mut node_ids: Vec<&Vec<u8>> = response.node_ids.iter().map(|id| &id.data).collect();
    node_ids.sort();

    for node_id in node_ids {
        println!("{}", hex::encode(node_id));
    }
    Ok(())
}

pub async fn list_channels(
    client: &mut SignerClient<transport::Channel>,
    node_id: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let list_request = Request::new(ListChannelsRequest {
        node_id: Some(NodeId { data: node_id }),
    });

    let response = client.list_channels(list_request).await?.into_inner();
    let mut channel_ids: Vec<&Vec<u8>> =
        response.channel_nonces.iter().map(|id| &id.data).collect();
    channel_ids.sort();

    for channel_nonce in channel_ids {
        println!("{}", hex::encode(channel_nonce));
    }
    Ok(())
}

pub async fn new_channel(
    client: &mut SignerClient<transport::Channel>,
    node_id: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut channel_nonce = [0u8; 32];
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut channel_nonce);

    let new_chan_request = Request::new(NewChannelRequest {
        node_id: Some(NodeId {
            data: node_id.clone(),
        }),
        channel_nonce0: Some(ChannelNonce {
            data: channel_nonce.to_vec(),
        }),
    });
    let _response = client.new_channel(new_chan_request).await?.into_inner();
    println!("{}", hex::encode(&channel_nonce));
    Ok(())
}

pub async fn integration_test(
    client: &mut SignerClient<transport::Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    ping(client).await?;

    let init_request = Request::new(InitRequest {
        node_config: Some(NodeConfig {
            key_derivation_style: KeyDerivationStyle::Native as i32,
        }),
        chainparams: None,
        coldstart: true,
        hsm_secret: Some(Bip32Seed {
            data: vec![0u8; 32],
        }),
    });

    let response = client.init(init_request).await?;
    let node_id = response.into_inner().node_id.expect("missing node_id").data;

    println!("new node {}", hex::encode(&node_id));

    let channel_nonce = [1u8];
    let new_chan_request = Request::new(NewChannelRequest {
        node_id: Some(NodeId {
            data: node_id.clone(),
        }),
        channel_nonce0: Some(ChannelNonce {
            data: channel_nonce.to_vec(),
        }),
    });
    let response = client.new_channel(new_chan_request).await?;

    let new_channel_nonce = response
        .into_inner()
        .channel_nonce0
        .expect("missing channel_id");
    assert_eq!(channel_nonce.to_vec(), new_channel_nonce.data);
    println!("new channel {}", hex::encode(&channel_nonce));

    let per_commit_request = Request::new(GetPerCommitmentPointRequest {
        node_id: Some(NodeId {
            data: node_id.clone(),
        }),
        channel_nonce: Some(ChannelNonce {
            data: channel_nonce.to_vec(),
        }),
        n: 3,
    });

    let response = client.get_per_commitment_point(per_commit_request).await?;
    let per_commit = response
        .into_inner()
        .per_commitment_point
        .expect("missing per_commit")
        .data;
    println!("per commit 3 {}", hex::encode(&per_commit));
    assert_eq!(
        hex::encode(&per_commit),
        "03b5497ca60ff3165908c521ea145e742c25dedd14f5602f3f502d1296c39618a5"
    );

    Ok(())
}

// END NOT TESTED
