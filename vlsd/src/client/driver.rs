use tonic::{transport, Request};

use remotesigner::signer_client::SignerClient;

use lightning_signer_server::grpc::remotesigner;
use remotesigner::node_config::KeyDerivationStyle;
use remotesigner::{
    AddAllowlistRequest, Bip32Seed, ChainParams, ChannelNonce, GetPerCommitmentPointRequest,
    InitRequest, ListAllowlistRequest, ListChannelsRequest, ListNodesRequest, NewChannelRequest,
    NodeConfig, NodeId, PingRequest, RemoveAllowlistRequest,
};

use bip39::{Language, Mnemonic};
use lightning_signer::bitcoin::secp256k1::rand;
use rand::{rngs::OsRng, RngCore};

pub async fn connect(
    uri: &str,
) -> Result<SignerClient<transport::Channel>, Box<dyn std::error::Error>> {
    let uri_clone = String::from(uri);
    Ok(SignerClient::connect(uri_clone).await?)
}

pub async fn ping(
    client: &mut SignerClient<transport::Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ping_request = Request::new(PingRequest { message: "hello".into() });

    let response = client.ping(ping_request).await?;

    println!("ping response={:?}", response);
    Ok(())
}

pub async fn new_node(
    client: &mut SignerClient<transport::Channel>,
    network_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = Mnemonic::generate_in(Language::English, 12).unwrap();
    new_node_with_mnemonic(client, mnemonic, network_name).await
}

pub async fn new_node_with_mnemonic(
    client: &mut SignerClient<transport::Channel>,
    mnemonic: Mnemonic,
    network_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret = mnemonic.to_seed("");
    let init_request = Request::new(InitRequest {
        node_config: Some(NodeConfig { key_derivation_style: KeyDerivationStyle::Native as i32 }),
        chainparams: Some(ChainParams { network_name }),
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
    let list_request =
        Request::new(ListChannelsRequest { node_id: Some(NodeId { data: node_id }) });

    let response = client.list_channels(list_request).await?.into_inner();
    let mut channel_ids: Vec<&Vec<u8>> =
        response.channel_nonces.iter().map(|id| &id.data).collect();
    channel_ids.sort();

    for channel_nonce in channel_ids {
        println!("{}", hex::encode(channel_nonce));
    }
    Ok(())
}

pub async fn list_allowlist(
    client: &mut SignerClient<transport::Channel>,
    node_id: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let list_request =
        Request::new(ListAllowlistRequest { node_id: Some(NodeId { data: node_id }) });

    let response = client.list_allowlist(list_request).await?.into_inner();
    for addr in response.addresses {
        println!("{}", addr);
    }
    Ok(())
}

pub async fn add_allowlist(
    client: &mut SignerClient<transport::Channel>,
    node_id: Vec<u8>,
    addresses: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let add_request =
        Request::new(AddAllowlistRequest { node_id: Some(NodeId { data: node_id }), addresses });

    client.add_allowlist(add_request).await?.into_inner();
    Ok(())
}

pub async fn remove_allowlist(
    client: &mut SignerClient<transport::Channel>,
    node_id: Vec<u8>,
    addresses: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let remove_request =
        Request::new(RemoveAllowlistRequest { node_id: Some(NodeId { data: node_id }), addresses });

    client.remove_allowlist(remove_request).await?.into_inner();
    Ok(())
}

pub async fn new_channel(
    client: &mut SignerClient<transport::Channel>,
    node_id: Vec<u8>,
    nonce_hex: Option<&str>,
    no_nonce: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut channel_nonce = [0u8; 32];
    if let Some(nonce_hex) = nonce_hex {
        channel_nonce.copy_from_slice(hex::decode(nonce_hex).unwrap().as_slice());
    } else {
        let mut rng = OsRng;
        rng.fill_bytes(&mut channel_nonce);
    }

    let new_chan_request = Request::new(NewChannelRequest {
        node_id: Some(NodeId { data: node_id.clone() }),
        channel_nonce0: if no_nonce {
            None
        } else {
            Some(ChannelNonce { data: channel_nonce.to_vec() })
        },
    });
    let response = client.new_channel(new_chan_request).await?.into_inner();
    if !no_nonce {
        assert_eq!(response.channel_nonce0, Some(ChannelNonce { data: channel_nonce.to_vec() }));
    }
    println!("{}", hex::encode(&response.channel_nonce0.unwrap().data));
    Ok(())
}

pub async fn integration_test(
    client: &mut SignerClient<transport::Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    ping(client).await?;

    let init_request = Request::new(InitRequest {
        node_config: Some(NodeConfig { key_derivation_style: KeyDerivationStyle::Native as i32 }),
        chainparams: None,
        coldstart: true,
        hsm_secret: Some(Bip32Seed { data: vec![0u8; 32] }),
    });

    let response = client.init(init_request).await?;
    let node_id = response.into_inner().node_id.expect("missing node_id").data;

    println!("new node {}", hex::encode(&node_id));

    let channel_nonce = [1u8];
    let new_chan_request = Request::new(NewChannelRequest {
        node_id: Some(NodeId { data: node_id.clone() }),
        channel_nonce0: Some(ChannelNonce { data: channel_nonce.to_vec() }),
    });
    let response = client.new_channel(new_chan_request).await?;

    let new_channel_nonce = response.into_inner().channel_nonce0.expect("missing channel_id");
    assert_eq!(channel_nonce.to_vec(), new_channel_nonce.data);
    println!("new channel {}", hex::encode(&channel_nonce));

    let per_commit_request = Request::new(GetPerCommitmentPointRequest {
        node_id: Some(NodeId { data: node_id.clone() }),
        channel_nonce: Some(ChannelNonce { data: channel_nonce.to_vec() }),
        n: 3,
        point_only: false,
    });

    let response = client.get_per_commitment_point(per_commit_request).await?;
    let per_commit = response.into_inner().per_commitment_point.expect("missing per_commit").data;
    println!("per commit 3 {}", hex::encode(&per_commit));
    assert_eq!(
        hex::encode(&per_commit),
        "03b5497ca60ff3165908c521ea145e742c25dedd14f5602f3f502d1296c39618a5"
    );

    Ok(())
}
