use tonic::Request;

use signer::*;
use signer::signer_client::SignerClient;

use crate::server::signer;

#[tokio::main]
pub async fn integration_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SignerClient::connect("http://[::1]:50051").await?;

    let ping_request = Request::new(PingRequest {
        message: "hello".into(),
    });

    let response = client.ping(ping_request).await?;

    println!("RESPONSE={:?}", response);

    let init_request = Request::new(InitRequest {
        key_version: None,
        chainparams: None,
        hsm_secret: vec![0u8; 32],
    });

    let response = client.init(init_request).await?;
    let node_id = response.into_inner().self_node_id;

    println!("new node {}", hex::encode(&node_id));

    let mut channel_id = [0u8; 32];
    channel_id[0] = 1u8;
    let new_chan_request = Request::new(NewChannelRequest {
        self_node_id: node_id.clone(),
        channel_nonce: channel_id.to_vec(),
        channel_value: 123,
        capabilities: 0
    });
    let response = client.new_channel(new_chan_request).await?;

    let channel_id = response.into_inner().channel_nonce;
    println!("new channel {}", hex::encode(&channel_id));

    let per_commit_request = Request::new(GetPerCommitmentPointRequest {
        self_node_id: node_id.clone(),
        channel_nonce: channel_id.clone(),
        n: 3
    });

    let response = client.get_per_commitment_point(per_commit_request).await?;
    let per_commit = response.into_inner().per_commitment_point;
    println!("per commit 3 {}", hex::encode(&per_commit));
    assert!(hex::encode(&per_commit) == "03b5497ca60ff3165908c521ea145e742c25dedd14f5602f3f502d1296c39618a5");

    Ok(())
}
