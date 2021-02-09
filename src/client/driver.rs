// FILE NOT TESTED

use tonic::Request;

use remotesigner::signer_client::SignerClient;
use remotesigner::*;

use crate::server::remotesigner;

// BEGIN NOT TESTED
#[tokio::main]
pub async fn integration_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SignerClient::connect("http://[::1]:50051").await?;

    let ping_request = Request::new(PingRequest {
        message: "hello".into(),
    });

    let response = client.ping(ping_request).await?;

    println!("RESPONSE={:?}", response);

    let init_request = Request::new(InitRequest {
        node_config: Some(NodeConfig {
            key_derivation_style: node_config::KeyDerivationStyle::Native as i32,
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

    let mut channel_id = [0u8; 32];
    channel_id[0] = 1u8;
    let new_chan_request = Request::new(NewChannelRequest {
        node_id: Some(NodeId {
            data: node_id.clone(),
        }),
        channel_nonce0: Some(ChannelNonce {
            data: channel_id.to_vec(),
        }),
    });
    let response = client.new_channel(new_chan_request).await?;

    let channel_id = response.into_inner().channel_nonce0;

    let per_commit_request = Request::new(GetPerCommitmentPointRequest {
        node_id: Some(NodeId {
            data: node_id.clone(),
        }),
        channel_nonce: channel_id.clone(),
        n: 3,
    });

    let response = client.get_per_commitment_point(per_commit_request).await?;
    let per_commit = response
        .into_inner()
        .per_commitment_point
        .expect("missing per_commit")
        .data;
    println!("per commit 3 {}", hex::encode(&per_commit));
    assert!(
        hex::encode(&per_commit)
            == "03b5497ca60ff3165908c521ea145e742c25dedd14f5602f3f502d1296c39618a5"
    );

    Ok(())
}
// END NOT TESTED
