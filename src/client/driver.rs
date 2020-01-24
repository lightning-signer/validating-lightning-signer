use signer::*;
use signer::signer_client::SignerClient;

pub mod signer {
    tonic::include_proto!("signer");
}

#[tokio::main]
pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SignerClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(PingRequest {
        message: "hello".into(),
    });

    let response = client.ping(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
