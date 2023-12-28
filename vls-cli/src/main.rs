use http::Uri;
use jsonrpsee::core::{client::ClientT, params::ArrayParams};
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use tracing::info;

use clap::{Parser, Subcommand};

use vls_proxy::config::RPC_SERVER_ENDPOINT;
use vls_proxy::rpc_server::{InfoModel, RpcMethods};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(
        short = 'u',
        long,
        help = "rpc server endpoint",
        default_value_t = Uri::from_static(RPC_SERVER_ENDPOINT),
        value_parser
    )]
    rpc_uri: Uri,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[clap(name = "info")]
    Info,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();
    let args = Cli::parse();

    match args.command {
        Commands::Info => {
            let params = rpc_params![];
            let response =
                send_rpc_request(&args.rpc_uri, RpcMethods::Info.as_str(), params).await?;
            let info: InfoModel = serde_json::from_value(response)?;
            println!("{:?}", info);
        }
    }

    Ok(())
}

async fn send_rpc_request(
    uri: &Uri,
    method: &str,
    params: ArrayParams,
) -> anyhow::Result<serde_json::Value> {
    let client = HttpClientBuilder::default().build(uri.to_string())?;
    let response: Result<serde_json::Value, _> = client.request(method, params).await;
    info!("{:?}", response);

    Ok(response?)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn test_cli() {
        let args = vec!["vls-cli", "info"];
        let cli = super::Cli::parse_from(args);
        assert!(matches!(cli.command, super::Commands::Info));
    }
}
