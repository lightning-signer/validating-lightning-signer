use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::{HeaderMap, HeaderValue, Uri};
use jsonrpsee::core::{client::ClientT, params::ArrayParams};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use tracing::*;

use clap::{Args, Parser, Subcommand};

use vls_proxy::config::RPC_SERVER_ENDPOINT;
use vls_proxy::rpc_server::RpcMethods;

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

    #[clap(long, help = "rpc server admin username", value_parser)]
    rpc_user: String,

    #[clap(long, help = "rpc server admin password", value_parser)]
    rpc_password: String,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Info about current state of signer
    #[clap(name = "info")]
    Info,
    /// Version of validating lightning signer
    #[clap(name = "version")]
    Version,
    /// Retrieve or edit allowlist
    #[clap(name = "allowlist")]
    AllowList(AllowListArgs),
}

#[derive(Debug, Args)]
struct AllowListArgs {
    #[clap(subcommand)]
    command: Option<AllowListCommands>,
}

#[derive(Debug, Subcommand)]
enum AllowListCommands {
    /// add address to allowlist
    #[clap(name = "add")]
    Add { address: String },
    /// remove address from allowlist
    #[clap(name = "remove")]
    Remove { address: String },
}

struct RpcRequestClient {
    client: HttpClient,
}

impl RpcRequestClient {
    pub fn new(uri: &Uri, auth_header_value: Option<&str>) -> Self {
        let mut client_builder = HttpClientBuilder::default();
        if let Some(value) = auth_header_value {
            let mut headers = HeaderMap::new();
            let header_value =
                HeaderValue::from_str(value).expect("can't convert value to auth header");
            headers.insert("Authorization", header_value);
            client_builder = client_builder.set_headers(headers);
        };
        let client = client_builder.build(uri.to_string()).expect("can't create rpc http client");
        Self { client: client }
    }

    pub async fn request(
        self,
        method: RpcMethods,
        params: ArrayParams,
    ) -> anyhow::Result<serde_json::Value> {
        let response = self.client.request(method.as_str(), params).await;
        info!("{:?}", response);

        Ok(response?)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();
    let args = Cli::parse();
    let auth_header_value =
        STANDARD.encode(format!("{}:{}", args.rpc_user, args.rpc_password).as_bytes());
    let rpc_client = RpcRequestClient::new(&args.rpc_uri, Some(&auth_header_value));

    let response = match args.command {
        Commands::Info => {
            let params = rpc_params![];
            let response = rpc_client.request(RpcMethods::Info, params).await?;
            Some(response)
        }
        Commands::Version => {
            let params = rpc_params![];
            let response = rpc_client.request(RpcMethods::Version, params).await?;
            Some(response)
        }
        Commands::AllowList(allow_list_args) => match allow_list_args.command {
            None => {
                let params = rpc_params![];
                let response = rpc_client.request(RpcMethods::AllowlistDisplay, params).await?;
                Some(response)
            }
            Some(allow_list_command) => match allow_list_command {
                AllowListCommands::Add { address } => {
                    let params = rpc_params![address];
                    rpc_client.request(RpcMethods::AllowlistAdd, params).await?;
                    None
                }
                AllowListCommands::Remove { address } => {
                    let params = rpc_params![address];
                    rpc_client.request(RpcMethods::AllowlistRemove, params).await?;
                    None
                }
            },
        },
    };

    if let Some(json_result) = response {
        println!("{}", serde_json::to_string_pretty(&json_result)?)
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn test_cli() {
        let args = vec!["vls-cli", "--rpc-user=user", "--rpc-password=password", "info"];
        let cli = super::Cli::parse_from(args);
        assert!(matches!(cli.command, super::Commands::Info));
    }

    #[test]
    fn test_fail_without_username() {
        let args = vec!["vls-cli", "info"];
        let cli = super::Cli::try_parse_from(args);
        assert!(cli.is_err())
    }
}
