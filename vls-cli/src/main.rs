use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::{HeaderMap, HeaderValue, Uri};
use jsonrpsee::core::{client::ClientT, params::ArrayParams};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use vls_proxy::config::RPC_SERVER_ENDPOINT;
use vls_proxy::rpc_server::RpcMethods;
use vls_proxy::util::get_rpc_credentials;

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

    #[clap(
        long,
        help = "rpc server admin username",
        value_parser,
        required_unless_present = "rpc-cookie",
        requires = "rpc-password"
    )]
    rpc_user: Option<String>,

    #[clap(
        long,
        help = "rpc server admin password",
        value_parser,
        required_unless_present = "rpc-cookie",
        requires = "rpc-user"
    )]
    rpc_password: Option<String>,

    #[clap(long, help = "rpc server admin cookie file path", value_parser)]
    rpc_cookie: Option<PathBuf>,

    #[clap(subcommand)]
    command: Commands,
}

impl Cli {
    /// Get the value for the Authorization header
    fn get_auth_header_value(&self) -> String {
        let (username, password) = match get_rpc_credentials(
            self.rpc_user.clone(),
            self.rpc_password.clone(),
            self.rpc_cookie.clone(),
        ) {
            Ok((username, password)) => (username, password),
            Err(e) => {
                eprintln!("Error getting rpc credentials: {}", e);
                std::process::exit(1);
            }
        };

        let raw_value = format!("{}:{}", username, password);
        STANDARD.encode(raw_value.as_bytes())
    }
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

        Ok(response?)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();
    let args = Cli::parse();
    let auth_header_value = args.get_auth_header_value();
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
    use std::io::Write;
    use tempfile::NamedTempFile;

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

    /// Test that the cli can be parsed with a cookie file
    #[test]
    fn test_cli_cookie() {
        let cookie_file = NamedTempFile::new().unwrap();
        cookie_file.as_file().write_all(b"user:password").unwrap();
        let path = cookie_file.path().to_str().unwrap();

        let args = vec!["vls-cli", "--rpc-cookie", path, "info"];

        let cli = super::Cli::parse_from(args);
        assert!(matches!(cli.command, super::Commands::Info));

        let auth_header = cli.get_auth_header_value();
        assert_eq!(auth_header, "dXNlcjpwYXNzd29yZA==");
    }

    /// Test that parsing fails if username is passed without password
    #[test]
    fn test_fail_without_password() {
        let args = vec!["vls-cli", "--rpc-user=user", "info"];
        let cli = super::Cli::try_parse_from(args);
        assert!(cli.is_err())
    }
}
