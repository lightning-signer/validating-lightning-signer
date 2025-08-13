use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bitcoin::bip32::DerivationPath;
use http::{HeaderMap, HeaderValue, Uri};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::traits::ToRpcParams;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{Args, Parser, Subcommand};

use vlsd::config::RPC_SERVER_ENDPOINT;
use vlsd::rpc_server::server::RpcMethods;
use vlsd::rpc_server::{AddressListRequest, AddressType, AddressVerifyRequest};
use vlsd::util::get_rpc_credentials;

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
        required_unless_present = "rpc_cookie",
        requires = "rpc_password"
    )]
    rpc_user: Option<String>,

    #[clap(
        long,
        help = "rpc server admin password",
        value_parser,
        required_unless_present = "rpc_cookie",
        requires = "rpc_user"
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
    /// Address generation and verification commands
    #[clap(name = "addresses")]
    Addresses(AddressArgs),
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

#[derive(Debug, Args)]
struct AddressArgs {
    #[clap(subcommand)]
    command: AddressAction,
}

#[derive(Debug, Subcommand)]
enum AddressAction {
    #[clap(name = "list")]
    List {
        #[clap(long, help = "address types to generate (default: native segwit)")]
        address_type: Option<AddressType>,
        #[clap(
            long,
            help = "child index to start address generation (default: 0)",
            default_value = "0"
        )]
        start: Option<u32>,
        #[clap(long, help = "number of addresses to generate (default: 10)", default_value = "10")]
        count: Option<u32>,
        #[clap(
            short,
            long,
            help = "bip32 derivation path to use as the base address for generating addresses (default: master)"
        )]
        path: Option<String>,
    },
    #[clap(name = "verify")]
    Verify {
        #[clap(long, help = "bitcoin layer 1 address to verify")]
        address: String,
        #[clap(long, help = "starting index for address discovery")]
        start: Option<u32>,
        #[clap(long, help = "number of addresses to check")]
        limit: Option<u32>,
        #[clap(
            short,
            long,
            help = "bip32 derivation path to use as the base address for searching addresses (default: master)"
        )]
        path: Option<String>,
    },
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

    pub async fn request<T: ToRpcParams + Send>(
        self,
        method: RpcMethods,
        params: T,
    ) -> anyhow::Result<serde_json::Value> {
        let response = self.client.request(method.as_str(), params).await;

        Ok(response?)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let auth_header_value = args.get_auth_header_value();
    let rpc_client = RpcRequestClient::new(&args.rpc_uri, Some(&auth_header_value));

    let response = match args.command {
        Commands::Info => {
            let params = rpc_params![];
            rpc_client.request(RpcMethods::Info, params).await.map(|result| Some(result))
        }
        Commands::Version => {
            let params = rpc_params![];
            rpc_client.request(RpcMethods::Version, params).await.map(|result| Some(result))
        }
        Commands::AllowList(allow_list_args) => match allow_list_args.command {
            None => {
                let params = rpc_params![];
                rpc_client
                    .request(RpcMethods::AllowlistDisplay, params)
                    .await
                    .map(|result| Some(result))
            }
            Some(allow_list_command) => match allow_list_command {
                AllowListCommands::Add { address } => {
                    let params = rpc_params![address];
                    rpc_client.request(RpcMethods::AllowlistAdd, params).await.map(|_| None)
                }
                AllowListCommands::Remove { address } => {
                    let params = rpc_params![address];
                    rpc_client.request(RpcMethods::AllowlistRemove, params).await.map(|_| None)
                }
            },
        },
        Commands::Addresses(address_args) => match address_args.command {
            AddressAction::List { address_type, count, start, path } => {
                let derivation_path = DerivationPath::from_str(&path.unwrap_or("".to_owned()))?;
                let request =
                    AddressListRequest { address_type, count, start, path: Some(derivation_path) };
                rpc_client
                    .request(RpcMethods::AddressList, request)
                    .await
                    .map(|result| Some(result))
            }
            AddressAction::Verify { address, start, limit, path } => {
                let derivation_path = DerivationPath::from_str(&path.unwrap_or("".to_owned()))?;
                let request =
                    AddressVerifyRequest { address, start, limit, path: Some(derivation_path) };
                rpc_client
                    .request(RpcMethods::AddressVerify, request)
                    .await
                    .map(|result| Some(result))
            }
        },
    };

    match response {
        Ok(Some(json_result)) => println!(
            "{}",
            serde_json::to_string_pretty(&json_result)
                .expect("Return value from server is valid json")
        ),
        Err(e) => eprintln!("Command failed: {}", e),
        _ => (),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use vlsd::rpc_server::AddressType;

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

    #[test]
    fn test_fail_without_password() {
        let args = vec!["vls-cli", "--rpc-user=user", "info"];
        let cli = super::Cli::try_parse_from(args);
        assert!(cli.is_err())
    }

    #[test]
    fn test_addresses_list_with_types_parsing_succeeds() {
        let args = vec![
            "vls-cli",
            "--rpc-user=user",
            "--rpc-password=password",
            "addresses",
            "list",
            "--address-type",
            "taproot",
            "--count",
            "11",
        ];
        let result = super::Cli::try_parse_from(args);
        assert!(result.is_ok());

        let cli = result.unwrap();
        if let super::Commands::Addresses(addr_args) = cli.command {
            if let super::AddressAction::List { address_type, start, count, path } =
                addr_args.command
            {
                assert_eq!(Some(AddressType::Taproot), address_type);
                assert_eq!(Some(0), start);
                assert_eq!(Some(11), count);
                assert_eq!(None, path);
            } else {
                panic!("Expected List command");
            }
        } else {
            panic!("Expected Addresses command");
        }
    }

    #[test]
    fn test_addresses_verify_with_start_parsing_succeeds() {
        let args = vec![
            "vls-cli",
            "--rpc-user=user",
            "--rpc-password=password",
            "addresses",
            "verify",
            "--address",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "--start",
            "5",
            "--path",
            "1h/42'/11",
        ];
        let result = super::Cli::try_parse_from(args);
        assert!(result.is_ok());

        let cli = result.unwrap();
        if let super::Commands::Addresses(addr_args) = cli.command {
            if let super::AddressAction::Verify { address, start, limit, path } = addr_args.command
            {
                assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
                assert_eq!(start, Some(5));
                assert_eq!(limit, None);
                assert_eq!(path, Some("1h/42'/11".to_owned()))
            } else {
                panic!("Expected Verify command");
            }
        } else {
            panic!("Expected Addresses command");
        }
    }
}
