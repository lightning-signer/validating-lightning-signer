use anyhow::Result;
use clap::{App, Arg, ArgMatches};

use lnrod::admin::cli::CLI;
use lnrod::log_utils::{parse_log_level_filter, ConsoleLogger, LOG_LEVEL_FILTER_NAMES};

fn make_node_subapp() -> App<'static> {
    App::new("node")
        .help("control a node")
        .subcommand(App::new("info").help("Get node information"))
}

fn node_subcommand(cli: &CLI, matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("info", _)) => cli.node_info()?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_node_subapp().print_help()?
        }
    };
    Ok(())
}

fn make_channel_subapp() -> App<'static> {
    App::new("channel")
        .help("control channels")
        .subcommand(App::new("list").help("List channels"))
        .subcommand(
            App::new("new")
                .help("New channel")
                .arg(
                    Arg::new("nodeid")
                        .help("node ID in hex")
                        .required(true)
                        .validator(|s| hex::decode(s)),
                )
                .arg(
                    Arg::new("value")
                        .help("value in satoshi")
                        .required(true)
                        .validator(|s| s.parse::<u64>()),
                )
                .arg(
                    Arg::new("push")
                        .long("push")
                        .help("push in milli-satoshi")
                        .validator(|s| s.parse::<u64>()),
                )
                .arg(Arg::new("public").short('b').long("public").help("announce the channel")),
        )
        .subcommand(
            App::new("close")
                .help("Close or force-close a channel")
                .arg(
                    Arg::new("channelid")
                        .help("channel ID in hex")
                        .required(true)
                        .validator(|s| hex::decode(s)),
                )
                .arg(Arg::new("force").short('f').long("force").help("force-close")),
        )
}

fn channel_subcommand(cli: &CLI, matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("list", _)) => cli.channel_list()?,
        Some(("new", submatches)) => {
            let node_id_hex: String = submatches.value_of_t("nodeid")?;
            let node_id = hex::decode(node_id_hex).expect("hex");
            let value_sat_str: String = submatches.value_of_t("value")?;
            let value_sat = value_sat_str.parse()?;
            let push_msat_str: String = submatches.value_of("push").unwrap_or("0").to_string();
            let push_msat = push_msat_str.parse()?;
            let is_public = submatches.is_present("public");
            cli.channel_new(node_id, value_sat, push_msat, is_public)?
        }
        Some(("close", submatches)) => {
            let channel_id_hex: String = submatches.value_of_t("channelid")?;
            let channel_id = hex::decode(channel_id_hex).expect("hex");
            cli.channel_close(channel_id, submatches.is_present("force"))?
        }
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_channel_subapp().print_help()?
        }
    };
    Ok(())
}

fn make_peer_subapp() -> App<'static> {
    App::new("peer")
        .help("control peer connections")
        .subcommand(App::new("list").help("List peers"))
        .subcommand(
            App::new("connect")
                .help("Connect to peer")
                .arg(Arg::new("nodeid").help("node ID in hex").required(true))
                .arg(
                    Arg::new("address")
                        .help("host:port - or include with the nodeid argument separated by @")
                        .required(false),
                ),
        )
}

fn peer_subcommand(cli: &CLI, matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("list", _)) => cli.peer_list()?,
        Some(("connect", submatches)) => {
            let (node_id_hex, address) = if submatches.is_present("address") {
                let node_id_hex: String = submatches.value_of_t("nodeid")?;
                let address: String = submatches.value_of_t("address")?;
                (node_id_hex, address)
            } else {
                let parts_str: String = submatches.value_of_t("nodeid")?;
                let mut parts = parts_str.splitn(2, "@");
                let node_id_hex = parts.next().unwrap().to_string();
                let address = parts.next().expect("missing @ separator").to_string();
                (node_id_hex, address)
            };
            let node_id = hex::decode(node_id_hex).expect("hex");
            cli.peer_connect(node_id, address)?
        }
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_peer_subapp().print_help()?
        }
    };
    Ok(())
}

fn make_invoice_subapp() -> App<'static> {
    App::new("invoice").help("control invoices").subcommand(
        App::new("new").help("Create invoice").arg(
            Arg::new("value")
                .help("value in millisats")
                .required(true)
                .validator(|s| s.parse::<u64>()),
        ),
    )
}

fn invoice_subcommand(cli: &CLI, matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("new", submatches)) => {
            let value_msat_str: String = submatches.value_of_t("value")?;
            let value_msat = value_msat_str.parse()?;
            cli.invoice_new(value_msat)?
        }
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_invoice_subapp().print_help()?
        }
    };
    Ok(())
}

fn make_payment_subapp() -> App<'static> {
    App::new("payment")
        .help("control payments")
        .subcommand(
            App::new("send")
                .help("Pay invoice")
                .arg(Arg::new("invoice").help("serialized invoice").required(true)),
        )
        .subcommand(
            App::new("keysend")
                .help("Pay to node_id")
                .arg(Arg::new("nodeid").help("the node ID").required(true))
                .arg(Arg::new("value").help("the amount in milli sat").required(true)),
        )
        .subcommand(App::new("list").help("List incoming and outgoing payments"))
}

fn payment_subcommand(cli: &CLI, matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("send", submatches)) => {
            let invoice: String = submatches.value_of_t("invoice")?;
            cli.payment_send(invoice)?
        }
        Some(("keysend", submatches)) => {
            let node_id_hex: String = submatches.value_of_t("nodeid")?;
            let node_id = hex::decode(node_id_hex).expect("hex");
            let value_msat_str: String = submatches.value_of_t("value")?;
            let value_msat = value_msat_str.parse()?;
            cli.payment_keysend(node_id, value_msat)?
        }
        Some(("list", _)) => cli.payment_list()?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_payment_subapp().print_help()?
        }
    };
    Ok(())
}

static CONSOLE_LOGGER: ConsoleLogger = ConsoleLogger;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = App::new("client")
        .help("a CLI utility which communicates with a running Lightning Signer server via gRPC")
        .arg(
            Arg::new("rpc")
                .short('c')
                .long("rpc")
                .default_value("http://127.0.0.1:8801")
                .help("Connect to an RPC address")
                .takes_value(true),
        )
        .arg(
            Arg::new("loglevelconsole")
                .help("logging level to console")
                .short('V')
                .long("log-level-console")
                .possible_values(&LOG_LEVEL_FILTER_NAMES)
                .default_value("OFF")
                .takes_value(true),
        )
        .subcommand(App::new("ping"))
        .subcommand(make_node_subapp())
        .subcommand(make_channel_subapp())
        .subcommand(make_peer_subapp())
        .subcommand(make_invoice_subapp())
        .subcommand(make_payment_subapp());
    let matches = app.clone().get_matches();
    log::set_logger(&CONSOLE_LOGGER)
        .map(|()| {
            log::set_max_level(
                parse_log_level_filter(matches.value_of_t("loglevelconsole").unwrap())
                    .expect("loglevel"),
            );
        })
        .expect("set_logger");
    let cli = CLI::new(matches.value_of("rpc").unwrap().to_string());
    match matches.subcommand() {
        None => app.print_help()?,
        Some(("ping", _)) => cli.ping()?,
        Some(("node", submatches)) => node_subcommand(&cli, submatches)?,
        Some(("channel", submatches)) => channel_subcommand(&cli, submatches)?,
        Some(("peer", submatches)) => peer_subcommand(&cli, submatches)?,
        Some(("invoice", submatches)) => invoice_subcommand(&cli, submatches)?,
        Some(("payment", submatches)) => payment_subcommand(&cli, submatches)?,
        Some((name, _)) => panic!("unimplemented command {}", name),
    }
    Ok(())
}
