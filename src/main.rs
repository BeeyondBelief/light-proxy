use clap::{ArgAction, Parser, Subcommand};
use light_proxy::{run, ExecuteConfig, ProxyMode, Result};
use log;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "Run with SOCKS5 protocol for proxy connections", long_about = None)]
struct Socks5Args {
    #[arg(
        short = 'f',
        long,
        help = "Path to the file where user credentials are stored. Format of a files is: \
            <user:password\n> or just <user:\n> in the second case <user:> means an access token"
    )]
    credentials_file: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(version, about = "Run with SOCKS4 protocol for proxy connections", long_about = None)]
struct Socks4Args {}

#[derive(Subcommand, Debug)]
enum Commands {
    Socks5(Socks5Args),
    Socks4(Socks4Args),
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        short = 'l',
        long,
        default_value = "127.0.0.1",
        help = "From what IP address listen for HTTP requests"
    )]
    #[clap(global = true)]
    listen_ip: IpAddr,

    #[arg(
        short = 'p',
        long,
        default_value = "8000",
        help = "From what port listen for HTTP requests"
    )]
    #[clap(global = true)]
    listen_port: u16,
    #[arg(
        short = 'v',
        action = ArgAction::Count,
        help = "How verbose logging messages are. The more value is set the more messages are \
                displayed. Maximum message verbosity set at 5"
    )]
    #[clap(global = true)]
    verbosity: u8,

    #[command(subcommand)]
    command: Commands,
}

impl Into<ExecuteConfig> for Args {
    fn into(self) -> ExecuteConfig {
        let mode = match self.command {
            Commands::Socks5(args) => ProxyMode::SOCKS5 {
                credentials_file: args.credentials_file,
            },
            Commands::Socks4(_) => ProxyMode::SOCKS4 {},
        };
        ExecuteConfig {
            listen_address: SocketAddr::new(self.listen_ip, self.listen_port),
            mode,
        }
    }
}

fn u8_to_log_level(value: u8) -> log::LevelFilter {
    match value {
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.verbosity > 0 {
        std::env::set_var(
            env_logger::DEFAULT_FILTER_ENV,
            u8_to_log_level(args.verbosity).as_str(),
        )
    }

    env_logger::init();
    if let Err(e) = run(args.into()).await {
        log::error!("{:?}", e);
        std::process::exit(1);
    }
    Ok(())
}
