use clap::{Parser, Subcommand};
use light_proxy::{run, ExecuteConfig, ProxyMode, Result};
use log;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "Run with SOCKS protocol for proxy connections", long_about = None)]
struct SocksArgs {
    #[arg(
        short = 'f',
        long,
        help = "Path to the file where user credentials are stored. Format of a files is: \
            <user:password\n> or just <user:\n> in the second case <user:> means an access token. \
            The file only used for SOCKS5 connections."
    )]
    credentials_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Socks(SocksArgs),
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
    listen_ip: IpAddr,

    #[arg(
        short = 'p',
        long,
        default_value = "8000",
        help = "From what port listen for HTTP requests"
    )]
    listen_port: u16,
    #[command(subcommand)]
    command: Commands,
}

impl Into<ExecuteConfig> for Args {
    fn into(self) -> ExecuteConfig {
        let mode = match self.command {
            Commands::Socks(args) => ProxyMode::SOCKS {
                credentials_file: args.credentials_file,
            },
        };
        ExecuteConfig {
            listen_address: SocketAddr::new(self.listen_ip, self.listen_port),
            mode,
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    if let Err(e) = run(args.into()) {
        log::error!("{:?}", e);
        std::process::exit(1);
    }
    Ok(())
}
