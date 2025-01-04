use clap::Parser;
use light_proxy::{run, ExecuteConfig, ProxyMode, Result};
use log;
use std::net::{IpAddr, SocketAddr};

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

    #[arg(short = 'm', long, default_value = "socks", help = "Proxy mode to use")]
    mode: ProxyMode,
}

impl Into<ExecuteConfig> for Args {
    fn into(self) -> ExecuteConfig {
        ExecuteConfig {
            listen_address: SocketAddr::new(self.listen_ip, self.listen_port),
            mode: self.mode,
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let cfg: ExecuteConfig = args.into();
    if let Err(e) = run(cfg) {
        log::error!("{:?}", e);
        std::process::exit(1);
    }
    Ok(())
}
