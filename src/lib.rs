use log;
use std::net::{SocketAddr, TcpListener, TcpStream};

mod error;
pub mod socks;

pub use self::error::{Error, Result};

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ProxyMode {
    SOCKS,
}

pub struct ExecuteConfig {
    pub listen_address: SocketAddr,
    pub mode: ProxyMode,
}

pub fn run(cfg: ExecuteConfig) -> Result<()> {
    log::info!("Starting proxy on \"{}\"", cfg.listen_address);
    log::debug!("Using mode: {:?}", cfg.mode);
    let listener = TcpListener::bind(cfg.listen_address)?;

    let mode_handle: fn(TcpStream) -> Result<()> = match cfg.mode {
        ProxyMode::SOCKS => |stream| socks::handle_socks(stream).or_else(|e| Err(Error::SOCKS(e))),
    };

    log::debug!("Waiting for connections");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = mode_handle(stream) {
                    log::error!("Error during connection handling: {:?}", e);
                }
            }
            Err(error) => {
                log::error!("Could not accept connection: {:?}", error);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    #[test]
    fn used_addr_cannot_bind() {
        let cfg = ExecuteConfig {
            listen_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            mode: ProxyMode::SOCKS,
        };

        let _already_bind_listener = TcpListener::bind(cfg.listen_address).unwrap();

        assert!(run(cfg).is_err());
    }
}
