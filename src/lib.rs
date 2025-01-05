use crate::proxy::Proxy;
use log;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;

mod proxy;

mod error;
pub mod socks;

pub use self::error::{Error, Result};

pub enum ProxyMode {
    SOCKS { credentials_file: Option<PathBuf> },
}

pub struct ExecuteConfig {
    pub listen_address: SocketAddr,
    pub mode: ProxyMode,
}

pub fn run(cfg: ExecuteConfig) -> Result<()> {
    log::info!("Starting proxy on \"{}\"", cfg.listen_address);
    let listener = TcpListener::bind(cfg.listen_address)?;

    let mode_handle: Box<dyn Proxy> = match cfg.mode {
        ProxyMode::SOCKS { credentials_file } => {
            Box::new(socks::SocksProxy::new(credentials_file)?)
        }
    };

    log::debug!("Waiting for connections");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = mode_handle.accept_stream(stream) {
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
            mode: ProxyMode::SOCKS {
                credentials_file: None,
            },
        };

        let _already_bind_listener = TcpListener::bind(cfg.listen_address).unwrap();

        assert!(run(cfg).is_err());
    }
}
