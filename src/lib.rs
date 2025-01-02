use log;
use std::net::{IpAddr, SocketAddr, TcpListener};

mod error;
pub mod socks;

pub use self::error::{Error, Result};

#[derive(Debug)]
pub struct ExecuteConfig {
    listen_address: SocketAddr,
}

impl ExecuteConfig {
    pub fn new(listen_ip: IpAddr, listen_port: u16) -> Self {
        Self {
            listen_address: SocketAddr::new(listen_ip, listen_port),
        }
    }
}

pub fn run(cfg: ExecuteConfig) -> Result<()> {
    log::info!("Starting proxy on \"{}\"", cfg.listen_address);
    let listener = TcpListener::bind(cfg.listen_address)?;
    log::debug!("Waiting for connections");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = socks::handle_socks(stream) {
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
    use std::net::Ipv4Addr;
    #[test]
    fn used_addr_cannot_bind() {
        let cfg = ExecuteConfig::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);

        let _already_bind_listener = TcpListener::bind(cfg.listen_address).unwrap();

        assert!(run(cfg).is_err());
    }
}
