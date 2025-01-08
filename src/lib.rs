use log;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

mod error;
pub mod socks5;

pub use self::error::{Error, Result};

pub enum ProxyMode {
    SOCKS5 { credentials_file: Option<PathBuf> },
}

pub struct ExecuteConfig {
    pub listen_address: SocketAddr,
    pub mode: ProxyMode,
}

enum ProxyImpl {
    SOCKS5(socks5::Socks5Proxy),
}

pub async fn run(cfg: ExecuteConfig) -> Result<()> {
    log::info!("Starting proxy on \"{}\"", cfg.listen_address);
    let listener = tokio::net::TcpListener::bind(cfg.listen_address).await?;

    let mode_handle: Arc<ProxyImpl> = match cfg.mode {
        ProxyMode::SOCKS5 { credentials_file } => Arc::new(ProxyImpl::SOCKS5(
            socks5::Socks5Proxy::new(credentials_file)?,
        )),
    };

    log::debug!("Waiting for connections");
    loop {
        let (stream, addr) = listener.accept().await?;
        log::info!("Accepted connection from \"{}\"", addr);
        let handle = Arc::clone(&mode_handle);
        tokio::spawn(async move {
            log::debug!("Processing connection \"{}\"", addr);
            if let Err(e) = match handle.as_ref() {
                ProxyImpl::SOCKS5(mode) => mode.accept_stream(stream).await,
            } {
                log::error!("Error during connection handling: {:?}", e);
            }
            log::info!("Connection closed \"{}\"", addr);
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn used_addr_cannot_bind() {}
}
