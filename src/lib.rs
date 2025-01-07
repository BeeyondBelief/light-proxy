use log;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

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

enum ProxyImpl {
    SOCKS(socks::SocksProxy),
}

pub async fn run(cfg: ExecuteConfig) -> Result<()> {
    log::info!("Starting proxy on \"{}\"", cfg.listen_address);
    let listener = tokio::net::TcpListener::bind(cfg.listen_address).await?;

    let mode_handle: Arc<ProxyImpl> = match cfg.mode {
        ProxyMode::SOCKS { credentials_file } => {
            Arc::new(ProxyImpl::SOCKS(socks::SocksProxy::new(credentials_file)?))
        }
    };

    log::debug!("Waiting for connections");
    loop {
        let (stream, _) = listener.accept().await?;

        let handle = Arc::clone(&mode_handle);
        tokio::spawn(async move {
            if let Err(e) = match handle.as_ref() {
                ProxyImpl::SOCKS(mode) => mode.accept_stream(stream).await,
            } {
                log::error!("Error during connection handling: {:?}", e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn used_addr_cannot_bind() {}
}
