mod error;
mod result;
mod types;
mod utils;

pub use error::Error;
use log;
pub use result::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// SOCKS5 handshake with credentials can allocate maximum 255 bytes at once
const MIN_BUFFER_SIZE: usize = 255;
const ANONIMUS_CLIENT_NAME: &'static str = "unknown";

pub struct Socks4Proxy;
impl Socks4Proxy {
    pub async fn accept_stream(&self, mut stream: tokio::net::TcpStream) -> Result<()> {
        match handshake_socks4(&mut stream).await {
            Ok((client_name, mut target)) => {
                let target_name = target.peer_addr()?.to_string();

                log::info!(
                    "Start bidirectional communication between \"{}\" and \"{}\"",
                    client_name,
                    target_name
                );

                let (client_sent, target_sent) =
                    tokio::io::copy_bidirectional(&mut stream, &mut target).await?;

                log::debug!(
                    "Client \"{}\" sent: {}. Bytes sent from \"{}\": {}",
                    client_name,
                    client_sent,
                    target_name,
                    target_sent
                );

                log::info!(
                    "End communication between \"{}\" and \"{}\"",
                    client_name,
                    target_name
                );
                Ok(())
            }
            Err(e) => {
                utils::send_socks4_error(&mut stream, &e)
                    .await
                    .unwrap_or_else(|_| log::error!("Failed to send SOCKS4 error code"));
                Err(e)
            }
        }
    }
}

/// Initiate SOCKS handshake communication. The provided `stream` will be advanced
/// to read and send protocol details. See more about
/// [protocol specification](https://www.openssh.com/txt/socks4.protocol)
async fn handshake_socks4(
    stream: &mut tokio::net::TcpStream,
) -> Result<(String, tokio::net::TcpStream)> {
    let mut buff = [0u8; MIN_BUFFER_SIZE];

    log::info!("Start SOCKS4 handshake");

    stream.read_exact(&mut buff[..2]).await?;

    if buff[0] != types::SOCKS4_VERSION {
        return Err(Error::SocksProtocolVersionNotSupported(buff[0]));
    }
    types::SocksCMD::try_from(buff[1])?;

    let port = {
        stream.read_exact(&mut buff[..2]).await?;
        u16::from_be_bytes(<[u8; 2]>::try_from(&buff[..2]).unwrap())
    };
    log::trace!("Got port number: {}", port);

    let address = {
        stream.read_exact(&mut buff[..4]).await?;
        IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&buff[..4]).unwrap()))
    };
    log::trace!("Got address: {}", address);

    let userid = {
        let length = stream.read(&mut buff).await?;
        if length < 2 {
            ANONIMUS_CLIENT_NAME.to_string()
        } else {
            let mut string = String::new();
            string.extend(buff[..length].iter_mut().map(|b| *b as char));
            string
        }
    };
    log::trace!("Got username: {}", userid);

    log::info!("Connecting to target \"{}:{}\"", address, port);
    let target_stream = tokio::net::TcpStream::connect(SocketAddr::new(address, port)).await?;
    let peer = target_stream.local_addr()?;
    let target_port = peer.port().to_be_bytes();

    let peer_ip4 = match peer.ip() {
        IpAddr::V4(ip) => &ip.octets(),
        _ => return Err(Error::SocksBadProtocol),
    };

    buff[0] = 0;
    buff[1] = types::SUCCESS_CODE;
    buff[2..4].clone_from_slice(&target_port);
    buff[4..8].clone_from_slice(peer_ip4);

    log::trace!("Send success SOCKS4: \"{:?}\"", &buff[..8]);
    stream.write_all(&buff[..8]).await?;

    log::info!("Successful SOCKS4 handshake");

    Ok((userid, target_stream))
}
