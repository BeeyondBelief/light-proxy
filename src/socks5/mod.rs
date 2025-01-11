mod error;
mod result;
mod types;
mod utils;

pub use error::Error;
use log;
pub use result::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Socks5Proxy {
    auth: types::SocksAuthMethod,
}
impl Socks5Proxy {
    pub fn new(credentials_file: Option<PathBuf>) -> Result<Self> {
        let auth = match credentials_file {
            Some(file) => types::SocksAuthMethod::Credentials {
                provider: types::Credentials::try_from(file)?,
            },
            None => types::SocksAuthMethod::NoAuth,
        };
        Ok(Socks5Proxy { auth })
    }

    pub async fn accept_stream(&self, mut stream: tokio::net::TcpStream) -> Result<()> {
        let target = handshake_socks5(&mut stream, &self.auth).await;
        if let Err(e) = target {
            utils::send_socks5_error(&mut stream, &e)
                .await
                .unwrap_or_else(|_| log::error!("Failed to send SOCKS5 error code"));
            return Err(e);
        };
        let mut target = target?;

        let client_name = stream.peer_addr()?.to_string();
        let target_name = target.peer_addr()?.to_string();

        log::info!(
            "Start bidirectional communication between \"{}\" and \"{}\"",
            client_name,
            target_name
        );

        let (client_sent, target_sent) =
            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;

        log::debug!(
            "Bytes sent from \"{}\" {}. Bytes sent from \"{}\": {}",
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
}

/// Initiate SOCKS handshake communication. The provided `stream` will be advanced
/// to read and send protocol details. See more about
/// [protocol specification](https://datatracker.ietf.org/doc/html/rfc1928)
async fn handshake_socks5(
    stream: &mut tokio::net::TcpStream,
    auth: &types::SocksAuthMethod,
) -> Result<tokio::net::TcpStream> {
    // SOCKS5 handshake with credentials can allocate maximum 255 bytes at once
    let mut buff = [0u8; 255];
    let supported_auth = start_socks5_handshake(stream, &mut buff).await?;
    handle_socks5_auth(&supported_auth, stream, auth, &mut buff).await?;
    finish_socks5_handshake(stream, &mut buff).await
}

/// Advances `stream` to read SOCKS5 version and its protocol data
async fn start_socks5_handshake(
    stream: &mut tokio::net::TcpStream,
    buff: &mut [u8],
) -> Result<Vec<u8>> {
    log::info!("Start SOCKS5 handshake");

    stream.read_exact(&mut buff[..2]).await?;

    if buff[0] != types::SOCKS5_VERSION {
        return Err(Error::SocksProtocolVersionNotSupported(buff[0]));
    }
    let length = buff[1] as usize;
    stream.read_exact(&mut buff[..length]).await?;

    log::trace!("Got auth methods: {:?}", &buff[..length]);
    Ok(buff[..length].to_vec())
}

/// Set authentication method required by SOCKS server to client, writing to the `stream`
/// details about chosen authentication method `auth`. Returns [`Ok`] if `stream` supports
/// `auth`.
async fn handle_socks5_auth(
    auth_methods: &Vec<u8>,
    stream: &mut tokio::net::TcpStream,
    auth: &types::SocksAuthMethod,
    buff: &mut [u8],
) -> Result<()> {
    log::debug!("Set authentication method \"{}\"", auth.value(),);
    if !auth_methods.contains(&auth.value()) {
        return Err(Error::SockAuthMethodNotSupportedByClient);
    }
    // Select auth method
    buff[0] = types::SOCKS5_VERSION;
    buff[1] = auth.value();
    stream.write(&buff[..2]).await?;
    match auth {
        types::SocksAuthMethod::NoAuth => Ok(()),
        types::SocksAuthMethod::Credentials { provider } => {
            let mut result = Ok(());
            let mut result_code = types::SUCCESS_CODE;
            if let Err(e) = socks5_credential_authentication(stream, provider, buff).await {
                result_code = types::Socks5ErrCode::from(&e).value();
                result = Err(e)
            }
            stream
                .write(&[types::CREDENTIAL_AUTH_VERSION, result_code])
                .await?;
            result
        }
    }
}

/// Advances `stream` to read client credentials and authenticate client with them.
/// See more about [protocol specification](https://datatracker.ietf.org/doc/html/rfc1929).
async fn socks5_credential_authentication(
    stream: &mut tokio::net::TcpStream,
    auth_provider: &types::Credentials,
    buff: &mut [u8],
) -> Result<()> {
    log::debug!("Starting credential authentication");
    stream.read_exact(&mut buff[..1]).await?;

    if buff[0] != types::CREDENTIAL_AUTH_VERSION {
        return Err(Error::SocksCredentialAuthVersionNotSupported(buff[0]));
    }

    let username = utils::read_utf8_str(stream, buff).await?;

    log::trace!("Got username");

    let password = utils::read_utf8_str(stream, buff).await?;

    log::trace!("Got password");

    if auth_provider.contains(&(username, password)) {
        log::info!("Successfully authenticated client");
        Ok(())
    } else {
        log::warn!("Failed to authenticate");
        Err(Error::SocksBadCredentialsProvided)
    }
}

/// Advances `stream` if server successfully establish connection with requested target.
async fn finish_socks5_handshake<const N: usize>(
    stream: &mut tokio::net::TcpStream,
    buff: &mut [u8; N],
) -> Result<tokio::net::TcpStream> {
    let addr = read_request_details(stream, buff).await?;

    log::info!("Connecting to target \"{}\"", addr);
    let target_stream = tokio::net::TcpStream::connect(addr).await?;
    let peer = target_stream.local_addr()?;

    let mut octets = vec![];
    let ip_ver;
    match peer.ip() {
        IpAddr::V4(ip) => {
            octets.extend_from_slice(&ip.octets());
            ip_ver = types::SocksAddrType::IPV4.value();
        }
        IpAddr::V6(ip) => {
            octets.extend_from_slice(&ip.octets());
            ip_ver = types::SocksAddrType::IPV6.value();
        }
    }
    buff[0] = types::SOCKS5_VERSION;
    buff[1] = types::SUCCESS_CODE;
    buff[2] = 0;
    buff[3] = ip_ver;

    let octets_len = octets.len();
    buff[4..octets_len + 4].clone_from_slice(&octets);
    buff[octets_len + 4..octets_len + 6].clone_from_slice(&peer.port().to_be_bytes());

    let response_length = octets_len + 6;

    log::trace!("Send success SOCKS5: \"{:?}\"", &buff[..response_length]);
    stream.write_all(&buff[..response_length]).await?;

    log::info!("Successful SOCKS5 handshake");
    Ok(target_stream)
}

/// Advances `stream` to read details about request target domain.
async fn read_request_details<const N: usize>(
    stream: &mut tokio::net::TcpStream,
    buff: &mut [u8; N],
) -> Result<SocketAddr> {
    stream.read_exact(&mut buff[..4]).await?;

    let cmd = types::SocksCMD::try_from(buff[1])?;

    log::trace!("CMD: {}", cmd.value());

    let addr_type = types::SocksAddrType::try_from(buff[3])?;

    log::trace!("Target address type: {}", addr_type.value());

    let addr = match addr_type {
        types::SocksAddrType::IPV4 => {
            let slice = &mut buff[..4];
            stream.read_exact(slice).await?;
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(slice).unwrap()))
        }
        types::SocksAddrType::IPV6 => {
            let slice = &mut buff[..16];
            stream.read_exact(slice).await?;
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(slice).unwrap()))
        }
    };

    log::trace!("Target address: {}", addr);

    let port = {
        let slice = &mut buff[..2];
        stream.read_exact(slice).await?;
        u16::from_be_bytes(<[u8; 2]>::try_from(slice).unwrap())
    };

    log::trace!("Target port: {}", port);

    Ok(SocketAddr::new(addr, port))
}
