mod error;
mod result;
mod types;
mod utils;

pub use error::Error;
use log;
pub use result::Result;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_CLIENT_BUFFER: usize = 1 << 20;

pub struct SocksProxy {
    auth: types::SocksAuthMethod,
}
impl SocksProxy {
    pub fn new(credentials_file: Option<PathBuf>) -> Result<Self> {
        let auth = match credentials_file {
            Some(file) => types::SocksAuthMethod::Credentials {
                provider: types::Credentials::try_from(file)?,
            },
            None => types::SocksAuthMethod::NoAuth,
        };
        Ok(SocksProxy { auth })
    }

    pub async fn accept_stream(&self, mut stream: tokio::net::TcpStream) -> Result<()> {
        let target = handshake_socks5(&mut stream, &self.auth).await;
        if let Err(e) = target {
            utils::send_socks5_error(&mut stream, &e)
                .await
                .unwrap_or_else(|_| log::error!("Failed to send SOCKS5 error code"));
            return Err(e);
        };
        let target = target?;

        let mut from = types::SockTarget {
            id: stream.peer_addr()?.to_string(),
            stream,
        };
        let mut to = types::SockTarget {
            id: target.peer_addr()?.to_string(),
            stream: target,
        };
        communicate_streams(&mut from, &mut to).await?;

        log::info!("Successfully finished connection with \"{}\"", from.id);
        Ok(())
    }
}

/// Initiate SOCKS handshake communication. The provided `stream` will be advanced
/// to read and send protocol details. See more about
/// [protocol specification](https://datatracker.ietf.org/doc/html/rfc1928).
async fn handshake_socks5(
    stream: &mut tokio::net::TcpStream,
    auth: &types::SocksAuthMethod,
) -> Result<tokio::net::TcpStream> {
    let (proto, methods) = start_socks5_handshake(stream).await?;
    if proto != types::SocksProtocol::SOCKS5 {
        return Err(Error::SocksProtocolVersionNotSupported(proto.value()));
    }
    handle_socks5_auth(&proto, &methods, stream, auth).await?;
    finish_socks5_handshake(&proto, stream).await
}

/// Advances `stream` to read SOCKS version and available authentication methods
/// on client side.
async fn start_socks5_handshake(
    stream: &mut tokio::net::TcpStream,
) -> Result<(types::SocksProtocol, Vec<u8>)> {
    log::info!("Start SOCKS handshake");

    let mut protocol_line = [0u8; 2];
    stream.read_exact(&mut protocol_line).await?;

    let protocol: types::SocksProtocol = protocol_line[0].try_into()?;
    log::trace!("Got SOCKS version: {}", protocol.value());
    let mut auth_methods = vec![0u8; protocol_line[1] as usize];
    stream.read_exact(&mut auth_methods).await?;

    log::trace!("Got auth methods: {:?}", auth_methods);

    Ok((protocol, auth_methods))
}

/// Set authentication method required by SOCKS server to client, writing to the `stream`
/// details about chosen authentication method `auth`.
async fn handle_socks5_auth(
    protocol: &types::SocksProtocol,
    auth_methods: &Vec<u8>,
    stream: &mut tokio::net::TcpStream,
    auth: &types::SocksAuthMethod,
) -> Result<()> {
    log::info!("Set authentication method \"{}\"", auth.value(),);
    if !auth_methods.contains(&auth.value()) {
        return Err(Error::SockAuthMethodNotSupportedByClient);
    }
    // Select auth method
    stream.write(&[protocol.value(), auth.value()]).await?;
    match auth {
        types::SocksAuthMethod::NoAuth => Ok(()),
        types::SocksAuthMethod::Credentials { provider } => {
            let mut result = Ok(());
            let mut result_code = types::SUCCESS_CODE;
            if let Err(e) = socks5_credential_authentication(stream, provider).await {
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
) -> Result<()> {
    log::info!("Starting credential authentication");
    let mut version = [0u8];
    stream.read_exact(&mut version).await?;

    let username = utils::read_utf8_str(stream).await?;

    log::trace!("Got username");

    let password = utils::read_utf8_str(stream).await?;

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
async fn finish_socks5_handshake(
    protocol: &types::SocksProtocol,
    stream: &mut tokio::net::TcpStream,
) -> Result<tokio::net::TcpStream> {
    let addr = read_request_details(stream).await?;

    log::info!("Connecting to \"{}\"", addr);
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
    let mut response = vec![
        protocol.value(),
        0,
        0, // reserved
        ip_ver,
    ];
    response.extend_from_slice(&octets);
    response.extend_from_slice(&peer.port().to_be_bytes());

    log::trace!("Send success SOCKS5: \"{:?}\"", response);
    stream.write_all(&response).await?;

    log::info!("Successful handshake");
    Ok(target_stream)
}

/// Advances `stream` to read details about request target domain.
async fn read_request_details(stream: &mut tokio::net::TcpStream) -> Result<SocketAddr> {
    let mut protocol_version = [0u8];
    stream.read_exact(&mut protocol_version).await?;

    let cmd: types::SocksCMD = {
        let mut buff = [0u8];
        stream.read_exact(&mut buff).await?;
        buff[0].try_into()?
    };

    log::trace!("Got cmd: {}", cmd.value());

    // reserved
    stream.read_exact(&mut [0u8]).await?;

    let addr_type: types::SocksAddrType = {
        let mut buff = [0u8];
        stream.read_exact(&mut buff).await?;
        buff[0].try_into()?
    };

    log::trace!("Got address type: {}", addr_type.value(),);

    let addr = read_address(stream, &addr_type).await?;

    log::trace!("Got address: {}", addr);

    let port = {
        let mut buff = [0u8; 2];
        stream.read_exact(&mut buff).await?;
        u16::from_be_bytes(buff)
    };

    log::trace!("Got port: {}", port);

    Ok(SocketAddr::new(addr, port))
}

/// Advances `stream` to read address and port of a requested target using `address_type`
/// to recognize address format.
async fn read_address(
    stream: &mut tokio::net::TcpStream,
    address_type: &types::SocksAddrType,
) -> Result<IpAddr> {
    match address_type {
        types::SocksAddrType::IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        types::SocksAddrType::IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
    }
}

/// Initiate communication between client and target connections.
async fn communicate_streams(
    from: &mut types::SockTarget,
    to: &mut types::SockTarget,
) -> Result<()> {
    log::info!(
        "Start communication between client \"{}\" and target \"{}\"",
        from.id,
        to.id
    );
    let mut client_buffer = vec![0u8; MAX_CLIENT_BUFFER];
    let mut target_buffer = vec![0u8; MAX_CLIENT_BUFFER];

    loop {
        tokio::select! {
            cr = from.stream.read(&mut client_buffer) => {
                let is_done = forward_data(cr, to, &mut client_buffer).await?;
                if is_done {
                    break;
                }
            }
            tr = to.stream.read(&mut target_buffer) => {
                forward_data(tr, from, &mut target_buffer).await?;
            }
        }
    }
    log::info!(
        "Finish communication between client \"{}\" and target \"{}\"",
        from.id,
        to.id
    );
    Ok(())
}

async fn forward_data(
    data: core::result::Result<usize, io::Error>,
    to: &mut types::SockTarget,
    buffer: &mut [u8],
) -> Result<bool> {
    let read = match data {
        Ok(0) => return Ok(true),
        Ok(read) => read,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(e) => return Err(e.into()),
    };

    log::trace!("Send {} bytes to \"{}\"", read, to.id);

    to.stream.write_all(&buffer[..read]).await?;
    Ok(false)
}
