mod error;
mod result;
mod types;
mod utils;

use crate::proxy::Proxy;
pub use error::Error;
use log;
pub use result::Result;
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

const MAX_CLIENT_BUFFER: usize = 1024;

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
}
impl Proxy for SocksProxy {
    fn accept_stream(&self, mut stream: TcpStream) -> crate::Result<()> {
        let target = handshake_socks5(&mut stream, &self.auth).map_err(|e| {
            utils::send_socks5_error(&mut stream, &e)
                .unwrap_or_else(|_| log::error!("Failed to send SOCKS5 error code"));
            e
        })?;

        let mut from = types::SockTarget {
            id: stream.peer_addr()?.to_string(),
            stream,
        };
        let mut to = types::SockTarget {
            id: target.peer_addr()?.to_string(),
            stream: target,
        };
        communicate_streams(&mut from, &mut to)?;

        log::info!("Successfully finished connection with \"{}\"", from.id);
        Ok(())
    }
}

/// Initiate SOCKS handshake communication. The provided `stream` will be advanced
/// to read and send protocol details. See more about
/// [protocol specification](https://datatracker.ietf.org/doc/html/rfc1928).
fn handshake_socks5(stream: &mut TcpStream, auth: &types::SocksAuthMethod) -> Result<TcpStream> {
    let (proto, methods) = start_socks5_handshake(stream)?;
    if proto != types::SocksProtocol::SOCKS5 {
        return Err(Error::SocksProtocolVersionNotSupported(proto.value()));
    }
    handle_socks5_auth(&proto, &methods, stream, auth)?;
    finish_socks5_handshake(&proto, stream)
}

/// Advances `stream` to read SOCKS version and available authentication methods
/// on client side.
fn start_socks5_handshake(stream: &mut TcpStream) -> Result<(types::SocksProtocol, Vec<u8>)> {
    log::info!("Start SOCKS handshake");

    let mut protocol_line = [0u8; 2];
    stream.read_exact(&mut protocol_line)?;

    let protocol: types::SocksProtocol = protocol_line[0].try_into()?;
    log::trace!("Got SOCKS version: {}", protocol.value());
    let mut auth_methods = vec![0u8; protocol_line[1] as usize];
    stream.read_exact(&mut auth_methods)?;

    log::trace!("Got auth methods: {:?}", auth_methods);

    Ok((protocol, auth_methods))
}

/// Set authentication method required by SOCKS server to client, writing to the `stream`
/// details about chosen authentication method `auth`.
fn handle_socks5_auth(
    protocol: &types::SocksProtocol,
    auth_methods: &Vec<u8>,
    stream: &mut TcpStream,
    auth: &types::SocksAuthMethod,
) -> Result<()> {
    log::info!("Set authentication method \"{}\"", auth.value(),);
    if !auth_methods.contains(&auth.value()) {
        return Err(Error::SockAuthMethodNotSupportedByClient);
    }
    // Select auth method
    stream.write(&[protocol.value(), auth.value()])?;
    match auth {
        types::SocksAuthMethod::NoAuth => Ok(()),
        types::SocksAuthMethod::Credentials { provider } => {
            if let Err(e) = socks5_credential_authentication(stream, provider) {
                stream.write(&[
                    types::CREDENTIAL_AUTH_VERSION,
                    types::Socks5ErrCode::from(&e).value(),
                ])?;
                Err(e)
            } else {
                stream.write(&[types::CREDENTIAL_AUTH_VERSION, types::SUCCESS_CODE])?;
                Ok(())
            }
        }
    }
}

/// Advances `stream` to read client credentials and authenticate client with them.
/// See more about [protocol specification](https://datatracker.ietf.org/doc/html/rfc1929).
fn socks5_credential_authentication(
    stream: &mut TcpStream,
    auth_provider: &types::Credentials,
) -> Result<()> {
    log::info!("Starting credential authentication");
    let mut version = [0u8];
    stream.read_exact(&mut version)?;

    let username = utils::read_utf8_str(stream)?;

    log::trace!("Got username");

    let password = utils::read_utf8_str(stream)?;

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
fn finish_socks5_handshake(
    protocol: &types::SocksProtocol,
    stream: &mut TcpStream,
) -> Result<TcpStream> {
    let addr = read_request_details(stream)?;

    log::info!("Connecting to \"{}\"", addr);
    let target_stream = TcpStream::connect(addr)?;
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
    stream.write_all(&response)?;

    log::info!("Successful handshake");
    Ok(target_stream)
}

/// Advances `stream` to read details about request target domain.
fn read_request_details(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut protocol_version = [0u8];
    stream.read_exact(&mut protocol_version)?;

    let cmd: types::SocksCMD = {
        let mut buff = [0u8];
        stream.read_exact(&mut buff)?;
        buff[0].try_into()?
    };

    log::trace!("Got cmd: {}", cmd.value());

    // reserved
    stream.read_exact(&mut [0u8])?;

    let addr_type: types::SocksAddrType = {
        let mut buff = [0u8];
        stream.read_exact(&mut buff)?;
        buff[0].try_into()?
    };

    log::trace!("Got address type: {}", addr_type.value(),);

    let addr = read_address(stream, &addr_type)?;

    log::trace!("Got address: {}", addr);

    let port = {
        let mut buff = [0u8; 2];
        stream.read_exact(&mut buff)?;
        u16::from_be_bytes(buff)
    };

    log::trace!("Got port: {}", port);

    Ok(SocketAddr::new(addr, port))
}

/// Advances `stream` to read address and port of a requested target using `address_type`
/// to recognize address format.
fn read_address(stream: &mut TcpStream, address_type: &types::SocksAddrType) -> Result<IpAddr> {
    match address_type {
        types::SocksAddrType::IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets)?;
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        types::SocksAddrType::IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets)?;
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
    }
}

/// Initiate communication between client and target connections.
fn communicate_streams(from: &mut types::SockTarget, to: &mut types::SockTarget) -> Result<()> {
    to.stream
        .set_read_timeout(Some(Duration::from_millis(100)))?;
    from.stream
        .set_read_timeout(Some(Duration::from_millis(100)))?;

    to.stream
        .set_read_timeout(Some(Duration::from_millis(100)))?;

    from.stream
        .set_read_timeout(Some(Duration::from_millis(100)))?;

    log::info!(
        "Start communication between client \"{}\" and target \"{}\"",
        from.id,
        to.id
    );

    loop {
        let r1 = forward_data(from, to)?;
        let r2 = forward_data(to, from)?;
        if !r1 && !r2 {
            break;
        }
    }
    Ok(())
}

fn forward_data(from: &mut types::SockTarget, to: &mut types::SockTarget) -> Result<bool> {
    let mut buffer = [0u8; MAX_CLIENT_BUFFER];
    let mut has_pending_reply = false;
    loop {
        let read = match from.stream.read(&mut buffer) {
            Ok(read) => {
                if read == 0 {
                    break;
                }
                read
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => return Err(e.into()),
        };
        log::trace!("Send {} bytes from \"{}\" to \"{}\"", read, from.id, to.id);
        to.stream.write(&buffer[..read])?;
        has_pending_reply = true;
    }
    Ok(has_pending_reply)
}
