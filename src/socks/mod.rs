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
    credentials: types::Credentials,
}
impl SocksProxy {
    pub fn new(credentials_file: Option<PathBuf>) -> Result<Self> {
        let credentials = match credentials_file {
            Some(file) => types::Credentials::try_from(file)?,
            None => types::Credentials::empty(),
        };
        Ok(SocksProxy { credentials })
    }
}
impl Proxy for SocksProxy {
    fn accept_stream(&self, stream: TcpStream) -> crate::Result<()> {
        let mut conn = handshake_socks5(
            stream,
            &types::SocksAuthMethod::Credentials {
                provider: &self.credentials,
            },
        )?;

        communicate_streams(&mut conn)?;

        log::info!("Successfully finished connection with \"{}\"", conn.from.id,);
        Ok(())
    }
}

/// Initiate SOCKS handshake communication. The provided `stream` will be advanced
/// to read and send protocol details. See more about
/// [protocol specification](https://datatracker.ietf.org/doc/html/rfc1928).
fn handshake_socks5(
    mut stream: TcpStream,
    auth: &types::SocksAuthMethod,
) -> Result<types::SocksConnection> {
    let handshake = start_socks5_handshake(&mut stream).or_else(|e| {
        utils::send_socks5_error(&mut stream, &e)?;
        return Err(e);
    })?;
    if let Err(e) = handle_socks5_auth(&handshake, &mut stream, auth) {
        utils::send_socks5_error(&mut stream, &e)?;
        return Err(e);
    }
    finish_socks5_handshake(&handshake, stream)
}

/// Advances `stream` to read SOCKS version and available authentication methods
/// on client side.
fn start_socks5_handshake(stream: &mut TcpStream) -> Result<types::SocksHandshake> {
    let peer = stream.peer_addr()?;
    log::info!("Start SOCKS handshake with \"{}\"", peer);

    let stream_id = peer.to_string();

    let mut protocol_line = [0u8; 2];
    stream.read_exact(&mut protocol_line)?;

    let protocol: types::SocksProtocol = protocol_line[0].try_into()?;
    log::trace!(
        "Got SOCKS version on client \"{}\": {}",
        stream_id,
        protocol.value()
    );
    let mut auth_methods = vec![0u8; protocol_line[1] as usize];
    stream.read_exact(&mut auth_methods)?;

    log::trace!(
        "Got auth methods on client \"{}\": {:?}",
        stream_id,
        auth_methods
    );

    Ok(types::SocksHandshake {
        id: stream_id,
        protocol,
        auth_methods,
    })
}

/// Set authentication method required by SOCKS server to client, writing to the `stream`
/// details about chosen authentication method `auth`.
fn handle_socks5_auth(
    handshake: &types::SocksHandshake,
    stream: &mut TcpStream,
    auth: &types::SocksAuthMethod,
) -> Result<()> {
    log::info!(
        "Setting authentication method \"{}\" for client \"{}\"",
        auth.value(),
        handshake.id,
    );
    if !handshake.is_auth_supported(auth) {
        return Err(Error::SockAuthMethodNotSupportedByClient);
    }
    // Select auth method
    stream.write(&[handshake.protocol.value(), auth.value()])?;
    match auth {
        types::SocksAuthMethod::NoAuth => Ok(()),
        types::SocksAuthMethod::Credentials { provider } => {
            if let Err(e) = socks5_credential_authentication(handshake, stream, provider) {
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
    handshake: &types::SocksHandshake,
    stream: &mut TcpStream,
    auth_provider: &types::Credentials,
) -> Result<()> {
    log::info!(
        "Starting credential authentication for client \"{}\"",
        handshake.id
    );
    let mut version = [0u8];
    stream.read_exact(&mut version)?;

    let username = utils::read_utf8_str(stream)?;

    log::trace!("Got username from client \"{}\"", handshake.id);

    let password = utils::read_utf8_str(stream)?;

    log::trace!("Got password from client \"{}\"", handshake.id);

    if auth_provider.contains(&(username, password)) {
        log::info!("Successfully authenticated client \"{}\"", handshake.id);
        Ok(())
    } else {
        log::warn!("Failed to authenticate client \"{}\"", handshake.id);
        Err(Error::SocksBadCredentialsProvided)
    }
}

/// Advances `stream` if server successfully establish connection with requested target.
fn finish_socks5_handshake(
    handshake: &types::SocksHandshake,
    mut stream: TcpStream,
) -> Result<types::SocksConnection> {
    let addr = read_request_details(&handshake, &mut stream)?;

    log::info!("Connecting to \"{}\" for client \"{}\"", addr, handshake.id);
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
        handshake.protocol.value(),
        0,
        0, // reserved
        ip_ver,
    ];
    response.extend_from_slice(&octets);
    response.extend_from_slice(&peer.port().to_be_bytes());

    log::trace!(
        "Writing success SOCKS5 to \"{}\": \"{:?}\"",
        handshake.id,
        response
    );
    stream.write_all(&response)?;

    let target_stream_id = target_stream.peer_addr()?.to_string();

    log::info!("Successful handshake with \"{}\"", handshake.id);
    Ok(types::SocksConnection {
        from: types::SockTarget {
            id: handshake.id.to_owned(),
            stream,
        },
        to: types::SockTarget {
            id: target_stream_id,
            stream: target_stream,
        },
    })
}

/// Advances `stream` to read details about request target domain.
fn read_request_details(
    handshake: &types::SocksHandshake,
    stream: &mut TcpStream,
) -> Result<SocketAddr> {
    let mut protocol_version = [0u8];
    stream.read_exact(&mut protocol_version)?;

    let cmd: types::SocksCMD = {
        let mut buff = [0u8];
        stream.read_exact(&mut buff)?;
        buff[0].try_into()?
    };

    log::trace!("Got cmd from client \"{}\": {}", handshake.id, cmd.value());

    // reserved
    stream.read_exact(&mut [0u8])?;

    let addr_type: types::SocksAddrType = {
        let mut buff = [0u8];
        stream.read_exact(&mut buff)?;
        buff[0].try_into()?
    };

    log::trace!(
        "Got address type from client \"{}\": {}",
        handshake.id,
        addr_type.value(),
    );

    let addr = read_address(stream, &addr_type)?;

    log::trace!("Got address from client \"{}\": {}", handshake.id, addr);

    let port = {
        let mut buff = [0u8; 2];
        stream.read_exact(&mut buff)?;
        u16::from_be_bytes(buff)
    };

    log::trace!("Got port from client \"{}\": {}", handshake.id, port);

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
fn communicate_streams(conn: &mut types::SocksConnection) -> Result<()> {
    conn.to
        .stream
        .set_read_timeout(Some(Duration::from_millis(100)))?;
    conn.from
        .stream
        .set_read_timeout(Some(Duration::from_millis(100)))?;

    conn.to
        .stream
        .set_read_timeout(Some(Duration::from_millis(100)))?;

    conn.from
        .stream
        .set_read_timeout(Some(Duration::from_millis(100)))?;

    log::info!(
        "Start communication between client \"{}\" and target \"{}\"",
        conn.from.id,
        conn.to.id
    );

    loop {
        let r1 = forward_data(&mut conn.from, &mut conn.to)?;
        let r2 = forward_data(&mut conn.to, &mut conn.from)?;
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
