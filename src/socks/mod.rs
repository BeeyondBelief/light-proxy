mod error;
mod result;
mod types;

pub use error::Error;
use log;
pub use result::Result;
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

const MAX_CLIENT_BUFFER: usize = 1024;

pub fn handle_socks(stream: TcpStream) -> Result<()> {
    let mut conn = handshake_socks5(
        stream,
        &types::SocksAuthMethod::Credentials {
            provider: Box::new(|username, pass| username == "111" && pass == "123"),
        },
    )?;

    communicate_streams(&mut conn)?;

    log::info!(
        "Successfully finished sending packets between client \"{}\" and target \"{}\"",
        conn.from.id,
        conn.to.id
    );
    Ok(())
}

/// Initiate SOCKS handshake communication. The provided `stream` will be advanced
/// to read and send protocol details. See more about
/// [protocol specification](https://datatracker.ietf.org/doc/html/rfc1928).
fn handshake_socks5(
    mut stream: TcpStream,
    auth: &types::SocksAuthMethod,
) -> Result<types::SocksConnection> {
    let handshake = start_socks5_handshake(&mut stream)?;
    handle_socks5_auth(&handshake, &mut stream, auth)?;
    finish_socks5_handshake(&handshake, stream)
}

/// Advances `stream` to read SOCKS version and available authentication methods
/// on client side.
fn start_socks5_handshake(stream: &mut TcpStream) -> Result<types::SocksHandshake> {
    let peer = stream.peer_addr()?;
    log::info!("Start SOCKS handshake with \"{}\"", peer);

    let stream_id = peer.to_string();

    let mut protocol_line = [0u8; 2];
    stream.read_exact(&mut protocol_line).or_else(|_| {
        send_socks5_error(stream, &types::Socks5ErrCode::GeneralFailure)?;
        Err(Error::SocksBadProtocol)
    })?;

    let protocol: types::SocksProtocol = protocol_line[0].try_into().or_else(|e| {
        send_socks5_error(stream, &types::Socks5ErrCode::GeneralFailure)?;
        Err(e)
    })?;
    log::trace!(
        "Got SOCKS version on client \"{}\": {}",
        stream_id,
        protocol.value()
    );
    if protocol_line[1] == 0 {
        send_socks5_error(stream, &types::Socks5ErrCode::GeneralFailure)?;
        return Err(Error::SocksBadProtocol);
    };
    log::trace!(
        "Number of supported authentication methods on client \"{}\": {}",
        stream_id,
        protocol_line[1]
    );
    let num_of_auth_methods = protocol_line[1] as usize;

    let mut auth_methods = vec![0u8; num_of_auth_methods];
    stream.read_exact(&mut auth_methods).or_else(|_| {
        send_socks5_error(stream, &types::Socks5ErrCode::GeneralFailure)?;
        Err(Error::SocksBadProtocol)
    })?;
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
        stream.write(&[
            handshake.protocol.value(),
            types::Socks5ErrCode::AuthMethodNotSupported.value(),
        ])?;
        return Err(Error::SockAuthMethodNotSupportedByClient);
    }

    stream.write(&[handshake.protocol.value(), auth.value()])?;
    match auth {
        types::SocksAuthMethod::NoAuth => Ok(()),
        types::SocksAuthMethod::Credentials { provider } => {
            socks5_credential_authentication(handshake, stream, provider)
        }
    }
}

/// Advances `stream` to read client credentials and authenticate client with them.
/// See more about [protocol specification](https://datatracker.ietf.org/doc/html/rfc1929).
fn socks5_credential_authentication(
    handshake: &types::SocksHandshake,
    stream: &mut TcpStream,
    auth_provider: &types::CredentialAuthProvider,
) -> Result<()> {
    log::info!(
        "Starting credential authentication for client \"{}\"",
        handshake.id
    );
    let mut version = [0u8];
    stream
        .read_exact(&mut version)
        .or(Err(Error::SocksBadProtocol))?;

    let mut username_length = [0u8];
    stream
        .read_exact(&mut username_length)
        .or(Err(Error::SocksBadUsername))?;

    let mut username = vec![0u8; username_length[0] as usize];
    stream
        .read_exact(&mut username)
        .or(Err(Error::SocksBadUsername))?;

    let username = String::from_utf8(username).or(Err(Error::SocksBadUsername))?;

    log::trace!("Got complete username from client \"{}\"", handshake.id);

    let mut password_length = [0u8];
    stream
        .read_exact(&mut password_length)
        .or(Err(Error::SocksBadPassword))?;

    let mut password = vec![0u8; password_length[0] as usize];
    stream
        .read_exact(&mut password)
        .or(Err(Error::SocksBadPassword))?;

    let password = String::from_utf8(password).or(Err(Error::SocksBadPassword))?;

    log::trace!("Got complete password from client \"{}\"", handshake.id);

    if auth_provider(&username, &password) {
        log::info!("Successfully authenticated client \"{}\"", handshake.id);
        stream.write(&[0x1, 0x0])?;
        Ok(())
    } else {
        log::error!("Failed to authenticate client \"{}\"", handshake.id);
        stream.write(&[0x1, types::Socks5ErrCode::ConnectionNotAllowed.value()])?;
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
    let target_stream = TcpStream::connect(addr).or_else(|e| {
        let err = match e.kind() {
            io::ErrorKind::ConnectionRefused => types::Socks5ErrCode::ConnectionRefused,
            io::ErrorKind::HostUnreachable => types::Socks5ErrCode::HostUnreachable,
            io::ErrorKind::NetworkUnreachable => types::Socks5ErrCode::NetworkUnreachable,
            _ => types::Socks5ErrCode::GeneralFailure,
        };
        send_socks5_error(&mut stream, &err)?;
        Err(<Error>::from(e))
    })?;
    let peer = target_stream.local_addr()?;

    log::trace!(
        "Assigned local ip \"{}\" for \"{}\" for client \"{}\"",
        peer,
        addr,
        handshake.id
    );
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
        0x00,
        0x00, // reserved
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
    stream.read_exact(&mut protocol_version).or_else(|_| {
        send_socks5_error(stream, &types::Socks5ErrCode::GeneralFailure)?;
        Err(Error::SocksBadProtocol)
    })?;

    let mut cmd = [0u8];
    stream.read_exact(&mut cmd).or_else(|_| {
        send_socks5_error(stream, &types::Socks5ErrCode::GeneralFailure)?;
        Err(Error::SocksBadProtocol)
    })?;

    let cmd: types::SocksCMD = cmd[0].try_into().or_else(|e| {
        send_socks5_error(stream, &types::Socks5ErrCode::CommandUnsupported)?;
        Err(e)
    })?;

    log::trace!("Got cmd from client \"{}\": {}", handshake.id, cmd.value());

    // reserved
    stream.read_exact(&mut [0u8]).or_else(|_| {
        send_socks5_error(stream, &types::Socks5ErrCode::GeneralFailure)?;
        Err(Error::SocksBadProtocol)
    })?;

    let mut addr_type = [0u8];
    stream.read(&mut addr_type).or_else(|_| {
        send_socks5_error(stream, &types::Socks5ErrCode::GeneralFailure)?;
        Err(Error::SocksBadProtocol)
    })?;

    let addr_type: types::SocksAddrType = addr_type[0].try_into().or_else(|e| {
        send_socks5_error(stream, &types::Socks5ErrCode::AddressTypeNotSupported)?;
        Err(e)
    })?;

    log::trace!(
        "Got address type from client \"{}\": {}",
        handshake.id,
        addr_type.value(),
    );

    let addr = read_address(stream, &addr_type).or_else(|_| {
        send_socks5_error(stream, &types::Socks5ErrCode::GeneralFailure)?;
        Err(Error::SocksBadProtocol)
    })?;

    log::trace!("Got address from client \"{}\": {}", handshake.id, addr);

    let mut port_octets = [0u8; 2];
    stream.read(&mut port_octets).or_else(|_| {
        send_socks5_error(stream, &types::Socks5ErrCode::GeneralFailure)?;
        Err(Error::SocksBadProtocol)
    })?;

    let port = u16::from_be_bytes(port_octets);

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
        "Start sending packets between client \"{}\" and target \"{}\"",
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

fn send_socks5_error(stream: &mut TcpStream, code: &types::Socks5ErrCode) -> Result<()> {
    let buffer = [
        types::SocksProtocol::SOCKS5.value(),
        code.value(),
        0, // reserved
        types::SocksAddrType::IPV4.value(),
        0, // address
        0,
        0,
        0,
        0, // port
        0,
    ];
    stream.write_all(&buffer)?;
    Ok(())
}
