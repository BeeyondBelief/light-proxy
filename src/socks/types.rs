use crate::socks::error::Error;
use crate::socks::result::Result;
use std::net::TcpStream;

// Описание протокола https://datatracker.ietf.org/doc/html/rfc1928
pub type StreamId = String;

pub type CredentialAuthProvider = Box<dyn Fn(&str, &str) -> bool>;

#[derive(Debug, Eq, PartialEq)]
pub enum SocksProtocol {
    SOCKS5,
}

impl SocksProtocol {
    pub fn value(&self) -> u8 {
        match self {
            SocksProtocol::SOCKS5 => 5,
        }
    }
}

impl TryFrom<u8> for SocksProtocol {
    type Error = Error;

    fn try_from(value: u8) -> Result<SocksProtocol> {
        match value {
            5 => Ok(SocksProtocol::SOCKS5),
            _ => Err(Error::SocksProtocolVersionNotSupported),
        }
    }
}

pub enum SocksCMD {
    CONNECT,
}

impl SocksCMD {
    pub fn value(&self) -> u8 {
        match self {
            SocksCMD::CONNECT => 1,
        }
    }
}

impl TryFrom<u8> for SocksCMD {
    type Error = Error;
    fn try_from(value: u8) -> Result<SocksCMD> {
        match value {
            1 => Ok(SocksCMD::CONNECT),
            _ => Err(Error::SocksCMDNotSupported),
        }
    }
}

pub enum Socks5ErrCode {
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandUnsupported,
    AddressTypeNotSupported,
    AuthMethodNotSupported,
}

impl Socks5ErrCode {
    pub fn value(&self) -> u8 {
        match self {
            Socks5ErrCode::GeneralFailure => 1,
            Socks5ErrCode::ConnectionNotAllowed => 2,
            Socks5ErrCode::NetworkUnreachable => 3,
            Socks5ErrCode::HostUnreachable => 4,
            Socks5ErrCode::ConnectionRefused => 5,
            Socks5ErrCode::TtlExpired => 6,
            Socks5ErrCode::CommandUnsupported => 7,
            Socks5ErrCode::AddressTypeNotSupported => 8,
            Socks5ErrCode::AuthMethodNotSupported => 255,
        }
    }
}

pub enum SocksAddrType {
    IPV4,
    // DOMAINNAME,
    IPV6,
}

impl SocksAddrType {
    pub fn value(&self) -> u8 {
        match self {
            SocksAddrType::IPV4 => 1,
            // SocksAddrType::DOMAINNAME => 3,
            SocksAddrType::IPV6 => 4,
        }
    }
}

impl TryFrom<u8> for SocksAddrType {
    type Error = Error;
    fn try_from(value: u8) -> Result<SocksAddrType> {
        match value {
            1 => Ok(SocksAddrType::IPV4),
            // 3 => Ok(SocksAddrType::DOMAINNAME),
            4 => Ok(SocksAddrType::IPV6),
            _ => Err(Error::SocksAddrTypeNotSupported),
        }
    }
}

pub enum SocksAuthMethod {
    NoAuth,
    Credentials { provider: CredentialAuthProvider },
}

impl SocksAuthMethod {
    pub fn value(&self) -> u8 {
        match self {
            SocksAuthMethod::NoAuth => 0,
            SocksAuthMethod::Credentials { provider: _ } => 2,
        }
    }
}

pub struct SocksHandshake {
    pub id: StreamId,
    pub protocol: SocksProtocol,
    pub auth_methods: Vec<u8>,
}

impl SocksHandshake {
    pub fn is_auth_supported(&self, auth: &SocksAuthMethod) -> bool {
        self.auth_methods.contains(&auth.value())
    }
}

pub struct SockTarget {
    pub id: StreamId,
    pub stream: TcpStream,
}

pub struct SocksConnection {
    pub from: SockTarget,
    pub to: SockTarget,
}
