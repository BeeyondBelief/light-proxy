use crate::socks::error::Error;
use crate::socks::result::Result;
use std::net::TcpStream;

// Описание протокола https://datatracker.ietf.org/doc/html/rfc1928
pub type StreamId = String;

pub const SOCKS5_AUTH_METHOD_NOT_SUPPORTED: u8 = 0xff;

pub type CredentialAuthProvider = Box<dyn Fn(&str, &str) -> bool>;

#[derive(Debug, Eq, PartialEq)]
pub enum SocksProtocol {
    SOCKS5,
}

impl SocksProtocol {
    pub fn value(&self) -> u8 {
        match self {
            SocksProtocol::SOCKS5 => 0x05,
        }
    }
    pub fn from_u8(value: u8) -> Result<SocksProtocol> {
        match value {
            0x05 => Ok(SocksProtocol::SOCKS5),
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
            SocksCMD::CONNECT => 0x01,
        }
    }
}

impl TryFrom<u8> for SocksCMD {
    type Error = Error;
    fn try_from(value: u8) -> Result<SocksCMD> {
        match value {
            0x1 => Ok(SocksCMD::CONNECT),
            _ => Err(Error::SocksCMDNotSupported),
        }
    }
}

pub enum SocksAddrType {
    IPV4,
    // DOMAINNAME,
    // IPV6,
}

impl SocksAddrType {
    pub fn value(&self) -> u8 {
        match self {
            SocksAddrType::IPV4 => 0x01,
            // SocksAddrType::DOMAINNAME => 0x03,
            // SocksAddrType::IPV6 => 0x04,
        }
    }
}

impl TryFrom<u8> for SocksAddrType {
    type Error = Error;
    fn try_from(value: u8) -> Result<SocksAddrType> {
        match value {
            0x01 => Ok(SocksAddrType::IPV4),
            // 0x03 => Ok(SocksAddrType::DOMAINNAME),
            // 0x04 => Ok(SocksAddrType::IPV6),
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
            SocksAuthMethod::NoAuth => 0x00,
            SocksAuthMethod::Credentials { provider: _ } => 0x02,
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
