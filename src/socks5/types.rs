use crate::socks5::error::Error;
use crate::socks5::result::Result;
use std::collections::HashSet;
use std::io;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

// Описание протокола https://datatracker.ietf.org/doc/html/rfc1928
pub const SUCCESS_CODE: u8 = 0;
pub const CREDENTIAL_AUTH_VERSION: u8 = 1;

pub const SOCKS5_VERSION: u8 = 5;

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
            n => Err(Error::SocksCMDNotSupported(n)),
        }
    }
}

pub enum Socks5ErrCode {
    GeneralFailure,
    ConnectionNotAllowed,
    // NetworkUnreachable,
    // HostUnreachable,
    ConnectionRefused,
    // TtlExpired,
    CommandUnsupported,
    AddressTypeNotSupported,
    AuthMethodNotSupported,
}

impl Socks5ErrCode {
    pub fn value(&self) -> u8 {
        match self {
            Socks5ErrCode::GeneralFailure => 1,
            Socks5ErrCode::ConnectionNotAllowed => 2,
            // Socks5ErrCode::NetworkUnreachable => 3,
            // Socks5ErrCode::HostUnreachable => 4,
            Socks5ErrCode::ConnectionRefused => 5,
            // Socks5ErrCode::TtlExpired => 6,
            Socks5ErrCode::CommandUnsupported => 7,
            Socks5ErrCode::AddressTypeNotSupported => 8,
            Socks5ErrCode::AuthMethodNotSupported => 255,
        }
    }
}

impl From<&Error> for Socks5ErrCode {
    fn from(value: &Error) -> Self {
        match value {
            Error::SocksCMDNotSupported(_) => Socks5ErrCode::CommandUnsupported,
            Error::SocksAddrTypeNotSupported => Socks5ErrCode::AddressTypeNotSupported,
            Error::SockAuthMethodNotSupportedByClient => Socks5ErrCode::AuthMethodNotSupported,
            Error::SocksBadCredentialsProvided => Socks5ErrCode::ConnectionNotAllowed,
            Error::IO(e) => match e.kind() {
                io::ErrorKind::ConnectionRefused => Socks5ErrCode::ConnectionRefused,
                // io::ErrorKind::HostUnreachable => Socks5ErrCode::HostUnreachable,
                // io::ErrorKind::NetworkUnreachable => Socks5ErrCode::NetworkUnreachable,
                _ => Socks5ErrCode::GeneralFailure,
            },
            _ => Socks5ErrCode::GeneralFailure,
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
    Credentials { provider: Credentials },
}

impl SocksAuthMethod {
    pub fn value(&self) -> u8 {
        match self {
            SocksAuthMethod::NoAuth => 0,
            SocksAuthMethod::Credentials { provider: _ } => 2,
        }
    }
}

pub struct Credentials {
    map: HashSet<(String, String)>,
}

impl Credentials {
    pub fn contains(&self, key: &(String, String)) -> bool {
        self.map.contains(key)
    }
}

impl TryFrom<PathBuf> for Credentials {
    type Error = Error;

    fn try_from(value: PathBuf) -> std::result::Result<Self, Self::Error> {
        let reader = BufReader::new(std::fs::File::open(value)?);

        let map = HashSet::from_iter(reader.lines().filter_map(|line| {
            if let Ok(line) = line {
                let (name, value) = line.split_once(':')?;
                Some((name.to_string(), value.to_string()))
            } else {
                None
            }
        }));

        Ok(Credentials { map })
    }
}
