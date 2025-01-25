use crate::socks4::error::Error;
use crate::socks4::result::Result;

pub const SUCCESS_CODE: u8 = 90;
pub const SOCKS4_VERSION: u8 = 4;

pub enum SocksCMD {
    CONNECT,
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

pub enum Socks4ErrCode {
    GeneralFailure,
    IdentUndefined,
}

impl Socks4ErrCode {
    pub fn value(&self) -> u8 {
        match self {
            Socks4ErrCode::GeneralFailure => 91,
            Socks4ErrCode::IdentUndefined => 92,
        }
    }
}

impl From<&Error> for Socks4ErrCode {
    fn from(value: &Error) -> Self {
        match value {
            Error::SocksProtocolVersionNotSupported(_)
            | Error::SocksCMDNotSupported(_)
            | Error::SocksBadProtocol
            | Error::BadString
            | Error::IO(_) => Socks4ErrCode::GeneralFailure,
            Error::SocksBadClientId => Socks4ErrCode::IdentUndefined,
        }
    }
}
