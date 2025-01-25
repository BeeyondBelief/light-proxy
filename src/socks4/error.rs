use derive_more::{Display, From};

#[derive(Debug, From, Display)]
pub enum Error {
    SocksProtocolVersionNotSupported(u8),
    SocksCMDNotSupported(u8),
    SocksBadProtocol,

    SocksBadClientId,

    BadString,

    #[from]
    IO(std::io::Error),
}

impl std::error::Error for Error {}
