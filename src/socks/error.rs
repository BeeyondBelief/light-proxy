use derive_more::{Display, From};

// https://www.youtube.com/watch?v=j-VQCYP7wyw&t=379s
#[derive(Debug, From, Display)]
pub enum Error {
    GenericError,

    SocksProtocolVersionNotSupported,
    SocksCMDNotSupported,
    SocksAddrTypeNotSupported,
    SocksBadProtocol,
    SocksNoAuthMethodsProvided,
    SocksUnknownAuthMethod,
    SockAuthMethodNotSupportedByClient,
    SocksNoCredentialsProvided,
    SocksBadCredentialsProvided,

    #[from]
    IO(std::io::Error),
}

impl std::error::Error for Error {}
