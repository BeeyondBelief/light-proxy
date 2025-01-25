use derive_more::From;

pub type Result<T> = std::result::Result<T, Error>;

// https://www.youtube.com/watch?v=j-VQCYP7wyw&t=379s
#[derive(Debug, From)]
pub enum Error {
    UnknownMode,

    #[from]
    SOCKS5(crate::socks5::Error),

    #[from]
    SOCKS4(crate::socks4::Error),

    #[from]
    IO(std::io::Error),
}
