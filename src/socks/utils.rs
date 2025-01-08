use crate::socks::result::Result;
use crate::socks::types::{Socks5ErrCode, SocksAddrType, SOCKS5_VERSION};
use crate::socks::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn send_socks5_error(
    stream: &mut tokio::net::TcpStream,
    code: impl Into<Socks5ErrCode>,
) -> Result<()> {
    let buffer = [
        SOCKS5_VERSION,
        code.into().value(),
        0, // reserved
        SocksAddrType::IPV4.value(),
        0, // address
        0,
        0,
        0,
        0, // port
        0,
    ];
    stream.write_all(&buffer).await?;
    Ok(())
}

pub async fn read_utf8_str(stream: &mut tokio::net::TcpStream) -> Result<String> {
    let mut length = [0u8];
    stream.read_exact(&mut length).await?;
    let mut content = vec![0u8; length[0] as usize];
    stream.read_exact(&mut content).await?;
    String::from_utf8(content).or(Err(Error::BadString))
}
