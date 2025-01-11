use crate::socks5::result::Result;
use crate::socks5::types::{Socks5ErrCode, SocksAddrType, SOCKS5_VERSION};
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

pub async fn read_utf8_str(stream: &mut tokio::net::TcpStream, buff: &mut [u8]) -> Result<String> {
    stream.read_exact(&mut buff[..1]).await?;
    let length = buff[0] as usize;
    stream.read_exact(&mut buff[..length]).await?;
    let ut8_str = String::from_utf8_lossy(&buff[..length]).to_string();
    buff[..length].fill(0u8);
    Ok(ut8_str)
}
