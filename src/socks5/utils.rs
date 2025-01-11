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

pub async fn read_credentials(
    stream: &mut tokio::net::TcpStream,
    buff: &mut [u8],
) -> Result<(String, String)> {
    let mut username = String::new();
    let mut password = String::new();

    read_safe_to_string(stream, &mut username, buff).await?;
    read_safe_to_string(stream, &mut password, buff).await?;

    Ok((username, password))
}

async fn read_safe_to_string(
    stream: &mut tokio::net::TcpStream,
    string: &mut String,
    buff: &mut [u8],
) -> Result<()> {
    stream.read_exact(&mut buff[..1]).await?;
    let length = buff[0] as usize;
    stream.read_exact(&mut buff[..length]).await?;
    string.extend(buff[..length].iter_mut().map(|b| {
        let o = *b as char;
        *b = 0u8;
        o
    }));
    Ok(())
}
