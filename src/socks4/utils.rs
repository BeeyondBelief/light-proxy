use crate::socks4::result::Result;
use crate::socks4::types::Socks4ErrCode;
use tokio::io::AsyncWriteExt;

pub async fn send_socks4_error(
    stream: &mut tokio::net::TcpStream,
    code: impl Into<Socks4ErrCode>,
) -> Result<()> {
    let buffer = [
        0,
        code.into().value(),
        0, // port
        0,
        0, // address
        0,
        0,
        0,
    ];
    stream.write_all(&buffer).await?;
    Ok(())
}
