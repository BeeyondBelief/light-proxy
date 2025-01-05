use crate::socks::result::Result;
use crate::socks::types::{Socks5ErrCode, SocksAddrType, SocksProtocol};
use crate::socks::Error;
use std::io::{Read, Write};
use std::net::TcpStream;

pub fn send_socks5_error(stream: &mut TcpStream, code: impl Into<Socks5ErrCode>) -> Result<()> {
    let buffer = [
        SocksProtocol::SOCKS5.value(),
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
    stream.write_all(&buffer)?;
    Ok(())
}

pub fn read_utf8_str(stream: &mut TcpStream) -> Result<String> {
    let mut length = [0u8];
    stream.read_exact(&mut length)?;
    let mut content = vec![0u8; length[0] as usize];
    stream.read_exact(&mut content)?;
    String::from_utf8(content).or(Err(Error::BadString))
}
