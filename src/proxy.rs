use crate::error::Result;
use std::net::TcpStream;

pub trait Proxy {
    fn accept_stream(&self, stream: TcpStream) -> Result<()>;
}
