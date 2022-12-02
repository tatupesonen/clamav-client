#![forbid(unsafe_code)]
use std::{
    io::Error,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
};
pub mod ping;
pub mod responses;
pub mod scan;
pub mod version;
pub use ping::ping;
pub use responses::ScanResult;
pub use scan::scan;
use thiserror::Error;
pub use version::version;

pub type Byte = u8;

#[derive(Error, Debug)]
pub enum ClamAVClientError {
    #[error("unable to connect to clamav")]
    /// If unable to establish a [TcpStream] with the ClamAV instance.
    UnableToConnect(#[from] Error), //- test
    #[error("invalid socket address")]
    /// If the socket address passed to [scan] or [ping] is invalid.
    ///
    /// eg.
    /// ```
    /// use clamav_tcp;
    /// assert_eq!(clamav_tcp::ping("hello world").is_err(), true);
    /// ```
    ///
    /// ```
    /// use clamav_tcp;
    /// assert_eq!(clamav_tcp::ping("127.0.0.1:3310").is_ok(), true);
    /// ```
    InvalidSocketAddress(Error),
    #[error("unable to parse response to utf-8")]
    /// When parsing the ClamAV response and the response is not valid UTF-8.
    InvalidUTf8(Error),
    /// When the response is valid UTF-8 but it cannot be mapped to a struct.
    #[error("unable to parse the clamav response")]
    UnableToParseResponse(String),
    #[error("unable to write to the stream")]
    /// Unable to write to the [TcpStream].
    UnableToWriteToStream(Error),
}

fn connect_tcp_socket(addr: impl ToSocketAddrs) -> Result<TcpStream, ClamAVClientError> {
    let addr: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .map_err(ClamAVClientError::InvalidSocketAddress)?
        .collect();

    let stream = TcpStream::connect(&addr[0..]).map_err(ClamAVClientError::UnableToConnect)?;
    Ok(stream)
}
