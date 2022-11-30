#[forbid(unsafe_code)]
use std::{
    io::{Error, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
};
use thiserror::Error;

type Byte = u8;

const PING_REQUEST: &[Byte] = b"zPING\0";
const HEADER: &[Byte] = b"zINSTREAM\0";
const FOOTER: &[Byte] = &[0; 4];
const PING_RESPONSE: &[Byte] = b"zPONG\0";
const PING_RESPONSE_CAPACITY: usize = PING_RESPONSE.len();

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
    InvalidUtf8Error(Error),
    #[error("unable to write to the stream")]
    /// Unable to write to the [TcpStream].
    UnableToWriteToStream(Error),
}

const DEFAULT_CHUNK_SIZE: usize = 4096;

/// Checks if the ClamAV host is up.
/// 
/// ```rust
/// use clamav_tcp;
/// let resp = clamav_tcp::ping("localhost:3310").unwrap();
/// assert_eq!(resp, "PONG\0");
/// ```
pub fn ping(addr: impl ToSocketAddrs) -> Result<String, ClamAVClientError> {
    let mut stream = connect_tcp_socket(addr)?;

    stream
        .write_all(PING_REQUEST)
        .map_err(ClamAVClientError::UnableToConnect)?;

    let mut resp = String::with_capacity(PING_RESPONSE_CAPACITY);
    stream.read_to_string(&mut resp).map_err(ClamAVClientError::InvalidUtf8Error)?;

    Ok(resp)
}


/// Scans something that is [Read] and returns the ClamAV response to the scanned item.
/// 
/// ```rust
/// use clamav_tcp;
/// let mut eicar = std::fs::File::open("resources/eicar.txt").unwrap();
/// let res = clamav_tcp::scan("localhost:3310", &mut eicar, None).unwrap();
/// assert_eq!(res, "stream: Win.Test.EICAR_HDB-1 FOUND\0");
/// ```
pub fn scan<A: ToSocketAddrs, D: Read>(
    addr: A,
    file: &mut D,
    chunk_size: Option<usize>,
) -> Result<String, ClamAVClientError> {
    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    let mut stream = connect_tcp_socket(addr)?;

    // Write header
    stream
        .write_all(HEADER)
        .map_err(ClamAVClientError::UnableToWriteToStream)?;

    // Write filesize
    let mut buf = vec![0; chunk_size];
    loop {
        let stream_portion_len = file
            .read(&mut buf[..])
            .map_err(ClamAVClientError::UnableToWriteToStream)?;
        if stream_portion_len != 0 {
            // Write the header to the stream. This is the size of the current chunk in big endian.
            stream
                .write_all(&(stream_portion_len as u32).to_be_bytes())
                .map_err(ClamAVClientError::UnableToWriteToStream)?;
            stream
                .write_all(&buf[0..stream_portion_len])
                .map_err(ClamAVClientError::UnableToWriteToStream)?;
        } else {
            // Write footer
            stream
                .write_all(FOOTER)
                .map_err(ClamAVClientError::UnableToWriteToStream)?;
            break;
        }
    }

    let mut buf = String::new();
    stream
        .read_to_string(&mut buf)
        .map_err(ClamAVClientError::InvalidUtf8Error)?;

    Ok(buf)
}

fn connect_tcp_socket(addr: impl ToSocketAddrs) -> Result<TcpStream, ClamAVClientError> {
    let addr: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .map_err(ClamAVClientError::InvalidSocketAddress)?
        .collect();

    let stream = TcpStream::connect(&addr[0..]).map_err(ClamAVClientError::UnableToConnect)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn ping_fails_with_invalid_addr() {
        let err = ping("asd").is_err();
        assert!(err);
    }

    #[test]
    fn can_scan_buf() {
        let mut buf = "This is not a virus.".as_bytes();
        let res = scan("localhost:3310", &mut buf, None).unwrap();
        assert_eq!(res, "stream: OK\0");
    }


    #[test]
    fn can_scan_file() {
        let mut eicar = std::fs::File::open("resources/eicar.txt").unwrap();
        let res = scan("localhost:3310", &mut eicar, None);
        assert!(res.is_ok());
    }


    #[test]
    fn detects_eicar() {
        let mut eicar = std::fs::File::open("resources/eicar.txt").unwrap();
        let res = scan("localhost:3310", &mut eicar, None).unwrap();
        assert_eq!(res, "stream: Win.Test.EICAR_HDB-1 FOUND\0");
    }


    #[test]
    fn can_scan_string() {
        let mut eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".as_bytes();
        let res = scan("localhost:3310", &mut eicar, None).unwrap();
        assert_eq!(res, "stream: Win.Test.EICAR_HDB-1 FOUND\0");
    }

    #[test]
    fn can_ping_with_valid_addr() {
        let resp = ping("localhost:3310");

        match resp {
            Ok(r) => assert_eq!(r, "PONG\0"),
            Err(_r) => println!("This test would succeed but ClamAV does not seem to be up."),
        }
    }
}
