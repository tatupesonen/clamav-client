use std::{
    io::{Read, Write},
    net::ToSocketAddrs,
};

use crate::{connect_tcp_socket, Byte, ClamAVClientError};
const VERSION_REQUEST: &[Byte] = b"zVERSION\0";

/// Checks ClamAV version.
///
/// ```rust
/// use clamav_tcp;
/// let resp = clamav_tcp::version("localhost:3310").unwrap();
/// println!("{}", resp); // "ClamAV 1.0.0/26734/Mon Nov 28 08:17:05 2022\"
/// ```
pub fn version(addr: impl ToSocketAddrs) -> Result<String, ClamAVClientError> {
    let mut stream = connect_tcp_socket(addr)?;

    stream
        .write_all(VERSION_REQUEST)
        .map_err(ClamAVClientError::UnableToConnect)?;

    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(ClamAVClientError::InvalidUTf8)?;

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_read_version() {
        let err = version("localhost:3310").is_ok();
        assert!(err);
    }
}
