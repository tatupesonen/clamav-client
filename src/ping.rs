use std::{
    io::{Read, Write},
    net::ToSocketAddrs,
};

use crate::{connect_tcp_socket, Byte, ClamAVClientError};
const PING_REQUEST: &[Byte] = b"zPING\0";
const PING_RESPONSE: &[Byte] = b"zPONG\0";
const PING_RESPONSE_CAPACITY: usize = PING_RESPONSE.len();

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
    stream
        .read_to_string(&mut resp)
        .map_err(ClamAVClientError::InvalidUTf8)?;

    Ok(resp)
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
    fn can_ping_with_valid_addr() {
        let resp = ping("localhost:3310");

        match resp {
            Ok(r) => assert_eq!(r, "PONG\0"),
            Err(_r) => println!("This test would succeed but ClamAV does not seem to be up."),
        }
    }
}
