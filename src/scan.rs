use std::{
    io::{Read, Write},
    net::ToSocketAddrs,
};

use crate::{connect_tcp_socket, Byte, ClamAVClientError, ScanResult};

const DEFAULT_CHUNK_SIZE: usize = 4096;
const HEADER: &[Byte] = b"zINSTREAM\0";
const FOOTER: &[Byte] = &[0; 4];

/// Scans something that is [Read] and returns the ClamAV response to the scanned item.
///
/// ```rust
/// use clamav_tcp;
/// let mut eicar = std::fs::File::open("resources/eicar.txt").unwrap();
/// let res = clamav_tcp::scan("localhost:3310", &mut eicar, None).unwrap();
/// assert_eq!(1, res.detected_infections.len());
/// ```
pub fn scan<A: ToSocketAddrs, D: Read>(
    addr: A,
    file: &mut D,
    chunk_size: Option<usize>,
) -> Result<ScanResult, ClamAVClientError> {
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
        .map_err(ClamAVClientError::InvalidUTf8)?;

    let parsed = buf.parse::<ScanResult>()?;

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn can_scan_buf() {
        let mut buf = "This is not a virus.".as_bytes();
        let res = scan("localhost:3310", &mut buf, None).unwrap();
        assert_eq!(res.is_infected, false);
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
				println!("{:?}", res.detected_infections);
        assert_eq!(1, res.detected_infections.len());
    }

    #[test]
    fn can_scan_string() {
        let mut eicar =
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".as_bytes();
        let res = scan("localhost:3310", &mut eicar, None).unwrap();
        assert_eq!(1, res.detected_infections.len());
    }
}
