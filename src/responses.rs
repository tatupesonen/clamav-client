use serde::{Deserialize, Serialize};

use crate::ClamAVClientError;
use std::str::FromStr;

/// A struct that describes the result of the scan.
#[derive(Deserialize, Debug, Serialize)]
pub struct ScanResult {
    /// If a malicious file was found within the scanned item.
    pub is_infected: bool,
    /// Names of the detected infections.
    pub detected_infections: Vec<String>,
}

impl FromStr for ScanResult {
    type Err = ClamAVClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Take section after "stream: "
        let stuff: Vec<&str> = s.split("stream: ").into_iter().skip(1).collect();
        if stuff.clone().into_iter().any(|x| x.starts_with("OK")) {
            return Ok(ScanResult {
                is_infected: false,
                detected_infections: vec![],
            });
        }

        let detections = stuff
            .into_iter()
            .map(|e| e.to_string().replace(" FOUND\0", ""))
            .collect();
        Ok(ScanResult {
            is_infected: true,
            detected_infections: detections,
        })
    }
}
