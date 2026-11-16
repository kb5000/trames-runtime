// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared cold control UI and wire values; no kernel, executor or resident agent.
pub mod archive;
pub mod copy;
pub mod guest;
mod ui;
use serde_json::{json, Value};
use std::io;
pub use ui::{run, Backend, Options};
pub const VERSION: u32 = 1;
pub const MAX_FRAME: usize = 32768;
pub const CAPABILITIES: &[(&str, &str)] = &[
    ("clipboard", "Clipboard"),
    ("files", "Shared files"),
    ("mounts", "Mounts"),
    ("ports", "Port publishing"),
    ("host-ui", "Host interface"),
    ("host-cli", "Host Trames CLI"),
    ("host-exec", "Host commands"),
];
#[derive(Debug, Clone)]
pub struct Error {
    pub code: String,
    pub message: String,
    pub hint: Option<String>,
    pub status: u8,
}
impl Error {
    pub fn new(code: &str, message: impl Into<String>, status: u8) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            hint: None,
            status,
        }
    }
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new("usage", message, 2)
    }
    pub fn denied(message: impl Into<String>) -> Self {
        Self::new("permission_denied", message, 77).hint(
            "Allow this feature in the host manager, then restart the environment when convenient.",
        )
    }
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new("unavailable", message, 69)
    }
    pub fn json(&self) -> Value {
        json!({"code":self.code,"message":self.message,"hint":self.hint})
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::new(
            if e.kind() == io::ErrorKind::PermissionDenied {
                "permission_denied"
            } else if e.kind() == io::ErrorKind::TimedOut {
                "timeout"
            } else {
                "io"
            },
            e.to_string(),
            if e.kind() == io::ErrorKind::PermissionDenied {
                77
            } else if e.kind() == io::ErrorKind::TimedOut {
                124
            } else if e.kind() == io::ErrorKind::BrokenPipe {
                141
            } else {
                1
            },
        )
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::new("protocol", e.to_string(), 69)
    }
}
pub type Result<T> = std::result::Result<T, Error>;
pub fn envelope(command: &str, result: std::result::Result<Value, &Error>) -> Value {
    match result {
        Ok(data) => json!({"schema_version":1,"command":command,"ok":true,"data":data}),
        Err(e) => json!({"schema_version":1,"command":command,"ok":false,"error":e.json()}),
    }
}

// Byte streams use RFC 4648 base64. File payloads never use this codec.
pub fn encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let a = c[0] as usize;
        let b = *c.get(1).unwrap_or(&0) as usize;
        let d = *c.get(2).unwrap_or(&0) as usize;
        out.push(T[a >> 2] as char);
        out.push(T[((a & 3) << 4) | (b >> 4)] as char);
        out.push(if c.len() > 1 {
            T[((b & 15) << 2) | (d >> 6)] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 { T[d & 63] as char } else { '=' });
    }
    out
}
pub fn decode(text: &str) -> Result<Vec<u8>> {
    fn digit(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bad = || Error::new("protocol", "Invalid base64 stream frame", 69);
    if !text.len().is_multiple_of(4) {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (index, c) in text.as_bytes().chunks(4).enumerate() {
        let a = digit(c[0]).ok_or_else(bad)?;
        let b = digit(c[1]).ok_or_else(bad)?;
        let pad = usize::from(c[3] == b'=') + usize::from(c[2] == b'=');
        if pad > 0 && (index + 1 != text.len() / 4 || c[2] == b'=' && c[3] != b'=') {
            return Err(bad());
        }
        let d = if c[2] == b'=' {
            0
        } else {
            digit(c[2]).ok_or_else(bad)?
        };
        let e = if c[3] == b'=' {
            0
        } else {
            digit(c[3]).ok_or_else(bad)?
        };
        if pad == 2 && b & 15 != 0 || pad == 1 && d & 3 != 0 {
            return Err(bad());
        }
        out.push((a << 2) | (b >> 4));
        if pad < 2 {
            out.push((b << 4) | (d >> 2));
        }
        if pad == 0 {
            out.push((d << 6) | e);
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_codec_roundtrips_and_rejects_malformed_padding() {
        for (a, b) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(a.as_bytes()), b);
            assert_eq!(decode(b).unwrap(), a.as_bytes());
        }
        let bytes = (0..=255).collect::<Vec<u8>>();
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
        for bad in ["a", "AA=A", "AB==", "AAB=", "AAAA====", "****"] {
            assert!(decode(bad).is_err(), "{bad}");
        }
    }
}
