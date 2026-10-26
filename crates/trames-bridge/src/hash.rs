// SPDX-License-Identifier: GPL-3.0-or-later
//! Opt-in host SHA-256 service and accounting, independent of guest execution.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Instant;
pub const ABI_VERSION: u32 = 1;
pub const MAX_INPUT: usize = 16 * 1024;
#[derive(Default, Serialize)]
pub struct Registry {
    pub enabled: bool,
    pub calls: u64,
    pub bytes: u64,
    pub nanoseconds: u64,
    pub fallbacks: u64,
}
impl Registry {
    pub fn sha256(&mut self, input: &[u8]) -> Result<String, &'static str> {
        if input.len() > MAX_INPUT {
            return Err("input_too_large");
        }
        if !self.enabled {
            self.fallbacks = self.fallbacks.saturating_add(1);
            return Err("disabled");
        }
        let start = Instant::now();
        let digest = Sha256::digest(input);
        self.calls = self.calls.saturating_add(1);
        self.bytes = self.bytes.saturating_add(input.len() as u64);
        self.nanoseconds = self
            .nanoseconds
            .saturating_add(start.elapsed().as_nanos().min(u64::MAX as u128) as u64);
        Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_fallback_and_known_vectors() {
        let mut r = Registry::default();
        assert_eq!(r.sha256(b"abc"), Err("disabled"));
        assert_eq!(r.calls, 0);
        assert_eq!(r.fallbacks, 1);
        r.enabled = true;
        assert_eq!(
            r.sha256(b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(r.sha256(&vec![0; MAX_INPUT + 1]), Err("input_too_large"));
        assert_eq!(r.calls, 1);
        assert_eq!(r.bytes, 3);
    }
}
