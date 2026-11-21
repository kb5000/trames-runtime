// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-task Linux execution-domain word. Worker handles observe the original
//! task. A clone (including CLONE_THREAD) inherits an independent value.
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use trames_vfs::Errno;

const DOMAIN: u32 = 0xff;
const LINUX32: u32 = 8;
const UNAME26: u32 = 0x0020000;
const SHORT_INODE: u32 = 0x1000000;
const WHOLE_SECONDS: u32 = 0x2000000;

#[derive(Clone, Default)]
pub struct TaskPersonality(Arc<AtomicU32>);
impl TaskPersonality {
    pub fn call(&self, word: u64) -> Result<u64, Errno> {
        let word = word as u32;
        if word == u32::MAX {
            return Ok(self.0.load(Ordering::Relaxed) as u64);
        }
        // AArch32 EL0 and flags requiring a different memory or signal ABI
        // are unsupported. The legacy inode/time bits are inert on AArch64.
        if word & DOMAIN == LINUX32 || word & !(DOMAIN | SHORT_INODE | WHOLE_SECONDS | UNAME26) != 0
        {
            return Err(Errno(22));
        }
        Ok(self.0.swap(word, Ordering::Relaxed) as u64)
    }
    pub(crate) fn fork(&self) -> Self {
        Self(Arc::new(AtomicU32::new(self.0.load(Ordering::Relaxed))))
    }
    pub(crate) fn uname26(&self) -> bool {
        self.0.load(Ordering::Relaxed) & UNAME26 != 0
    }
}
