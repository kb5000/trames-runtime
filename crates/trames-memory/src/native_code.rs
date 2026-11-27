// SPDX-License-Identifier: GPL-3.0-or-later
//! Entry-scoped hardware operands and signal-safe native-code fixups.
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Protected aliases of the canonical bytes, never kernel/native RW pointers.
/// A zero pointer declines that access. See CpuMemory::cpu_native_page.
pub struct NativePage {
    pub base: u64,
    pub read: usize,
    pub write: usize,
}

const SLOTS: usize = 65536;
struct Site {
    pc: AtomicUsize,
    recovery: AtomicUsize,
}
static SITES: [Site; SLOTS] = [const {
    Site {
        pc: AtomicUsize::new(0),
        recovery: AtomicUsize::new(0),
    }
}; SLOTS];

/// Publication/retirement happens on the code owner's thread, outside signal
/// handling. The handler reads only lock-free atomics, never heap metadata.
/// Thread affinity prevents retiring a PC while its interrupted owner uses it.
pub struct NativeCodeFixups {
    slots: Vec<usize>,
    _thread: PhantomData<Rc<()>>,
}
impl NativeCodeFixups {
    /// # Safety
    /// Each pair identifies an exact potentially faulting native RAM instruction
    /// and a local recovery site in the same live executable allocation. Recovery
    /// must preserve Rust stack/destructor boundaries and precise guest state.
    /// No thread may execute those instructions after this token is dropped;
    /// retain this token until all native entries return, then drop before munmap.
    pub unsafe fn register(pairs: &[(usize, usize)]) -> std::io::Result<Self> {
        let mut token = Self {
            slots: Vec::with_capacity(pairs.len()),
            _thread: PhantomData,
        };
        for &(pc, recovery) in pairs {
            if pc <= 1 || recovery == 0 {
                return Err(std::io::Error::other("invalid native fault site"));
            }
            let Some(slot) = SITES.iter().position(|site| {
                site.pc
                    .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            }) else {
                return Err(std::io::Error::other("native fault table full"));
            };
            SITES[slot].recovery.store(recovery, Ordering::Relaxed);
            SITES[slot].pc.store(pc, Ordering::Release);
            token.slots.push(slot);
        }
        Ok(token)
    }
}
impl Drop for NativeCodeFixups {
    fn drop(&mut self) {
        for &slot in &self.slots {
            SITES[slot].pc.store(0, Ordering::Release);
        }
    }
}
pub(crate) fn recovery(pc: usize) -> Option<usize> {
    SITES.iter().find_map(|site| {
        (site.pc.load(Ordering::Acquire) == pc && pc > 1)
            .then(|| site.recovery.load(Ordering::Relaxed))
    })
}
