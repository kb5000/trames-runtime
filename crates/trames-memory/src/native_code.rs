// SPDX-License-Identifier: GPL-3.0-or-later
//! Entry-scoped hardware operands and signal-safe native-code fixups.
/// Entry-scoped protected VA for variable-length native instructions. Allocation
/// uses the MMU's existing bounded VA budget, with no executable permissions.
/// This owner is thread-local and cannot retain guest aliases across CPU entries.
pub struct NativeOperand {
    mapping: crate::mmu::host::NativeRange,
    _thread: PhantomData<Rc<()>>,
}
impl NativeOperand {
    pub fn new(length: usize) -> std::io::Result<Self> {
        Ok(Self {
            mapping: crate::mmu::host::NativeRange::new(length)
                .ok_or_else(|| std::io::Error::other("native operand VA capacity"))?,
            _thread: PhantomData,
        })
    }
    pub fn address(&self) -> usize {
        self.mapping.address()
    }
    pub fn length(&self) -> usize {
        self.mapping.length()
    }
    /// # Safety
    /// Source is a current protected CpuMemory export, never an ordinary Rust
    /// byte reference or unchecked host pointer. Retain the original loan until
    /// this alias is replaced/dropped, before any non-admitted CpuMemory call.
    /// The source and target intervals are host-granule aligned and non-executable.
    pub unsafe fn alias(&mut self, offset: usize, source: usize, len: usize) -> bool {
        unsafe { self.mapping.alias(offset, source, len) }
    }
    /// Populate fresh private staging bytes; no alias may be executing or have a
    /// live byte reference during this mutation. The owned VA bounds are checked.
    pub fn stage(&mut self, offset: usize, len: usize) -> bool {
        self.mapping.replace(offset, len, true)
    }
    /// Restrict populated host granules to reads when source and destination
    /// share one overlapping operand but only the source owns the next chunk.
    pub fn read_only(&mut self, offset: usize, len: usize) -> bool {
        self.mapping.read_only(offset, len)
    }
    /// Discard physical aliases/staging and restore inaccessible owned VA.
    pub fn reset(&mut self, offset: usize, len: usize) -> bool {
        self.mapping.replace(offset, len, false)
    }
}

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
    fault_registers: AtomicUsize,
}
static SITES: [Site; SLOTS] = [const {
    Site {
        pc: AtomicUsize::new(0),
        recovery: AtomicUsize::new(0),
        fault_registers: AtomicUsize::new(0),
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
        unsafe { Self::register_impl(pairs, 0) }
    }
    /// Preserve the data-abort address in a declared AArch64 caller-saved
    /// register when resuming a local native recovery site. No TLS/task state.
    ///
    /// # Safety
    /// The same live-code/stack contract as register() applies. Recovery reserves
    /// this host register and consumes it before any call or guest writeback.
    pub unsafe fn register_with_address(
        pairs: &[(usize, usize)],
        register: u8,
    ) -> std::io::Result<Self> {
        if !cfg!(target_arch = "aarch64") || register > 17 {
            return Err(std::io::Error::other(
                "invalid native fault-address register",
            ));
        }
        unsafe { Self::register_impl(pairs, usize::from(register) + 1) }
    }
    /// Supply the actual data-abort address and access kind (0=read, 1=write,
    /// 2=unavailable) in two reserved caller-saved registers on recovery.
    ///
    /// # Safety
    /// The live-code/stack contract of register_with_address applies to both
    /// distinct registers. Neither may contain live guest values at recovery.
    pub unsafe fn register_with_memory(
        pairs: &[(usize, usize)],
        address: u8,
        access: u8,
    ) -> std::io::Result<Self> {
        if !cfg!(target_arch = "aarch64") || address > 17 || access > 17 || address == access {
            return Err(std::io::Error::other(
                "invalid native memory-fault registers",
            ));
        }
        unsafe {
            Self::register_impl(
                pairs,
                (usize::from(address) + 1) | ((usize::from(access) + 1) << 8),
            )
        }
    }
    unsafe fn register_impl(pairs: &[(usize, usize)], registers: usize) -> std::io::Result<Self> {
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
            SITES[slot]
                .fault_registers
                .store(registers, Ordering::Relaxed);
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
pub(crate) struct Recovery {
    pub pc: usize,
    pub address: Option<usize>,
    pub access: Option<usize>,
}
pub(crate) fn recovery(pc: usize) -> Option<Recovery> {
    SITES.iter().find_map(|site| {
        (site.pc.load(Ordering::Acquire) == pc && pc > 1).then(|| Recovery {
            pc: site.recovery.load(Ordering::Relaxed),
            address: (site.fault_registers.load(Ordering::Relaxed) & 255).checked_sub(1),
            access: ((site.fault_registers.load(Ordering::Relaxed) >> 8) & 255).checked_sub(1),
        })
    })
}
