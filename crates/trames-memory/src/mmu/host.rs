// SPDX-License-Identifier: GPL-3.0-or-later
//! Separate physical RAM and protected CPU views; neither is executable.
use std::{
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

// Sparse Go heaps/libraries and retained fork slots must not reserve 32MiB
// for every small live range. Still a power of two and >= any host granule.
pub(super) const WINDOW: usize = 1024 * 1024;
// Physical storage, coordinator views and retained fork/worker CPU aliases all
// consume this virtual budget. A 4 GiB guest can need many GiB of aliases
// without duplicating its resident RAM. Keep a bounded VA ceiling without
// forcing large multi-process workloads onto software memory access.
const MAX_VIRTUAL_BYTES: usize = 32 * 1024 * 1024 * 1024;
struct Budget {
    used: AtomicUsize,
    limit: usize,
}
impl Budget {
    const fn new(limit: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            limit,
        }
    }
    fn acquire(&'static self) -> Option<Reservation> {
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(WINDOW).filter(|&next| next <= self.limit)
            })
            .ok()?;
        Some(Reservation(self))
    }
}
static BUDGET: Budget = Budget::new(MAX_VIRTUAL_BYTES);
struct Reservation(&'static Budget);
impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.used.fetch_sub(WINDOW, Ordering::Relaxed);
    }
}

/// Physical owners retain only RW storage. Fork/worker slot ownership cannot
/// keep an unused CPU reservation alive.
pub(crate) struct Mapping {
    pub kernel: NonNull<u8>,
    _reservation: Reservation,
}
// SAFETY: immutable ownership; byte access needs the coordinator borrow or
// worker region guard. This handle alone grants no byte references.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

/// Frozen workers reserve only CPU VA; their frames own the actual source RAM.
pub(super) struct CpuMapping {
    pub cpu: NonNull<u8>,
    registration: usize,
    _reservation: Reservation,
}
// SAFETY: frozen views outlive workers and are edited only after join.
unsafe impl Send for CpuMapping {}
unsafe impl Sync for CpuMapping {}

pub(super) fn page_size() -> Option<usize> {
    // SAFETY: sysconf has no pointer arguments or memory side effects.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let size = usize::try_from(size).ok()?;
    (size.is_power_of_two() && (4096..=65536).contains(&size)).then_some(size)
}
impl Mapping {
    pub fn new() -> Option<Self> {
        Self::with_budget(&BUDGET)
    }
    fn with_budget(budget: &'static Budget) -> Option<Self> {
        let reservation = budget.acquire()?;
        // SAFETY: kernel-selected RW VA, never executable or fixed over host
        // allocations. Failed setup releases the FD and reservation budget.
        let kernel = unsafe {
            #[cfg(target_os = "linux")]
            {
                let fd = libc::memfd_create(c"trames-ram".as_ptr(), libc::MFD_CLOEXEC);
                if fd < 0 {
                    return None;
                }
                if libc::ftruncate(fd, WINDOW as libc::off_t) != 0 {
                    libc::close(fd);
                    return None;
                }
                let kernel = libc::mmap(
                    std::ptr::null_mut(),
                    WINDOW,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                );
                libc::close(fd);
                kernel
            }
            #[cfg(target_vendor = "apple")]
            {
                libc::mmap(
                    std::ptr::null_mut(),
                    WINDOW,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            }
        };
        if kernel == libc::MAP_FAILED {
            return None;
        }
        let Some(kernel) = NonNull::new(kernel.cast()) else {
            // SAFETY: successful but unusable zero-address mapping.
            unsafe {
                libc::munmap(kernel, WINDOW);
            }
            return None;
        };
        Some(Self {
            kernel,
            _reservation: reservation,
        })
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: final physical owner; every page/slot reference is gone.
        unsafe {
            libc::munmap(self.kernel.as_ptr().cast(), WINDOW);
        }
    }
}
impl CpuMapping {
    pub fn new() -> Option<Self> {
        Self::with_budget(&BUDGET)
    }
    fn with_budget(budget: &'static Budget) -> Option<Self> {
        let reservation = budget.acquire()?;
        if !super::fault::install() {
            return None;
        }
        // SAFETY: fresh inaccessible, non-executable VA owns no physical guest
        // bytes. Only alias() replaces subranges of this reservation.
        unsafe {
            let cpu = libc::mmap(
                std::ptr::null_mut(),
                WINDOW,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            );
            if cpu == libc::MAP_FAILED {
                return None;
            }
            let Some(pointer) = NonNull::new(cpu.cast()) else {
                libc::munmap(cpu, WINDOW);
                return None;
            };
            let Some(registration) = super::fault::register(cpu as usize) else {
                libc::munmap(cpu, WINDOW);
                return None;
            };
            Some(Self {
                cpu: pointer,
                registration,
                _reservation: reservation,
            })
        }
    }
    /// Replace only owned CPU VA with a view of retained physical RAM.
    /// Source ownership stays in coordinator/frozen frames, never a raw lease.
    pub fn alias(&self, offset: usize, source: &Mapping, source_offset: usize, len: usize) -> bool {
        debug_assert!(offset <= WINDOW && len <= WINDOW - offset);
        debug_assert!(source_offset <= WINDOW && len <= WINDOW - source_offset);
        // SAFETY: fixed replacement stays inside our reservation. Linux
        // old_size=0 duplicates a MAP_SHARED source without moving its storage.
        unsafe {
            let target = self.cpu.as_ptr().add(offset).cast::<libc::c_void>();
            let source = source
                .kernel
                .as_ptr()
                .add(source_offset)
                .cast::<libc::c_void>();
            #[cfg(target_os = "linux")]
            let ok = libc::mremap(
                source,
                0,
                len,
                libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
                target,
            ) == target;
            #[cfg(target_vendor = "apple")]
            let ok = {
                let mut address = target as u64;
                let (mut current, mut maximum) = (0, 0);
                mach_vm_remap(
                    mach_task_self_,
                    &mut address,
                    len as u64,
                    0,
                    0x4000,
                    mach_task_self_,
                    source as u64,
                    0,
                    &mut current,
                    &mut maximum,
                    2,
                ) == 0
                    && address == target as u64
            };
            ok
        }
    }
    pub fn protect(&self, offset: usize, len: usize, permissions: i32) -> bool {
        debug_assert!(offset <= WINDOW && len <= WINDOW - offset);
        // SAFETY: host-page-aligned, owned CPU VA only; physical storage and
        // unrelated host mappings retain their existing permissions.
        unsafe { libc::mprotect(self.cpu.as_ptr().add(offset).cast(), len, permissions) == 0 }
    }
}
impl Drop for CpuMapping {
    fn drop(&mut self) {
        super::fault::unregister(self.registration);
        // SAFETY: joined/retired CPU view; TLBs/descriptor caches are cleared.
        unsafe {
            libc::munmap(self.cpu.as_ptr().cast(), WINDOW);
        }
    }
}
#[cfg(target_vendor = "apple")]
unsafe extern "C" {
    static mach_task_self_: libc::mach_port_t;
    fn mach_vm_remap(
        target: libc::mach_port_t,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        source: libc::mach_port_t,
        source_address: u64,
        copy: i32,
        current: *mut i32,
        maximum: *mut i32,
        inheritance: i32,
    ) -> i32;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_cpu_aliases_do_not_exhaust_a_one_gib_guest_workload() {
        // A physical window, its coordinator alias and a retained fork alias
        // already need 3 GiB of VA for 1 GiB of guest RAM. These inaccessible
        // CPU reservations allocate no guest storage and must stay eligible
        // beyond the old combined 1 GiB / 2048-registration limits.
        let views: Vec<_> = (0..2050)
            .map(|_| CpuMapping::new().expect("CPU VA capacity"))
            .collect();
        assert_eq!(views.len(), 2050);
    }
    #[test]
    fn physical_and_cpu_reservations_are_separate_bounded_and_released() {
        static BUDGET: Budget = Budget::new(3 * WINDOW);
        let physical = Mapping::with_budget(&BUDGET).unwrap();
        let cpu = CpuMapping::with_budget(&BUDGET).unwrap();
        assert_eq!(BUDGET.used.load(Ordering::Relaxed), 2 * WINDOW);
        assert!(cpu.alias(0, &physical, 0, WINDOW));
        assert!(cpu.protect(0, WINDOW, libc::PROT_READ));
        // SAFETY: private in-bounds storage and its live readable CPU alias.
        unsafe {
            physical.kernel.as_ptr().write(42);
            assert_eq!(cpu.cpu.as_ptr().read(), 42);
        }
        let extra = Mapping::with_budget(&BUDGET).unwrap();
        assert!(Mapping::with_budget(&BUDGET).is_none());
        assert!(CpuMapping::with_budget(&BUDGET).is_none());
        drop(cpu);
        assert_eq!(BUDGET.used.load(Ordering::Relaxed), 2 * WINDOW);
        // SAFETY: retiring a CPU view leaves the physical owner and bytes live.
        assert_eq!(unsafe { physical.kernel.as_ptr().read() }, 42);
        drop(extra);
        drop(physical);
        assert_eq!(BUDGET.used.load(Ordering::Relaxed), 0);
        assert!(CpuMapping::with_budget(&BUDGET).is_some());
        assert_eq!(BUDGET.used.load(Ordering::Relaxed), 0);
    }
}
