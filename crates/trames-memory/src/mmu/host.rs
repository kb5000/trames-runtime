// SPDX-License-Identifier: GPL-3.0-or-later
//! Two aliases of anonymous RAM. Neither alias is executable host memory.
use std::ptr::NonNull;

pub(super) const WINDOW: usize = 16 * 1024 * 1024;

pub(crate) struct Mapping {
    pub cpu: NonNull<u8>,
    pub kernel: NonNull<u8>,
    pub registration: usize,
}
// SAFETY: ownership is immutable, mappings remain until the final owner drops.
// Byte access requires the coordinator borrow or worker region guards. Merely
// owning this handle grants no Rust reference or permission to access bytes.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

pub(super) fn page_size() -> Option<usize> {
    // SAFETY: sysconf has no pointer arguments and no memory side effects.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let size = usize::try_from(size).ok()?;
    (size.is_power_of_two() && (4096..=65536).contains(&size)).then_some(size)
}

impl Mapping {
    /// Replace a range of our CPU alias with a shared view of an existing RAM
    /// object. Source ownership stays in the frozen frames, never a raw lease.
    pub fn alias(&self, offset: usize, source: &Mapping, source_offset: usize, len: usize) -> bool {
        debug_assert!(offset <= WINDOW && len <= WINDOW - offset);
        debug_assert!(source_offset <= WINDOW && len <= WINDOW - source_offset);
        // SAFETY: fixed replacement is restricted to our reserved CPU range.
        // Linux old_size=0 duplicates a MAP_SHARED view instead of moving it.
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
    pub fn new() -> Option<Self> {
        if !super::fault::install() {
            return None;
        }
        // SAFETY: all mappings use kernel-selected addresses, never MAP_FIXED
        // over application allocations. Each success is cleaned up on failure.
        unsafe {
            #[cfg(target_os = "linux")]
            let (cpu, kernel) = {
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
                let cpu = libc::mmap(
                    std::ptr::null_mut(),
                    WINDOW,
                    libc::PROT_NONE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                );
                libc::close(fd);
                (cpu, kernel)
            };
            #[cfg(target_vendor = "apple")]
            let (cpu, kernel) = {
                let kernel = libc::mmap(
                    std::ptr::null_mut(),
                    WINDOW,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                );
                let cpu = libc::mmap(
                    std::ptr::null_mut(),
                    WINDOW,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                );
                if kernel != libc::MAP_FAILED && cpu != libc::MAP_FAILED {
                    let mut address = cpu as u64;
                    let (mut current, mut maximum) = (0, 0);
                    let task = mach_task_self_;
                    if mach_vm_remap(
                        task,
                        &mut address,
                        WINDOW as u64,
                        0,
                        0x4000,
                        task,
                        kernel as u64,
                        0,
                        &mut current,
                        &mut maximum,
                        2,
                    ) != 0
                        || address != cpu as u64
                        || libc::mprotect(cpu, WINDOW, libc::PROT_NONE) != 0
                    {
                        libc::munmap(cpu, WINDOW);
                        libc::munmap(kernel, WINDOW);
                        return None;
                    }
                }
                (cpu, kernel)
            };
            if cpu == libc::MAP_FAILED || kernel == libc::MAP_FAILED {
                if cpu != libc::MAP_FAILED {
                    libc::munmap(cpu, WINDOW);
                }
                if kernel != libc::MAP_FAILED {
                    libc::munmap(kernel, WINDOW);
                }
                return None;
            }
            let Some(registration) = super::fault::register(cpu as usize) else {
                libc::munmap(cpu, WINDOW);
                libc::munmap(kernel, WINDOW);
                return None;
            };
            Some(Self {
                cpu: NonNull::new_unchecked(cpu.cast()),
                kernel: NonNull::new_unchecked(kernel.cast()),
                registration,
            })
        }
    }
    pub fn protect(&self, offset: usize, len: usize, permissions: i32) -> bool {
        debug_assert!(offset <= WINDOW && len <= WINDOW - offset);
        // SAFETY: callers provide host-page-aligned ranges within our owned
        // CPU alias. The kernel alias and unrelated host allocations are intact.
        unsafe { libc::mprotect(self.cpu.as_ptr().add(offset).cast(), len, permissions) == 0 }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        super::fault::unregister(self.registration);
        // SAFETY: final ownership; no pointer, slice or worker survives this.
        unsafe {
            libc::munmap(self.cpu.as_ptr().cast(), WINDOW);
            libc::munmap(self.kernel.as_ptr().cast(), WINDOW);
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
