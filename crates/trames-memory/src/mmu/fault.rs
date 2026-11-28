// SPDX-License-Identifier: GPL-3.0-or-later
//! Recover only our exact scalar memory instructions inside a live arena.
use super::host::WINDOW;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    OnceLock,
};

const MAX_WINDOWS: usize = 32768;
static WINDOWS: [AtomicUsize; MAX_WINDOWS] = [const { AtomicUsize::new(0) }; MAX_WINDOWS];
static SEGV_RESET: AtomicBool = AtomicBool::new(false);
static BUS_RESET: AtomicBool = AtomicBool::new(false);
static STARTED: OnceLock<bool> = OnceLock::new();
struct Previous {
    segv: libc::sigaction,
    bus: libc::sigaction,
}
static PREVIOUS: OnceLock<Previous> = OnceLock::new();

pub(super) fn register(base: usize) -> Option<usize> {
    WINDOWS.iter().position(|slot| {
        slot.compare_exchange(0, base, Ordering::Release, Ordering::Relaxed)
            .is_ok()
    })
}
pub(super) fn unregister(slot: usize) {
    WINDOWS[slot].store(0, Ordering::Release);
}
pub(super) fn install() -> bool {
    *STARTED.get_or_init(|| {
        // SAFETY: zero initializes sigsets/unused union fields; sigaction fills
        // both saved dispositions before any arena or assembly access exists.
        unsafe {
            let (mut segv, mut bus): (libc::sigaction, libc::sigaction) = std::mem::zeroed();
            if libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut segv) != 0
                || libc::sigaction(libc::SIGBUS, std::ptr::null(), &mut bus) != 0
            {
                return false;
            }
            if PREVIOUS.set(Previous { segv, bus }).is_err() {
                return false;
            }
            let mut action: libc::sigaction = std::mem::zeroed();
            let previous = PREVIOUS.get().expect("saved signal dispositions");
            action.sa_flags = libc::SA_SIGINFO
                | libc::SA_ONSTACK
                | (previous.segv.sa_flags & (libc::SA_NODEFER | libc::SA_RESTART));
            action.sa_sigaction = handle as *const () as usize;
            action.sa_mask = previous.segv.sa_mask;
            if libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()) != 0 {
                return false;
            }
            action.sa_flags = libc::SA_SIGINFO
                | libc::SA_ONSTACK
                | (previous.bus.sa_flags & (libc::SA_NODEFER | libc::SA_RESTART));
            action.sa_mask = previous.bus.sa_mask;
            if libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut()) != 0 {
                libc::sigaction(
                    libc::SIGSEGV,
                    &PREVIOUS.get().unwrap().segv,
                    std::ptr::null_mut(),
                );
                return false;
            }
            true
        }
    })
}

extern "C" fn handle(signal: i32, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    // SAFETY: the kernel supplies this context and siginfo for SA_SIGINFO. No
    // allocation, Rust panic, locks, TLS, longjmp or unwinding occurs here.
    unsafe {
        if !info.is_null() && !context.is_null() && (*info).si_code > 0 {
            let address = (*info).si_addr() as usize;
            let pc = context_pc(context);
            if !pc.is_null() {
                let recovery = super::access::recovery(*pc);
                #[cfg(feature = "native-code")]
                let native = if recovery.is_none() {
                    crate::native_code::recovery(*pc)
                } else {
                    None
                };
                #[cfg(feature = "native-code")]
                let recovery = recovery.or_else(|| native.as_ref().map(|site| site.pc));
                if let Some(recovery) = recovery {
                    if WINDOWS.iter().any(|slot| {
                        let base = slot.load(Ordering::Acquire);
                        base != 0 && address.wrapping_sub(base) < WINDOW
                    }) {
                        #[cfg(feature = "native-code")]
                        if let Some(site) = native {
                            if let Some(register) = site.address {
                                *context_register(context, register) = address as u64;
                            }
                            if let Some(register) = site.access {
                                *context_register(context, register) =
                                    context_memory_access(context);
                            }
                        }
                        *pc = recovery;
                        return;
                    }
                }
            }
        }
        let Some(previous) = PREVIOUS.get() else {
            libc::_exit(128 + signal);
        };
        let old = if signal == libc::SIGBUS {
            &previous.bus
        } else {
            &previous.segv
        };
        if old.sa_sigaction == libc::SIG_IGN {
            return;
        }
        let reset = if signal == libc::SIGBUS {
            &BUS_RESET
        } else {
            &SEGV_RESET
        };
        let already_reset =
            old.sa_flags & libc::SA_RESETHAND != 0 && reset.swap(true, Ordering::Relaxed);
        if old.sa_sigaction == libc::SIG_DFL || already_reset {
            let mut default: libc::sigaction = std::mem::zeroed();
            default.sa_sigaction = libc::SIG_DFL;
            libc::sigemptyset(&mut default.sa_mask);
            libc::sigaction(signal, &default, std::ptr::null_mut());
            // A forwarding dispatcher may have blocked this signal. Unblock
            // before redelivery so Darwin/Linux cannot return with it pending.
            libc::sigaddset(&mut default.sa_mask, signal);
            libc::sigprocmask(libc::SIG_UNBLOCK, &default.sa_mask, std::ptr::null_mut());
            libc::raise(signal);
        } else {
            // Interposed signal dispatchers (including TSan) may invoke us with
            // their own mask. Establish the previous handler's POSIX mask from
            // the interrupted context, then restore our caller's mask on return.
            let mut saved: libc::sigset_t = std::mem::zeroed();
            libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut saved);
            let original = if context.is_null() {
                &raw const saved
            } else {
                context_mask(context)
            };
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            let maximum = if cfg!(target_vendor = "apple") {
                31
            } else {
                64
            };
            for number in 1..=maximum {
                if libc::sigismember(original, number) == 1
                    || libc::sigismember(&old.sa_mask, number) == 1
                {
                    libc::sigaddset(&mut mask, number);
                }
            }
            if old.sa_flags & libc::SA_NODEFER == 0 {
                libc::sigaddset(&mut mask, signal);
            }
            libc::sigprocmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
            if old.sa_flags & libc::SA_SIGINFO != 0 {
                let callback: extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) =
                    std::mem::transmute(old.sa_sigaction);
                callback(signal, info, context);
            } else {
                let callback: extern "C" fn(i32) = std::mem::transmute(old.sa_sigaction);
                callback(signal);
            }
            libc::sigprocmask(libc::SIG_SETMASK, &saved, std::ptr::null_mut());
        }
    }
}

#[cfg(feature = "native-code")]
unsafe fn context_register(context: *mut libc::c_void, register: usize) -> *mut u64 {
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    unsafe {
        (&raw mut (*context.cast::<libc::ucontext_t>()).uc_mcontext.regs[register]).cast()
    }
    #[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
    unsafe {
        let context = &mut *context.cast::<DarwinContext>();
        // context_pc already validated the same machine pointer and size.
        &raw mut (*context.machine).x[register]
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (context, register);
        std::ptr::null_mut()
    }
}

// Optional kernel ESR metadata is consumed only after an exact registered
// native PC and owned fault VA match. No TLS, allocation or extension-state copy.
#[cfg(feature = "native-code")]
unsafe fn context_memory_access(context: *mut libc::c_void) -> u64 {
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    unsafe {
        // Linux UAPI struct sigcontext: 35 u64 fields, then 16-byte alignment
        // and __reserved[4096]. ESR must be in this first reserved area, never
        // in an extra-context allocation. Bionic/glibc expose different names.
        let machine = &raw const (*context.cast::<libc::ucontext_t>()).uc_mcontext;
        let records = std::slice::from_raw_parts(machine.cast::<u8>().add(288), 4096);
        esr_access(records)
    }
    #[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
    unsafe {
        let machine = (*context.cast::<DarwinContext>()).machine;
        let esr = std::ptr::read_unaligned((*machine).exception.as_ptr().add(8).cast::<u32>());
        u64::from((esr >> 6) & 1)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = context;
        2
    }
}
#[cfg(all(
    feature = "native-code",
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "aarch64", test)
))]
fn esr_access(records: &[u8]) -> u64 {
    let mut offset = 0;
    while offset + 16 <= records.len() {
        let magic = u32::from_ne_bytes(records[offset..offset + 4].try_into().unwrap());
        let size = u32::from_ne_bytes(records[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if size < 16 || !size.is_multiple_of(16) || size > records.len() - offset {
            break;
        }
        if magic == 0x45535201 {
            let esr = u64::from_ne_bytes(records[offset + 8..offset + 16].try_into().unwrap());
            return (esr >> 6) & 1;
        }
        offset += size;
    }
    2
}

unsafe fn context_mask(context: *mut libc::c_void) -> *const libc::sigset_t {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: same kernel-provided ucontext as context_pc; passing its address
    // avoids reading unused platform sigset padding as initialized Rust values.
    unsafe {
        &raw const (*context.cast::<libc::ucontext_t>()).uc_sigmask
    }
    #[cfg(target_vendor = "apple")]
    unsafe {
        &raw const (*context.cast::<DarwinContext>()).mask
    }
}

unsafe fn context_pc(context: *mut libc::c_void) -> *mut usize {
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "x86_64"
    ))]
    // SAFETY: Linux's SA_SIGINFO ucontext matches this target's libc ABI.
    unsafe {
        (&raw mut (*(context.cast::<libc::ucontext_t>())).uc_mcontext.gregs[libc::REG_RIP as usize])
            .cast()
    }
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    unsafe {
        (&raw mut (*(context.cast::<libc::ucontext_t>())).uc_mcontext.pc).cast()
    }
    #[cfg(target_vendor = "apple")]
    // Public Darwin ucontext/mcontext prefixes. arm64e is not a build target;
    // the x86_64 layout permits native development/CI on Intel Macs.
    unsafe {
        let context = &mut *context.cast::<DarwinContext>();
        if context.machine.is_null() || context.size < std::mem::size_of::<DarwinMachine>() {
            return std::ptr::null_mut();
        }
        (&raw mut (*context.machine).pc).cast()
    }
}
#[cfg(target_vendor = "apple")]
#[repr(C)]
struct DarwinContext {
    onstack: i32,
    mask: libc::sigset_t,
    stack: libc::stack_t,
    link: *mut libc::c_void,
    size: usize,
    machine: *mut DarwinMachine,
}
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[repr(C)]
struct DarwinMachine {
    exception: [u8; 16],
    x: [u64; 29],
    fp: u64,
    lr: u64,
    sp: u64,
    pc: u64,
    cpsr: u32,
    padding: u32,
}

#[cfg(all(target_vendor = "apple", target_arch = "x86_64"))]
#[repr(C)]
struct DarwinMachine {
    exception: [u8; 16],
    registers: [u64; 16],
    pc: u64,
    flags: u64,
    cs: u64,
    fs: u64,
    gs: u64,
}

#[cfg(all(
    test,
    feature = "native-code",
    any(target_os = "linux", target_os = "android")
))]
mod esr_tests {
    use super::esr_access;
    #[test]
    fn optional_esr_metadata_accepts_real_record_order_and_bounds() {
        let mut records = [0u8; 64];
        records[..4].copy_from_slice(&0x46508001u32.to_ne_bytes());
        records[4..8].copy_from_slice(&32u32.to_ne_bytes());
        records[32..36].copy_from_slice(&0x45535201u32.to_ne_bytes());
        records[36..40].copy_from_slice(&16u32.to_ne_bytes());
        assert_eq!(esr_access(&records), 0);
        records[40..48].copy_from_slice(&64u64.to_ne_bytes());
        assert_eq!(esr_access(&records), 1);
        for size in [0u32, 8, 17, 80, u32::MAX] {
            records[4..8].copy_from_slice(&size.to_ne_bytes());
            assert_eq!(esr_access(&records), 2);
        }
        assert_eq!(esr_access(&[]), 2);
    }
}
