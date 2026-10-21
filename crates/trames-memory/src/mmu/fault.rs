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
                if let Some(recovery) = super::access::recovery(*pc) {
                    if WINDOWS.iter().any(|slot| {
                        let base = slot.load(Ordering::Acquire);
                        base != 0 && address.wrapping_sub(base) < WINDOW
                    }) {
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

unsafe fn context_mask(context: *mut libc::c_void) -> *const libc::sigset_t {
    #[cfg(target_os = "linux")]
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    // SAFETY: Linux's SA_SIGINFO ucontext matches this target's libc ABI.
    unsafe {
        (&raw mut (*(context.cast::<libc::ucontext_t>())).uc_mcontext.gregs[libc::REG_RIP as usize])
            .cast()
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
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
