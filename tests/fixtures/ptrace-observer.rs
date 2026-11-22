// SPDX-License-Identifier: GPL-3.0-or-later
//! ARM64 Linux guest fixture for exit events and external syscall observers.
use std::{
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};

unsafe extern "C" {
    fn ptrace(request: i32, ...) -> i64;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn raise(signal: i32) -> i32;
    fn signal(number: i32, handler: extern "C" fn(i32)) -> usize;
    fn syscall(number: i64, ...) -> i64;
    fn _exit(code: i32) -> !;
}

fn trace(request: i32, pid: i32, data: usize) -> i64 {
    unsafe { ptrace(request, pid, 0usize, data) }
}

fn wait(pid: i32) -> i32 {
    let mut status = 0;
    assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
    status
}

fn observe_exit(mode: i32, expected: i32) {
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        assert_eq!(trace(0, 0, 0), 0); // TRACEME
        assert_eq!(unsafe { raise(19) }, 0); // SIGSTOP
        unsafe {
            match mode {
                0 => {
                    syscall(93, 37usize);
                } // exit
                1 => {
                    syscall(94, 38usize);
                } // exit_group
                _ => {
                    raise(9);
                } // self-directed SIGKILL
            }
            _exit(77)
        }
    }
    assert_eq!(wait(child), 0x137f);
    assert_eq!(trace(0x4200, child, 64), 0); // SETOPTIONS(TRACEEXIT)
    assert_eq!(trace(7, child, 0), 0); // CONT
    assert_eq!(wait(child), 0x6057f); // PTRACE_EVENT_EXIT, before reaping
    let mut message = usize::MAX;
    assert_eq!(trace(0x4201, child, ptr::addr_of_mut!(message) as usize), 0);
    assert_eq!(message, expected as usize);
    assert_eq!(trace(7, child, 0), 0);
    assert_eq!(wait(child), expected);
    println!("mode {mode} event 6 message {message}, reaped");
}

static HANDLED: AtomicU32 = AtomicU32::new(0);

extern "C" fn handle_signal(_: i32) {
    HANDLED.fetch_add(1, Ordering::Relaxed);
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("signal") {
        assert_ne!(unsafe { signal(10, handle_signal) }, usize::MAX);
        for expected in 1..=2 {
            assert_eq!(unsafe { raise(10) }, 0);
            assert_eq!(HANDLED.load(Ordering::Relaxed), expected);
        }
        println!("handled both signals");
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("workload") {
        assert_eq!(unsafe { syscall(57, -1i32) }, -1); // close(-1)
        let delay = [0i64, 3_000_000];
        assert_eq!(
            unsafe { syscall(101, delay.as_ptr(), ptr::null_mut::<i64>()) },
            0
        );
        println!("completed");
        return;
    }
    for (mode, expected) in [(0, 37 << 8), (1, 38 << 8), (2, 9)] {
        observe_exit(mode, expected);
    }
}
