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
    fn kill(pid: i32, signal: i32) -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn write(fd: i32, data: *const std::ffi::c_void, len: usize) -> isize;
    fn read(fd: i32, data: *mut std::ffi::c_void, len: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn execv(path: *const std::ffi::c_char, argv: *const *const std::ffi::c_char) -> i32;
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

fn observe_group_continue(continue_before_listen: bool) {
    const SIGCONT: i32 = 18;
    const SIGSTOP: i32 = 19;
    const SEIZE: i32 = 0x4206;
    const LISTEN: i32 = 0x4208;
    const DETACH: i32 = 17;
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        assert_eq!(unsafe { raise(SIGSTOP) }, 0);
        unsafe { _exit(42) }
    }
    let mut status = 0;
    assert_eq!(unsafe { waitpid(child, &mut status, 2) }, child);
    assert_eq!(status, 0x137f);
    assert_eq!(trace(SEIZE, child, 0), 0);
    assert_eq!(wait(child), 0x80137f);
    if continue_before_listen {
        assert_eq!(unsafe { kill(child, SIGCONT) }, 0);
    }
    assert_eq!(trace(LISTEN, child, 0), 0);
    if !continue_before_listen {
        assert_eq!(unsafe { kill(child, SIGCONT) }, 0);
    }
    assert_eq!(wait(child), 0x80057f);
    assert_eq!(trace(DETACH, child, 0), 0);
    assert_eq!(wait(child), 42 << 8);
    println!(
        "group continued and child reaped (continue before listen = {continue_before_listen})"
    );
}

fn observe_vfork_done() {
    let mut channel = [-1; 2];
    assert_eq!(unsafe { pipe(channel.as_mut_ptr()) }, 0);
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe { close(channel[0]) };
        let block_chld = 1u64 << 16;
        assert_eq!(
            unsafe { syscall(135, 0usize, &block_chld, 0usize, 8usize) },
            0
        );
        assert_eq!(trace(0, 0, 0), 0);
        assert_eq!(unsafe { raise(19) }, 0);
        for exec in [false, true] {
            // CLONE_VFORK | SIGCHLD uses a private stack while exercising the
            // same mm-release wait as libc vfork. The child runs to exit or exec.
            let id = unsafe { syscall(220, 0x4011usize, 0usize, 0usize, 0usize, 0usize) } as i32;
            assert!(id >= 0);
            if id == 0 {
                if exec {
                    let path = c"/bin/true".as_ptr();
                    unsafe { execv(path, [path, ptr::null()].as_ptr()) };
                    unsafe { _exit(99) }
                }
                unsafe { _exit(37) }
            }
            assert_eq!(
                unsafe { write(channel[1], id.to_ne_bytes().as_ptr().cast(), 4) },
                4
            );
            assert_eq!(wait(id), if exec { 0 } else { 37 << 8 });
        }
        unsafe { _exit(0) }
    }
    unsafe { close(channel[1]) };
    assert_eq!(wait(child), 0x137f);
    assert_eq!(trace(0x4200, child, (1 << 5) | 1), 0);
    assert_eq!(trace(7, child, 0), 0);
    for exec in [false, true] {
        assert_eq!(wait(child), 0x5057f);
        let mut pid = 0usize;
        assert_eq!(trace(0x4201, child, ptr::addr_of_mut!(pid) as usize), 0);
        assert!(pid > 0);
        assert_eq!(trace(24, child, 0), 0); // PTRACE_SYSCALL
        assert_eq!(wait(child), 0x857f);
        let mut info = [0u8; 88];
        let size = unsafe { ptrace(0x420e, child, info.len(), info.as_mut_ptr()) };
        assert!(size >= 33);
        assert_eq!(info[0], 2); // PTRACE_SYSCALL_INFO_EXIT
        assert_eq!(
            i64::from_ne_bytes(info[24..32].try_into().unwrap()),
            pid as i64
        );
        assert_eq!(trace(7, child, 0), 0);
        let mut reported = [0; 4];
        assert_eq!(
            unsafe { read(channel[0], reported.as_mut_ptr().cast(), 4) },
            4
        );
        assert_eq!(pid, i32::from_ne_bytes(reported) as usize);
        println!(
            "vfork done after {} with guest PID {pid}",
            if exec { "exec" } else { "exit" }
        );
    }
    assert_eq!(wait(child), 0);
    unsafe { close(channel[0]) };
}

fn observe_thread_traceme() {
    let mut channel = [-1; 2];
    assert_eq!(unsafe { pipe(channel.as_mut_ptr()) }, 0);
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe { close(channel[0]) };
        std::thread::spawn(move || {
            let tid = unsafe { syscall(178) } as i32;
            assert_eq!(trace(0, 0, 0), 0);
            assert_eq!(
                unsafe { write(channel[1], tid.to_ne_bytes().as_ptr().cast(), 4) },
                4
            );
            assert_eq!(unsafe { raise(19) }, 0);
        })
        .join()
        .unwrap();
        unsafe { _exit(42) }
    }
    unsafe { close(channel[1]) };
    let mut data = [0; 4];
    assert_eq!(unsafe { read(channel[0], data.as_mut_ptr().cast(), 4) }, 4);
    let tid = i32::from_ne_bytes(data);
    assert_ne!(tid, child);
    assert_eq!(wait(tid), 0x137f);
    assert_eq!(trace(7, tid, 0), 0);
    assert_eq!(wait(tid), 0);
    assert_eq!(wait(child), 42 << 8);
    unsafe { close(channel[0]) };
    println!("nonleader TRACEME stopped and reaped independently from process {child}");
}

fn observe_clone() {
    let mut channel = [-1; 2];
    assert_eq!(unsafe { pipe(channel.as_mut_ptr()) }, 0);
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe { close(channel[0]) };
        assert_eq!(trace(0, 0, 0), 0);
        assert_eq!(unsafe { raise(19) }, 0);
        std::thread::spawn(move || {
            let tid = unsafe { syscall(178) } as i32;
            assert_eq!(
                unsafe { write(channel[1], tid.to_ne_bytes().as_ptr().cast(), 4) },
                4
            );
        })
        .join()
        .unwrap();
        unsafe { _exit(42) }
    }
    unsafe { close(channel[1]) };
    assert_eq!(wait(child), 0x137f);
    assert_eq!(trace(0x4200, child, 1 << 3), 0);
    assert_eq!(trace(7, child, 0), 0);
    assert_eq!(wait(child), 0x3057f);
    let mut tid = 0usize;
    assert_eq!(trace(0x4201, child, ptr::addr_of_mut!(tid) as usize), 0);
    assert!(tid > 0 && tid != child as usize);
    assert_eq!(wait(tid as i32), 0x137f);
    assert_eq!(trace(7, child, 0), 0);
    assert_eq!(trace(7, tid as i32, 0), 0);
    let mut actual = [0; 4];
    assert_eq!(
        unsafe { read(channel[0], actual.as_mut_ptr().cast(), 4) },
        4
    );
    assert_eq!(i32::from_ne_bytes(actual), tid as i32);
    assert_eq!(wait(tid as i32), 0);
    assert_eq!(wait(child), 42 << 8);
    unsafe { close(channel[0]) };
    println!("observed distinct thread {tid} and process {child} exits");
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

#[unsafe(naked)]
unsafe extern "C" fn step_program() -> ! {
    std::arch::naked_asm!(
        "mov x19, #41",
        "add x19, x19, #1",
        "ldr x21, [x20]",
        "str x19, [x20]",
        "mov x8, #172",
        "svc #0",
        "brk #0",
        "mov x0, #42",
        "mov x8, #93",
        "svc #0"
    )
}

fn registers(pid: i32, write: bool, regs: &mut [u64; 34]) {
    let iov = [regs.as_mut_ptr() as usize, std::mem::size_of_val(regs)];
    assert_eq!(
        unsafe {
            ptrace(
                if write { 0x4205 } else { 0x4204 },
                pid,
                1usize,
                iov.as_ptr(),
            )
        },
        0
    );
}

static STEP_DATA: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(77);

fn modify_and_step() {
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        assert_eq!(trace(0, 0, 0), 0);
        assert_eq!(unsafe { raise(19) }, 0);
        unsafe { _exit(99) }
    }
    assert_eq!(wait(child), 0x137f);
    let pc = step_program as *const () as u64;
    let mut regs = [0; 34];
    registers(child, false, &mut regs);
    regs[32] = pc;
    regs[20] = STEP_DATA.as_ptr() as u64;
    registers(child, true, &mut regs);
    // Replace RX text in the child. The debugger's private text must retain 41.
    let word = 0x91000673_d2800513u64;
    assert_eq!(unsafe { ptrace(4, child, pc, word) }, 0);
    assert_eq!(unsafe { ptrace(1, child, pc, 0usize) } as u64, word);
    assert_eq!(unsafe { *(pc as *const u32) }, 0xd2800533);
    for (i, value) in [(1, 40), (2, 41), (3, 41), (4, 41), (5, 41), (6, 41)] {
        assert_eq!(trace(9, child, 0), 0);
        assert_eq!(wait(child), 0x57f);
        registers(child, false, &mut regs);
        assert_eq!(regs[32], pc + i * 4);
        assert_eq!(regs[19], value);
        if i >= 3 {
            assert_eq!(regs[21], 77);
        }
        if i == 6 {
            assert_eq!(regs[0], child as u64);
        }
        let mut info = [0u8; 128];
        assert_eq!(trace(0x4202, child, info.as_mut_ptr() as usize), 0);
        assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), 2);
    }
    assert_eq!(trace(7, child, 0), 0);
    assert_eq!(wait(child), 0x57f);
    registers(child, false, &mut regs);
    assert_eq!(regs[32], pc + 24);
    regs[32] += 4;
    registers(child, true, &mut regs);
    assert_eq!(trace(7, child, 0), 0);
    assert_eq!(wait(child), 42 << 8);
    assert_eq!(STEP_DATA.load(Ordering::Relaxed), 77);
    println!("modified RX text and registers; stepped ALU, memory and syscall; recovered BRK");
}

static HANDLED: AtomicU32 = AtomicU32::new(0);

extern "C" fn handle_signal(_: i32) {
    HANDLED.fetch_add(1, Ordering::Relaxed);
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("traceme-thread") {
        observe_thread_traceme();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("modify") {
        modify_and_step();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("clone") {
        observe_clone();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("vfork-done") {
        observe_vfork_done();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("listen") {
        observe_group_continue(true);
        observe_group_continue(false);
        return;
    }
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
