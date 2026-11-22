// SPDX-License-Identifier: GPL-3.0-or-later
//! Standalone AArch64 Linux proc-memory and guest-only Yama conformance fixture.
use std::{
    ffi::{c_char, c_void},
    ptr,
};
unsafe extern "C" {
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn preadv(fd: i32, iov: *const Iovec, count: i32, offset: i64) -> isize;
    fn pwritev(fd: i32, iov: *const Iovec, count: i32, offset: i64) -> isize;
    fn read(fd: i32, out: *mut c_void, n: usize) -> isize;
    fn write(fd: i32, data: *const c_void, n: usize) -> isize;
    fn pread(fd: i32, out: *mut c_void, n: usize, at: i64) -> isize;
    fn pwrite(fd: i32, data: *const c_void, n: usize, at: i64) -> isize;
    fn lseek(fd: i32, at: i64, whence: i32) -> i64;
    fn mmap(at: *mut c_void, n: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void;
    fn mprotect(at: *mut c_void, n: usize, prot: i32) -> i32;
    fn munmap(at: *mut c_void, n: usize) -> i32;
    fn getpagesize() -> i32;
    fn fork() -> i32;
    fn getppid() -> i32;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn ptrace(request: i32, ...) -> i64;
    fn prctl(option: i32, ...) -> i32;
    fn capget(header: *mut u32, data: *mut u32) -> i32;
    fn capset(header: *const u32, data: *const u32) -> i32;
    fn execv(path: *const c_char, args: *const *const c_char) -> i32;
    fn __errno_location() -> *mut i32;
    fn _exit(code: i32) -> !;
}
#[repr(C)]
struct Iovec {
    base: *mut c_void,
    len: usize,
}

fn errno() -> i32 {
    unsafe { *__errno_location() }
}
fn fd(path: &str, flags: i32) -> i32 {
    let s = std::ffi::CString::new(path).unwrap();
    let f = unsafe { open(s.as_ptr(), flags, 0o700) };
    assert!(f >= 0, "open {path}: {}", errno());
    f
}
fn page() -> usize {
    unsafe { getpagesize() as usize }
}
fn map(n: usize, flags: i32, fd: i32) -> usize {
    let at = unsafe { mmap(ptr::null_mut(), n, 3, flags, fd, 0) };
    assert_ne!(at as isize, -1, "mmap: {}", errno());
    at as usize
}
fn protect(at: usize, n: usize, prot: i32) {
    assert_eq!(unsafe { mprotect(at as *mut _, n, prot) }, 0);
}
fn load(mem: i32, at: usize, n: usize) -> Vec<u8> {
    let mut out = vec![0; n];
    assert_eq!(
        unsafe { pread(mem, out.as_mut_ptr().cast(), n, at as i64) },
        n as isize,
        "pread: {}",
        errno()
    );
    out
}
fn store(mem: i32, at: usize, data: &[u8]) -> isize {
    unsafe { pwrite(mem, data.as_ptr().cast(), data.len(), at as i64) }
}
fn failed(result: isize, error: i32) {
    assert_eq!(result, -1);
    assert_eq!(errno(), error);
}
fn done_map(at: usize, n: usize) {
    assert_eq!(unsafe { munmap(at as *mut _, n) }, 0);
}
fn permissions(at: usize) -> String {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let mut range = fields.next().unwrap().split('-');
        let start = usize::from_str_radix(range.next().unwrap(), 16).unwrap();
        let end = usize::from_str_radix(range.next().unwrap(), 16).unwrap();
        if at >= start && at < end {
            return fields.next().unwrap().into();
        }
    }
    panic!("missing mapping {at:x}")
}
fn protection_and_files() {
    let p = page();
    let mem = fd("/proc/self/mem", 2);
    let at = map(2 * p, 0x22, -1);
    let data: Vec<_> = (0..2 * p).map(|i| (i % 251) as u8).collect();
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), at as *mut u8, data.len());
    }
    protect(at, 2 * p, 0);
    assert_eq!(load(mem, at, 2 * p), data);
    assert_eq!(store(mem, at + p - 2, b"force"), 5);
    assert_eq!(load(mem, at + p - 2, 5), b"force");
    assert!(permissions(at).starts_with("---"));
    done_map(at, 2 * p);
    let at = map(p, 0x21, -1);
    unsafe {
        *(at as *mut u8) = 17;
    }
    protect(at, p, 1);
    assert_eq!(load(mem, at, 1), [17]);
    failed(store(mem, at, b"x"), 5);
    done_map(at, p);
    let path = format!("/tmp/proc-mem-{}", std::process::id());
    let f = fd(&path, 2 | 0x40 | 0x200);
    let data = vec![0x39; p];
    assert_eq!(unsafe { write(f, data.as_ptr().cast(), p) }, p as isize);
    let private = map(p, 2, f);
    protect(private, p, 4);
    assert_eq!(load(mem, private, 8), data[..8]);
    assert_eq!(store(mem, private, b"private"), 7);
    assert_eq!(load(mem, private, 7), b"private");
    assert_eq!(load(f, 0, 7), data[..7]);
    assert!(permissions(private).starts_with("--x"));
    let shared = map(p, 1, f);
    protect(shared, p, 0);
    assert_eq!(load(mem, shared, 8), data[..8]);
    failed(store(mem, shared, b"x"), 5);
    protect(shared, p, 3);
    assert_eq!(store(mem, shared, b"shared"), 6);
    assert_eq!(load(f, 0, 6), b"shared");
    assert_eq!(unsafe { pwrite(f, b"live".as_ptr().cast(), 4, 8) }, 4);
    assert_eq!(load(mem, shared + 8, 4), b"live");
    done_map(private, p);
    done_map(shared, p);
    unsafe {
        close(mem);
        close(f);
    };
    std::fs::remove_file(path).unwrap();
    println!("PASS force protections, private-file COW and live shared-file mappings");
}
fn partial_and_large() {
    let p = page();
    let mem = fd("/proc/self/mem", 2);
    let at = map(2 * p, 0x22, -1);
    done_map(at + p, p);
    protect(at, p, 0);
    assert_eq!(store(mem, at + p - 1, b"ab"), 1);
    let mut out = vec![0; p];
    assert_eq!(
        unsafe { pread(mem, out.as_mut_ptr().cast(), p, (at + p - 1) as i64) },
        1
    );
    assert_eq!(out[0], b'a');
    assert_eq!(
        unsafe { lseek(mem, (at + p - 1) as i64, 0) },
        (at + p - 1) as i64
    );
    assert_eq!(unsafe { read(mem, out.as_mut_ptr().cast(), p) }, 1);
    assert_eq!(unsafe { lseek(mem, 0, 1) }, (at + p) as i64);
    failed(unsafe { read(mem, out.as_mut_ptr().cast(), 1) }, 5);
    assert_eq!(unsafe { lseek(mem, 0, 1) }, (at + p) as i64);
    assert_eq!(store(mem, at, b"z"), 1);
    assert_eq!(load(mem, at, 1), b"z");
    assert_eq!(unsafe { lseek(mem, 0, 1) }, (at + p) as i64);
    assert_eq!(unsafe { lseek(mem, -8192, 0) }, -8192);
    assert_eq!(unsafe { read(mem, out.as_mut_ptr().cast(), 0) }, 0);
    failed(unsafe { pread(mem, out.as_mut_ptr().cast(), 1, -8192) }, 5);
    failed(unsafe { read(mem, out.as_mut_ptr().cast(), 1) }, 5);
    assert_eq!(unsafe { lseek(mem, 8192, 1) }, 0);
    failed(unsafe { lseek(mem, 0, 2) } as isize, 22);
    done_map(at, p);
    let n = 3 * 256 * 1024 + p;
    let at = map(n, 0x22, -1);
    let data: Vec<_> = (0..n).map(|i| (i % 239) as u8).collect();
    protect(at, n, 0);
    assert_eq!(unsafe { lseek(mem, at as i64, 0) }, at as i64);
    assert_eq!(unsafe { write(mem, data.as_ptr().cast(), n) }, n as isize);
    assert_eq!(unsafe { lseek(mem, 0, 1) }, (at + n) as i64);
    assert_eq!(unsafe { lseek(mem, at as i64, 0) }, at as i64);
    let mut out = vec![0; n];
    assert_eq!(unsafe { read(mem, out.as_mut_ptr().cast(), n) }, n as isize);
    assert_eq!(out, data);
    assert_eq!(unsafe { lseek(mem, 0, 1) }, (at + n) as i64);
    let mut v0 = [0u8; 2];
    let mut v1 = [0u8; 3];
    let iov = [
        Iovec {
            base: v0.as_mut_ptr().cast(),
            len: 2,
        },
        Iovec {
            base: v1.as_mut_ptr().cast(),
            len: 3,
        },
    ];
    assert_eq!(unsafe { preadv(mem, iov.as_ptr(), 2, at as i64) }, 5);
    assert_eq!(v0, [0, 1]);
    assert_eq!(v1, [2, 3, 4]);
    v0.copy_from_slice(b"ab");
    v1.copy_from_slice(b"cde");
    assert_eq!(unsafe { pwritev(mem, iov.as_ptr(), 2, at as i64) }, 5);
    assert_eq!(load(mem, at, 5), b"abcde");
    failed(unsafe { preadv(mem, iov.as_ptr(), 2, -8192) }, 5);
    failed(unsafe { pwritev(mem, iov.as_ptr(), 2, -8192) }, 5);
    assert_eq!(unsafe { lseek(mem, 0, 1) }, (at + n) as i64);
    done_map(at, n);
    unsafe {
        close(mem);
    }
    println!("PASS partial progress, unsigned offsets and multi-window reads/writes");
}
fn shared_offset() {
    let mem = fd("/proc/self/mem", 0);
    let duplicate = unsafe { dup(mem) };
    assert!(duplicate >= 0);
    let half = 2 * 256 * 1024;
    let at = map(half * 2, 0x22, -1);
    unsafe {
        ptr::write_bytes(at as *mut u8, b'A', half);
        ptr::write_bytes((at + half) as *mut u8, b'B', half);
    }
    protect(at, half * 2, 0);
    assert_eq!(unsafe { lseek(mem, at as i64, 0) }, at as i64);
    let reader = move |fd| {
        let mut out = vec![0; half];
        assert_eq!(
            unsafe { read(fd, out.as_mut_ptr().cast(), half) },
            half as isize
        );
        let marker = out[0];
        assert!(out.iter().all(|b| *b == marker));
        marker
    };
    let a = std::thread::spawn(move || reader(mem));
    let b = std::thread::spawn(move || reader(duplicate));
    let mut markers = [a.join().unwrap(), b.join().unwrap()];
    markers.sort();
    assert_eq!(markers, [b'A', b'B']);
    assert_eq!(unsafe { lseek(mem, 0, 1) }, (at + 2 * half) as i64);
    done_map(at, half * 2);
    unsafe {
        close(mem);
        close(duplicate);
    }
    println!("PASS duplicate-FD concurrent reads serialize one complete offset transaction");
}

fn send(fd: i32, ch: u8) {
    assert_eq!(unsafe { write(fd, ptr::addr_of!(ch).cast(), 1) }, 1);
}
fn recv(fd: i32) -> u8 {
    let mut ch = 0;
    assert_eq!(unsafe { read(fd, ptr::addr_of_mut!(ch).cast(), 1) }, 1);
    ch
}
fn wait(pid: i32, status: i32, flags: i32) {
    let mut got = 0;
    assert_eq!(unsafe { waitpid(pid, &mut got, flags) }, pid);
    assert_eq!(got, status);
}
fn drop_ptrace_cap() {
    let mut h = [0x20080522u32, 0];
    let mut d = [0u32; 6];
    assert_eq!(unsafe { capget(h.as_mut_ptr(), d.as_mut_ptr()) }, 0);
    d[0] &= !(1 << 19);
    assert_eq!(unsafe { capset(h.as_ptr(), d.as_ptr()) }, 0);
}
const FIXED: usize = 0x5a000000000;
fn fixed(value: u8) {
    let at = unsafe { mmap(FIXED as *mut _, page(), 3, 0x32, -1, 0) };
    assert_eq!(at as usize, FIXED);
    unsafe {
        *(at as *mut u8) = value;
    }
}
fn lifecycle() {
    let mut command = [-1; 2];
    let mut reply = [-1; 2];
    assert_eq!(unsafe { pipe(command.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { pipe(reply.as_mut_ptr()) }, 0);
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe {
            close(command[1]);
            close(reply[0]);
        }
        fixed(b'O');
        send(reply[1], b'R');
        assert_eq!(recv(command[0]), b'D');
        assert_eq!(unsafe { prctl(4, 0usize) }, 0);
        send(reply[1], b'D');
        assert_eq!(recv(command[0]), b'E');
        let exe = std::env::current_exe().unwrap();
        let args = [
            exe.to_str().unwrap().to_string(),
            "replacement".into(),
            command[0].to_string(),
            reply[1].to_string(),
        ];
        let args: Vec<_> = args
            .iter()
            .map(|x| std::ffi::CString::new(x.as_str()).unwrap())
            .collect();
        let mut ptrs: Vec<_> = args.iter().map(|x| x.as_ptr()).collect();
        ptrs.push(ptr::null());
        unsafe {
            execv(args[0].as_ptr(), ptrs.as_ptr());
            _exit(99)
        }
    }
    unsafe {
        close(command[0]);
        close(reply[1]);
    }
    assert_eq!(recv(reply[0]), b'R');
    let path = format!("/proc/{child}/mem");
    let mem = fd(&path, 2);
    send(command[1], b'D');
    assert_eq!(recv(reply[0]), b'D');
    drop_ptrace_cap();
    let name = std::ffi::CString::new(path).unwrap();
    failed(unsafe { open(name.as_ptr(), 0) } as isize, 13);
    assert_eq!(load(mem, FIXED, 1), b"O");
    assert_eq!(store(mem, FIXED, b"W"), 1);
    send(command[1], b'E');
    assert_eq!(recv(reply[0]), b'E');
    let mut out = [0];
    assert_eq!(
        unsafe { pread(mem, out.as_mut_ptr().cast(), 1, FIXED as i64) },
        0
    );
    assert_eq!(store(mem, FIXED, b"X"), 0);
    send(command[1], b'X');
    wait(child, 0, 0);
    assert_eq!(
        unsafe { pread(mem, out.as_mut_ptr().cast(), 1, FIXED as i64) },
        0
    );
    unsafe {
        close(mem);
        close(command[1]);
        close(reply[0]);
    }
    println!("PASS open-time admission and original-mm identity through exec/exit");
}
fn yama() {
    let path = "/proc/sys/kernel/yama/ptrace_scope";
    let scope = fd(path, 2);
    let set = |value: &[u8]| {
        assert_eq!(unsafe { lseek(scope, 0, 0) }, 0);
        assert_eq!(
            unsafe { write(scope, value.as_ptr().cast(), value.len()) },
            value.len() as isize
        );
        assert_eq!(unsafe { lseek(scope, 0, 0) }, 0);
        let mut out = [0; 8];
        let n = unsafe { read(scope, out.as_mut_ptr().cast(), 8) };
        assert_eq!(&out[..n as usize], &[value[0], b'\n']);
    };
    for value in [b"0".as_slice(), b"1\n".as_slice(), b"2".as_slice()] {
        set(value);
        let child = unsafe { fork() };
        assert!(child >= 0);
        if child == 0 {
            drop_ptrace_cap();
            let parent = unsafe { getppid() };
            let result = unsafe { ptrace(16, parent, 0usize, 0usize) };
            if value[0] == b'0' {
                assert_eq!(result, 0);
                wait(parent, 0x137f, 0);
                assert_eq!(unsafe { ptrace(17, parent, 0usize, 0usize) }, 0);
            } else {
                failed(result as isize, 1);
            }
            unsafe { _exit(0) }
        }
        wait(child, 0, 0);
    }
    set(b"3");
    assert_eq!(unsafe { lseek(scope, 0, 0) }, 0);
    failed(unsafe { write(scope, b"0".as_ptr().cast(), 1) }, 22);
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        failed(unsafe { ptrace(0, 0, 0usize, 0usize) } as isize, 1);
        unsafe { _exit(0) }
    }
    wait(child, 0, 0);
    unsafe {
        close(scope);
    }
    println!("PASS guest-only Yama scope 0/1/2/3 and irreversible scope 3");
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("replacement") => {
            fixed(b'N');
            let command = args[2].parse().unwrap();
            let reply = args[3].parse().unwrap();
            send(reply, b'E');
            assert_eq!(recv(command), b'X');
            unsafe { _exit(0) }
        }
        Some("yama") => yama(),
        _ => {
            protection_and_files();
            partial_and_large();
            shared_offset();
            lifecycle();
        }
    }
}
