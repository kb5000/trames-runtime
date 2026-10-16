// SPDX-License-Identifier: GPL-3.0-or-later
//! Independent original libwayland-client C ABI: resource ownership and frames.
use std::{
    io,
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use trames_wayland::{Server, WindowMode};

#[test]
#[ignore = "build original C client with scripts/test-wayland.sh"]
fn original_c_client_two_windows_resize_frames_and_native_close() {
    let client = std::env::var("TRAMES_WAYLAND_C_CLIENT").expect("original C fixture path");
    for close in [false, true] {
        let server = Server::new().unwrap();
        let (_, socket) = server.connect(8, 1000, 1000).unwrap();
        let fd = socket.as_raw_fd();
        let mut command = Command::new(&client);
        command
            .arg(if close { "1000" } else { "40" })
            .env("WAYLAND_SOCKET", fd.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: child-only async-signal-safe fcntl on a retained inherited FD;
        // no allocator, lock or parent descriptor mutation occurs after fork.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut child = command.spawn().unwrap();
        drop(socket);
        let began = Instant::now();
        let mut resized = false;
        let mut verified = false;
        let mut closed = false;
        let mut hidden = false;
        loop {
            let snapshot = server.snapshot();
            if snapshot.windows.len() == 2 {
                for window in &snapshot.windows {
                    let buffer = &window.scene[0].buffer.shm().unwrap();
                    let color = if window.title.ends_with('1') {
                        0xff224466u32
                    } else {
                        0xffaa6633
                    };
                    // SAFETY: the client uses a fresh immutable buffer per frame;
                    // both this diagnostic read and the scene retain its lease.
                    unsafe {
                        buffer
                            .mapping
                            .with_read(0, 4, |b| assert_eq!(b, color.to_le_bytes()));
                    }
                }
                if !resized {
                    server.resize(snapshot.windows[0].id, 320, 200).unwrap();
                    resized = true;
                }
                if snapshot.windows[0].scene[0].buffer.shm().unwrap().width == 320
                    && snapshot.windows[0].scene[0].buffer.shm().unwrap().height == 200
                {
                    verified = true;
                }
                if close && verified && !closed {
                    server.close(snapshot.windows[0].id).unwrap();
                    closed = true;
                }
                if !close && verified && !hidden {
                    server
                        .set_mode(snapshot.windows[0].id, WindowMode::Minimized)
                        .unwrap();
                    hidden = true;
                }
                if hidden && began.elapsed() > Duration::from_millis(150) {
                    server
                        .set_mode(snapshot.windows[0].id, WindowMode::Floating)
                        .unwrap();
                }
                for window in &snapshot.windows {
                    if window.mode != WindowMode::Minimized {
                        server
                            .presented(
                                window.id,
                                snapshot.revision,
                                began.elapsed().as_millis() as u32,
                            )
                            .unwrap();
                    }
                }
            }
            if let Some(status) = child.try_wait().unwrap() {
                let output = child.wait_with_output().unwrap();
                assert!(
                    status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(String::from_utf8_lossy(&output.stdout).contains("wayland-client-ok"));
                break;
            }
            if began.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "C client stalled: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(4));
        }
        assert!(verified && resized);
    }
}

#[test]
#[ignore = "build original C client with scripts/test-wayland.sh"]
fn producer_readiness_fifo_and_external_image_leases_survive_server_teardown() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct Image {
        width: u32,
        ready: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }
    impl Drop for Image {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }
    // SAFETY: this diagnostic capability has no native handle or pending GPU
    // work. Atomics model independent producer completion and final lease drop.
    unsafe impl trames_wayland::GpuImage for Image {
        fn dimensions(&self) -> (u32, u32) {
            (self.width, 64)
        }
        fn metal_texture(&self) -> usize {
            0
        }
        fn ready(&self) -> io::Result<bool> {
            Ok(self.ready.load(Ordering::Acquire))
        }
    }
    let budget = trames_wayland::GpuBudget::default();
    let mut permits: Vec<_> = (0..64).map(|_| budget.reserve().unwrap()).collect();
    assert!(budget.reserve().is_none());
    permits.pop();
    assert!(budget.reserve().is_some());
    drop(permits);
    let server = Server::new().unwrap();
    let (_, socket) = server.connect(8, 1000, 1000).unwrap();
    let fd = socket.as_raw_fd();
    let mut command = Command::new(std::env::var("TRAMES_WAYLAND_C_CLIENT").unwrap());
    command
        .args(["1", "hold"])
        .env("WAYLAND_SOCKET", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: same child-only retained descriptor/CLOEXEC contract as above.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = command.spawn().unwrap();
    drop(socket);
    fn wait(
        server: &Server,
        predicate: impl Fn(&trames_wayland::Snapshot) -> bool,
    ) -> trames_wayland::Snapshot {
        let start = Instant::now();
        loop {
            let scene = server.snapshot();
            if predicate(&scene) {
                return scene;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "native scene stalled"
            );
            thread::sleep(Duration::from_millis(2));
        }
    }
    let scene = wait(&server, |s| s.windows.len() == 2);
    let id = scene.windows[0].id;
    drop(scene);
    let ready = Arc::new(AtomicBool::new(false));
    let dropped1 = Arc::new(AtomicBool::new(false));
    let dropped2 = Arc::new(AtomicBool::new(false));
    server
        .present_gpu(
            id,
            Arc::new(Image {
                width: 111,
                ready: ready.clone(),
                dropped: dropped1.clone(),
            }),
        )
        .unwrap();
    server
        .present_gpu(
            id,
            Arc::new(Image {
                width: 222,
                ready: Arc::new(AtomicBool::new(true)),
                dropped: dropped2.clone(),
            }),
        )
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    assert!(server.snapshot().windows[0].scene[0].buffer.shm().is_some());
    ready.store(true, Ordering::Release);
    let held = wait(&server, |s| {
        s.windows[0].scene[0].buffer.dimensions() == (111, 64)
    });
    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        server.snapshot().windows[0].scene[0].buffer.dimensions(),
        (111, 64)
    );
    server.presented(id, held.windows[0].revision, 100).unwrap();
    let last = wait(&server, |s| {
        s.windows[0].scene[0].buffer.dimensions() == (222, 64)
    });
    assert!(!dropped1.load(Ordering::Acquire));
    drop(held);
    let start = Instant::now();
    while !dropped1.load(Ordering::Acquire) {
        assert!(start.elapsed() < Duration::from_secs(5));
        thread::yield_now();
    }
    server.close(id).unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(start.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(2));
    }
    assert!(child.wait_with_output().unwrap().status.success());
    drop(server);
    assert!(
        !dropped2.load(Ordering::Acquire),
        "UI lease must outlive the producer and native server"
    );
    drop(last);
    assert!(dropped2.load(Ordering::Acquire));
}
