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
                    let buffer = &window.scene[0].buffer.pixels;
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
                if snapshot.windows[0].scene[0].buffer.pixels.width == 320
                    && snapshot.windows[0].scene[0].buffer.pixels.height == 200
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
