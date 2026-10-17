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
        mailbox: bool,
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
        fn mailbox(&self) -> bool {
            self.mailbox
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
                mailbox: false,
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
                mailbox: false,
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
    // A canceled mailbox frame retains its independent producer lease. A new
    // ready mailbox frame may replace the current frame before UI presentation,
    // while already acquired UI leases still keep the old image alive.
    let canceled_drop = Arc::new(AtomicBool::new(false));
    let producer: Arc<dyn trames_wayland::GpuImage> = Arc::new(Image {
        width: 333,
        mailbox: true,
        ready: Arc::new(AtomicBool::new(false)),
        dropped: canceled_drop.clone(),
    });
    server.present_gpu(id, producer.clone()).unwrap();
    let mailbox_drop = Arc::new(AtomicBool::new(false));
    server
        .present_gpu(
            id,
            Arc::new(Image {
                width: 444,
                mailbox: true,
                ready: Arc::new(AtomicBool::new(true)),
                dropped: mailbox_drop.clone(),
            }),
        )
        .unwrap();
    let mailbox_ui = wait(&server, |s| {
        s.windows[0].scene[0].buffer.dimensions() == (444, 64)
    });
    assert!(!canceled_drop.load(Ordering::Acquire));
    drop(producer);
    assert!(canceled_drop.load(Ordering::Acquire));
    let newest_ready = Arc::new(AtomicBool::new(false));
    server
        .present_gpu(
            id,
            Arc::new(Image {
                width: 555,
                mailbox: true,
                ready: newest_ready.clone(),
                dropped: Arc::new(AtomicBool::new(false)),
            }),
        )
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        server.snapshot().windows[0].scene[0].buffer.dimensions(),
        (444, 64)
    );
    newest_ready.store(true, Ordering::Release);
    let newest = wait(&server, |s| {
        s.windows[0].scene[0].buffer.dimensions() == (555, 64)
    });
    assert!(!mailbox_drop.load(Ordering::Acquire));
    drop(mailbox_ui);
    assert!(mailbox_drop.load(Ordering::Acquire));
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
    drop(newest);
}

#[test]
#[ignore = "build original C scene peer with scripts/test-wayland.sh"]
fn original_c_scene_atomic_subsurface_popup_and_pointer_grab() {
    use std::io::Read;
    use trames_wayland::InputEvent;
    let server = Server::new().unwrap();
    let (_, socket) = server.connect(9, 1000, 1000).unwrap();
    let fd = socket.as_raw_fd();
    let mut cmd = Command::new(std::env::var("TRAMES_WAYLAND_SCENE_CLIENT").unwrap());
    cmd.env("WAYLAND_SOCKET", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: child-only CLOEXEC update on the inherited retained Unix socket.
    unsafe {
        cmd.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = cmd.spawn().unwrap();
    drop(socket);
    let mut stdout = child.stdout.take().unwrap();
    // SAFETY: a live uniquely-owned diagnostic pipe; only adds nonblocking I/O.
    unsafe {
        assert!(libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) >= 0);
    }
    let mut log = String::new();
    let start = Instant::now();
    let mut phase = 0;
    let key = |value| {
        for pressed in [true, false] {
            server
                .input(InputEvent::Key {
                    key: value,
                    pressed,
                    modifiers: 0,
                    time: 10,
                })
                .unwrap();
        }
    };
    loop {
        let mut bytes = [0; 4096];
        loop {
            match stdout.read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => log.push_str(&String::from_utf8_lossy(&bytes[..n])),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        let scene = server.snapshot();
        if let Some(w) = scene.windows.first() {
            let root = w.id;
            if w.scene.len() == 3 {
                let child_image = &w.scene[1];
                let popup = &w.scene[2];
                let color = |image: &trames_wayland::SurfaceImage| -> u32 {
                    let mut value = 0;
                    let pixels = image.buffer.shm().unwrap();
                    // SAFETY: immutable client frame plus retained SHM lease.
                    unsafe {
                        pixels
                            .mapping
                            .with_read(0, 4, |p| value = u32::from_le_bytes(p.try_into().unwrap()));
                    }
                    value
                };
                if phase == 0 {
                    assert_eq!((child_image.x, child_image.y), (20, 30));
                    assert_eq!(color(child_image), 0xffcc0000);
                    assert_eq!(
                        (popup.x, popup.y, popup.buffer.dimensions()),
                        (203, 115, (80, 60))
                    );
                    assert_eq!(w.bounds(), [-10, -10, 293, 185]);
                    // The child's input region excludes its border. Once pressed
                    // inside, its implicit grab keeps the release even outside.
                    for (x, y) in [(21.0, 31.0), (25.0, 35.0)] {
                        server
                            .input(InputEvent::Pointer {
                                window: root,
                                x,
                                y,
                                time: 1,
                            })
                            .unwrap();
                    }
                    server
                        .input(InputEvent::Button {
                            button: 0x110,
                            pressed: true,
                            time: 2,
                        })
                        .unwrap();
                    server
                        .input(InputEvent::Pointer {
                            window: root,
                            x: 0.0,
                            y: 0.0,
                            time: 3,
                        })
                        .unwrap();
                    server
                        .input(InputEvent::Button {
                            button: 0x110,
                            pressed: false,
                            time: 4,
                        })
                        .unwrap();
                    server
                        .input(InputEvent::Focus { window: Some(root) })
                        .unwrap();
                    key(30);
                    phase = 1;
                } else if phase == 1 && log.contains("staged") {
                    assert_eq!((child_image.x, child_image.y), (20, 30));
                    assert_eq!(color(child_image), 0xffcc0000);
                    assert!(
                        log.contains("pointer=root")
                            && log.contains("pointer=child")
                            && log.contains("motion=child -20,-30")
                            && log.contains("button=child 0"),
                        "{log}"
                    );
                    key(31);
                    phase = 2;
                } else if phase == 2 && log.contains("applied") {
                    assert_eq!((child_image.x, child_image.y), (60, 40));
                    assert_eq!(color(child_image), 0xff00cc00);
                    key(32);
                    phase = 3;
                } else if phase == 3 && popup.buffer.dimensions() == (60, 40) {
                    assert_eq!((popup.x, popup.y), (0, 0));
                    key(33);
                    phase = 4;
                }
            }
        }
        if phase == 4
            && log.contains("grabbed")
            && scene
                .windows
                .first()
                .is_some_and(|w| w.scene.len() == 3 && w.scene[2].x == 110)
        {
            let root = scene.windows[0].id;
            server
                .input(InputEvent::Pointer {
                    window: root,
                    x: 1.0,
                    y: 1.0,
                    time: 20,
                })
                .unwrap();
            server
                .input(InputEvent::Button {
                    button: 0x110,
                    pressed: true,
                    time: 21,
                })
                .unwrap();
            server
                .input(InputEvent::Button {
                    button: 0x110,
                    pressed: false,
                    time: 22,
                })
                .unwrap();
            phase = 5;
        }
        if phase == 5
            && log.contains("popup-dismissed")
            && scene.windows.first().is_some_and(|w| w.scene.len() == 2)
        {
            server.close(scene.windows[0].id).unwrap();
            phase = 6;
        }
        if let Some(status) = child.try_wait().unwrap() {
            stdout.read_to_string(&mut log).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                status.success(),
                "{log}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            break;
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "scene peer stalled phase={phase}: {log}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(phase, 6, "{log}");
    assert!(log.contains("repositioned=17"), "{log}");
}

#[test]
#[ignore = "build original C text-input-v3 peer with scripts/test-wayland.sh"]
fn original_c_text_v3_composition_utf8_serial_and_surrounding_ack() {
    use std::io::Read;
    use trames_wayland::{InputEvent, TextEdit};
    let server = Server::new().unwrap();
    let (_, socket) = server.connect(10, 1000, 1000).unwrap();
    let fd = socket.as_raw_fd();
    let mut command = Command::new(std::env::var("TRAMES_WAYLAND_TEXT_V3_CLIENT").unwrap());
    command
        .env("WAYLAND_SOCKET", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: retained child-only Unix descriptor; async-signal-safe CLOEXEC update.
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
    let mut stdout = child.stdout.take().unwrap();
    // SAFETY: a uniquely owned diagnostic pipe; no other flags are in use.
    unsafe {
        assert!(libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) >= 0);
    }
    let began = Instant::now();
    let mut focused = false;
    let mut sent = false;
    let mut closed = false;
    let mut log = String::new();
    loop {
        let mut bytes = [0; 4096];
        loop {
            match stdout.read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => log.push_str(&String::from_utf8_lossy(&bytes[..n])),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        let scene = server.snapshot();
        if let Some(w) = scene.windows.first() {
            if !focused {
                server
                    .input(InputEvent::Focus { window: Some(w.id) })
                    .unwrap();
                focused = true;
            }
        }
        if let Some(t) = scene.text {
            assert_eq!(t.version, 3);
            if !sent {
                assert_eq!(
                    (t.text.as_str(), t.cursor, t.anchor, t.serial),
                    ("a🙂中", 8, 1, 1)
                );
                server
                    .edit_text(TextEdit {
                        context: t.id,
                        epoch: t.epoch,
                        serial: t.serial,
                        preedit: Some(("ni".into(), 2, 2)),
                        ..Default::default()
                    })
                    .unwrap();
                // v3 preedit/commit replaces the selection itself; there is no
                // surrounding deletion for the selected seven UTF-8 bytes.
                server
                    .edit_text(TextEdit {
                        context: t.id,
                        epoch: t.epoch,
                        serial: t.serial,
                        preedit: Some((String::new(), 0, 0)),
                        commit: Some("你好🙂".into()),
                        ..Default::default()
                    })
                    .unwrap();
                sent = true;
            } else if t.text == "a你好🙂" && t.serial == 2 && !closed {
                assert_eq!((t.cursor, t.anchor), (11, 11));
                server.close(t.window).unwrap();
                closed = true;
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            stdout.read_to_string(&mut log).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                status.success(),
                "{log}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            break;
        }
        if began.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "v3 peer stalled: {log}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(sent && closed, "{log}");
    assert!(
        log.contains("v3-preedit:ni:2:2")
            && log.contains("v3-commit:你好🙂")
            && log.contains("v3-done:1"),
        "{log}"
    );
    assert!(
        !log.contains("v3-delete:"),
        "selected text must not also be deleted as surrounding bytes: {log}"
    );
}

#[test]
#[ignore = "build original C client with scripts/test-wayland.sh"]
fn original_c_v1_widget_switching_has_balanced_exclusive_activation() {
    use trames_wayland::InputEvent;
    let server = Server::new().unwrap();
    let (_, socket) = server.connect(11, 1000, 1000).unwrap();
    let fd = socket.as_raw_fd();
    let mut command = Command::new(std::env::var("TRAMES_WAYLAND_TEXT_V1_CLIENT").unwrap());
    command
        .env("WAYLAND_SOCKET", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: child-only async-signal-safe CLOEXEC change on a retained FD.
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
    let mut focused = false;
    loop {
        if !focused {
            if let Some(window) = server.snapshot().windows.first() {
                server
                    .input(InputEvent::Focus {
                        window: Some(window.id),
                    })
                    .unwrap();
                focused = true;
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            assert!(
                status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("v1-multiwidget-ok"));
            break;
        }
        if began.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            panic!("v1 activation peer stalled");
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(focused);
}
