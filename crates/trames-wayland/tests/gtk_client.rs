// SPDX-License-Identifier: GPL-3.0-or-later
use std::{
    io,
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use trames_wayland::Server;

#[test]
#[ignore = "requires original system GTK3 and mousepad"]
fn original_gtk3_seat_and_mousepad_open_without_gdk_errors() {
    #[derive(Clone)]
    struct Clipboard(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
    impl trames_wayland::HostClipboard for Clipboard {
        fn read(&self, fd: std::os::fd::OwnedFd) -> io::Result<()> {
            use std::io::Write;
            let mut pipe = trames_shared::NativePipe::import(fd)?;
            pipe.write_all("host 中文 🧪".as_bytes())
        }
        fn write(&self, mut pipe: trames_shared::NativePipe) -> io::Result<()> {
            let values = self.0.clone();
            thread::spawn(move || {
                use std::io::Read;
                let began = Instant::now();
                let mut data = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    match pipe.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => data.extend_from_slice(&buffer[..n]),
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock
                                && began.elapsed() < Duration::from_secs(3) =>
                        {
                            thread::sleep(Duration::from_millis(1))
                        }
                        _ => return,
                    }
                }
                values
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(data).unwrap());
            });
            Ok(())
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (program, args) in [
        (
            "python3",
            vec![root
                .join("tests/fixtures/gtk-seat.py")
                .to_string_lossy()
                .into_owned()],
        ),
        ("mousepad", vec!["--disable-server".into()]),
    ] {
        let server = Server::new().unwrap();
        let clipboard = Clipboard(Default::default());
        server
            .attach_clipboard(std::sync::Arc::new(clipboard.clone()))
            .unwrap();
        let (_, socket) = server.connect(400, 1000, 1000).unwrap();
        let fd = socket.as_raw_fd();
        let temp =
            std::env::temp_dir().join(format!("trames-gtk-{}-{}", std::process::id(), program));
        std::fs::create_dir_all(&temp).unwrap();
        let mut command = Command::new(program);
        command
            .args(args)
            .env("WAYLAND_SOCKET", fd.to_string())
            .env("GDK_BACKEND", "wayland")
            .env("GSETTINGS_BACKEND", "memory")
            .env("GTK_USE_PORTAL", "0")
            .env("NO_AT_BRIDGE", "1")
            .env("XDG_CONFIG_HOME", &temp)
            .env("XDG_DATA_HOME", &temp)
            .env("XDG_CACHE_HOME", &temp)
            .env("XDG_RUNTIME_DIR", &temp)
            .env("WAYLAND_DISPLAY", "wayland-0")
            .env("TRAMES_GTK_CLIPBOARD", "1")
            .env("G_DEBUG", "fatal-criticals")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: child-only fcntl; socket stays alive until spawn finishes.
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
        let mut rendered = false;
        let mut closed = false;
        let mut focused = false;
        let mut resized_dialog = false;
        let mut fixed_dialog = false;
        loop {
            let scene = server.snapshot();
            for window in &scene.windows {
                if window.parent.is_some()
                    && window.min_size.0 > 0
                    && window.min_size == window.max_size
                {
                    if !resized_dialog {
                        server.resize(window.id, 800, 600).unwrap();
                        resized_dialog = true;
                    } else if (window.width, window.height) == window.max_size {
                        fixed_dialog = true;
                    }
                }
                if !window.scene.is_empty() {
                    rendered = true;
                    if !focused {
                        server
                            .input(trames_wayland::InputEvent::Focus {
                                window: Some(window.id),
                            })
                            .unwrap();
                        focused = true;
                    }
                }
                server
                    .presented(
                        window.id,
                        scene.revision,
                        began.elapsed().as_millis() as u32,
                    )
                    .unwrap();
                if program == "mousepad" && rendered && !closed {
                    server.close(window.id).unwrap();
                    closed = true;
                }
            }
            if let Some(status) = child.try_wait().unwrap() {
                let output = child.wait_with_output().unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(status.success(), "{program}: {status}: {stderr}");
                assert!(
                    rendered,
                    "{program} did not submit a real GTK window: {stderr}"
                );
                assert!(
                    !stderr.contains("Gdk-CRITICAL") && !stderr.contains("dispatching to Wayland"),
                    "{stderr}"
                );
                if program == "python3" {
                    assert_eq!(&*clipboard.0.lock().unwrap(), &["guest 剪贴板 ✅"]);
                    assert!(resized_dialog && fixed_dialog,"Original GTK fixed-size transient dialog must retain its client dimensions");
                }
                println!(
                    "{program}: original GTK seat, clipboard and SHM window passed; {}",
                    String::from_utf8_lossy(&output.stdout)
                );
                break;
            }
            if began.elapsed() > Duration::from_secs(30) {
                child.kill().unwrap();
                panic!(
                    "{program} timed out: {:?}",
                    child.wait_with_output().unwrap()
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = std::fs::remove_dir_all(temp);
    }
}

#[test]
#[ignore = "requires original system GTK3"]
fn original_gtk_context_menu_copy_keeps_selection_and_keyboard_focus() {
    #[derive(Clone, Default)]
    struct Clipboard(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
    impl trames_wayland::HostClipboard for Clipboard {
        fn read(&self, _: std::os::fd::OwnedFd) -> io::Result<()> {
            Ok(())
        }
        fn write(&self, mut pipe: trames_shared::NativePipe) -> io::Result<()> {
            let values = self.0.clone();
            thread::spawn(move || {
                use std::io::Read;
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut value = Vec::new();
                let mut bytes = [0; 4096];
                loop {
                    match pipe.read(&mut bytes) {
                        Ok(0) => {
                            values
                                .lock()
                                .unwrap()
                                .push(String::from_utf8(value).unwrap());
                            break;
                        }
                        Ok(n) => value.extend_from_slice(&bytes[..n]),
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(1))
                        }
                        _ => break,
                    }
                }
            });
            Ok(())
        }
    }
    let server = Server::new().unwrap();
    let clipboard = Clipboard::default();
    server
        .attach_clipboard(std::sync::Arc::new(clipboard.clone()))
        .unwrap();
    let (_, socket) = server.connect(400, 1000, 1000).unwrap();
    let fd = socket.as_raw_fd();
    let marker = std::env::temp_dir().join(format!("trames-gtk-menu-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let runtime = marker.with_extension("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    let mut command = Command::new("python3");
    command
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/gtk-editing.py"),
        )
        .env("WAYLAND_SOCKET", fd.to_string())
        .env("GDK_BACKEND", "wayland")
        .env("GTK_IM_MODULE", "wayland")
        .env("GSETTINGS_BACKEND", "memory")
        .env("GTK_USE_PORTAL", "0")
        .env("NO_AT_BRIDGE", "1")
        .env("GTK_CSD", "0")
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_CACHE_HOME", &runtime)
        .env("XDG_CONFIG_HOME", &runtime)
        .env("WAYLAND_DISPLAY", "wayland-0")
        .env("TRAMES_GTK_EDITING_MARKER", &marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: child-only fcntl on the live inherited Wayland socket.
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
    let mut clicked = false;
    let mut opened = false;
    let mut activated = false;
    let mut restored = false;
    loop {
        let scene = server.snapshot();
        for window in &scene.windows {
            server
                .presented(
                    window.id,
                    scene.revision,
                    began.elapsed().as_millis() as u32,
                )
                .unwrap();
            if !clicked && !window.scene.is_empty() && began.elapsed() > Duration::from_millis(500)
            {
                server
                    .input(trames_wayland::InputEvent::Focus {
                        window: Some(window.id),
                    })
                    .unwrap();
                clicked = true;
            }
            if clicked && !opened && scene.text.is_some() {
                // GTK's standard Shift+F10 opens the same text context menu
                // without depending on theme-specific CSD pixel positions.
                for (key, modifiers) in [(30, 4), (68, 1)] {
                    for pressed in [true, false] {
                        server
                            .input(trames_wayland::InputEvent::Key {
                                key,
                                pressed,
                                modifiers: if pressed { modifiers } else { 0 },
                                time: 2,
                            })
                            .unwrap();
                    }
                }
                opened = true;
            }
            if !activated && marker.exists() && window.scene.len() > 1 {
                for pressed in [true, false] {
                    server
                        .input(trames_wayland::InputEvent::Key {
                            key: 46,
                            pressed,
                            modifiers: 0,
                            time: 3,
                        })
                        .unwrap();
                }
                activated = true;
            }
            restored |= activated && scene.text.as_ref().is_some_and(|t| t.surface == window.id);
        }
        if !clipboard.0.lock().unwrap().is_empty() && restored {
            break;
        }
        if child.try_wait().unwrap().is_some() || began.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "GTK menu copy failed: clicked={clicked}, windows={:?}, activated={activated}, restored={restored}, copied={:?}: {}",
                scene.windows.iter().map(|w|(&w.title,w.scene.len())).collect::<Vec<_>>(),clipboard.0.lock().unwrap(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(5));
    }
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(&*clipboard.0.lock().unwrap(), &["menu clipboard 中文 🧪"]);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("CRITICAL"));
    let _ = std::fs::remove_file(marker);
    let _ = std::fs::remove_dir_all(runtime);
}
