// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::AtomicUsize,
    time::{Duration, Instant},
};
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_shared::{HostEvents, IoSignal, IoWake, ReadinessDriver};
use trames_vfs::{Vfs, O_NONBLOCK};
struct Endpoint(trames_vfs::NativeEvent);
impl Notification for Endpoint {
    fn notify(&self) {
        self.0.notify();
    }
    fn register(&self, source: std::sync::Weak<dyn ReadinessDriver>) -> std::io::Result<()> {
        self.0.attach_source(source);
        Ok(())
    }
}
struct Waiter {
    hub: Arc<HostEvents>,
    wakes: AtomicUsize,
}
impl IoWake for Waiter {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }
    fn host_events(&self) -> std::io::Result<Option<Arc<HostEvents>>> {
        Ok(Some(self.hub.clone()))
    }
}
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> Fixture {
    let path = std::env::temp_dir().join(format!("trames-alsa-test-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/clock-pcm.c");
    assert!(Command::new("cc")
        .args(["-DPIC", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .args(["-lasound", "-o"])
        .arg(path.join("libasound_module_pcm_trames_clock.so"))
        .status()
        .unwrap()
        .success());
    let config=format!("</usr/share/alsa/alsa.conf>\npcm.trames_clock {{type trames_clock}}\npcm.trames_removed {{type trames_clock}}\npcm.trames_suspended {{type trames_clock}}\npcm.trames_xrun {{type trames_clock}}\npcm.trames_file {{type file slave.pcm null file \"{}\" format raw}}\n",path.join("samples.raw").display());
    std::fs::write(path.join("asound.conf"), config).unwrap();
    std::env::set_var("ALSA_PLUGIN_DIR", &path);
    std::env::set_var("ALSA_CONFIG_PATH", path.join("asound.conf"));
    Fixture(path)
}
fn record(memory: &mut Memory, a: &[u64]) {
    let mut b = [0; 128];
    for (dst, n) in b.chunks_exact_mut(8).zip(a) {
        dst.copy_from_slice(&n.to_le_bytes());
    }
    memory.write(0x1000, &b).unwrap();
}
fn call(
    context: &Context,
    memory: &mut Memory,
    op: u64,
    args: &[u64],
    notify: Option<Notify>,
) -> i64 {
    record(memory, args);
    context.invoke(memory, op, 0x1000, 128, notify).unwrap() as i64
}
#[test]
fn alsa_bytes_readiness_controls_and_original_endpoint_lifetime() {
    let fixture = fixture();
    let mut memory = Memory::default();
    memory.map(0x1000, 16 * PAGE_SIZE, Permissions::RW).unwrap();
    let mut vfs = Vfs::default();
    let fd = vfs.eventfd(0, O_NONBLOCK).unwrap();
    let original = vfs.direct_descriptors().get(fd).unwrap();
    let notify: Notify = Arc::new(Endpoint(vfs.native_events().event(fd).unwrap()));
    let context = Context::new(3);
    std::env::set_var("TRAMES_AUDIO_OUTPUT_DEVICE", "trames_file");
    let id = call(
        &context,
        &mut memory,
        OPEN,
        &[u64::from(fd), 0, 48000, 2, 0, 480, 1920],
        Some(notify.clone()),
    );
    assert!(id > 0, "open={id}");
    let samples: Vec<u8> = (0..1920).map(|n| (n % 251) as u8).collect();
    memory.write(0x2000, &samples).unwrap();
    assert_eq!(
        call(&context, &mut memory, 6, &[id as u64, 0x2000, 480], None),
        480
    );
    assert_eq!(call(&context, &mut memory, 3, &[id as u64], None), 0);
    assert_eq!(call(&context, &mut memory, 3, &[id as u64], None), 0);
    assert_eq!(call(&context, &mut memory, 2, &[id as u64], None), 0);
    assert_eq!(
        std::fs::read(fixture.0.join("samples.raw")).unwrap(),
        samples
    );
    std::env::set_var("TRAMES_AUDIO_OUTPUT_DEVICE", "null");
    let id = call(
        &context,
        &mut memory,
        OPEN,
        &[u64::from(fd), 0, 48000, 2, 1, 480, 1920],
        Some(notify.clone()),
    );
    assert!(id > 0);
    assert_eq!(
        call(&context, &mut memory, 6, &[id as u64, 0x2000, 240], None),
        240
    );
    assert_eq!(call(&context, &mut memory, 2, &[id as u64], None), 0);
    std::env::set_var("TRAMES_AUDIO_INPUT_DEVICE", "trames_clock");
    assert_eq!(
        call(
            &context,
            &mut memory,
            OPEN,
            &[u64::from(fd), 1, 44100, 2, 0, 480, 1920],
            Some(notify.clone())
        ),
        -22
    );
    let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let first = call(
        &context,
        &mut memory,
        OPEN,
        &[u64::from(fd), 1, 48000, 2, 0, 480, 1920],
        Some(notify.clone()),
    );
    assert!(first > 0, "capture open={first}");
    assert_eq!(
        call(&context, &mut memory, 6, &[first as u64, 0x3000, 480], None),
        -11
    );
    assert_eq!(call(&context, &mut memory, 3, &[first as u64], None), 0);
    while original.read(8).is_ok() {}
    let hub = HostEvents::new().unwrap();
    let waiter = Arc::new(Waiter {
        hub: hub.clone(),
        wakes: AtomicUsize::new(0),
    });
    let wake: Arc<dyn IoWake> = waiter.clone();
    let signal = IoSignal::new(1, Arc::downgrade(&wake));
    let subscriptions = original.subscribe(&signal);
    assert!(subscriptions.iter().all(|s| !s.notification_external()));
    hub.wait(Some(Instant::now() + Duration::from_secs(1)))
        .unwrap();
    assert!(!signal.ready(), "first raw timer event must be filtered");
    hub.wait(Some(Instant::now() + Duration::from_secs(1)))
        .unwrap();
    assert!(signal.ready(), "second timer event must wake the guest");
    assert_eq!(
        call(&context, &mut memory, 6, &[first as u64, 0x3000, 480], None),
        480
    );
    assert!(memory
        .read_array::<1920>(0x3000)
        .unwrap()
        .iter()
        .all(|b| *b == 0x5a));
    assert_eq!(call(&context, &mut memory, 8, &[first as u64, 1], None), 0);
    assert_eq!(call(&context, &mut memory, 8, &[first as u64, 0], None), 0);
    assert_eq!(call(&context, &mut memory, 4, &[first as u64], None), 0);
    assert_eq!(call(&context, &mut memory, 5, &[first as u64], None), 0);
    assert_eq!(
        call(&context, &mut memory, 7, &[first as u64, 0x4000], None),
        0
    );
    assert_eq!(memory.read_u64(0x4000).unwrap(), 0);
    let second = call(
        &context,
        &mut memory,
        OPEN,
        &[u64::from(fd), 1, 48000, 2, 0, 480, 1920],
        Some(notify.clone()),
    );
    assert!(second > 0);
    // Closing/reusing the guest FD must not retarget native completion.
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(77, O_NONBLOCK).unwrap(), fd);
    assert_eq!(call(&context, &mut memory, 2, &[first as u64], None), 0);
    assert_eq!(call(&context, &mut memory, 3, &[second as u64], None), 0);
    drop(subscriptions);
    while original.read(8).is_ok() {}
    signal.reset();
    let subscriptions = original.subscribe(&signal);
    for _ in 0..2 {
        hub.wait(Some(Instant::now() + Duration::from_secs(1)))
            .unwrap();
        if signal.ready() {
            break;
        }
    }
    assert!(signal.ready());
    assert_eq!(vfs.read(fd, 8).unwrap(), 77u64.to_le_bytes());
    assert_eq!(call(&context, &mut memory, 2, &[second as u64], None), 0);
    while original.read(8).is_ok() {}
    signal.reset();
    hub.wait(Some(Instant::now() + Duration::from_millis(30)))
        .unwrap();
    assert!(!signal.ready(), "closed PCM must unregister timer FDs");
    drop(subscriptions);
    for (device, error) in [
        ("trames_removed", -19),
        ("trames_suspended", -86),
        ("trames_xrun", -32),
    ] {
        std::env::set_var("TRAMES_AUDIO_INPUT_DEVICE", device);
        let id = call(
            &context,
            &mut memory,
            OPEN,
            &[u64::from(fd), 1, 48000, 2, 0, 480, 1920],
            Some(notify.clone()),
        );
        assert!(id > 0);
        assert_eq!(call(&context, &mut memory, 3, &[id as u64], None), 0);
        while original.read(8).is_ok() {}
        signal.reset();
        let subscriptions = original.subscribe(&signal);
        hub.wait(Some(Instant::now() + Duration::from_secs(1)))
            .unwrap();
        assert!(!signal.ready());
        hub.wait(Some(Instant::now() + Duration::from_secs(1)))
            .unwrap();
        assert!(signal.ready());
        assert_eq!(
            call(&context, &mut memory, 7, &[id as u64, 0x4000], None),
            error
        );
        assert_eq!(
            call(&context, &mut memory, 6, &[id as u64, 0x3000, 480], None),
            error
        );
        // A native prepare clears the latched poll error. Count an XRUN once.
        assert_eq!(call(&context, &mut memory, 5, &[id as u64], None), 0);
        assert_eq!(
            call(&context, &mut memory, 7, &[id as u64, 0x4000], None),
            0
        );
        assert_eq!(memory.read_u64(0x4020).unwrap(), u64::from(error == -32));
        assert_eq!(call(&context, &mut memory, 2, &[id as u64], None), 0);
        drop(subscriptions);
    }
    drop(hub);
    drop(wake);
    drop(waiter);
    assert_eq!(std::fs::read_dir("/proc/self/fd").unwrap().count(), before);
}
