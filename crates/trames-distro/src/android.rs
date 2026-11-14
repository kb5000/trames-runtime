// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold preparation for the original Waydroid init. This supplies container
//! inputs only: init, properties, logging, Binder and ART remain guest programs.
use trames_vfs::{Errno, Vfs, AT_FDCWD};
// A stock desktop already uses about 1,000 sleeping/runnable guest tasks.
// Leave room for application worker pools (including nested codec pools).
// Admission is atomic metadata only: no RAM or host threads are preallocated.
pub const TASK_LIMIT: usize = trames_vfs::MAX_TASKS;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub fn command() -> Vec<String> {
    vec!["/system/bin/init".into(), "second_stage".into()]
}
/// Validate a cold Android image before publishing an environment. Ordinary
/// syscalls, buffer access and frame presentation never consult this metadata.
pub fn validate_image(vfs: &mut Vfs) -> Result<()> {
    crate::rootfs::validate_command(vfs, &command())?;
    for path in [
        b"/system/bin/init".as_slice(),
        b"/system/bin/bootstrap/linker64",
    ] {
        vfs.executable(path)?;
    }
    for path in [
        b"/vendor/lib64/hw/vulkan.trames.so".as_slice(),
        b"/vendor/lib64/hw/gralloc.trames.so",
        b"/vendor/bin/hw/trames-hal-service",
    ] {
        let bytes = optional_file(vfs, path)?
            .ok_or("Android support components are missing; import a Trames Android package")?;
        if bytes.get(..5) != Some(b"\x7fELF\x02")
            || bytes.get(18..20) != Some(&183u16.to_le_bytes())
        {
            return Err("Android support component is not ARM64 ELF".into());
        }
    }
    if let Some(bytes) = optional_file(vfs, b"/.trames-android.json")? {
        let metadata: serde_json::Value = serde_json::from_slice(&bytes)?;
        if metadata["schema"] != 1
            || metadata["target"] != "android"
            || metadata["abi"] != "arm64-v8a"
            || metadata["graphics_contract"] != 1
            || metadata["android_api"] != 33
        {
            return Err("Android package requires a different Trames version or ABI".into());
        }
    }
    Ok(())
}
fn directory(vfs: &mut Vfs, path: &[u8], mode: u32) -> Result<()> {
    match vfs.mkdir_at(AT_FDCWD, path, mode) {
        Ok(()) => Ok(()),
        Err(Errno(17)) => {
            let stat = vfs.stat_at(AT_FDCWD, path)?;
            if u32::from_le_bytes(stat[16..20].try_into()?) & 0o170000 != 0o40000 {
                return Err("Android boot directory is not a directory".into());
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}
fn optional_file(vfs: &mut Vfs, path: &[u8]) -> Result<Option<Vec<u8>>> {
    let fd = match vfs.open_at(AT_FDCWD, path, 0, 0) {
        Ok(fd) => fd,
        Err(Errno(2)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let result = (|| {
        let mut bytes = Vec::new();
        loop {
            let chunk = vfs.read(fd, 65536)?;
            if chunk.is_empty() {
                break;
            }
            bytes.extend(chunk);
        }
        Ok::<_, Errno>(bytes)
    })();
    let closed = vfs.close(fd);
    let bytes = result?;
    closed?;
    Ok(Some(bytes))
}
fn overlay(vfs: &mut Vfs, name: &str, target: &[u8], bytes: &[u8]) -> Result<()> {
    let source = format!("/run/trames-android/{name}");
    crate::systemd::file(vfs, source.as_bytes(), bytes)?;
    if vfs.stat_at(AT_FDCWD, target).is_err_and(|e| e.0 == 2) {
        crate::systemd::file(vfs, target, b"")?;
    }
    vfs.mount(Some(source.as_bytes()), target, None, 4096, None)?;
    Ok(())
}
fn audio_launcher(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes)?;
    let mut selected = false;
    let mut lines = Vec::new();
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) && !line.starts_with('#') && !line.is_empty() {
            selected =
                line == "service vendor.audio-hal /vendor/bin/hw/android.hardware.audio.service";
            if selected {
                lines.push("service vendor.audio-hal /vendor/bin/hw/trames-hal-service android.hardware.audio@4.0::IDevicesFactory android.hardware.audio.effect@4.0::IEffectsFactory");
                continue;
            }
        }
        // No realtime-priority inheritance is claimed by the current runtime.
        // Preserve the remaining original service credentials and options.
        if selected && line.trim_start().starts_with("rlimit rtprio ") {
            continue;
        }
        lines.push(line);
    }
    Ok((lines.join("\n") + "\n").into_bytes())
}
pub fn environment() -> Vec<String> {
    [
        "PATH=/system/bin:/system/xbin:/vendor/bin",
        "ANDROID_ROOT=/system",
        "ANDROID_DATA=/data",
        "ANDROID_STORAGE=/storage",
        "ANDROID_RUNTIME_ROOT=/apex/com.android.runtime",
        "ANDROID_ART_ROOT=/apex/com.android.art",
        "ANDROID_I18N_ROOT=/apex/com.android.i18n",
        "ANDROID_TZDATA_ROOT=/apex/com.android.tzdata",
        "EXTERNAL_STORAGE=/sdcard",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn prepare_network(vfs: &mut Vfs) -> Result<()> {
    let path = b"/data/misc/ethernet/ipconfig.txt";
    let current = b"/data/misc/apexdata/com.android.tethering/misc/ethernet/ipconfig.txt";
    if optional_file(vfs, path)?.is_some() || optional_file(vfs, current)?.is_some() {
        return Ok(());
    }
    // Original Android 13 IpConfigStore v3 / DataOutputStream format. Configure
    // the guest IP uplink, not a host NIC; EthernetTracker/IpClient/netd still
    // perform their original service registration and kernel operations.
    fn utf(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    let mut bytes = 3u32.to_be_bytes().to_vec();
    for text in ["ipAssignment", "STATIC", "linkAddress", "10.0.0.2"] {
        utf(&mut bytes, text);
    }
    bytes.extend_from_slice(&24u32.to_be_bytes());
    utf(&mut bytes, "gateway");
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    for text in [
        "10.0.0.1",
        "dns",
        "10.0.0.1",
        "proxySettings",
        "NONE",
        "id",
        "eth0",
        "eos",
    ] {
        utf(&mut bytes, text);
    }
    directory(vfs, b"/data/misc", 0o771)?;
    directory(vfs, b"/data/misc/ethernet", 0o770)?;
    crate::systemd::file(vfs, path, &bytes)?;
    vfs.chown_at(AT_FDCWD, b"/data/misc/ethernet", 1000, 1000, false)?;
    vfs.chmod_at(AT_FDCWD, b"/data/misc/ethernet", 0o770)?;
    vfs.chown_at(AT_FDCWD, path, 1000, 1000, false)?;
    Ok(())
}
/// Each boot gets fresh device/property/socket state; /data stays private and
/// persistent. The image's Waydroid property overlay, if supplied, is retained.
pub fn prepare(vfs: &mut Vfs) -> Result<()> {
    vfs.executable(b"/system/bin/init")
        .map_err(|e| format!("Android init is missing: {e}"))?;
    vfs.executable(b"/system/bin/bootstrap/linker64")
        .map_err(|e| format!("Android bootstrap linker is missing: {e}"))?;
    vfs.set_runtime_info(1, Default::default());
    for path in [
        b"/dev".as_slice(),
        b"/run",
        b"/mnt",
        b"/data",
        b"/metadata",
        b"/data/cache",
        b"/apex",
        b"/linkerconfig",
    ] {
        directory(vfs, path, 0o755)?;
    }
    // Android remounts the root image read-only. Persistent container data must
    // be independent mounts, just as they are under its original launcher.
    for path in [b"/data".as_slice(), b"/metadata"] {
        vfs.mount(Some(path), path, None, 4096, None)?;
    }
    prepare_network(vfs)?;
    // Waydroid's launcher normally supplies this writable container mount.
    // Zygote creates per-user storage views here after Android remounts / RO.
    vfs.mount(
        Some(b"tmpfs"),
        b"/mnt",
        Some(b"tmpfs"),
        2 | 4 | 8,
        Some(b"mode=755,uid=0,gid=0,size=0,nr_inodes=0"),
    )?;
    vfs.mount(
        Some(b"tmpfs"),
        b"/dev",
        Some(b"tmpfs"),
        2,
        Some(b"mode=755,uid=0,gid=0,size=0,nr_inodes=0"),
    )?;
    let umask = vfs.set_umask(0);
    let result = (|| {
        for (name, major, minor, mode) in [
            ("null", 1, 3, 0o666),
            ("zero", 1, 5, 0o666),
            ("full", 1, 7, 0o666),
            ("random", 1, 8, 0o666),
            ("urandom", 1, 9, 0o666),
            ("tty", 5, 0, 0o666),
            ("kmsg", 1, 11, 0o600),
            ("binder", 241, 0, 0o666),
            ("hwbinder", 241, 1, 0o666),
            ("vndbinder", 241, 2, 0o666),
            ("sw_sync", 242, 0, 0o666),
        ] {
            vfs.mknod_at(
                AT_FDCWD,
                format!("/dev/{name}").as_bytes(),
                0o20000 | mode,
                major * 256 + minor,
            )?;
        }
        for path in [b"/dev/socket".as_slice(), b"/dev/pts", b"/dev/dm-user"] {
            directory(vfs, path, 0o755)?;
        }
        // Waydroid's launcher normally provisions these named pipes before
        // EventHub scans /dev/input. The original image supplies the device
        // capabilities and reads Linux input_event records directly from them.
        directory(vfs, b"/dev/input", 0o755)?;
        for name in ["touch", "keyboard", "pointer", "tablet"] {
            let path = format!("/dev/input/wl_{name}_events");
            vfs.mknod_at(AT_FDCWD, path.as_bytes(), 0o10660, 0)?;
            vfs.chown_at(AT_FDCWD, path.as_bytes(), 1000, 1004, false)?;
        }
        vfs.mount(
            Some(b"devpts"),
            b"/dev/pts",
            Some(b"devpts"),
            2 | 8,
            Some(b"newinstance,mode=620,ptmxmode=666"),
        )?;
        vfs.symlink_at(b"pts/ptmx", AT_FDCWD, b"/dev/ptmx")?;
        vfs.symlink_at(b"/proc/self/fd", AT_FDCWD, b"/dev/fd")?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })();
    vfs.set_umask(umask);
    result?;
    // All container devices are provisioned above; there is no asynchronous
    // physical-device enumeration for guest ueventd to complete.
    crate::systemd::file(vfs, b"/dev/.coldboot_done", b"")?;
    // The immutable vendor image contains a dummy Waydroid overlay. Retain
    // caller settings, fill absent container defaults, and bind a per-boot
    // copy over it without changing the original image inode.
    let mut properties = Vec::new();
    match vfs.open_at(AT_FDCWD, b"/vendor/waydroid.prop", 0, 0) {
        Ok(fd) => {
            let read = (|| {
                loop {
                    let chunk = vfs.read(fd, 65536)?;
                    if chunk.is_empty() {
                        break;
                    }
                    properties.extend(chunk);
                }
                Ok::<_, Errno>(())
            })();
            let closed = vfs.close(fd);
            read?;
            closed?;
        }
        Err(Errno(2)) => {
            let fd = vfs.open_at(AT_FDCWD, b"/vendor/waydroid.prop", 0xc1, 0o644)?;
            vfs.close(fd)?;
        }
        Err(error) => return Err(error.into()),
    }
    if !properties.ends_with(b"\n") {
        properties.push(b'\n');
    }
    // There is no Linux PSI/vmpressure source in the host-managed memory mode.
    // Upstream LMKD explicitly skips zero-threshold monitors. Keep its original
    // control socket, process priorities and replies alive; otherwise every OOM
    // adjustment waits 3 seconds while holding ActivityManager locks. This does
    // not advertise PSI support or perform pressure-based Android app killing.
    // The original HWC can also put its cursor on a native-image subsurface.
    // Use that same retained GPU transport instead of its unaccepted EGL-to-SHM
    // cursor readback path. Explicit caller settings still win over defaults.
    let defaults = b"ro.lmk.use_new_strategy=true\nro.lmk.psi_partial_stall_ms=0\nro.lmk.psi_complete_stall_ms=0\nro.cold_boot_done=true\nro.zygote=zygote64\ndalvik.vm.dex2oat64.enabled=true\nro.product.cpu.abilist=arm64-v8a\nro.product.cpu.abilist64=arm64-v8a\nro.product.cpu.abilist32=\nsys.use_memfd=true\nwaydroid.stub_sensors_hal=true\nwaydroid.xdg_runtime_dir=/run/trames-wayland\nwaydroid.wayland_display=wayland-0\npersist.waydroid.cursor_on_subsurface=true\n";
    for line in defaults
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
    {
        let key = &line[..line.iter().position(|b| *b == b'=').unwrap()];
        if !properties
            .split(|b| *b == b'\n')
            .any(|old| old.split(|b| *b == b'=').next() == Some(key))
        {
            properties.extend(line);
            properties.push(b'\n');
        }
    }
    vfs.mount(
        Some(b"tmpfs"),
        b"/run",
        Some(b"tmpfs"),
        2 | 4,
        Some(b"mode=755,uid=0,gid=0,size=0,nr_inodes=0"),
    )?;
    directory(vfs, b"/run/trames-android", 0o755)?;
    // The selected Waydroid image has 64-bit audio implementations but a
    // 32-bit launcher. An explicitly installed ARM64 launcher reuses those
    // original implementations; other images and absent helpers stay intact.
    if optional_file(vfs, b"/vendor/bin/hw/trames-hal-service")?.is_some()
        && optional_file(vfs, b"/vendor/bin/hw/android.hardware.audio.service")?
            .is_some_and(|bytes| bytes.starts_with(b"\x7fELF\x01"))
    {
        for (name, path) in [
            (
                "audio-service.rc",
                b"/vendor/etc/init/android.hardware.audio.service.rc".as_slice(),
            ),
            ("waydroid-init.rc", b"/system/etc/init/init.waydroid.rc"),
        ] {
            if let Some(bytes) = optional_file(vfs, path)? {
                overlay(vfs, name, path, &audio_launcher(&bytes)?)?;
            }
        }
    }
    // This image ships a 64/32 service file but not a 64-only variant. Retain
    // its original primary zygote service and omit the unsupported 32-bit one.
    if optional_file(vfs, b"/system/etc/init/hw/init.zygote64.rc")?.is_none_or(|v| v.is_empty()) {
        if let Some(bytes) = optional_file(vfs, b"/system/etc/init/hw/init.zygote64_32.rc")? {
            let end = bytes
                .windows(b"\nservice zygote_secondary ".len())
                .position(|s| s == b"\nservice zygote_secondary ")
                .unwrap_or(bytes.len());
            overlay(
                vfs,
                "zygote64.rc",
                b"/system/etc/init/hw/init.zygote64.rc",
                &bytes[..end],
            )?;
        }
    }
    // Waydroid's original loader supports no-BPF operation. A zero memlock
    // ceiling must not prevent that program from reaching its own fallback;
    // do not advertise memory pinning or a successful BPF load in the kernel.
    if let Some(bytes) = optional_file(vfs, b"/system/etc/init/bpfloader.rc")? {
        let text = String::from_utf8(bytes)?;
        let configured = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("rlimit memlock "))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        overlay(
            vfs,
            "bpfloader.rc",
            b"/system/etc/init/bpfloader.rc",
            configured.as_bytes(),
        )?;
    }
    // Init's physical keychord scanner opens /dev/input entries without
    // O_NONBLOCK, before InputFlinger/HWC start. Named Waydroid input pipes
    // therefore deadlock the boot if the Lineage bugreport hardware chord is
    // registered. Keep the original bugreport service, omit its physical chord.
    if let Some(bytes) = optional_file(vfs, b"/system_ext/etc/init/init.lineage-system_ext.rc")? {
        let text = String::from_utf8(bytes)?;
        let configured = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("keycodes "))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        overlay(
            vfs,
            "lineage-system_ext.rc",
            b"/system_ext/etc/init/init.lineage-system_ext.rc",
            configured.as_bytes(),
        )?;
    }
    // An explicit pressure configuration can still be unsupported. This
    // experimental profile must report that failure without reboot-looping.
    if let Some(bytes) = optional_file(vfs, b"/system/etc/init/lmkd.rc")? {
        let text = String::from_utf8(bytes)?;
        let configured = text
            .lines()
            .map(|line| {
                if line.trim() == "critical" {
                    "    restart_period 60"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        overlay(
            vfs,
            "lmkd.rc",
            b"/system/etc/init/lmkd.rc",
            configured.as_bytes(),
        )?;
    }
    crate::systemd::file(
        vfs,
        b"/run/trames-android/cmdline",
        b"selinux=0 androidboot.hardware=waydroid androidboot.container=trames\n",
    )?;
    vfs.mount(
        Some(b"/run/trames-android/cmdline"),
        b"/proc/cmdline",
        None,
        4096,
        None,
    )?;
    crate::systemd::file(vfs, b"/run/trames-android/waydroid.prop", &properties)?;
    vfs.mount(
        Some(b"/run/trames-android/waydroid.prop"),
        b"/vendor/waydroid.prop",
        None,
        4096,
        None,
    )?;
    Ok(())
}

/// The Android composer runs as a non-root guest service. Grant that guest
/// endpoint access only; no host socket or host filesystem permissions change.
pub fn display(vfs: &mut Vfs, directory: &[u8]) -> Result<()> {
    vfs.chmod_at(AT_FDCWD, directory, 0o755)?;
    let mut socket = directory.to_vec();
    socket.extend_from_slice(b"/wayland-0");
    vfs.chmod_at(AT_FDCWD, &socket, 0o666)?;
    // Original Waydroid HWC defaults to a background-only session until its
    // launcher requests the full UI. Let HWC publish its own active-app state.
    let mut properties = optional_file(vfs, b"/vendor/waydroid.prop")?.unwrap_or_default();
    if !properties
        .split(|b| *b == b'\n')
        .any(|line| line.starts_with(b"waydroid.background_start="))
    {
        properties.extend_from_slice(b"\nwaydroid.background_start=false\n");
        let fd = vfs.open_at(AT_FDCWD, b"/vendor/waydroid.prop", 0x201, 0)?;
        let result = vfs.write(fd, &properties);
        let closed = vfs.close(fd);
        if result? != properties.len() {
            return Err("short Android display property write".into());
        }
        closed?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn package_rejects_foreign_init_missing_hal_and_incompatible_contract() {
        let mut vfs = Vfs::default();
        let mut elf = vec![0; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        vfs.import_executable(b"/system/bin/init", elf.clone())
            .unwrap();
        vfs.import_executable(b"/system/bin/bootstrap/linker64", elf.clone())
            .unwrap();
        assert!(validate_image(&mut vfs).is_err());
        for path in [
            b"/vendor/lib64/hw/vulkan.trames.so".as_slice(),
            b"/vendor/lib64/hw/gralloc.trames.so",
            b"/vendor/bin/hw/trames-hal-service",
        ] {
            vfs.import_executable(path, elf.clone()).unwrap();
        }
        validate_image(&mut vfs).unwrap();
        crate::systemd::file(&mut vfs, b"/.trames-android.json", br#"{"schema":1,"target":"android","abi":"arm64-v8a","graphics_contract":2,"android_api":33}"#).unwrap();
        assert!(validate_image(&mut vfs).is_err());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        let mut foreign = Vfs::default();
        foreign.import_executable(b"/system/bin/init", elf).unwrap();
        assert!(validate_image(&mut foreign)
            .unwrap_err()
            .to_string()
            .contains("ARM64"));
    }
    #[test]
    fn arm64_audio_launcher_preserves_original_service_policy_and_other_sections() {
        let source=b"service vendor.audio-hal /vendor/bin/hw/android.hardware.audio.service\n    override\n    user host\n    capabilities BLOCK_SUSPEND\n    rlimit rtprio 10 10\n    onrestart restart audioserver\n\nservice camera /system/bin/cameraserver\n    rlimit rtprio 10 10\n";
        let text = String::from_utf8(audio_launcher(source).unwrap()).unwrap();
        assert!(text.contains("/vendor/bin/hw/trames-hal-service android.hardware.audio@4.0::IDevicesFactory android.hardware.audio.effect@4.0::IEffectsFactory\n"));
        assert!(text.contains(
            "    user host\n    capabilities BLOCK_SUSPEND\n    onrestart restart audioserver\n"
        ));
        assert!(text.contains("service camera /system/bin/cameraserver\n    rlimit rtprio 10 10\n"));
        assert_eq!(text.matches("rlimit rtprio").count(), 1);
    }
    #[test]
    fn boot_resets_property_socket_state_but_keeps_data_and_user_overlay() {
        let mut vfs = Vfs::default();
        for file in [
            b"/system/bin/init".as_slice(),
            b"/system/bin/bootstrap/linker64",
        ] {
            vfs.import_executable(file, b"fixture".to_vec()).unwrap();
        }
        vfs.mkdir_at(AT_FDCWD, b"/vendor", 0o755).unwrap();
        crate::systemd::file(
            &mut vfs,
            b"/vendor/waydroid.prop",
            b"custom\npersist.waydroid.cursor_on_subsurface=false\n",
        )
        .unwrap();
        prepare(&mut vfs).unwrap();
        crate::systemd::file(&mut vfs, b"/dev/socket/old", b"old").unwrap();
        crate::systemd::file(&mut vfs, b"/data/retained", b"data").unwrap();
        prepare(&mut vfs).unwrap();
        assert!(vfs.stat_at(AT_FDCWD, b"/dev/socket/old").is_err());
        for (file, expected) in [
            (b"/data/retained".as_slice(), b"data".as_slice()),
            (b"/vendor/waydroid.prop", b"custom"),
        ] {
            let fd = vfs.open_at(AT_FDCWD, file, 0, 0).unwrap();
            assert!(vfs.read(fd, 1024).unwrap().starts_with(expected));
            vfs.close(fd).unwrap();
        }
        assert_eq!(
            vfs.readlink_at(AT_FDCWD, b"/dev/ptmx").unwrap(),
            b"pts/ptmx"
        );
        assert!(vfs.open_at(AT_FDCWD, b"/dev/binder", 2, 0).is_ok());
        let properties = optional_file(&mut vfs, b"/vendor/waydroid.prop")
            .unwrap()
            .unwrap();
        let properties = String::from_utf8(properties).unwrap();
        assert!(properties.contains("ro.lmk.psi_partial_stall_ms=0\n"));
        assert!(properties.contains("dalvik.vm.dex2oat64.enabled=true\n"));
        assert!(properties.contains("persist.waydroid.cursor_on_subsurface=false\n"));
        assert!(!properties.contains("persist.waydroid.cursor_on_subsurface=true"));
        for name in ["touch", "keyboard", "pointer", "tablet"] {
            let path = format!("/dev/input/wl_{name}_events");
            let stat = vfs.stat_at(AT_FDCWD, path.as_bytes()).unwrap();
            assert_eq!(
                u32::from_le_bytes(stat[16..20].try_into().unwrap()),
                0o10660
            );
        }
    }
    #[test]
    fn full_init_profile_keeps_storage_writable_and_derives_primary_zygote() {
        let mut vfs = Vfs::default();
        for path in [
            b"/system/bin/init".as_slice(),
            b"/system/bin/bootstrap/linker64",
        ] {
            vfs.import_executable(path, b"fixture".to_vec()).unwrap();
        }
        for path in [
            b"/vendor".as_slice(),
            b"/data",
            b"/system/etc",
            b"/system/etc/init",
            b"/system/etc/init/hw",
        ] {
            vfs.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        }
        vfs.symlink_at(b"/data/cache", AT_FDCWD, b"/cache").unwrap();
        crate::systemd::file(&mut vfs, b"/system/etc/init/hw/init.zygote64.rc", b"").unwrap();
        crate::systemd::file(&mut vfs,b"/system/etc/init/hw/init.zygote64_32.rc",b"service zygote /system/bin/app_process64\n    class main\n\nservice zygote_secondary /system/bin/app_process32\n    class main\n").unwrap();
        for path in [
            b"/system_ext".as_slice(),
            b"/system_ext/etc",
            b"/system_ext/etc/init",
        ] {
            vfs.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        }
        crate::systemd::file(
            &mut vfs,
            b"/system_ext/etc/init/init.lineage-system_ext.rc",
            b"service bugreport /system/bin/dumpstate\n    keycodes 114 115 116\n    disabled\n",
        )
        .unwrap();
        prepare(&mut vfs).unwrap();
        let chord = optional_file(&mut vfs, b"/system_ext/etc/init/init.lineage-system_ext.rc")
            .unwrap()
            .unwrap();
        assert_eq!(
            chord,
            b"service bugreport /system/bin/dumpstate\n    disabled\n"
        );
        let fd = vfs
            .open_at(AT_FDCWD, b"/system/etc/init/hw/init.zygote64.rc", 0, 0)
            .unwrap();
        assert_eq!(
            vfs.read(fd, 4096).unwrap(),
            b"service zygote /system/bin/app_process64\n    class main\n"
        );
        vfs.close(fd).unwrap();
        directory(&mut vfs, b"/run/display", 0o755).unwrap();
        crate::systemd::file(&mut vfs, b"/run/display/wayland-0", b"").unwrap();
        display(&mut vfs, b"/run/display").unwrap();
        let props = optional_file(&mut vfs, b"/vendor/waydroid.prop")
            .unwrap()
            .unwrap();
        assert!(props
            .windows(b"persist.waydroid.cursor_on_subsurface=true".len())
            .any(|s| s == b"persist.waydroid.cursor_on_subsurface=true"));
        assert!(props
            .windows(b"waydroid.background_start=false".len())
            .any(|s| s == b"waydroid.background_start=false"));
        vfs.mount(None, b"/", None, 32 | 1, None).unwrap();
        directory(&mut vfs, b"/mnt/user", 0o755).unwrap();
        directory(&mut vfs, b"/mnt/user/0", 0o755).unwrap();
        crate::systemd::file(&mut vfs, b"/mnt/user/0/live", b"volatile").unwrap();
        crate::systemd::file(&mut vfs, b"/data/live", b"persistent").unwrap();
        assert!(matches!(
            vfs.open_at(AT_FDCWD, b"/system/new", 0x41, 0o600),
            Err(Errno(30))
        ));
    }
}
