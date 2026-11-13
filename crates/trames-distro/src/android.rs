// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold preparation for the original Waydroid init. This supplies container
//! inputs only: init, properties, logging, Binder and ART remain guest programs.
use trames_vfs::{Errno, Vfs, AT_FDCWD};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
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
        b"/apex",
        b"/linkerconfig",
    ] {
        directory(vfs, path, 0o755)?;
    }
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
    let defaults = b"ro.cold_boot_done=true\nro.zygote=zygote64\nro.product.cpu.abilist=arm64-v8a\nro.product.cpu.abilist64=arm64-v8a\nro.product.cpu.abilist32=\nsys.use_memfd=true\n";
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

#[cfg(test)]
mod tests {
    use super::*;
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
        crate::systemd::file(&mut vfs, b"/vendor/waydroid.prop", b"custom").unwrap();
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
    }
}
