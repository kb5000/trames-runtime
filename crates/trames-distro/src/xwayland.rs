// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

/// Install the small guest launcher before starting guest processes.
pub fn install_xwayland_launcher(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    install(reader, vfs, b"/usr/bin/trames-xwayland", 1024 * 1024)
}

/// Original Xwayland/glamor with the bundled DRM-less EGL transport. Keep the
/// apk-owned server available for the explicit SHM path and package upgrades.
pub fn install_xwayland_native(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    install(
        reader,
        vfs,
        b"/usr/libexec/trames/Xwayland-native",
        16 * 1024 * 1024,
    )
}

fn install(
    reader: &mut impl Read,
    vfs: &mut Vfs,
    path: &[u8],
    limit: usize,
) -> Result<bool, Error> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Invalid("Xwayland executable too large"));
    }
    trames_elf::load_with_interpreter(&bytes, trames_memory::DEFAULT_MEMORY_LIMIT, |path| {
        if path != MUSL_LOADER {
            return Err(trames_elf::ElfError::Invalid(
                "unexpected Xwayland interpreter",
            ));
        }
        vfs.executable(path)
            .map_err(|e| trames_elf::ElfError::Interpreter(e.0))
    })
    .map_err(|_| Error::Invalid("invalid AArch64 Xwayland executable"))?;
    crate::vulkan::replace_mode(vfs, path, &bytes, 0o755)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn executable() -> Vec<u8> {
        let mut b = vec![0u8; 132];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, n) in [(16, 2u16), (18, 183), (52, 64), (54, 56), (56, 1)] {
            b[at..at + 2].copy_from_slice(&n.to_le_bytes());
        }
        for (at, n) in [(20, 1u32), (64, 1), (68, 5), (128, 0xd65f03c0)] {
            b[at..at + 4].copy_from_slice(&n.to_le_bytes());
        }
        for (at, n) in [
            (24, 0x10080u64),
            (32, 64),
            (80, 0x10000),
            (96, 132),
            (104, 4096),
            (112, 4096),
        ] {
            b[at..at + 8].copy_from_slice(&n.to_le_bytes());
        }
        b
    }
    #[test]
    fn xwayland_installers_follow_host_namespace_and_keep_identical_inodes() {
        use std::os::unix::fs::{symlink, MetadataExt};
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Scratch(
            std::env::temp_dir().join(format!("trames-xwayland-sdk-{}", std::process::id())),
        );
        std::fs::create_dir(&root.0).unwrap();
        std::fs::create_dir(root.0.join("assets")).unwrap();
        symlink("assets", root.0.join("usr")).unwrap();
        let mut vfs = Vfs::default();
        vfs.mkdir_at(AT_FDCWD, b"/guest", 0o755).unwrap();
        vfs.mount_host(b"/guest", &root.0, false).unwrap();
        vfs.chroot(b"/guest").unwrap();
        vfs.chdir(b"/").unwrap();
        let bytes = executable();
        assert!(install_xwayland_launcher(&mut bytes.as_slice(), &mut vfs).unwrap());
        let path = root.0.join("assets/bin/trames-xwayland");
        let inode = std::fs::metadata(&path).unwrap().ino();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o755);
        assert!(!install_xwayland_launcher(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        vfs.chmod_at(AT_FDCWD, b"/usr/bin/trames-xwayland", 0o644)
            .unwrap();
        assert!(install_xwayland_launcher(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        assert!(install_xwayland_native(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(
            std::fs::read(root.0.join("assets/libexec/trames/Xwayland-native")).unwrap(),
            bytes
        );
        assert!(install_xwayland_launcher(&mut b"bad".as_slice(), &mut vfs).is_err());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    #[test]
    fn xwayland_installers_keep_private_storage_behavior() {
        let mut vfs = Vfs::default();
        let bytes = executable();
        assert!(install_xwayland_launcher(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert!(!install_xwayland_launcher(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(vfs.executable(b"/usr/bin/trames-xwayland").unwrap(), bytes);
        assert!(install_xwayland_native(&mut bytes.as_slice(), &mut vfs).unwrap());
    }
}
