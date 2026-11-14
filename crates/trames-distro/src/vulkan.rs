// SPDX-License-Identifier: GPL-3.0-or-later
//! Install app-owned graphics/video libraries before guest startup.
use crate::{Error, Vfs, AT_FDCWD};
use std::{
    io::Read,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_STAGING: AtomicU64 = AtomicU64::new(1);
const LIMIT: usize = 4 * 1024 * 1024;
const GALLIUM_LIMIT: usize = 64 * 1024 * 1024;
const LIBRARY: &[u8] = b"/usr/lib/libtrames_vulkan_icd.so";
const MANIFEST: &[u8] = b"/usr/share/vulkan/icd.d/trames.json";
const JSON: &[u8] = br#"{"file_format_version":"1.0.0","ICD":{"api_version":"1.1.0","library_path":"/usr/lib/libtrames_vulkan_icd.so"}}"#;

/// Validate before changing the namespace, keep identical inodes, and replace
/// updated files with a synced sibling + atomic rename before guest startup.
pub fn install_vulkan_icd(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    let mut bytes = Vec::new();
    reader.take(LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT
        || bytes.get(..6) != Some(b"\x7fELF\x02\x01")
        || bytes.get(18..20) != Some(&183u16.to_le_bytes())
    {
        return Err(Error::Invalid("invalid bundled AArch64 Vulkan ICD"));
    }
    let library = replace(vfs, LIBRARY, &bytes)?;
    let manifest = replace(vfs, MANIFEST, JSON)?;
    Ok(library || manifest)
}
/// The optional app-owned Mesa EGL platform adapter uses the standard SONAME
/// in musl's /usr/local/lib search path. Original apk-owned Mesa/Gallium files
/// stay under /usr/lib, so installing/upgrading signed packages cannot overwrite
/// the adapter and existing rootfs data needs no migration.
pub fn install_zink_egl(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    install_library(reader, vfs, b"/usr/local/lib/libEGL.so.1", LIMIT)
}
/// The EGL frontend and Gallium share Mesa's private ABI. Install the matching
/// patched Zink library beside EGL, leaving signed distro package files intact.
pub fn install_zink_gallium(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    install_library(
        reader,
        vfs,
        b"/usr/local/lib/libgallium-25.1.9.so",
        GALLIUM_LIMIT,
    )
}
/// Cold-start app-owned VideoToolbox VA-API driver, using the same atomic
/// replacement and unchanged-file handling as the graphics adapters.
pub fn install_vaapi_driver(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    install_library(
        reader,
        vfs,
        b"/usr/local/lib/dri/trames_drv_video.so",
        LIMIT,
    )
}
/// ABI-compatible decoder overlay; distro libraries remain under /usr/lib.
pub fn install_video_codec(
    reader: &mut impl Read,
    vfs: &mut Vfs,
    name: &str,
) -> Result<bool, Error> {
    if !matches!(
        name,
        "libavcodec.so.61" | "libavutil.so.59" | "libswresample.so.5" | "libswscale.so.8"
    ) {
        return Err(Error::Invalid("unsupported bundled video library"));
    }
    install_library(
        reader,
        vfs,
        format!("/usr/local/lib/{name}").as_bytes(),
        GALLIUM_LIMIT,
    )
}
fn install_library(
    reader: &mut impl Read,
    vfs: &mut Vfs,
    path: &[u8],
    limit: usize,
) -> Result<bool, Error> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit
        || bytes.get(..6) != Some(b"\x7fELF\x02\x01")
        || bytes.get(18..20) != Some(&183u16.to_le_bytes())
    {
        return Err(Error::Invalid("invalid bundled AArch64 guest library"));
    }
    replace(vfs, path, &bytes)
}
fn replace(vfs: &mut Vfs, path: &[u8], bytes: &[u8]) -> Result<bool, Error> {
    if let Ok(fd) = vfs.open_at(AT_FDCWD, path, 0, 0) {
        // VFS reads may be short (including its per-call transfer ceiling).
        // Compare in bounded chunks so large Gallium files keep their inode
        // on subsequent boots without allocating another library-sized copy.
        let current: Result<bool, trames_vfs::Errno> = (|| {
            let mut offset = 0;
            loop {
                let chunk = vfs.read(fd, (bytes.len() - offset + 1).min(1 << 20))?;
                if chunk.is_empty() {
                    return Ok(offset == bytes.len());
                }
                if bytes.get(offset..offset + chunk.len()) != Some(chunk.as_slice()) {
                    return Ok(false);
                }
                offset += chunk.len();
            }
        })();
        vfs.close(fd)?;
        if current == Ok(true) {
            return Ok(false);
        }
    }
    let mut staging = None;
    for _ in 0..128 {
        let mut candidate = path.to_vec();
        candidate.extend_from_slice(
            format!(
                ".trames-icd-{}.new",
                NEXT_STAGING.fetch_add(1, Ordering::Relaxed)
            )
            .as_bytes(),
        );
        match vfs.stat_at_flags(AT_FDCWD, &candidate, true) {
            Err(error) if error.0 == 2 => {
                staging = Some(candidate);
                break;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
    }
    let staging = staging.ok_or(Error::Invalid("Vulkan staging names exhausted"))?;
    let mut reader = bytes;
    vfs.import_reader(&staging, &mut reader, false)?;
    let result = vfs.rename_at(AT_FDCWD, &staging, AT_FDCWD, path, 0);
    if result.is_err() {
        let _ = vfs.unlink_at(AT_FDCWD, &staging, false);
    }
    result?;
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn library() -> Vec<u8> {
        // Installation checks the same signed-bundle header as the embedding;
        // this fixture is never executed or passed to a native driver.
        let mut bytes = vec![0; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
        bytes
    }
    fn read(vfs: &mut Vfs, path: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        vfs.export_writer(path, &mut bytes).unwrap();
        bytes
    }
    #[test]
    fn refreshes_old_instance_manifest_without_replacing_identical_library() {
        let mut vfs = Vfs::default();
        let bytes = library();
        vfs.import_file(LIBRARY, bytes.clone()).unwrap();
        vfs.import_file(
            MANIFEST,
            String::from_utf8(JSON.to_vec())
                .unwrap()
                .replace("1.1.0", "1.0.0")
                .into_bytes(),
        )
        .unwrap();
        let inode = vfs.stat_at(AT_FDCWD, LIBRARY).unwrap();
        assert!(install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(read(&mut vfs, MANIFEST), JSON);
        assert_eq!(
            &inode[8..16],
            &vfs.stat_at(AT_FDCWD, LIBRARY).unwrap()[8..16]
        );
        assert!(!install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap());
    }
    #[test]
    fn repeated_install_keeps_inodes_updates_bundles_and_preserves_user_files() {
        let mut vfs = Vfs::default();
        vfs.import_file(b"/root/user-data", b"keep".to_vec())
            .unwrap();
        let mut bytes = library();
        assert!(install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap());
        let before = vfs.stat_at(AT_FDCWD, LIBRARY).unwrap();
        let manifest = vfs.stat_at(AT_FDCWD, MANIFEST).unwrap();
        assert!(!install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(
            &before[8..16],
            &vfs.stat_at(AT_FDCWD, LIBRARY).unwrap()[8..16]
        );
        bytes.push(42);
        assert!(install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(read(&mut vfs, LIBRARY), bytes);
        assert_eq!(
            &manifest[8..16],
            &vfs.stat_at(AT_FDCWD, MANIFEST).unwrap()[8..16]
        );
        assert_eq!(read(&mut vfs, b"/root/user-data"), b"keep");
        vfs.unlink_at(AT_FDCWD, MANIFEST, false).unwrap();
        assert!(install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(read(&mut vfs, MANIFEST), JSON);
        vfs.unlink_at(AT_FDCWD, LIBRARY, false).unwrap();
        vfs.symlink_at(b"/root/user-data", AT_FDCWD, LIBRARY)
            .unwrap();
        install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap();
        assert_eq!(read(&mut vfs, b"/root/user-data"), b"keep");
        assert_eq!(read(&mut vfs, LIBRARY), bytes);
        assert!(install_vulkan_icd(&mut b"bad".as_slice(), &mut vfs).is_err());
        assert_eq!(read(&mut vfs, LIBRARY), bytes);
    }
    #[test]
    fn egl_adapter_install_is_atomic_and_keeps_apk_owned_mesa() {
        let mut vfs = Vfs::default();
        let apk = b"original signed Mesa package";
        vfs.import_file(b"/usr/lib/libEGL.so.1", apk.to_vec())
            .unwrap();
        let mut bytes = library();
        let path = b"/usr/local/lib/libEGL.so.1";
        assert!(install_zink_egl(&mut bytes.as_slice(), &mut vfs).unwrap());
        let first = vfs.stat_at(AT_FDCWD, path).unwrap();
        assert!(!install_zink_egl(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(&first[8..16], &vfs.stat_at(AT_FDCWD, path).unwrap()[8..16]);
        bytes.push(1);
        assert!(install_zink_egl(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert!(install_zink_egl(&mut b"invalid".as_slice(), &mut vfs).is_err());
        assert_eq!(read(&mut vfs, path), bytes);
        assert_eq!(read(&mut vfs, b"/usr/lib/libEGL.so.1"), apk);
    }
    #[test]
    fn paired_gallium_can_exceed_the_small_icd_limit_and_keeps_package_files() {
        let mut vfs = Vfs::default();
        let apk = b"original distro Gallium";
        vfs.import_file(b"/usr/lib/libgallium-25.1.9.so", apk.to_vec())
            .unwrap();
        let mut bytes = library();
        bytes.resize(LIMIT + 1, 0);
        let path = b"/usr/local/lib/libgallium-25.1.9.so";
        assert!(install_zink_gallium(&mut bytes.as_slice(), &mut vfs).unwrap());
        let first = vfs.stat_at(AT_FDCWD, path).unwrap();
        assert!(!install_zink_gallium(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(&first[8..16], &vfs.stat_at(AT_FDCWD, path).unwrap()[8..16]);
        assert!(install_zink_gallium(&mut b"invalid".as_slice(), &mut vfs).is_err());
        assert_eq!(read(&mut vfs, path), bytes);
        assert_eq!(read(&mut vfs, b"/usr/lib/libgallium-25.1.9.so"), apk);
    }
}
