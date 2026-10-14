// SPDX-License-Identifier: GPL-3.0-or-later
//! Install the host's original TZif rules, including historical offsets and DST.
use crate::{Error, Vfs, AT_FDCWD};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_STAGING: AtomicU64 = AtomicU64::new(1);

pub fn synchronize_timezone(vfs: &mut Vfs, identifier: &str, data: &[u8]) -> Result<(), Error> {
    if identifier.is_empty()
        || identifier.len() > 255
        || identifier
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !identifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_+-".contains(&b))
        || !(44..=16384).contains(&data.len())
        || !data.starts_with(b"TZif")
    {
        return Err(Error::Invalid("invalid host timezone name or TZif data"));
    }
    // This is an explicit embedding update to three system files. It does not
    // change the running guest's credentials or export host filesystem access.
    let mut admin = vfs.clone();
    admin.credentials = trames_vfs::Credentials::default();
    for (path, bytes) in [
        (format!("/usr/share/zoneinfo/{identifier}"), data.to_vec()),
        ("/etc/localtime".into(), data.to_vec()),
        (
            "/etc/timezone".into(),
            format!("{identifier}\n").into_bytes(),
        ),
    ] {
        if let Ok(fd) = admin.open_at(AT_FDCWD, path.as_bytes(), 0, 0) {
            let current = admin.read(fd, 16385);
            admin.close(fd)?;
            if current.is_ok_and(|current| current == bytes) {
                continue;
            }
        }
        let mut staging = None;
        for _ in 0..128 {
            let sequence = NEXT_STAGING.fetch_add(1, Ordering::Relaxed);
            let candidate = format!("{path}.trames-timezone-{sequence}");
            match admin.stat_at_flags(AT_FDCWD, candidate.as_bytes(), true) {
                Err(error) if error.0 == 2 => {
                    staging = Some(candidate);
                    break;
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
        }
        let staging = staging.ok_or(Error::Invalid("timezone staging names exhausted"))?;
        admin.import_file(staging.as_bytes(), bytes)?;
        let result = admin.rename_at(AT_FDCWD, staging.as_bytes(), AT_FDCWD, path.as_bytes(), 0);
        if result.is_err() {
            let _ = admin.unlink_at(AT_FDCWD, staging.as_bytes(), false);
        }
        result?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rules() -> Vec<u8> {
        let mut data = vec![0; 44];
        data[..4].copy_from_slice(b"TZif");
        data[36..40].copy_from_slice(&1u32.to_be_bytes());
        data[40..44].copy_from_slice(&4u32.to_be_bytes());
        data.extend_from_slice(&28800i32.to_be_bytes());
        data.extend_from_slice(b"\0\0CST\0");
        data
    }
    fn read(vfs: &mut Vfs, path: &[u8]) -> Vec<u8> {
        let fd = vfs.open_at(AT_FDCWD, path, 0, 0).unwrap();
        let bytes = vfs.read(fd, 16384).unwrap();
        vfs.close(fd).unwrap();
        bytes
    }
    #[test]
    fn timezone_update_replaces_a_dangling_link_preserves_identity_and_is_idempotent() {
        let mut vfs = Vfs::default();
        vfs.mkdir_at(AT_FDCWD, b"/etc", 0o755).unwrap();
        vfs.symlink_at(b"/missing-zone", AT_FDCWD, b"/etc/localtime")
            .unwrap();
        vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        synchronize_timezone(&mut vfs, "Asia/Shanghai", &rules()).unwrap();
        assert_eq!(vfs.credentials.euid, 1000);
        assert_eq!(read(&mut vfs, b"/etc/localtime"), rules());
        assert_eq!(
            read(&mut vfs, b"/usr/share/zoneinfo/Asia/Shanghai"),
            rules()
        );
        assert_eq!(read(&mut vfs, b"/etc/timezone"), b"Asia/Shanghai\n");
        let inode = vfs.stat_at(AT_FDCWD, b"/etc/localtime").unwrap();
        synchronize_timezone(&mut vfs, "Asia/Shanghai", &rules()).unwrap();
        let after = vfs.stat_at(AT_FDCWD, b"/etc/localtime").unwrap();
        assert_eq!(&after[8..16], &inode[8..16]);
        assert_eq!(&after[88..120], &inode[88..120]); // reads may update atime
    }
    #[test]
    fn invalid_timezone_input_leaves_the_namespace_untouched() {
        let mut vfs = Vfs::default();
        let before = vfs.capacity().nodes_used;
        for name in ["", "../escape", "/etc/passwd", "A/../../B", "A//B", "A\0B"] {
            assert!(synchronize_timezone(&mut vfs, name, &rules()).is_err());
        }
        assert!(synchronize_timezone(&mut vfs, "UTC", b"bad").is_err());
        assert_eq!(vfs.capacity().nodes_used, before);
    }
}
