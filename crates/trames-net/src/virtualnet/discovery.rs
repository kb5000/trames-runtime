// SPDX-License-Identifier: GPL-3.0-or-later
//! Host-owned names, alive only while the endpoint retains its kernel file leases.
//! Consulted only for local DNS questions; no packet-loop scans, watcher or service thread.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

pub(super) struct Discovery {
    _id: File,
    _name: Option<File>,
}
fn label(name: &str) -> io::Result<String> {
    if name.is_empty()
        || name.len() > 40
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(name.to_ascii_lowercase())
}
fn lease(path: &Path, record: &[u8]) -> io::Result<File> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    file.try_lock().map_err(|e| match e {
        fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::AddrInUse,
            "network DNS name or address is already active",
        ),
        fs::TryLockError::Error(e) => e,
    })?;
    file.write_all(record)?;
    file.set_len(record.len() as u64)?;
    Ok(file)
}
impl Discovery {
    pub fn bind(dir: &Path, id: u8, name: Option<&str>) -> io::Result<Self> {
        let socket = fs::symlink_metadata(dir.join(format!("p{id}")))?;
        let record = format!("{id} {} {}\n", socket.dev(), socket.ino());
        let id_file = lease(&dir.join(format!("id-{id}")), record.as_bytes())?;
        let name_file = name
            .map(|n| lease(&dir.join(format!("name-{}", label(n)?)), record.as_bytes()))
            .transpose()?;
        Ok(Self {
            _id: id_file,
            _name: name_file,
        })
    }
}
fn active(dir: &Path, key: &str) -> Option<u8> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(dir.join(key))
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    match file.try_lock() {
        Err(fs::TryLockError::WouldBlock) => (),
        _ => return None,
    }
    let mut text = String::new();
    (&file).take(128).read_to_string(&mut text).ok()?;
    let fields = text.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 {
        return None;
    }
    let id = fields[0].parse::<u8>().ok()?;
    if !(2..=254).contains(&id) {
        return None;
    }
    let socket = fs::symlink_metadata(dir.join(format!("p{id}"))).ok()?;
    (socket.file_type().is_socket()
        && fields[1].parse::<u64>().ok()? == socket.dev()
        && fields[2].parse::<u64>().ok()? == socket.ino())
    .then_some(id)
}
pub(super) fn resolve(dir: &Path, name: &str) -> Option<u8> {
    let stem = name.strip_suffix(".trames")?;
    // Qualified human names also cover labels reserved for the legacy numeric aliases.
    if let Some(name) = stem.strip_suffix(".env") {
        active(dir, &format!("name-{}", label(name).ok()?))
    } else if let Some(id) = stem.strip_prefix("env").and_then(|n| n.parse::<u8>().ok()) {
        active(dir, &format!("id-{id}"))
    } else {
        active(dir, &format!("name-{}", label(stem).ok()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    #[test]
    fn leases_stop_stale_names_case_collisions_and_address_reuse() {
        let root = std::env::temp_dir().join(format!("trames-dns-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let socket = UnixListener::bind(root.join("p2")).unwrap();
        let live = Discovery::bind(&root, 2, Some("DB")).unwrap();
        for name in ["db.trames", "db.env.trames", "env2.trames"] {
            assert_eq!(resolve(&root, name), Some(2));
        }
        let other = UnixListener::bind(root.join("p3")).unwrap();
        assert!(Discovery::bind(&root, 3, Some("db")).is_err());
        assert_eq!(resolve(&root, "env3.trames"), None);
        assert_eq!(resolve(&root, "../escape.trames"), None);
        // Simulate process death: stale socket/record files do not keep the name alive.
        drop(live);
        drop(socket);
        assert_eq!(resolve(&root, "db.trames"), None);
        assert_eq!(resolve(&root, "env2.trames"), None);
        fs::remove_file(root.join("p2")).unwrap();
        let _socket = UnixListener::bind(root.join("p2")).unwrap();
        let _reused = Discovery::bind(&root, 2, Some("new")).unwrap();
        assert_eq!(resolve(&root, "db.trames"), None);
        assert_eq!(resolve(&root, "new.trames"), Some(2));
        let _reserved = Discovery::bind(&root, 3, Some("env2")).unwrap();
        assert_eq!(resolve(&root, "env2.env.trames"), Some(3));
        assert_eq!(resolve(&root, "env2.trames"), Some(2));
        drop(other);
        fs::remove_dir_all(root).unwrap();
    }
}
