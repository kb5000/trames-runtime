// SPDX-License-Identifier: GPL-3.0-or-later
//! Pinned distribution verification and checked import into the private VFS.
mod timezone;
mod vulkan;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{self, Read},
};
pub use timezone::synchronize_timezone;
use trames_vfs::{Errno, Vfs, AT_FDCWD, MAX_PATH};
pub use vulkan::install_vulkan_icd;
pub const ALPINE_VERSION: &str = "3.22.6";
pub const ALPINE_URL: &str = "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.6-aarch64.tar.gz";
pub const ALPINE_SHA256: &str = "821565fa8f3953eefd12497b166b4b50add2f7c57fb312e75862f5867e06fefe";
const ARCHIVE_LIMIT: usize = 16 * 1024 * 1024;
const EXPANDED_LIMIT: u64 = 128 * 1024 * 1024;
const ENTRY_LIMIT: usize = 16_384;
pub const MUSL_LOADER: &[u8] = b"/lib/ld-musl-aarch64.so.1";
/// Replace the standard loader inode before starting any guest process.
/// A sibling file is synced before one atomic namespace rename; the ordinary
/// Alpine libc symlink continues to refer to that loader. Identical bytes are
/// a no-op, so opening an existing environment does not rewrite its library.
pub fn install_musl(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    let mut bytes = Vec::new();
    reader
        .take(trames_elf::MAX_ELF_SIZE as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > trames_elf::MAX_ELF_SIZE || bytes.get(16..18) != Some(&3u16.to_le_bytes()) {
        return Err(Error::Invalid("musl must be an AArch64 shared ELF"));
    }
    trames_elf::load(&bytes, trames_memory::DEFAULT_MEMORY_LIMIT)
        .map_err(|_| Error::Invalid("invalid musl ELF or segment layout"))?;
    let alias = vfs.readlink_at(AT_FDCWD, b"/lib/libc.musl-aarch64.so.1")?;
    if alias != b"ld-musl-aarch64.so.1" && alias != MUSL_LOADER {
        return Err(Error::Invalid("unexpected libc alias"));
    }
    if vfs.executable(MUSL_LOADER)? == bytes {
        return Ok(false);
    }
    let staging = b"/lib/.ld-musl-aarch64.so.1.new";
    vfs.import_reader(staging, &mut bytes.as_slice(), true)?;
    let result = (|| {
        vfs.chown_at(AT_FDCWD, staging, 0, 0, false)?;
        vfs.chmod_at(AT_FDCWD, staging, 0o755)?;
        vfs.rename_at(AT_FDCWD, staging, AT_FDCWD, MUSL_LOADER, 0)?;
        Ok(true)
    })();
    if result.is_err() {
        let _ = vfs.unlink_at(AT_FDCWD, staging, false);
    }
    result
}
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Vfs(Errno),
    Invalid(&'static str),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Vfs(e) => e.fmt(f),
            Self::Invalid(e) => write!(f, "distribution archive: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        Self::Vfs(e)
    }
}
enum Content {
    Directory,
    File(Vec<u8>),
    Link(Vec<u8>),
}
struct Entry {
    path: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
    content: Content,
}
fn path(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let bytes = bytes.strip_prefix(b"./").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"/").unwrap_or(bytes);
    if bytes.is_empty() || bytes == b"." {
        return Ok(b"/".to_vec());
    }
    if bytes.starts_with(b"/")
        || bytes.contains(&0)
        || bytes.len() + 1 >= MAX_PATH
        || bytes
            .split(|&b| b == b'/')
            .any(|p| p.is_empty() || p == b".." || p == b"." || p.len() > 255)
    {
        return Err(Error::Invalid("unsafe entry path"));
    }
    let mut out = vec![b'/'];
    out.extend(bytes);
    Ok(out)
}
/// All archive bytes, paths, types and quotas are checked before namespace writes.
/// Only the pinned upstream AArch64 minirootfs is accepted; no tar host extraction.
pub fn install_alpine(reader: &mut impl Read, vfs: &mut Vfs) -> Result<usize, Error> {
    let mut bytes = Vec::new();
    reader
        .take(ARCHIVE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > ARCHIVE_LIMIT {
        return Err(Error::Invalid("compressed size limit"));
    }
    let hash = format!("{:x}", Sha256::digest(&bytes));
    if hash != ALPINE_SHA256 {
        return Err(Error::Invalid("SHA-256 mismatch"));
    }
    let mut tar_bytes = Vec::new();
    flate2::read::GzDecoder::new(bytes.as_slice())
        .take(EXPANDED_LIMIT + 1)
        .read_to_end(&mut tar_bytes)?;
    if tar_bytes.len() as u64 > EXPANDED_LIMIT {
        return Err(Error::Invalid("expanded size limit"));
    }
    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for item in archive.entries()? {
        let mut item = item?;
        let path = path(&item.path_bytes())?;
        if path == b"/" {
            continue;
        }
        if entries.len() >= ENTRY_LIMIT || !names.insert(path.clone()) {
            return Err(Error::Invalid("duplicate entry or entry limit"));
        }
        let mode = item.header().mode()? & 0o7777;
        let uid =
            u32::try_from(item.header().uid()?).map_err(|_| Error::Invalid("uid overflow"))?;
        let gid =
            u32::try_from(item.header().gid()?).map_err(|_| Error::Invalid("gid overflow"))?;
        let content = match item.header().entry_type() {
            tar::EntryType::Directory => Content::Directory,
            tar::EntryType::Regular => {
                if item.size() > 64 * 1024 * 1024 {
                    return Err(Error::Invalid("file size limit"));
                }
                let mut data = Vec::new();
                item.read_to_end(&mut data)?;
                total = total
                    .checked_add(data.len() as u64)
                    .ok_or(Error::Invalid("file size overflow"))?;
                Content::File(data)
            }
            tar::EntryType::Symlink => {
                let target = item
                    .link_name_bytes()
                    .ok_or(Error::Invalid("link target missing"))?
                    .into_owned();
                if target.is_empty() || target.len() >= MAX_PATH || target.contains(&0) {
                    return Err(Error::Invalid("link target"));
                }
                Content::Link(target)
            }
            _ => return Err(Error::Invalid("unsupported archive entry type")),
        };
        entries.push(Entry {
            path,
            mode,
            uid,
            gid,
            content,
        });
    }
    let capacity = vfs.capacity();
    if total > capacity.budget_bytes.saturating_sub(capacity.used_bytes)
        || entries.len() + capacity.nodes_used > capacity.node_limit
    {
        return Err(Error::Invalid("storage capacity"));
    }
    if vfs.stat_at(AT_FDCWD, b"/etc/alpine-release").is_ok() {
        return Err(Error::Invalid("distribution already installed"));
    }
    for e in &entries {
        match vfs.stat_at_flags(AT_FDCWD, &e.path, true) {
            Ok(stat)
                if matches!(e.content, Content::Directory)
                    && u32::from_le_bytes(stat[16..20].try_into().expect("stat mode"))
                        & 0o170000
                        == 0o40000 => {}
            Ok(_) => return Err(Error::Invalid("existing namespace entry")),
            Err(Errno(2)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    entries.sort_by_key(|e| {
        (
            match e.content {
                Content::Directory => 0,
                Content::File(_) => 1,
                Content::Link(_) => 2,
            },
            e.path.len(),
        )
    });
    let count = entries.len();
    let directory_modes: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.content, Content::Directory))
        .map(|e| (e.path.clone(), e.mode))
        .collect();
    for e in entries {
        let regular = matches!(&e.content, Content::File(_));
        match e.content {
            Content::Directory => match vfs.mkdir_at(AT_FDCWD, &e.path, 0o755) {
                Ok(()) | Err(Errno(17)) => {}
                Err(e) => return Err(e.into()),
            },
            Content::File(data) => {
                vfs.import_reader(&e.path, &mut data.as_slice(), e.mode & 0o111 != 0)?;
            }
            Content::Link(target) => vfs.symlink_at(&target, AT_FDCWD, &e.path)?,
        }
        vfs.chown_at(AT_FDCWD, &e.path, e.uid, e.gid, true)?;
        if regular {
            // Restore set-ID bits after ownership changes, as a tar installer does.
            vfs.chmod_at(AT_FDCWD, &e.path, e.mode)?;
        }
    }
    for (path, mode) in directory_modes.into_iter().rev() {
        vfs.chmod_at(AT_FDCWD, &path, mode)?;
    }
    vfs.sync()?;
    Ok(count)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_musl_does_not_modify_existing_loader_or_user_data() {
        let mut vfs = Vfs::default();
        vfs.mkdir_at(AT_FDCWD, b"/lib", 0o755).unwrap();
        vfs.import_executable(MUSL_LOADER, b"original".to_vec())
            .unwrap();
        vfs.import_file(b"/user-data", b"retained".to_vec())
            .unwrap();
        let before = vfs.capacity();
        assert!(install_musl(&mut b"untrusted".as_slice(), &mut vfs).is_err());
        assert_eq!(vfs.executable(MUSL_LOADER).unwrap(), b"original");
        assert_eq!(vfs.capacity().nodes_used, before.nodes_used);
        assert_eq!(vfs.capacity().used_bytes, before.used_bytes);
    }
    #[test]
    fn rejects_host_paths_and_traversal() {
        for p in [
            b"/etc/host".as_slice(),
            b"../x",
            b"a/../b",
            b"a//b",
            b"a\0b",
        ] {
            assert!(path(p).is_err());
        }
        assert_eq!(path(b"./etc/apk/").unwrap(), b"/etc/apk");
    }
    #[test]
    fn mismatch_leaves_namespace_unchanged() {
        let mut v = Vfs::default();
        let before = v.capacity();
        assert!(install_alpine(&mut b"untrusted".as_slice(), &mut v).is_err());
        assert_eq!(v.capacity().nodes_used, before.nodes_used);
    }
}
