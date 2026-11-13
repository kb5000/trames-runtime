// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold product import into an unpublished guest store. Never extracts on host.
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use trames_vfs::{Vfs, AT_FDCWD, MAX_PATH};

pub(super) fn temporary() -> Result<File> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for _ in 0..32 {
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("trames-rootfs-{}-{id}", std::process::id()));
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                fs::remove_file(path)?;
                return Ok(file);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err("cannot allocate rootfs snapshot".into())
}
pub(super) fn mkdirs(vfs: &mut Vfs, path: &[u8]) -> Result<()> {
    let mut current = Vec::new();
    for part in path.split(|&b| b == b'/').filter(|p| !p.is_empty()) {
        current.push(b'/');
        current.extend_from_slice(part);
        match vfs.stat_at(AT_FDCWD, &current) {
            Ok(stat) if u32::from_le_bytes(stat[16..20].try_into()?) & 0o170000 == 0o40000 => (),
            Ok(_) => return Err("rootfs parent is not a directory".into()),
            Err(e) if e.0 == 2 => vfs.mkdir_at(AT_FDCWD, &current, 0o755)?,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn copy_bounded(input: &mut impl Read, output: &mut File, limit: u64) -> Result<()> {
    if io::copy(&mut input.take(limit.saturating_add(1)), output)? > limit {
        return Err("rootfs exceeds this store's storage capacity".into());
    }
    output.seek(SeekFrom::Start(0))?;
    Ok(())
}
/// Snapshot before hashing/reading, including directory symlinks as links.
/// Only index metadata stays in RAM; archive and decompression use temp files.
pub fn install(source: &Path, vfs: &mut Vfs, expected: Option<&str>) -> Result<String> {
    let capacity = vfs.capacity();
    let limit = capacity
        .budget_bytes
        .saturating_add(capacity.node_limit as u64 * (MAX_PATH as u64 + 1024));
    let mut snapshot = temporary()?;
    if source.is_dir() {
        if expected.is_some() {
            return Err("--sha256 applies to archive bytes, not a directory".into());
        }
        snapshot_directory(source, &mut snapshot, limit)?;
        snapshot.seek(SeekFrom::Start(0))?;
    } else {
        copy_bounded(&mut File::open(source)?, &mut snapshot, limit)?;
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = snapshot.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    let digest = format!("{:x}", hash.finalize());
    if expected.is_some_and(|e| !e.eq_ignore_ascii_case(&digest)) {
        return Err("rootfs SHA-256 mismatch".into());
    }
    snapshot.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 2];
    snapshot.read_exact(&mut magic)?;
    snapshot.seek(SeekFrom::Start(0))?;
    if magic == [0x1f, 0x8b] {
        let mut tar = temporary()?;
        copy_bounded(
            &mut flate2::read::MultiGzDecoder::new(snapshot),
            &mut tar,
            limit,
        )?;
        import_tar(&mut tar, vfs)?;
    } else {
        import_tar(&mut snapshot, vfs)?;
    }
    Ok(digest)
}
struct LimitedWriter<'a> {
    file: &'a mut File,
    remaining: u64,
}
impl Write for LimitedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(io::Error::other(
                "rootfs directory exceeds storage capacity",
            ));
        }
        let n = self.file.write(bytes)?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn snapshot_directory(source: &Path, file: &mut File, limit: u64) -> Result<()> {
    let mut builder = tar::Builder::new(LimitedWriter {
        file,
        remaining: limit,
    });
    builder.follow_symlinks(false);
    let mut pending = vec![(source.to_path_buf(), std::path::PathBuf::from("."))];
    let mut files = BTreeMap::new();
    while let Some((host, guest)) = pending.pop() {
        let metadata = fs::symlink_metadata(&host)?;
        if metadata.is_dir() {
            builder.append_dir(&guest, &host)?;
            let mut children: Vec<_> = fs::read_dir(&host)?.collect::<io::Result<_>>()?;
            children.sort_by_key(|entry| entry.file_name());
            for child in children.into_iter().rev() {
                pending.push((child.path(), guest.join(child.file_name())));
            }
        } else if metadata.is_file() && metadata.nlink() > 1 {
            if let Some(target) = files.get(&(metadata.dev(), metadata.ino())) {
                let mut header = tar::Header::new_gnu();
                header.set_metadata(&metadata);
                header.set_entry_type(tar::EntryType::Link);
                header.set_size(0);
                builder.append_link(&mut header, &guest, target)?;
            } else {
                builder.append_path_with_name(&host, &guest)?;
                files.insert((metadata.dev(), metadata.ino()), guest);
            }
        } else {
            builder.append_path_with_name(&host, &guest)?;
        }
    }
    builder.finish()?;
    Ok(())
}
#[derive(Clone)]
enum Kind {
    Directory,
    File { offset: u64, size: u64 },
    Symlink(Vec<u8>),
    Hardlink(Vec<u8>),
    Device(u32, u64),
}
struct Entry {
    path: Vec<u8>,
    kind: Kind,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: i64,
}
fn archive_path(mut bytes: &[u8]) -> Result<Vec<u8>> {
    while let Some(rest) = bytes.strip_prefix(b"./") {
        bytes = rest;
    }
    while let Some(rest) = bytes.strip_suffix(b"/") {
        bytes = rest;
    }
    if bytes.is_empty() || bytes == b"." {
        return Ok(b"/".to_vec());
    }
    if bytes.starts_with(b"/")
        || bytes.contains(&0)
        || bytes.len() + 1 >= MAX_PATH
        || bytes
            .split(|b| *b == b'/')
            .any(|p| p.is_empty() || p == b".." || p == b"." || p.len() > 255)
    {
        return Err("unsafe rootfs archive path".into());
    }
    Ok([b"/".as_slice(), bytes].concat())
}
fn resolve(path: &[u8], final_link: bool, links: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<Vec<u8>> {
    let mut pending: VecDeque<Vec<u8>> = path.split(|b| *b == b'/').map(Vec::from).collect();
    let mut result: Vec<Vec<u8>> = vec![];
    let mut hops = 0;
    while let Some(part) = pending.pop_front() {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            result.pop();
            continue;
        }
        let mut key = vec![b'/'];
        for p in &result {
            key.extend(p);
            key.push(b'/');
        }
        key.extend(&part);
        if key.len() >= MAX_PATH {
            return Err("rootfs link path too long".into());
        }
        if let Some(target) = links
            .get(&key)
            .filter(|_| final_link || !pending.is_empty())
        {
            hops += 1;
            if hops > 40 {
                return Err("rootfs symlink loop".into());
            }
            if target.starts_with(b"/") {
                result.clear();
            }
            for p in target.split(|b| *b == b'/').rev() {
                pending.push_front(p.to_vec());
            }
        } else {
            result.push(part);
        }
    }
    let mut bytes = vec![b'/'];
    for (i, part) in result.iter().enumerate() {
        if i != 0 {
            bytes.push(b'/');
        }
        bytes.extend(part);
    }
    Ok(bytes)
}
fn import_tar(input: &mut File, vfs: &mut Vfs) -> Result<()> {
    let length = input.metadata()?.len();
    let mut archive = tar::Archive::new(&mut *input);
    let mut entries = vec![];
    let mut links = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    let capacity = vfs.capacity();
    for item in archive.entries_with_seek()? {
        let item = item?;
        let path = archive_path(&item.path_bytes())?;
        if entries.len() >= capacity.node_limit || !names.insert(path.clone()) {
            return Err("duplicate rootfs path or inode capacity exceeded".into());
        }
        let header = item.header();
        let mode = header.mode()? & 0o7777;
        let kind = match header.entry_type() {
            tar::EntryType::Directory => Kind::Directory,
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let size = item.size(); let offset = item.raw_file_position();
                if offset.checked_add(size).is_none_or(|end| end > length) { return Err("truncated rootfs file".into()); }
                total = total.checked_add(size).ok_or("rootfs size overflow")?;
                Kind::File { offset, size }
            }
            tar::EntryType::Symlink => {
                let target = item.link_name_bytes().ok_or("missing rootfs symlink target")?.into_owned();
                if target.is_empty() || target.contains(&0) || target.len() >= MAX_PATH { return Err("invalid rootfs link target".into()); }
                links.insert(path.clone(), target.clone()); Kind::Symlink(target)
            }
            tar::EntryType::Link => Kind::Hardlink(archive_path(&item.link_name_bytes().ok_or("missing rootfs hardlink target")?)?),
            tar::EntryType::Fifo => Kind::Device(0o10000, 0),
            kind @ (tar::EntryType::Char | tar::EntryType::Block) => {
                let major = header.device_major()?.ok_or("missing device major")?;
                let minor = header.device_minor()?.ok_or("missing device minor")?;
                if major > 0xfff || minor > 0xfffff { return Err("rootfs device number exceeds Linux ABI".into()); }
                Kind::Device(if kind==tar::EntryType::Char {0o20000} else {0o60000}, ((major << 8) | (minor & 255) | ((minor & !255) << 12)) as u64)
            }
            _ => return Err("unsupported rootfs entry type (use an ordinary rootfs tar, not an OCI image archive or sparse tar)".into()),
        };
        entries.push(Entry {
            path,
            kind,
            mode,
            uid: header.uid()?.try_into()?,
            gid: header.gid()?.try_into()?,
            mtime: header.mtime()?.try_into()?,
        });
    }
    if total > capacity.available_bytes {
        return Err("rootfs exceeds available private storage".into());
    }
    let mut canonical = BTreeSet::new();
    for e in &mut entries {
        e.path = resolve(&e.path, false, &links)?;
        if !canonical.insert(e.path.clone()) {
            return Err("rootfs entries alias the same guest path".into());
        }
        if let Kind::Hardlink(target) = &mut e.kind {
            *target = resolve(target, false, &links)?;
        }
    }
    entries.sort_by_key(|e| {
        (
            match e.kind {
                Kind::Directory => 0,
                Kind::Hardlink(_) => 2,
                _ => 1,
            },
            e.path.len(),
        )
    });
    let umask = vfs.set_umask(0);
    let result = (|| {
        let mut hardlinks = vec![];
        for e in &entries {
            if e.path == b"/" {
                if !matches!(e.kind, Kind::Directory) {
                    return Err("rootfs root must be a directory".into());
                }
                continue;
            }
            let parent = &e.path[..e.path.iter().rposition(|b| *b == b'/').unwrap()];
            mkdirs(vfs, parent)?;
            if matches!(e.kind, Kind::Directory) {
                mkdirs(vfs, &e.path)?;
                continue;
            }
            // The fresh VFS supplies /dev/null. Replace that placeholder only
            // inside this unpublished guest store, using the image's inode.
            if vfs.stat_at_flags(AT_FDCWD, &e.path, true).is_ok() {
                vfs.unlink_at(AT_FDCWD, &e.path, false)?;
            }
            match &e.kind {
                Kind::File { offset, size } => {
                    input.seek(SeekFrom::Start(*offset))?;
                    if vfs.import_reader(
                        &e.path,
                        &mut (&mut *input).take(*size),
                        e.mode & 0o111 != 0,
                    )? != *size
                    {
                        return Err("truncated rootfs file".into());
                    }
                }
                Kind::Symlink(target) => vfs.symlink_at(target, AT_FDCWD, &e.path)?,
                Kind::Device(kind, dev) => vfs.mknod_at(AT_FDCWD, &e.path, kind | e.mode, *dev)?,
                Kind::Hardlink(target) => hardlinks.push((e.path.as_slice(), target.as_slice())),
                Kind::Directory => unreachable!(),
            }
        }
        while !hardlinks.is_empty() {
            let before = hardlinks.len();
            let mut next = vec![];
            for (path, target) in hardlinks {
                match vfs.link_at(AT_FDCWD, target, AT_FDCWD, path) {
                    Ok(()) => (),
                    Err(trames_vfs::Errno(2)) => next.push((path, target)),
                    Err(e) => return Err(e.into()),
                }
            }
            if next.len() == before {
                return Err("missing or cyclic rootfs hardlink target".into());
            }
            hardlinks = next;
        }
        for e in entries.iter().rev() {
            vfs.chown_at(AT_FDCWD, &e.path, e.uid, e.gid, true)?;
            let symlink = matches!(e.kind, Kind::Symlink(_))
                || (matches!(e.kind, Kind::Hardlink(_))
                    && u32::from_le_bytes(
                        vfs.stat_at_flags(AT_FDCWD, &e.path, true)?[16..20].try_into()?,
                    ) & 0o170000
                        == 0o120000);
            if !symlink {
                vfs.chmod_at(AT_FDCWD, &e.path, e.mode)?;
            }
            vfs.set_times_flags(AT_FDCWD, Some(&e.path), Some([[e.mtime, 0]; 2]), 0x100)?;
        }
        vfs.sync()?;
        Ok(())
    })();
    vfs.set_umask(umask);
    result
}

/// Validate only the selected entrypoint, not every image binary. Execution
/// still uses the common ELF loader and normal guest permissions.
pub fn validate_command(vfs: &mut Vfs, argv: &[String]) -> Result<()> {
    let mut path = argv
        .first()
        .ok_or("missing Linux command")?
        .as_bytes()
        .to_vec();
    for _ in 0..5 {
        let stat = vfs.stat_at(AT_FDCWD, &path)?;
        if u32::from_le_bytes(stat[16..20].try_into()?) & 0o111 == 0 {
            return Err("Linux command is not executable".into());
        }
        let fd = vfs.open_at(AT_FDCWD, &path, 0, 0)?;
        let bytes = vfs.read(fd, 4096);
        vfs.close(fd)?;
        let bytes = bytes?;
        if let Some((interpreter, _)) = trames_vfs::script_interpreter(&bytes)? {
            path = interpreter;
            continue;
        }
        if bytes.get(..4) == Some(b"\x7fELF")
            && bytes.get(4..6) == Some(&[2, 1])
            && matches!(bytes.get(7), Some(0 | 3))
            && bytes.get(18..20) == Some(&183u16.to_le_bytes())
        {
            return Ok(());
        }
        return Err(
            "rootfs command must be a Linux ARM64 ELF or script (x86 and Mach-O are not supported)"
                .into(),
        );
    }
    Err("rootfs command interpreter loop".into())
}
