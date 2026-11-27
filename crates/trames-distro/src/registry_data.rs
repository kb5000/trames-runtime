// SPDX-License-Identifier: GPL-3.0-or-later
//! Portable cold storage operations. Host grants are never copied to a new identity.
use crate::{
    environment::{self as model, Manifest, Result},
    registry::{digest, load, private_dir, Registry},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use trames_vfs::{DiskOptions, Vfs};
pub fn backup(r: &Registry, n: &str, destination: &Path) -> Result<()> {
    let _lock = r.owner_lock(n)?;
    let dir = r.directory(n)?;
    load(&dir)?;
    let vfs = Vfs::open_disk(dir.join("store"), DiskOptions::default())?;
    if destination.try_exists()? {
        return Err("backup destination already exists".into());
    }
    let absolute = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?
        .join(
            destination
                .file_name()
                .ok_or("invalid backup destination")?,
        );
    if absolute.starts_with(&dir.canonicalize()?) {
        return Err("backup destination must be outside the environment".into());
    }
    let temp = destination.with_extension(format!("partial-{}", model::uuid()?));
    let result = (|| {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp)?;
        let gzip = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar = tar::Builder::new(gzip);
        let mut inventory = BTreeMap::new();
        let mut paths = vec![
            PathBuf::from("instance.toml"),
            PathBuf::from("store/manifest"),
        ];
        for e in fs::read_dir(dir.join("store/objects"))? {
            paths.push(PathBuf::from("store/objects").join(e?.file_name()));
        }
        for file in ["env.toml", "effective.toml"] {
            if dir.join(file).is_file() {
                paths.push(file.into());
            }
        }
        paths.sort();
        for rel in paths {
            if !backup_path(&rel) {
                return Err("unexpected store object".into());
            }
            let path = dir.join(&rel);
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err("backup refuses nonregular objects".into());
            }
            inventory.insert(rel.to_string_lossy().into_owned(), digest(&path)?);
            tar.append_path_with_name(path, rel)?;
        }
        let bytes = serde_json::to_vec(&inventory)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append_data(&mut header, "inventory.json", bytes.as_slice())?;
        let file = tar.into_inner()?.finish()?;
        file.sync_all()?;
        // A hard link publishes without replacing an existing destination.
        fs::hard_link(&temp, destination)?;
        File::open(
            destination
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(&temp);
    drop(vfs);
    result
}
fn backup_path(p: &Path) -> bool {
    let Some(s) = p.to_str() else {
        return false;
    };
    matches!(s, "instance.toml" | "env.toml" | "effective.toml")
        || s == "store/manifest"
        || s.strip_prefix("store/objects/").is_some_and(|x| {
            x.len() == 20
                && (x.ends_with(".dat") || x.ends_with(".cap"))
                && x.as_bytes()[..16].iter().all(u8::is_ascii_hexdigit)
        })
}
pub fn restore(
    r: &Registry,
    n: &str,
    archive: &Path,
    check: impl Fn(&Manifest) -> Result<()>,
) -> Result<()> {
    let dir = r.directory(n)?;
    if dir.try_exists()? {
        return Err("restore requires a new environment name".into());
    }
    let stage = r.stage()?;
    private_dir(&stage.0.join("store/objects"))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(File::open(archive)?));
    let mut hashes = BTreeMap::new();
    let mut inventory = None;
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for item in tar.entries()? {
        let mut item = item?;
        let p = item.path()?.into_owned();
        if !seen.insert(p.clone())
            || !item.header().entry_type().is_file()
            || (!backup_path(&p) && p != Path::new("inventory.json"))
        {
            return Err("invalid backup path, type or duplicate entry".into());
        }
        total = total
            .checked_add(item.size())
            .ok_or("backup size overflow")?;
        if total > 1 << 40 || seen.len() > 262146 {
            return Err("backup exceeds supported store size".into());
        }
        if p == Path::new("inventory.json") {
            let mut bytes = vec![];
            item.take(32 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 32 * 1024 * 1024 {
                return Err("oversized backup inventory".into());
            }
            inventory = Some(serde_json::from_slice::<BTreeMap<String, String>>(&bytes)?);
            continue;
        }
        let path = stage.0.join(&p);
        let mut out = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        io::copy(&mut item, &mut out)?;
        out.sync_all()?;
        hashes.insert(p.to_string_lossy().into_owned(), digest(&path)?);
    }
    // Force gzip trailer validation even though tar stops at its end markers.
    io::copy(&mut tar.into_inner(), &mut io::sink())?;
    if inventory.as_ref() != Some(&hashes) {
        return Err("backup file checksum/inventory mismatch".into());
    }
    let mut c = load(&stage.0)?;
    // A portable backup never grants new native paths to its recipient.
    c.environment.name = n.into();
    c.environment.uuid = model::uuid()?;
    c.mounts.clear();
    check(&c)?;
    r.register(&stage.0, &c, true)?;
    let mut vfs = Vfs::open_disk(stage.0.join("store"), DiskOptions::default())?;
    crate::systemd::renew_identity(&mut vfs)?;
    vfs.sync()?;
    drop(vfs);
    r.publish(&stage.0, &c)?;
    println!("Restored {n}; shared directories must be selected again");
    Ok(())
}
/// Copy original private-store objects under its existing single-writer lease.
/// Ordinary file copy (which may use filesystem CoW) never shares writable hardlinks.
pub fn import_store(
    r: &Registry,
    n: &str,
    source: &Path,
    check: impl Fn(&Manifest) -> Result<()>,
) -> Result<()> {
    crate::registry::name(n)?;
    if r.directory(n)?.exists() {
        return Err("environment name already exists".into());
    }
    let source = source.canonicalize()?;
    let source = if source.join("fs/manifest").is_file() {
        source.join("fs")
    } else {
        source
    };
    if !source.join("manifest").is_file() || !source.join("objects").is_dir() {
        return Err("source is not an existing private store".into());
    }
    let original = Vfs::open_disk(&source, DiskOptions::default())?;
    let mut c = if source
        .parent()
        .is_some_and(|p| p.join("instance.toml").is_file())
    {
        load(source.parent().unwrap())?
    } else {
        r.config()?.defaults.using_image("custom")
    };
    c.environment.name = n.into();
    c.environment.uuid = model::uuid()?;
    c.mounts.clear();
    check(&c)?;
    let stage = r.stage()?;
    private_dir(&stage.0.join("store"))?;
    private_dir(&stage.0.join("store/objects"))?;
    let mut paths = vec![PathBuf::from("store/manifest")];
    for e in fs::read_dir(source.join("objects"))? {
        paths.push(PathBuf::from("store/objects").join(e?.file_name()));
    }
    for p in paths {
        if !backup_path(&p) {
            return Err("unexpected private-store object".into());
        }
        let relative = p.strip_prefix("store").unwrap();
        let from = source.join(relative);
        if !fs::symlink_metadata(&from)?.is_file() {
            return Err("store import refuses nonregular objects".into());
        }
        fs::copy(from, stage.0.join(&p))?;
        File::open(stage.0.join(&p))?.sync_all()?;
    }
    drop(original);
    let mut vfs = Vfs::open_disk(stage.0.join("store"), DiskOptions::default())?;
    crate::systemd::renew_identity(&mut vfs)?;
    vfs.sync()?;
    drop(vfs);
    r.register(&stage.0, &c, true)?;
    r.publish(&stage.0, &c)?;
    println!("Imported {n}; shared directories must be selected again");
    Ok(())
}
pub fn clone_environment(
    r: &Registry,
    n: &str,
    new: &str,
    check: impl Fn(&Manifest) -> Result<()>,
) -> Result<()> {
    let _owner = r.owner_lock(n)?;
    import_store(r, new, &r.require(n)?.join("store"), check)
}
