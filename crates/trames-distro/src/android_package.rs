// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold Android composition: pinned upstream ZIP/ext4 images plus a small
//! adapter archive. No mounted image, block emulator or runtime I/O wrapper.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};
use trames_vfs::{Vfs, AT_FDCWD};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const LIMIT: u64 = 4 * 1024 * 1024;
const MANIFEST: &str = ".trames-android.json";
const COMPONENTS: [&str; 3] = [
    "vendor/lib64/hw/vulkan.trames.so",
    "vendor/lib64/hw/gralloc.trames.so",
    "vendor/bin/hw/trames-hal-service",
];
pub const IMAGE_PINS: &str = include_str!("../../../scripts/android-images.json");

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Image {
    pub filename: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
    pub image_name: String,
    pub image_size: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    pub images: Vec<Image>,
}
fn archive(source: &Path) -> Result<tar::Archive<impl Read>> {
    Ok(tar::Archive::new(
        flate2::read::MultiGzDecoder::new(File::open(source)?).take(LIMIT),
    ))
}
/// Only new adapter packages begin with the bounded manifest. Legacy full
/// rootfs archives keep their existing import path, without a full second scan.
pub fn plan(source: &Path) -> Result<Option<Plan>> {
    if source.is_dir() {
        return Ok(None);
    }
    if source.metadata()?.len() > LIMIT {
        return Ok(None);
    }
    let mut magic = [0; 2];
    File::open(source)?.read_exact(&mut magic)?;
    if magic != [0x1f, 0x8b] {
        return Ok(None);
    }
    let mut archive = archive(source)?;
    let mut entries = archive.entries()?;
    let Some(entry) = entries.next() else {
        return Ok(None);
    };
    let mut entry = entry?;
    if entry.path_bytes().as_ref() != MANIFEST.as_bytes() {
        return Ok(None);
    }
    if entry.size() > 65536 {
        return Err("Android package manifest too large".into());
    }
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value["package_kind"] != "adapters" {
        return Ok(None);
    }
    manifest_plan(&value).map(Some)
}
fn manifest_plan(value: &serde_json::Value) -> Result<Plan> {
    if value["schema"] != 1
        || value["target"] != "android"
        || value["android_api"] != 33
        || value["abi"] != "arm64-v8a"
        || value["graphics_contract"] != 1
    {
        return Err("unsupported Android adapter package ABI".into());
    }
    let pins: serde_json::Value = serde_json::from_str(IMAGE_PINS)?;
    if value["images"] != pins {
        return Err("Android package requires unsupported upstream images; update Trames".into());
    }
    Ok(Plan {
        images: ["system", "vendor"]
            .iter()
            .map(|key| serde_json::from_value(pins[key].clone()))
            .collect::<std::result::Result<_, _>>()?,
    })
}
/// Host UI/download code resolves missing inputs; this parser never downloads
/// or creates a service thread. Revalidate bytes before publishing the store.
pub fn install(
    source: &Path,
    images: &Path,
    vfs: &mut Vfs,
    expected: Option<&str>,
) -> Result<String> {
    let mut compressed = Vec::new();
    File::open(source)?
        .take(LIMIT + 1)
        .read_to_end(&mut compressed)?;
    if compressed.len() as u64 > LIMIT {
        return Err("Android adapter archive too large".into());
    }
    let digest = format!("{:x}", Sha256::digest(&compressed));
    if expected.is_some_and(|hash| !hash.eq_ignore_ascii_case(&digest)) {
        return Err("Android adapter SHA-256 mismatch".into());
    }
    let mut payload = BTreeMap::new();
    let mut archive =
        tar::Archive::new(flate2::read::MultiGzDecoder::new(compressed.as_slice()).take(LIMIT));
    let mut total = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = String::from_utf8(entry.path_bytes().into_owned())?;
        if !entry.header().entry_type().is_file()
            || !(COMPONENTS.contains(&name.as_str())
                || [
                    MANIFEST,
                    "vendor/waydroid.prop",
                    ".trames-android/GPL-3.0.txt",
                    ".trames-android/SOURCES.json",
                ]
                .contains(&name.as_str()))
        {
            return Err("unexpected Android adapter payload".into());
        }
        total = total
            .checked_add(entry.size())
            .ok_or("Android adapter size overflow")?;
        if total > LIMIT || payload.contains_key(&name) {
            return Err("oversized or duplicate Android adapter payload".into());
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        payload.insert(name, bytes);
    }
    let manifest: serde_json::Value = serde_json::from_slice(
        payload
            .get(MANIFEST)
            .ok_or("missing Android adapter manifest")?,
    )?;
    if manifest["package_kind"] != "adapters" {
        return Err("not an Android adapter package".into());
    }
    let plan = manifest_plan(&manifest)?;
    if payload.len() != 7
        || payload.get("vendor/waydroid.prop").map(Vec::as_slice)
            != Some(
                b"ro.hardware.vulkan=trames\nro.hardware.egl=angle\nro.hardware.gralloc=trames\n",
            )
    {
        return Err("incomplete Android adapter payload/configuration".into());
    }
    for name in COMPONENTS {
        let bytes = payload
            .get(name)
            .ok_or("missing Android adapter component")?;
        if bytes.get(..5) != Some(b"\x7fELF\x02")
            || bytes.get(18..20) != Some(&183u16.to_le_bytes())
            || manifest["components"][format!("/{name}")]["sha256"]
                != format!("{:x}", Sha256::digest(bytes))
            || manifest["components"][format!("/{name}")]["size"] != bytes.len()
        {
            return Err("Android adapter component digest/ABI mismatch".into());
        }
    }
    for (image, prefix) in plan.images.iter().zip(["", "/vendor"]) {
        let mut input = File::open(images.join(&image.filename))?;
        if input.metadata()?.len() != image.size {
            return Err("upstream Android ZIP size mismatch".into());
        }
        let mut hash = Sha256::new();
        let mut buffer = [0; 65536];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        if format!("{:x}", hash.finalize()) != image.sha256 {
            return Err("upstream Android ZIP SHA-256 mismatch".into());
        }
        input.seek(SeekFrom::Start(0))?;
        let mut zip = zip::ZipArchive::new(input)?;
        if zip.len() != 1 {
            return Err("unexpected upstream Android ZIP entries".into());
        }
        let mut entry = zip.by_name(&image.image_name)?;
        if entry.size() != image.image_size {
            return Err("upstream Android image size mismatch".into());
        }
        // One seekable image at a time, unlinked immediately. No host file tree
        // and no multi-gigabyte buffer; cancellation/error drops the temporary.
        let mut raw = crate::rootfs::temporary()?;
        if io::copy(&mut (&mut entry).take(image.image_size + 1), &mut raw)? != image.image_size {
            return Err("truncated upstream Android image".into());
        }
        raw.seek(SeekFrom::Start(0))?;
        import_ext4(raw, prefix, vfs)?;
    }
    for (name, bytes) in payload {
        let path = format!("/{name}");
        crate::rootfs::mkdirs(vfs, &path.as_bytes()[..path.rfind('/').unwrap()])?;
        if vfs.stat_at_flags(AT_FDCWD, path.as_bytes(), true).is_ok() {
            vfs.unlink_at(AT_FDCWD, path.as_bytes(), false)?;
        }
        let executable = name.starts_with("vendor/bin/");
        vfs.import_reader(path.as_bytes(), &mut bytes.as_slice(), executable)?;
        vfs.chown_at(AT_FDCWD, path.as_bytes(), 0, 0, false)?;
        vfs.chmod_at(
            AT_FDCWD,
            path.as_bytes(),
            if executable { 0o755 } else { 0o644 },
        )?;
    }
    vfs.sync()?;
    crate::android::validate_image(vfs)?;
    Ok(digest)
}

fn import_ext4(raw: File, prefix: &str, vfs: &mut Vfs) -> Result<()> {
    let fs = ext4_view::Ext4::load(Box::new(raw))?;
    let mut pending = vec![ext4_view::PathBuf::try_from("/")?];
    let mut hardlinks = BTreeMap::<u32, Vec<u8>>::new();
    let mut directories = Vec::new();
    let mut seen_dirs = BTreeSet::new();
    let mut count = 0;
    let mut total = 0u64;
    let available = vfs.capacity().available_bytes;
    while let Some(path) = pending.pop() {
        let guest = [prefix.as_bytes(), path.as_ref()].concat();
        crate::rootfs::mkdirs(vfs, &guest)?;
        directories.push((guest.clone(), fs.symlink_metadata(&path)?));
        for entry in fs.read_dir(&path)? {
            let entry = entry?;
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            count += 1;
            if count > vfs.capacity().node_limit {
                return Err("Android image exceeds inode capacity".into());
            }
            let path = entry.path();
            let bytes: &[u8] = path.as_ref();
            if prefix.is_empty()
                && [
                    b"/data/".as_slice(),
                    b"/dev/",
                    b"/proc/",
                    b"/sys/",
                    b"/run/",
                    b"/mnt/",
                    b"/storage/",
                    b"/cache/",
                    b"/metadata/",
                ]
                .iter()
                .any(|p| bytes.starts_with(p))
            {
                continue;
            }
            let guest = [prefix.as_bytes(), bytes].concat();
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                if !seen_dirs.insert(entry.inode_number()) {
                    return Err("cyclic Android image directory".into());
                }
                pending.push(path);
                continue;
            }
            if let Some(previous) = hardlinks.get(&entry.inode_number()) {
                vfs.link_at(AT_FDCWD, previous, AT_FDCWD, &guest)?;
            } else {
                if metadata.is_symlink() {
                    vfs.symlink_at(fs.read_link(&path)?.as_ref(), AT_FDCWD, &guest)?;
                } else if metadata.file_type().is_regular_file() {
                    total = total
                        .checked_add(metadata.len())
                        .ok_or("Android image size overflow")?;
                    if total > available {
                        return Err("Android image exceeds available storage".into());
                    }
                    if vfs.import_reader(
                        &guest,
                        &mut fs.open(&path)?,
                        metadata.mode() & 0o111 != 0,
                    )? != metadata.len()
                    {
                        return Err("truncated Android image file".into());
                    }
                } else {
                    return Err("unsupported special file in Android system/vendor image".into());
                }
                hardlinks.insert(entry.inode_number(), guest.clone());
            }
            attributes(vfs, &guest, &metadata)?;
        }
    }
    for (path, metadata) in directories.iter().rev() {
        attributes(vfs, path, metadata)?;
    }
    Ok(())
}
fn attributes(vfs: &mut Vfs, path: &[u8], metadata: &ext4_view::Metadata) -> Result<()> {
    vfs.chown_at(AT_FDCWD, path, metadata.uid(), metadata.gid(), true)?;
    if !metadata.is_symlink() {
        vfs.chmod_at(AT_FDCWD, path, metadata.mode() as u32)?;
    }
    let a = metadata.accessed();
    let m = metadata.modified();
    vfs.set_times_flags(
        AT_FDCWD,
        Some(path),
        Some([
            [a.seconds(), a.nanoseconds() as i64],
            [m.seconds(), m.nanoseconds() as i64],
        ]),
        0x100,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Archive(std::path::PathBuf);
    impl Archive {
        fn new(files: &[(&str, &[u8])]) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "trames-android-package-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
            let mut tar = tar::Builder::new(encoder);
            for (name, data) in files {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                tar.append_data(&mut h, name, *data).unwrap();
            }
            tar.into_inner().unwrap().finish().unwrap();
            Self(path)
        }
    }
    impl Drop for Archive {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    fn manifest() -> serde_json::Value {
        serde_json::json!({"schema":1,"package_kind":"adapters","target":"android","abi":"arm64-v8a","android_api":33,"graphics_contract":1,"images":serde_json::from_str::<serde_json::Value>(IMAGE_PINS).unwrap()})
    }
    #[test]
    fn plan_only_accepts_pinned_images_and_legacy_does_not_scan_whole_archive() {
        let mut value = manifest();
        let package = Archive::new(&[(MANIFEST, &serde_json::to_vec(&value).unwrap())]);
        let p = plan(&package.0).unwrap().unwrap();
        assert_eq!(p.images.len(), 2);
        assert_eq!(p.images[0].image_size, 1994985472);
        value["images"]["system"]["url"] = "https://invalid.test/custom.zip".into();
        let forged = Archive::new(&[(MANIFEST, &serde_json::to_vec(&value).unwrap())]);
        assert!(plan(&forged.0)
            .unwrap_err()
            .to_string()
            .contains("unsupported upstream"));
        let legacy = Archive::new(&[
            ("init", b"old rootfs"),
            (MANIFEST, b"intentionally invalid later manifest"),
        ]);
        assert!(plan(&legacy.0).unwrap().is_none());
    }
    #[test]
    fn invalid_or_tampered_adapters_fail_before_opening_upstream_images() {
        let value = serde_json::to_vec(&manifest()).unwrap();
        let package = Archive::new(&[(MANIFEST, &value)]);
        let mut vfs = Vfs::default();
        assert!(install(
            &package.0,
            Path::new("/absent-image-cache"),
            &mut vfs,
            Some("incorrect")
        )
        .unwrap_err()
        .to_string()
        .contains("SHA-256"));
        assert!(
            install(&package.0, Path::new("/absent-image-cache"), &mut vfs, None)
                .unwrap_err()
                .to_string()
                .contains("incomplete")
        );
        let duplicate = Archive::new(&[(MANIFEST, &value), (MANIFEST, &value)]);
        assert!(install(
            &duplicate.0,
            Path::new("/absent-image-cache"),
            &mut vfs,
            None
        )
        .unwrap_err()
        .to_string()
        .contains("duplicate"));
        let unexpected = Archive::new(&[(MANIFEST, &value), ("system/bin/init", b"replacement")]);
        assert!(install(
            &unexpected.0,
            Path::new("/absent-image-cache"),
            &mut vfs,
            None
        )
        .unwrap_err()
        .to_string()
        .contains("unexpected"));
        assert!(vfs.stat_at(AT_FDCWD, b"/system").is_err());
    }
    #[test]
    fn ext4_preserves_hardlinks_symlinks_permissions_ids_and_excludes_mutable_payloads() {
        let mut raw = crate::rootfs::temporary().unwrap();
        let compressed = include_bytes!("../../../tests/fixtures/android-import.ext4.gz");
        std::io::copy(
            &mut flate2::read::GzDecoder::new(compressed.as_slice()),
            &mut raw,
        )
        .unwrap();
        raw.flush().unwrap();
        let mut vfs = Vfs::default();
        import_ext4(raw, "", &mut vfs).unwrap();
        let stat = vfs.stat_at(AT_FDCWD, b"/bin/tool").unwrap();
        assert_eq!(
            u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o7777,
            0o755
        );
        assert_eq!(u32::from_le_bytes(stat[24..28].try_into().unwrap()), 1000);
        assert_eq!(u32::from_le_bytes(stat[28..32].try_into().unwrap()), 1001);
        assert_eq!(
            &stat[8..16],
            &vfs.stat_at(AT_FDCWD, b"/bin/tool-hard").unwrap()[8..16]
        );
        assert_eq!(
            vfs.readlink_at(AT_FDCWD, b"/bin/tool-soft").unwrap(),
            b"tool"
        );
        assert_eq!(vfs.readlink_at(AT_FDCWD, b"/tools").unwrap(), b"/bin");
        let fd = vfs.open_at(AT_FDCWD, b"/bin/tool", 0, 0).unwrap();
        assert_eq!(vfs.read(fd, 32).unwrap(), b"preserved");
        vfs.close(fd).unwrap();
        assert!(vfs.stat_at(AT_FDCWD, b"/data/private").is_err());
    }
}
