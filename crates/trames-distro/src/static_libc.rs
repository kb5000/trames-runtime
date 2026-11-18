// SPDX-License-Identifier: GPL-3.0-or-later
//! Reversible, cold whole-library selection shared by pinned libc adapters.
use crate::Error;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};
use trames_vfs::{Errno, Vfs, AT_FDCWD};
const LIMIT: u64 = 4 << 20;
pub(crate) struct Spec {
    pub kind: &'static str,
    pub original: &'static str,
    pub android_api: Option<u32>,
    pub version: Option<&'static str>,
    pub paths: &'static [&'static [u8]],
    pub record: &'static [u8],
    pub tail: &'static str,
    pub mode: u32,
    pub prerequisites: &'static [(&'static [u8], &'static str)],
}
#[derive(Deserialize)]
struct Patch {
    offset: usize,
    original: String,
    nativecall: String,
}
#[derive(Deserialize)]
pub(crate) struct Manifest {
    schema: u32,
    kind: String,
    android_api: Option<u32>,
    version: Option<String>,
    abi: String,
    original_sha256: String,
    original_size: usize,
    native_profile: u64,
    tail_sha256: String,
    added_file_bytes: usize,
    patches: Vec<Patch>,
}
fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Invalid("oversized static libc resource"));
    }
    Ok(bytes)
}
fn contents(vfs: &Vfs, path: &[u8]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    vfs.export_writer(path, &mut bytes)?;
    Ok(bytes)
}
pub(crate) fn manifest(bytes: &[u8], spec: &Spec) -> Result<Manifest, Error> {
    let m: Manifest = serde_json::from_slice(bytes)
        .map_err(|_| Error::Invalid("invalid static libc manifest"))?;
    if m.schema != 1
        || m.kind != spec.kind
        || m.android_api != spec.android_api
        || m.version.as_deref() != spec.version
        || m.abi != "arm64-v8a"
        || m.original_sha256 != spec.original
        || m.native_profile != 0x10001
        || m.original_size > LIMIT as usize
        || m.added_file_bytes > 65536
    {
        return Err(Error::Invalid("unsupported static libc image/ABI"));
    }
    Ok(m)
}
pub(crate) fn hex(text: &str) -> Result<Vec<u8>, Error> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return Err(Error::Invalid("invalid static libc patch bytes"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| Error::Invalid("invalid static libc patch bytes"))
        })
        .collect()
}
pub(crate) fn apply(bytes: &mut [u8], m: &Manifest, reverse: bool) -> Result<(), Error> {
    for p in &m.patches {
        let original = hex(&p.original)?;
        let native = hex(&p.nativecall)?;
        let (from, to) = if reverse {
            (&native, &original)
        } else {
            (&original, &native)
        };
        let end = p
            .offset
            .checked_add(from.len())
            .ok_or(Error::Invalid("static libc patch offset overflow"))?;
        if from.len() != to.len()
            || end > m.original_size
            || bytes.get(p.offset..end) != Some(from.as_slice())
        {
            return Err(Error::Invalid("static libc static layout mismatch"));
        }
        bytes[p.offset..end].copy_from_slice(to);
    }
    Ok(())
}
fn original(current: &[u8], m: &Manifest, spec: &Spec) -> Result<Vec<u8>, Error> {
    if format!("{:x}", Sha256::digest(current)) == spec.original {
        return Ok(current.to_vec());
    }
    let tail = current
        .get(m.original_size..)
        .ok_or(Error::Invalid("unsupported guest static libc"))?;
    if tail.len() != m.added_file_bytes || format!("{:x}", Sha256::digest(tail)) != m.tail_sha256 {
        return Err(Error::Invalid("unsupported guest static libc tail"));
    }
    let mut bytes = current[..m.original_size].to_vec();
    apply(&mut bytes, m, true)?;
    if format!("{:x}", Sha256::digest(&bytes)) != spec.original {
        return Err(Error::Invalid(
            "guest static libc differs from the supported image; retained unchanged",
        ));
    }
    Ok(bytes)
}
fn derived_header(current: &[u8], m: &Manifest) -> bool {
    m.patches.iter().find(|p| p.offset == 32).is_some_and(|p| {
        hex(&p.nativecall)
            .ok()
            .is_some_and(|bytes| current.get(32..32 + bytes.len()) == Some(bytes.as_slice()))
    })
}
/// Called under exclusive environment-store ownership, before any guest runs.
/// `nativecall` is chosen once from the execution backend/configuration. Both
/// variants use the standard supported libc paths and identical dynamic ABI.
/// The small resource contains precompiled code and a fixed installation recipe;
/// constructing guest ELF data here is not compilation of host executable code.
pub(crate) fn install(
    bundle: &Path,
    vfs: &mut Vfs,
    mut nativecall: bool,
    spec: &Spec,
    optional: bool,
) -> Result<bool, Error> {
    let record = bounded(&bundle.join("manifest.json"), 32768)?;
    let m = manifest(&record, spec)?;
    for &(path, expected) in spec.prerequisites {
        let bytes = match contents(vfs, path) {
            Ok(b) => b,
            Err(Error::Vfs(Errno(2))) if optional => {
                // Still restore a previously installed derivative when the
                // paired loader disappeared, before another loader can run it.
                nativecall = false;
                continue;
            }
            Err(e) => return Err(e),
        };
        if format!("{:x}", Sha256::digest(&bytes)) != expected {
            if optional {
                nativecall = false;
            } else {
                return Err(Error::Invalid(
                    "unsupported libc loader; retained unchanged",
                ));
            }
        }
    }
    let tail = bounded(&bundle.join(spec.tail), 65536)?;
    if tail.len() != m.added_file_bytes || format!("{:x}", Sha256::digest(&tail)) != m.tail_sha256 {
        return Err(Error::Invalid("static libc resource digest mismatch"));
    }
    let previous = contents(vfs, spec.record)
        .ok()
        .and_then(|b| manifest(&b, spec).ok());
    let mut changes = Vec::new();
    let mut selected = None;
    // Validate all originals before staging any. Stored prior provenance
    // also restores an older derivative when changing code or disabling thunks.
    for &path in spec.paths {
        let current = match contents(vfs, path) {
            Ok(b) => b,
            Err(Error::Vfs(Errno(2))) if optional => return Ok(false),
            Err(e) => return Err(e),
        };
        let mut bytes = match original(&current, &m, spec).or_else(|error| {
            previous
                .as_ref()
                .map_or(Err(error), |old| original(&current, old, spec))
        }) {
            Ok(bytes) => bytes,
            Err(e) if optional => {
                if derived_header(&current, &m)
                    || previous
                        .as_ref()
                        .is_some_and(|old| derived_header(&current, old))
                {
                    return Err(e);
                }
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        if nativecall {
            apply(&mut bytes, &m, false)?;
            bytes.extend_from_slice(&tail);
        }
        if current != bytes {
            changes.push(path);
        }
        selected = Some(bytes);
    }
    let bytes = selected.ok_or(Error::Invalid("missing static libc paths"))?;
    // Exact original bytes plus the verified static recipe determine the ELF
    // layout. Normal DSO loading preserves the original entry/loader contract.
    // Namespace replacement is per inode, as with musl; not a rootfs
    // transaction. A failed cold startup never proceeds to guest execution.
    // Either variant can recover a partially completed installation on retry.
    for path in &changes {
        let mut staging = path.to_vec();
        staging.extend_from_slice(b".trames-new");
        vfs.import_reader(&staging, &mut bytes.as_slice(), true)?;
        let result = (|| {
            vfs.chown_at(AT_FDCWD, &staging, 0, 0, false)?;
            vfs.chmod_at(AT_FDCWD, &staging, spec.mode)?;
            vfs.rename_at(AT_FDCWD, &staging, AT_FDCWD, path, 0)?;
            Ok::<_, Error>(())
        })();
        if result.is_err() {
            let _ = vfs.unlink_at(AT_FDCWD, &staging, false);
        }
        result?;
    }
    if contents(vfs, spec.record).ok().as_deref() != Some(record.as_slice()) {
        vfs.import_reader_replace(spec.record, &mut record.as_slice())?;
    }
    Ok(!changes.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        path: std::path::PathBuf,
        raw: Vec<u8>,
        loader: Vec<u8>,
        spec: Spec,
        record: serde_json::Value,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    fn fixture() -> Fixture {
        let path = std::env::temp_dir().join(format!(
            "trames-static-libc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let mut raw: Vec<u8> = (0..96).collect();
        raw[32..40].copy_from_slice(&64u64.to_le_bytes());
        let loader = b"original paired loader".to_vec();
        let tail = b"signed-in guest code";
        let spec = Spec {
            kind: "glibc-static",
            original: Box::leak(format!("{:x}", Sha256::digest(&raw)).into_boxed_str()),
            android_api: None,
            version: Some("test"),
            paths: &[b"/usr/lib/libc.so"],
            record: b"/usr/lib/.trames-libc.json",
            tail: "glibc-nativecall.bin",
            mode: 0o755,
            prerequisites: Box::leak(
                vec![(
                    b"/usr/lib/ld.so".as_slice(),
                    Box::leak(format!("{:x}", Sha256::digest(&loader)).into_boxed_str()) as &str,
                )]
                .into_boxed_slice(),
            ),
        };
        let record = serde_json::json!({"schema":1,"kind":spec.kind,"version":"test","abi":"arm64-v8a","original_sha256":spec.original,"original_size":raw.len(),"native_profile":65537,"added_file_bytes":tail.len(),"tail_sha256":format!("{:x}",Sha256::digest(tail)),"patches":[{"offset":1,"original":"01","nativecall":"f5"},{"offset":32,"original":hex_string(&64u64.to_le_bytes()),"nativecall":hex_string(&4096u64.to_le_bytes())}]});
        std::fs::write(
            path.join("manifest.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        std::fs::write(path.join(spec.tail), tail).unwrap();
        Fixture {
            path,
            raw,
            loader,
            spec,
            record,
        }
    }
    fn hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn filesystem(f: &Fixture) -> Vfs {
        let mut v = Vfs::default();
        v.import_reader_replace(f.spec.paths[0], &mut f.raw.as_slice())
            .unwrap();
        v.import_reader_replace(f.spec.prerequisites[0].0, &mut f.loader.as_slice())
            .unwrap();
        v
    }
    #[test]
    fn cold_selection_is_idempotent_reversible_and_preserves_unrelated_data() {
        let f = fixture();
        let mut v = filesystem(&f);
        v.import_reader_replace(b"/user-data", &mut b"retained".as_slice())
            .unwrap();
        assert!(install(&f.path, &mut v, true, &f.spec, false).unwrap());
        let native = contents(&v, f.spec.paths[0]).unwrap();
        assert_ne!(native, f.raw);
        assert!(!install(&f.path, &mut v, true, &f.spec, false).unwrap());
        assert!(install(&f.path, &mut v, false, &f.spec, false).unwrap());
        assert_eq!(contents(&v, f.spec.paths[0]).unwrap(), f.raw);
        assert_eq!(contents(&v, b"/user-data").unwrap(), b"retained");
    }
    #[test]
    fn unsupported_images_are_not_downgraded_and_changed_loader_restores_owned_code() {
        let f = fixture();
        let mut v = filesystem(&f);
        v.import_reader_replace(f.spec.paths[0], &mut b"other vendor version".as_slice())
            .unwrap();
        assert!(install(&f.path, &mut v, true, &f.spec, false).is_err());
        assert!(!install(&f.path, &mut v, true, &f.spec, true).unwrap());
        assert_eq!(
            contents(&v, f.spec.paths[0]).unwrap(),
            b"other vendor version"
        );
        v.import_reader_replace(f.spec.paths[0], &mut f.raw.as_slice())
            .unwrap();
        install(&f.path, &mut v, true, &f.spec, false).unwrap();
        v.import_reader_replace(
            f.spec.prerequisites[0].0,
            &mut b"different loader".as_slice(),
        )
        .unwrap();
        assert!(install(&f.path, &mut v, true, &f.spec, false).is_err());
        assert!(install(&f.path, &mut v, true, &f.spec, true).unwrap());
        assert_eq!(contents(&v, f.spec.paths[0]).unwrap(), f.raw);
        v.import_reader_replace(f.spec.prerequisites[0].0, &mut f.loader.as_slice())
            .unwrap();
        install(&f.path, &mut v, true, &f.spec, false).unwrap();
        v.unlink_at(AT_FDCWD, f.spec.prerequisites[0].0, false)
            .unwrap();
        assert!(install(&f.path, &mut v, false, &f.spec, true).unwrap());
        assert_eq!(contents(&v, f.spec.paths[0]).unwrap(), f.raw);
    }
    #[test]
    fn owned_corruption_and_bad_resources_fail_before_replacement() {
        let f = fixture();
        let mut v = filesystem(&f);
        install(&f.path, &mut v, true, &f.spec, false).unwrap();
        let mut damaged = contents(&v, f.spec.paths[0]).unwrap();
        damaged[3] ^= 1;
        v.import_reader_replace(f.spec.paths[0], &mut damaged.as_slice())
            .unwrap();
        assert!(install(&f.path, &mut v, true, &f.spec, true).is_err());
        assert_eq!(contents(&v, f.spec.paths[0]).unwrap(), damaged);
        std::fs::write(f.path.join(f.spec.tail), b"wrong bytes").unwrap();
        assert!(install(&f.path, &mut v, false, &f.spec, true).is_err());
        assert_eq!(contents(&v, f.spec.paths[0]).unwrap(), damaged);
    }
    #[test]
    fn provenance_restores_old_derivative_for_recipe_upgrade() {
        let f = fixture();
        let mut v = filesystem(&f);
        install(&f.path, &mut v, true, &f.spec, false).unwrap();
        let mut record = f.record.clone();
        let tail = b"new signed-in guest code";
        record["added_file_bytes"] = tail.len().into();
        record["tail_sha256"] = format!("{:x}", Sha256::digest(tail)).into();
        std::fs::write(
            f.path.join("manifest.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        std::fs::write(f.path.join(f.spec.tail), tail).unwrap();
        assert!(install(&f.path, &mut v, true, &f.spec, false).unwrap());
        assert!(contents(&v, f.spec.paths[0]).unwrap().ends_with(tail));
        install(&f.path, &mut v, false, &f.spec, false).unwrap();
        assert_eq!(contents(&v, f.spec.paths[0]).unwrap(), f.raw);
    }
}
