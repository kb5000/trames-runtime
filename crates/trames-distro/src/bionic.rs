// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold, whole-library selection for the pinned Android image. No ELF symbol
//! interposition, CPU/architecture checks or extra dispatch in guest calls.
use crate::Error;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};
use trames_vfs::{Vfs, AT_FDCWD};

const ORIGINAL: &str = "6aa289f3b6042793ccacd873ce3724dcaae240943112eec126f7be654f01e6cc";
const LIMIT: u64 = 4 << 20;
const PATHS: [&[u8]; 2] = [
    b"/system/apex/com.android.runtime/lib64/bionic/libc.so",
    b"/system/lib64/bootstrap/libc.so",
];
const RECORD: &[u8] = b"/system/lib64/.trames-bionic.json";

#[derive(Deserialize)]
struct Patch {
    offset: usize,
    original: String,
    nativecall: String,
}
#[derive(Deserialize)]
struct Manifest {
    schema: u32,
    kind: String,
    android_api: u32,
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
        return Err(Error::Invalid("oversized Bionic resource"));
    }
    Ok(bytes)
}
fn contents(vfs: &Vfs, path: &[u8]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    vfs.export_writer(path, &mut bytes)?;
    Ok(bytes)
}
fn manifest(bytes: &[u8]) -> Result<Manifest, Error> {
    let m: Manifest =
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid("invalid Bionic manifest"))?;
    if m.schema != 1
        || m.kind != "bionic-static"
        || m.android_api != 33
        || m.abi != "arm64-v8a"
        || m.original_sha256 != ORIGINAL
        || m.native_profile != 0x10001
        || m.original_size > LIMIT as usize
        || m.added_file_bytes > 65536
    {
        return Err(Error::Invalid("unsupported Bionic image/ABI"));
    }
    Ok(m)
}
fn hex(text: &str) -> Result<Vec<u8>, Error> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return Err(Error::Invalid("invalid Bionic patch bytes"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| Error::Invalid("invalid Bionic patch bytes"))
        })
        .collect()
}
fn apply(bytes: &mut [u8], m: &Manifest, reverse: bool) -> Result<(), Error> {
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
            .ok_or(Error::Invalid("Bionic patch offset overflow"))?;
        if from.len() != to.len()
            || end > m.original_size
            || bytes.get(p.offset..end) != Some(from.as_slice())
        {
            return Err(Error::Invalid("Bionic static layout mismatch"));
        }
        bytes[p.offset..end].copy_from_slice(to);
    }
    Ok(())
}
fn original(current: &[u8], m: &Manifest) -> Result<Vec<u8>, Error> {
    if format!("{:x}", Sha256::digest(current)) == ORIGINAL {
        return Ok(current.to_vec());
    }
    let tail = current
        .get(m.original_size..)
        .ok_or(Error::Invalid("unsupported guest Bionic"))?;
    if tail.len() != m.added_file_bytes || format!("{:x}", Sha256::digest(tail)) != m.tail_sha256 {
        return Err(Error::Invalid("unsupported guest Bionic tail"));
    }
    let mut bytes = current[..m.original_size].to_vec();
    apply(&mut bytes, m, true)?;
    if format!("{:x}", Sha256::digest(&bytes)) != ORIGINAL {
        return Err(Error::Invalid(
            "guest Bionic differs from the supported image; retained unchanged",
        ));
    }
    Ok(bytes)
}
/// Called under exclusive environment-store ownership, before any guest runs.
/// `nativecall` is chosen once from the execution backend/configuration. Both
/// variants use the standard Android libc paths and identical dynamic ABI.
/// The small resource contains precompiled code and a fixed installation recipe;
/// constructing guest ELF data here is not compilation of host executable code.
pub fn install(bundle: &Path, vfs: &mut Vfs, nativecall: bool) -> Result<bool, Error> {
    let record = bounded(&bundle.join("manifest.json"), 32768)?;
    let m = manifest(&record)?;
    let tail = bounded(&bundle.join("bionic-nativecall.bin"), 65536)?;
    if tail.len() != m.added_file_bytes || format!("{:x}", Sha256::digest(&tail)) != m.tail_sha256 {
        return Err(Error::Invalid("Bionic resource digest mismatch"));
    }
    let previous = contents(vfs, RECORD).ok().and_then(|b| manifest(&b).ok());
    let mut changes = Vec::new();
    let mut selected = None;
    // Validate both originals before staging either. Stored prior provenance
    // also restores an older derivative when changing code or disabling thunks.
    for path in PATHS {
        let current = contents(vfs, path)?;
        let mut bytes = original(&current, &m).or_else(|error| {
            previous
                .as_ref()
                .map_or(Err(error), |old| original(&current, old))
        })?;
        if nativecall {
            apply(&mut bytes, &m, false)?;
            bytes.extend_from_slice(&tail);
        }
        if current != bytes {
            changes.push(path);
        }
        selected = Some(bytes);
    }
    let bytes = selected.ok_or(Error::Invalid("missing Bionic paths"))?;
    // Exact original bytes plus the verified static recipe determine the ELF
    // layout. Do not load a shared library as an executable for validation:
    // Bionic deliberately has e_entry == 0 and is loaded by Android's linker.
    // Namespace replacement is per inode, as with musl; not a rootfs
    // transaction. A failed cold startup never proceeds to guest execution.
    // Either variant can recover a partially completed installation on retry.
    for path in &changes {
        let mut staging = path.to_vec();
        staging.extend_from_slice(b".trames-new");
        vfs.import_reader(&staging, &mut bytes.as_slice(), true)?;
        let result = (|| {
            vfs.chown_at(AT_FDCWD, &staging, 0, 0, false)?;
            vfs.chmod_at(AT_FDCWD, &staging, 0o644)?;
            vfs.rename_at(AT_FDCWD, &staging, AT_FDCWD, path, 0)?;
            Ok::<_, Error>(())
        })();
        if result.is_err() {
            let _ = vfs.unlink_at(AT_FDCWD, &staging, false);
        }
        result?;
    }
    if contents(vfs, RECORD).ok().as_deref() != Some(record.as_slice()) {
        vfs.import_reader_replace(RECORD, &mut record.as_slice())?;
    }
    Ok(!changes.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::json!({"schema":1,"kind":"bionic-static","android_api":33,
            "abi":"arm64-v8a","original_sha256":ORIGINAL,"native_profile":65537,
            "original_size":4,"added_file_bytes":1,"tail_sha256":"unused",
            "patches":[{"offset":1,"original":"0203","nativecall":"0405"}]})
    }
    #[test]
    fn rejects_wrong_image_and_abi() {
        let m = fixture();
        assert!(manifest(&serde_json::to_vec(&m).unwrap()).is_ok());
        for (field, bad) in [
            ("original_sha256", serde_json::json!("other image")),
            ("native_profile", serde_json::json!(65538)),
            ("abi", serde_json::json!("x86_64")),
        ] {
            let mut changed = m.clone();
            changed[field] = bad;
            assert!(manifest(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
    }
    #[test]
    fn exact_static_patch_is_reversible_and_rejects_mismatch() {
        let m = manifest(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
        let mut bytes = vec![1, 2, 3, 4];
        apply(&mut bytes, &m, false).unwrap();
        assert_eq!(bytes, [1, 4, 5, 4]);
        apply(&mut bytes, &m, true).unwrap();
        assert_eq!(bytes, [1, 2, 3, 4]);
        bytes[2] = 9;
        assert!(apply(&mut bytes, &m, false).is_err());
        assert!(hex("not hex").is_err());
    }
}
