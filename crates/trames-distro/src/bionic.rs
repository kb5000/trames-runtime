// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold whole-library selection for the pinned Android image.
use crate::{static_libc::Spec, Error};
use std::path::Path;
use trames_vfs::Vfs;
const ORIGINAL: &str = "6aa289f3b6042793ccacd873ce3724dcaae240943112eec126f7be654f01e6cc";
const SPEC: Spec = Spec {
    kind: "bionic-static",
    original: ORIGINAL,
    android_api: Some(33),
    version: None,
    paths: &[
        b"/system/apex/com.android.runtime/lib64/bionic/libc.so",
        b"/system/lib64/bootstrap/libc.so",
    ],
    record: b"/system/lib64/.trames-bionic.json",
    tail: "bionic-nativecall.bin",
    mode: 420,
    prerequisites: &[],
};
pub fn install(bundle: &Path, vfs: &mut Vfs, nativecall: bool) -> Result<bool, Error> {
    crate::static_libc::install(bundle, vfs, nativecall, &SPEC, false)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_libc::{apply, hex, manifest};
    fn fixture() -> serde_json::Value {
        serde_json::json!({"schema":1,"kind":"bionic-static","android_api":33,
            "abi":"arm64-v8a","original_sha256":ORIGINAL,"native_profile":65537,
            "original_size":4,"added_file_bytes":1,"tail_sha256":"unused",
            "patches":[{"offset":1,"original":"0203","nativecall":"0405"}]})
    }
    #[test]
    fn rejects_wrong_image_and_abi() {
        let m = fixture();
        assert!(manifest(&serde_json::to_vec(&m).unwrap(), &SPEC).is_ok());
        for (field, bad) in [
            ("original_sha256", serde_json::json!("other image")),
            ("native_profile", serde_json::json!(65538)),
            ("abi", serde_json::json!("x86_64")),
        ] {
            let mut changed = m.clone();
            changed[field] = bad;
            assert!(manifest(&serde_json::to_vec(&changed).unwrap(), &SPEC).is_err());
        }
    }
    #[test]
    fn exact_static_patch_is_reversible_and_rejects_mismatch() {
        let m = manifest(&serde_json::to_vec(&fixture()).unwrap(), &SPEC).unwrap();
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
