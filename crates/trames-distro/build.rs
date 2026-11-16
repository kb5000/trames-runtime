// SPDX-License-Identifier: GPL-3.0-or-later
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let dir = root.join("target/guest-cli");
    let record = dir.join("manifest.json");
    let binary = dir.join("trames");
    println!("cargo:rerun-if-changed={}", record.display());
    println!("cargo:rerun-if-changed={}", binary.display());
    let mut paths = vec![
        root.join("Cargo.lock"),
        root.join("rust-toolchain.toml"),
        root.join("crates/trames-control/Cargo.toml"),
    ];
    fn scan(p: &Path, paths: &mut Vec<PathBuf>) {
        for e in fs::read_dir(p).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                scan(&p, paths)
            } else if p.extension().is_some_and(|e| e == "rs") {
                paths.push(p);
            }
        }
    }
    scan(&root.join("crates/trames-control/src"), &mut paths);
    paths.sort();
    let mut hash = Sha256::new();
    for p in paths {
        if p.is_file() {
            println!("cargo:rerun-if-changed={}", p.display());
            hash.update(p.strip_prefix(&root).unwrap().to_str().unwrap().as_bytes());
            hash.update([0]);
            hash.update(fs::read(p).unwrap());
        }
    }
    let raw=fs::read(&record).unwrap_or_else(|_|panic!("Missing guest CLI artifact. Run python3 scripts/build-guest-cli.py in the runtime before Cargo."));
    let value: serde_json::Value =
        serde_json::from_slice(&raw).expect("invalid guest CLI manifest");
    assert_eq!(
        value["source_sha256"],
        format!("{:x}", hash.finalize()),
        "Guest CLI sources changed: run python3 scripts/build-guest-cli.py"
    );
    assert_eq!(
        value["binary_sha256"],
        format!(
            "{:x}",
            Sha256::digest(fs::read(&binary).expect("missing guest CLI binary"))
        ),
        "Guest CLI artifact hash mismatch"
    );
    let binary = fs::canonicalize(binary).unwrap();
    println!("cargo:rustc-env=TRAMES_GUEST_CLI={}", binary.display());
}
