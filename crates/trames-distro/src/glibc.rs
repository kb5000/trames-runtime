// SPDX-License-Identifier: GPL-3.0-or-later
//! Paired Debian 13 glibc/loader; unrecognized custom images stay unchanged.
use crate::{static_libc::Spec, Error};
use std::path::Path;
use trames_vfs::Vfs;
const SPEC: Spec = Spec {
    kind: "glibc-static",
    original: "70fa4c4cf57eabeb96097cce47582d02379c4cd1de3db3e98ade4dd7089a1b13",
    android_api: None,
    version: Some("2.41-12+deb13u4"),
    paths: &[b"/usr/lib/aarch64-linux-gnu/libc.so.6"],
    record: b"/usr/lib/aarch64-linux-gnu/.trames-glibc.json",
    tail: "glibc-nativecall.bin",
    mode: 493,
    prerequisites: &[(
        b"/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        "1b882eddacd494b060413a8aa4f0a4754ee3f84775e68cecbf8a86092b59cca6",
    )],
};
pub fn install(bundle: &Path, vfs: &mut Vfs, nativecall: bool) -> Result<bool, Error> {
    crate::static_libc::install(bundle, vfs, nativecall, &SPEC, false)
}
pub fn install_if_supported(bundle: &Path, vfs: &mut Vfs, nativecall: bool) -> Result<bool, Error> {
    crate::static_libc::install(bundle, vfs, nativecall, &SPEC, true)
}
