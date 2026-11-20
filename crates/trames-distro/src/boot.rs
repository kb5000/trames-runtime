// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold product selection, independent of the CPU executor and Linux session mounts.
use serde::{Deserialize, Serialize};
use trames_vfs::{Errno, Vfs, AT_FDCWD};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    #[default]
    Linux,
    Android,
}
impl Target {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "linux" => Ok(Self::Linux),
            "android" => Ok(Self::Android),
            _ => Err("target must be linux or android"),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Android => "android",
        }
    }
}

fn ensure_directory(vfs: &mut Vfs, path: &[u8], mode: u32) -> Result<(), Errno> {
    match vfs.mkdir_at(AT_FDCWD, path, mode) {
        Ok(()) | Err(Errno(17)) => Ok(()),
        Err(error) => Err(error),
    }
}

fn ensure_tmpfs(
    vfs: &mut Vfs,
    path: &[u8],
    parent: &[u8],
    mode: u32,
    options: &[u8],
) -> Result<(), Errno> {
    ensure_directory(vfs, path, mode)?;
    let (stat, mount) = vfs.stat_at_with_mount(AT_FDCWD, path, true)?;
    let kind = u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o170000;
    // A custom image can redirect this path. Preserve the image's choice
    // without mounting over the symlink target elsewhere in the namespace.
    if kind == 0o120000 {
        return Ok(());
    }
    if kind != 0o040000 {
        return Err(Errno(20));
    }
    if mount == vfs.mount_id_at(AT_FDCWD, parent, false)? {
        vfs.mount(Some(b"tmpfs"), path, Some(b"tmpfs"), 0, Some(options))?;
    }
    Ok(())
}

/// Session-local POSIX shared memory for Linux shell boots.
pub fn prepare_shared_memory(vfs: &mut Vfs) -> Result<(), Errno> {
    ensure_directory(vfs, b"/dev", 0o755)?;
    ensure_tmpfs(vfs, b"/dev/shm", b"/dev", 0o1777, b"size=64m,mode=1777")
}

/// The iPad session also keeps its runtime sockets and state in volatile /run.
pub fn prepare_runtime_mounts(vfs: &mut Vfs) -> Result<(), Errno> {
    ensure_tmpfs(vfs, b"/run", b"/", 0o755, b"mode=755")?;
    prepare_shared_memory(vfs)
}
