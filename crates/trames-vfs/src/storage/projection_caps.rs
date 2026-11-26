// SPDX-License-Identifier: GPL-3.0-or-later
//! Immutable capability payloads, prepared before the namespace commit budget.
use super::*;

/// A suspended projection owns this path; the provider keeps only a Weak.
/// The ordinary .cap file and its cache are unchanged until publication.
pub(crate) struct Staged {
    backing: Arc<DiskBacking>,
    path: PathBuf,
}
impl Staged {
    pub(crate) fn new(backing: Arc<DiskBacking>, caps: file_caps::FileCaps) -> Result<Self> {
        let bytes = caps.encode(&UserNamespace::default())?;
        let permit = cgroup::admit_io(bytes.len() as u64, true).map_err(host_errno)?;
        let id = trames_memory::new_backing_identity();
        let path = backing.path.with_extension(format!("{id:016x}.new"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&path).map_err(host_errno)?;
        let staged = Self { backing, path };
        io_write::write_all(&mut file, &bytes, permit).map_err(host_errno)?;
        file.sync_all().map_err(host_errno)?;
        Ok(staged)
    }
}
impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// A native rename rollback needs no second data write or IO admission. This
/// is the existing sidecar-before-manifest durability order, not a new promise
/// of atomic crash recovery across the two records.
pub(crate) struct Published {
    path: PathBuf,
    backup: Option<PathBuf>,
    old: Option<file_caps::FileCaps>,
}
impl DiskObject {
    pub(crate) fn publish_projected_caps(
        &mut self,
        caps: Option<file_caps::FileCaps>,
        staged: Option<&Staged>,
    ) -> Result<Published> {
        let path = self.backing.path.with_extension("cap");
        let id = trames_memory::new_backing_identity();
        let backup_path = self.backing.path.with_extension(format!("{id:016x}.old"));
        // Preserve the original data-before-capability durability barrier.
        if caps.is_some() {
            self.backing.file(false)?.sync_all().map_err(host_errno)?;
        }
        let backup = if self.capabilities.is_some() {
            fs::hard_link(&path, &backup_path).map_err(host_errno)?;
            Some(backup_path)
        } else {
            None
        };
        let published = Published {
            path,
            backup,
            old: self.capabilities,
        };
        let result = if caps.is_some() {
            let staged = staged.ok_or(Errno(5))?;
            if !Arc::ptr_eq(&staged.backing, &self.backing) {
                return Err(Errno(5));
            }
            let temp = self.backing.path.with_extension(format!("{id:016x}.pub"));
            // Keep the immutable staged payload usable if a true manifest
            // error rolls back this publication.
            fs::hard_link(&staged.path, &temp).map_err(host_errno)?;
            let result = fs::rename(&temp, &published.path).map_err(host_errno);
            if result.is_err() {
                let _ = fs::remove_file(temp);
            }
            result
        } else {
            fs::remove_file(&published.path).map_err(host_errno)
        };
        result?;
        self.capabilities = caps;
        if let Err(error) = sync_parent(&published.path) {
            // Cache always describes the actual sidecar, including a failed
            // native rollback. Never manufacture a successful restoration.
            return match self.rollback_projected_caps(published) {
                Ok(()) => Err(error),
                Err(rollback) => Err(rollback),
            };
        }
        Ok(published)
    }
    pub(crate) fn rollback_projected_caps(&mut self, mut published: Published) -> Result<()> {
        match &published.backup {
            Some(backup) => {
                if let Err(error) = fs::rename(backup, &published.path) {
                    // Keep the original inode record available on native
                    // failure instead of deleting the only rollback handle.
                    published.backup.take();
                    return Err(host_errno(error));
                }
            }
            None => fs::remove_file(&published.path).map_err(host_errno)?,
        }
        self.capabilities = published.old;
        sync_parent(&published.path)
    }
}
fn sync_parent(path: &Path) -> Result<()> {
    File::open(path.parent().unwrap())
        .and_then(|f| f.sync_all())
        .map_err(host_errno)
}
impl Drop for Published {
    fn drop(&mut self) {
        if let Some(backup) = &self.backup {
            let _ = fs::remove_file(backup);
        }
    }
}

/// Only our fixed-width, lowercase names are accepted as abandoned staging.
pub(super) fn temporary_name(name: &str) -> bool {
    name.len() == 37
        && name.as_bytes()[16] == b'.'
        && matches!(&name.as_bytes()[33..], b".new" | b".old" | b".pub")
        && name.as_bytes()[..16]
            .iter()
            .chain(&name.as_bytes()[17..33])
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
