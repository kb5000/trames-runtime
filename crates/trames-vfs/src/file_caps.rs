// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux file capability records use namespace-relative root IDs at the ABI.
use super::*;

pub(super) const NAME: &[u8] = b"security.capability";
const V2: u32 = 0x0200_0000;
const V3: u32 = 0x0300_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileCaps {
    root: u32,
    pub permitted: u64,
    pub inheritable: u64,
    pub effective: bool,
}

impl FileCaps {
    pub(super) fn parse(bytes: &[u8], ns: &UserNamespace) -> Result<Self> {
        if !matches!(bytes.len(), 20 | 24) {
            return Err(Errno(22));
        }
        let word = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        let magic = word(0);
        let root = match (magic & !1, bytes.len()) {
            (V2, 20) => 0,
            (V3, 24) => word(20),
            _ => return Err(Errno(22)),
        };
        if root != 0 && !ns.is_initial() {
            return Err(Errno(1));
        }
        Ok(Self {
            root: ns.to_global(false, root).ok_or(Errno(22))?,
            permitted: u64::from(word(4)) | (u64::from(word(12)) << 32),
            inheritable: u64::from(word(8)) | (u64::from(word(16)) << 32),
            effective: magic & 1 != 0,
        })
    }

    pub(super) fn applies(self, ns: &UserNamespace) -> bool {
        let mut current = Some(ns.clone());
        while let Some(level) = current {
            if level.to_global(false, 0) == Some(self.root) {
                return true;
            }
            current = level.parent();
        }
        false
    }

    pub(super) fn encode(self, ns: &UserNamespace) -> Result<Vec<u8>> {
        let root = match ns.from_global(false, self.root) {
            Some(root) => root,
            None if self.applies(ns) => 0,
            None => return Err(Errno(61)),
        };
        let revision = if root == 0 { V2 } else { V3 };
        let mut bytes = Vec::with_capacity(if root == 0 { 20 } else { 24 });
        for word in [
            revision | u32::from(self.effective),
            self.permitted as u32,
            self.inheritable as u32,
            (self.permitted >> 32) as u32,
            (self.inheritable >> 32) as u32,
        ] {
            bytes.extend(word.to_le_bytes());
        }
        if root != 0 {
            bytes.extend(root.to_le_bytes());
        }
        Ok(bytes)
    }
}

impl Node {
    fn cap_file(&self) -> Option<Arc<file_data::PlainFile>> {
        match &self.content {
            Content::File(storage::FileData::Plain(file)) => Some(file.clone()),
            Content::File(storage::FileData::Mapped(data)) => data.plain_file(),
            _ => None,
        }
    }

    pub(super) fn file_caps(&self) -> Option<FileCaps> {
        self.cap_file()?.capabilities()
    }

    pub(super) fn edit_caps(&self, caps: Option<FileCaps>, flags: u32) -> Result<()> {
        if caps.is_some() {
            if let Content::File(storage::FileData::Mapped(data)) = &self.content {
                if data.has_writers() {
                    return Err(Errno(16));
                }
                data.sync(false)?;
            }
        }
        self.cap_file()
            .ok_or(Errno(95))?
            .edit_capabilities(caps, flags)
    }

    pub(super) fn revoke_file_caps(&self) -> Result<()> {
        self.cap_file()
            .map_or(Ok(()), |file| file.revoke_capabilities())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_grants_respect_the_mount_bounding_set_and_no_new_privileges() {
        for nosuid in [false, true] {
            let mut fs = Vfs::default();
            fs.mkdir_at(AT_FDCWD, b"/bin", 0o755).unwrap();
            fs.mount(
                None,
                b"/bin",
                Some(b"tmpfs"),
                if nosuid { mounts::MS_NOSUID } else { 0 },
                None,
            )
            .unwrap();
            let path = b"/bin/test";
            let fd = fs.open_at(AT_FDCWD, path, 0x42, 0o755).unwrap();
            fs.close(fd).unwrap();
            let bit = 1u64 << capabilities::NET_BIND_SERVICE;
            let cap = FileCaps {
                root: 0,
                permitted: bit,
                effective: true,
                inheritable: 0,
            };
            let record = cap.encode(&fs.credentials.user_namespace).unwrap();
            fs.set_xattr(AT_FDCWD, Some(path), true, NAME, Some(&record), 0)
                .unwrap();
            for (bounded, restricted) in [(true, false), (false, true), (false, false)] {
                fs.credentials = Credentials::user(1000, 1000);
                if bounded {
                    fs.credentials.caps.bounding &= !bit;
                }
                if restricted {
                    fs.credentials.caps.no_new_privs.set();
                }
                let result = fs.apply_exec_credentials(path);
                if bounded && !nosuid {
                    assert_eq!(result, Err(Errno(1)));
                    continue;
                }
                result.unwrap();
                let gained = !restricted && !nosuid;
                assert_eq!(fs.credentials.caps.effective, if gained { bit } else { 0 });
                if gained {
                    assert!(fs.credentials.secure_exec());
                    assert_eq!(fs.dumpable(), 0);
                }
            }
        }
    }
}
