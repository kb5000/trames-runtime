// SPDX-License-Identifier: GPL-3.0-or-later
//! Original environment sysctl capabilities; no coordinator or service task.
use super::*;
#[derive(Clone)]
pub(super) enum Control {
    Network(network::Control),
    NrOpen(DescriptorCeiling),
}
impl Control {
    pub fn authorized(&self, credentials: &Credentials) -> bool {
        credentials.euid == 0
            || credentials.has_cap(match self {
                Self::Network(_) => capabilities::NET_ADMIN,
                Self::NrOpen(_) => capabilities::SYS_RESOURCE,
            })
    }
    pub fn read(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        match self {
            Self::Network(control) => control.read(offset, count),
            Self::NrOpen(limit) => {
                let bytes = format!("{}\n", limit.get()).into_bytes();
                let start = usize::try_from(offset)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                Ok(bytes[start..start + count.min(bytes.len() - start)].to_vec())
            }
        }
    }
    pub fn write(&self, bytes: &[u8], offset: u64, authorized: bool) -> Result<usize> {
        match self {
            Self::Network(control) => control.write(bytes, offset, authorized),
            Self::NrOpen(limit) => {
                if !authorized {
                    return Err(Errno(13));
                }
                if bytes.is_empty() {
                    return Ok(0);
                }
                if offset != 0 || bytes.len() > 4096 {
                    return Err(Errno(22));
                }
                let value = std::str::from_utf8(bytes)
                    .map_err(|_| Errno(22))?
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| Errno(22))?;
                if value == 0 || value > MAX_FDS {
                    return Err(Errno(22));
                }
                limit.set(value);
                Ok(bytes.len())
            }
        }
    }
}
impl Vfs {
    pub(super) fn sysctl_control(&self, path: &ResolvedPath) -> Option<Control> {
        if self.uses_pseudo(path) && path.as_ref() == b"/proc/sys/fs/nr_open" {
            Some(Control::NrOpen(self.descriptor_ceiling()))
        } else {
            self.network_control(path).map(Control::Network)
        }
    }
}
