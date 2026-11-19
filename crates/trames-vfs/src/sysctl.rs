// SPDX-License-Identifier: GPL-3.0-or-later
//! Original environment sysctl capabilities; no coordinator or service task.
use super::*;
#[derive(Clone)]
pub(super) enum Control {
    Network(network::Control),
    NrOpen(DescriptorCeiling),
    UserMap(Arc<user_namespace::MapFile>),
}
impl Control {
    pub fn reopen(&self, credentials: &Credentials) -> Self {
        match self {
            Self::UserMap(control) => Self::UserMap(Arc::new(control.reopen(credentials))),
            _ => self.clone(),
        }
    }
    pub fn authorized(&self, credentials: &Credentials) -> bool {
        match self {
            Self::UserMap(control) => control.authorized(credentials),
            Self::Network(control) => control.authorized(credentials),
            Self::NrOpen(_) => {
                credentials.has_cap(capabilities::SYS_RESOURCE)
                    || credentials.euid == 0 && credentials.user_namespace.is_initial()
            }
        }
    }
    pub fn read(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        match self {
            Self::UserMap(control) => control.read(offset, count),
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
    pub fn write(&self, bytes: &[u8], offset: u64, credentials: &Credentials) -> Result<usize> {
        let authorized = self.authorized(credentials);
        match self {
            Self::UserMap(control) => control.write(bytes, offset, credentials),
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
        if let Some(control) = self.user_map_control(path) {
            Some(Control::UserMap(Arc::new(control)))
        } else if self.uses_pseudo(path) && path.as_ref() == b"/proc/sys/fs/nr_open" {
            Some(Control::NrOpen(self.descriptor_ceiling()))
        } else {
            self.network_control(path).map(Control::Network)
        }
    }
}
