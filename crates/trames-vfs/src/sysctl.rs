// SPDX-License-Identifier: GPL-3.0-or-later
//! Original environment sysctl capabilities; no coordinator or service task.
use super::*;
pub(super) const MAX_USER_NAMESPACES: &[u8] = b"/proc/sys/user/max_user_namespaces";

#[derive(Clone)]
pub(super) enum Control {
    Network(network::Control),
    NrOpen(DescriptorCeiling),
    UserNamespaces(UserNamespace, Arc<user_namespace::UserNamespaceLimits>),
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
            Self::UserNamespaces(owner, _) => {
                owner.capable(credentials, capabilities::SYS_RESOURCE)
            }
            Self::NrOpen(_) => {
                credentials.has_cap(capabilities::SYS_RESOURCE)
                    || credentials.euid == 0 && credentials.user_namespace.is_initial()
            }
        }
    }
    pub fn read(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        let value = match self {
            Self::UserMap(control) => return control.read(offset, count),
            Self::Network(control) => return control.read(offset, count),
            Self::NrOpen(limit) => limit.get(),
            Self::UserNamespaces(_, limit) => limit.max(),
        };
        let bytes = format!("{value}\n").into_bytes();
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        Ok(bytes[start..start + count.min(bytes.len() - start)].to_vec())
    }
    pub fn write(&self, bytes: &[u8], offset: u64, credentials: &Credentials) -> Result<usize> {
        let authorized = self.authorized(credentials);
        match self {
            Self::UserMap(control) => control.write(bytes, offset, credentials),
            Self::Network(control) => control.write(bytes, offset, authorized),
            Self::NrOpen(_) | Self::UserNamespaces(_, _) => {
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
                match self {
                    Self::NrOpen(limit) if (1..=MAX_FDS).contains(&value) => limit.set(value),
                    Self::UserNamespaces(_, limit) if value <= i32::MAX as u32 => limit.set(value),
                    _ => return Err(Errno(22)),
                }
                Ok(bytes.len())
            }
        }
    }
}
impl Vfs {
    pub(super) fn sysctl_control(&self, path: &ResolvedPath) -> Option<Control> {
        if let Some(control) = self.user_map_control(path) {
            Some(Control::UserMap(Arc::new(control)))
        } else if path.as_ref() == MAX_USER_NAMESPACES && self.uses_pseudo(path) {
            Some(Control::UserNamespaces(
                self.credentials.user_namespace.clone(),
                self.user_namespace_limits(),
            ))
        } else if self.uses_pseudo(path) && path.as_ref() == b"/proc/sys/fs/nr_open" {
            Some(Control::NrOpen(self.descriptor_ceiling()))
        } else {
            self.network_control(path).map(Control::Network)
        }
    }
}
