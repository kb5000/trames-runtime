// SPDX-License-Identifier: GPL-3.0-or-later
//! Original environment sysctl capabilities; no coordinator or service task.
use super::*;
pub(super) const MAX_USER_NAMESPACES: &[u8] = b"/proc/sys/user/max_user_namespaces";

#[derive(Clone)]
pub(super) enum Control {
    Network(network::Control),
    NrOpen(DescriptorCeiling),
    MountMax(Arc<mounts::MountPolicy>),
    Comm {
        task: Arc<dyn ProcTask>,
        thread_entry: bool,
    },
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
    pub fn authorized(&self, credentials: &Credentials, tgid: u32) -> bool {
        match self {
            Self::Comm { task, thread_entry } => {
                *thread_entry && task.comm().is_some_and(|(group, _)| group == tgid)
            }
            Self::UserMap(control) => control.authorized(credentials),
            Self::Network(control) => control.authorized(credentials),
            Self::UserNamespaces(owner, _) => {
                owner.capable(credentials, capabilities::SYS_RESOURCE)
            }
            Self::MountMax(_) => credentials.euid == 0 && credentials.user_namespace.is_initial(),
            Self::NrOpen(_) => {
                credentials.has_cap(capabilities::SYS_RESOURCE)
                    || credentials.euid == 0 && credentials.user_namespace.is_initial()
            }
        }
    }
    pub fn read(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        let value = match self {
            Self::Comm { task, .. } => {
                let (_, name) = task.comm().ok_or(Errno(3))?;
                let mut bytes = name.get();
                bytes.push(b'\n');
                return Ok(slice(&bytes, offset, count));
            }
            Self::UserMap(control) => return control.read(offset, count),
            Self::Network(control) => return control.read(offset, count),
            Self::MountMax(policy) => policy.get(),
            Self::NrOpen(limit) => limit.get(),
            Self::UserNamespaces(_, limit) => limit.max(),
        };
        let bytes = format!("{value}\n").into_bytes();
        Ok(slice(&bytes, offset, count))
    }
    pub fn write(
        &self,
        bytes: &[u8],
        offset: u64,
        credentials: &Credentials,
        tgid: u32,
    ) -> Result<usize> {
        match self {
            Self::Comm { task, .. } => {
                let (group, name) = task.comm().ok_or(Errno(3))?;
                if group != tgid {
                    return Err(Errno(22));
                }
                let bytes_to_copy = &bytes[..bytes.len().min(15)];
                name.set(bytes_to_copy.split(|b| *b == 0).next().unwrap_or_default());
                Ok(bytes.len())
            }
            Self::UserMap(control) => control.write(bytes, offset, credentials),
            Self::Network(control) => control.write(bytes, offset, control.authorized(credentials)),
            Self::MountMax(_) | Self::NrOpen(_) | Self::UserNamespaces(_, _) => {
                if !self.authorized(credentials, tgid) {
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
                    Self::MountMax(policy) if value > 0 => policy.set(value),
                    Self::NrOpen(limit) if (1..=MAX_FDS).contains(&value) => limit.set(value),
                    Self::UserNamespaces(_, limit) if value <= i32::MAX as u32 => limit.set(value),
                    _ => return Err(Errno(22)),
                }
                Ok(bytes.len())
            }
        }
    }
}
fn slice(bytes: &[u8], offset: u64, count: usize) -> Vec<u8> {
    let start = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    bytes[start..start + count.min(bytes.len() - start)].to_vec()
}
impl Vfs {
    pub(super) fn sysctl_control(&self, path: &ResolvedPath) -> Option<Control> {
        if path.ends_with(b"/comm") && self.uses_pseudo(path) {
            let rest = path.strip_prefix(b"/proc/")?;
            let mut parts = rest.split(|b| *b == b'/');
            let pid = proc_task_id(parts.next()?)?;
            let (id, thread_entry) = match parts.next()? {
                b"comm" => (pid, false),
                b"task" => {
                    let tid = proc_task_id(parts.next()?)?;
                    if parts.next()? != b"comm" {
                        return None;
                    }
                    (tid, true)
                }
                _ => return None,
            };
            if parts.next().is_some() {
                return None;
            }
            let ns = self.proc_namespace(path);
            let id = ns.global(id)?;
            let task = path
                .proc_binding
                .as_ref()
                .and_then(|p| p.at(path, ns.id()))
                .filter(|p| p.target.pid() == id)
                .map(|p| p.target.clone())
                .or_else(|| self.pseudo.borrow().source.as_ref()?.task(id))?;
            task.comm()?;
            return Some(Control::Comm { task, thread_entry });
        }
        if let Some(control) = self.user_map_control(path) {
            Some(Control::UserMap(Arc::new(control)))
        } else if path.as_ref() == MAX_USER_NAMESPACES && self.uses_pseudo(path) {
            Some(Control::UserNamespaces(
                self.credentials.user_namespace.clone(),
                self.user_namespace_limits(),
            ))
        } else if path.as_ref() == b"/proc/sys/fs/mount-max" && self.uses_pseudo(path) {
            Some(Control::MountMax(self.pseudo.borrow().mount_policy.clone()))
        } else if self.uses_pseudo(path) && path.as_ref() == b"/proc/sys/fs/nr_open" {
            Some(Control::NrOpen(self.descriptor_ceiling()))
        } else {
            self.network_control(path).map(Control::Network)
        }
    }
}
