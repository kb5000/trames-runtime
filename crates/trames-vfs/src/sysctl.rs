// SPDX-License-Identifier: GPL-3.0-or-later
//! Original environment sysctl capabilities; no coordinator or service task.
use super::*;
pub(super) const MAX_USER_NAMESPACES: &[u8] = b"/proc/sys/user/max_user_namespaces";

#[derive(Clone, Copy)]
pub(super) enum Protection {
    Hardlinks,
    Symlinks,
    Fifos,
    Regular,
}
impl Protection {
    pub(super) fn at(path: &[u8]) -> Option<Self> {
        match path {
            b"/proc/sys/fs/protected_hardlinks" => Some(Self::Hardlinks),
            b"/proc/sys/fs/protected_symlinks" => Some(Self::Symlinks),
            b"/proc/sys/fs/protected_fifos" => Some(Self::Fifos),
            b"/proc/sys/fs/protected_regular" => Some(Self::Regular),
            _ => None,
        }
    }
    fn max(self) -> u32 {
        match self {
            Self::Hardlinks | Self::Symlinks => 1,
            Self::Fifos | Self::Regular => 2,
        }
    }
}
pub(super) struct NameiPolicy([std::sync::atomic::AtomicU32; 4]);
impl Default for NameiPolicy {
    fn default() -> Self {
        Self([1, 1, 0, 0].map(std::sync::atomic::AtomicU32::new))
    }
}
impl NameiPolicy {
    pub(super) fn get(&self, kind: Protection) -> u32 {
        self.0[kind as usize].load(Ordering::Relaxed)
    }
}
#[derive(Clone)]
pub(super) enum Control {
    Network(network::Control),
    NrOpen(DescriptorCeiling),
    OverflowId(bool, Arc<user_namespace::OverflowIds>),
    UtsName(bool, Arc<readiness::ProcWatch>),
    Namei(Protection, Arc<NameiPolicy>),
    MountMax(Arc<mounts::MountPolicy>),
    TaskIo {
        task: Arc<dyn ProcTask>,
        whole: bool,
    },
    CoreFilter(Arc<dyn ProcTask>),
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
            Self::UtsName(domain, watch) => Self::UtsName(*domain, watch.reopen()),
            Self::UserMap(control) => Self::UserMap(Arc::new(control.reopen(credentials))),
            _ => self.clone(),
        }
    }
    pub fn authorized(&self, credentials: &Credentials, tgid: u32) -> bool {
        match self {
            Self::Comm { task, thread_entry } => {
                *thread_entry && task.comm().is_some_and(|(group, _)| group == tgid)
            }
            Self::CoreFilter(_) | Self::TaskIo { .. } => false, // ordinary inode owner/mode checks
            Self::UtsName(..) => credentials.euid == 0,
            Self::UserMap(control) => control.authorized(credentials),
            Self::Network(control) => control.authorized(credentials),
            Self::UserNamespaces(owner, _) => {
                owner.capable(credentials, capabilities::SYS_RESOURCE)
            }
            Self::OverflowId(..) | Self::MountMax(_) | Self::Namei(..) => {
                credentials.euid == 0 && credentials.user_namespace.is_initial()
            }
            Self::NrOpen(_) => {
                credentials.has_cap(capabilities::SYS_RESOURCE)
                    || credentials.euid == 0 && credentials.user_namespace.is_initial()
            }
        }
    }
    pub fn read(&self, offset: u64, count: usize, caller: &Vfs) -> Result<Vec<u8>> {
        let value = match self {
            Self::TaskIo { task, whole } => {
                let text = task.io_text(*whole, caller.lock_owner, &caller.credentials)?;
                return Ok(slice(&text, offset, count));
            }
            Self::CoreFilter(task) => {
                let Some(policy) = task.dump_policy()? else {
                    return Ok(Vec::new());
                };
                return Ok(slice(
                    format!("{:08x}\n", policy.filter()).as_bytes(),
                    offset,
                    count,
                ));
            }
            Self::Comm { task, .. } => {
                let (_, name) = task.comm().ok_or(Errno(3))?;
                let mut bytes = name.get();
                bytes.push(b'\n');
                return Ok(slice(&bytes, offset, count));
            }
            Self::UtsName(domain, _) => {
                let mut name = caller.uts.name(*domain);
                name.truncate(name.iter().position(|&b| b == 0).unwrap_or(name.len()));
                name.push(b'\n');
                return Ok(slice(&name, offset, count));
            }
            Self::UserMap(control) => return control.read(offset, count),
            Self::Network(control) => return control.read(offset, count),
            Self::Namei(kind, policy) => policy.get(*kind),
            Self::MountMax(policy) => policy.get(),
            Self::OverflowId(group, ids) => ids.get(*group),
            Self::NrOpen(limit) => limit.get(),
            Self::UserNamespaces(_, limit) => limit.max(),
        };
        let bytes = format!("{value}\n").into_bytes();
        Ok(slice(&bytes, offset, count))
    }
    pub fn write(&self, bytes: &[u8], position: &mut u64, caller: &Vfs) -> Result<usize> {
        let offset = *position;
        let credentials = &caller.credentials;
        let tgid = caller.lock_owner;
        let n = match self {
            Self::TaskIo { .. } => return Err(Errno(5)),
            Self::CoreFilter(task) => {
                let value = parse_dump_filter(bytes)?;
                task.dump_policy()?.ok_or(Errno(3))?.set_filter(value);
                return Ok(bytes.len());
            }
            Self::UtsName(domain, _) => {
                if !self.authorized(credentials, tgid) {
                    return Err(Errno(13));
                }
                caller.uts.write_sysctl(*domain, bytes, position);
                return Ok(bytes.len());
            }
            Self::Comm { task, .. } => {
                let (group, name) = task.comm().ok_or(Errno(3))?;
                if group != tgid {
                    return Err(Errno(22));
                }
                let bytes_to_copy = &bytes[..bytes.len().min(15)];
                name.set(bytes_to_copy.split(|b| *b == 0).next().unwrap_or_default());
                return Ok(bytes.len());
            }
            Self::UserMap(control) => control.write(bytes, offset, credentials),
            Self::Network(control) => control.write(bytes, offset, control.authorized(credentials)),
            Self::OverflowId(..)
            | Self::Namei(..)
            | Self::MountMax(_)
            | Self::NrOpen(_)
            | Self::UserNamespaces(_, _) => {
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
                    Self::OverflowId(group, ids) if value <= u16::MAX as u32 => {
                        ids.set(*group, value)
                    }
                    Self::Namei(kind, policy) if value <= kind.max() => {
                        policy.0[*kind as usize].store(value, Ordering::Relaxed)
                    }
                    Self::MountMax(policy) if value > 0 => policy.set(value),
                    Self::NrOpen(limit) if (1..=MAX_FDS).contains(&value) => limit.set(value),
                    Self::UserNamespaces(_, limit) if value <= i32::MAX as u32 => limit.set(value),
                    _ => return Err(Errno(22)),
                }
                Ok(bytes.len())
            }
        }?;
        *position += n as u64;
        Ok(n)
    }
}
fn parse_dump_filter(bytes: &[u8]) -> Result<u32> {
    // kstrtouint_from_user, base 0. The input buffer fits a binary u32,
    // one leading sign and a final newline.
    let bytes = &bytes[..bytes.len().min(34)];
    let bytes = bytes.split(|&b| b == 0).next().unwrap_or_default();
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_prefix(b"+").unwrap_or(bytes);
    let (radix, digits) = if let Some(digits) = bytes
        .strip_prefix(b"0x")
        .or_else(|| bytes.strip_prefix(b"0X"))
    {
        (16, digits)
    } else if bytes.starts_with(b"0") {
        (8, bytes)
    } else {
        (10, bytes)
    };
    let digits = std::str::from_utf8(digits).map_err(|_| Errno(22))?;
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return Err(Errno(22));
    }
    u32::from_str_radix(digits, radix).map_err(|_| Errno(34))
}
fn slice(bytes: &[u8], offset: u64, count: usize) -> Vec<u8> {
    let start = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    bytes[start..start + count.min(bytes.len() - start)].to_vec()
}
impl Vfs {
    pub(super) fn sysctl_control(&self, path: &ResolvedPath) -> Option<Control> {
        if matches!(
            path.as_ref(),
            b"/proc/sys/kernel/overflowuid" | b"/proc/sys/kernel/overflowgid"
        ) && self.uses_pseudo(path)
        {
            return Some(Control::OverflowId(
                path.ends_with(b"gid"),
                self.credentials.user_namespace.overflow().clone(),
            ));
        }
        let domain = match path.as_ref() {
            b"/proc/sys/kernel/hostname" => Some(false),
            b"/proc/sys/kernel/domainname" => Some(true),
            _ => None,
        };
        if let Some(domain) = domain.filter(|_| self.uses_pseudo(path)) {
            return Some(Control::UtsName(domain, self.uts.watch_name(domain)));
        }
        if (path.ends_with(b"/comm")
            || path.ends_with(b"/coredump_filter")
            || path.ends_with(b"/io"))
            && self.uses_pseudo(path)
        {
            let rest = path.strip_prefix(b"/proc/")?;
            let mut parts = rest.split(|b| *b == b'/');
            let pid = proc_task_id(parts.next()?)?;
            let (id, thread_entry) = match parts.next()? {
                b"comm" | b"coredump_filter" | b"io" => (pid, false),
                b"task" => {
                    let tid = proc_task_id(parts.next()?)?;
                    if !matches!(parts.next()?, b"comm" | b"io") {
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
            if path.ends_with(b"/io") {
                return Some(Control::TaskIo {
                    task,
                    whole: !thread_entry,
                });
            }
            if path.ends_with(b"/coredump_filter") {
                return Some(Control::CoreFilter(task));
            }
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
        } else if let Some(kind) = Protection::at(path).filter(|_| self.uses_pseudo(path)) {
            Some(Control::Namei(kind, self.namei_policy.clone()))
        } else if path.as_ref() == b"/proc/sys/fs/mount-max" && self.uses_pseudo(path) {
            Some(Control::MountMax(self.pseudo.borrow().mount_policy.clone()))
        } else if self.uses_pseudo(path) && path.as_ref() == b"/proc/sys/fs/nr_open" {
            Some(Control::NrOpen(self.descriptor_ceiling()))
        } else {
            self.network_control(path).map(Control::Network)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_filter_inheritance_and_linux_integer_syntax() {
        let policy = Dumpable::default();
        let sibling = policy.clone();
        let child = policy.fork();
        assert_eq!(child.filter(), 0x33);
        for (input, value) in [(b"+0x123\n".as_slice(), 0x123), (b"077", 63), (b"512", 0)] {
            sibling.set_filter(parse_dump_filter(input).unwrap());
            assert_eq!(policy.filter(), value);
            assert_eq!(child.filter(), 0x33);
        }
        for invalid in [b"".as_slice(), b"-1", b"08", b"0x", b"++1", b"1 ", b"1\n\n"] {
            assert_eq!(parse_dump_filter(invalid), Err(Errno(22)));
        }
        assert_eq!(parse_dump_filter(b"4294967296"), Err(Errno(34)));
    }

    const HOST: &[u8] = b"/proc/sys/kernel/hostname";
    const DOMAIN: &[u8] = b"/proc/sys/kernel/domainname";

    #[test]
    fn uts_sysctl_offsets_and_change_cursors_follow_open_descriptions() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        let fd = v.open_at(AT_FDCWD, HOST, 2, 0).unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let independent = v.open_at(AT_FDCWD, HOST, 0, 0).unwrap();
        let domain = v.open_at(AT_FDCWD, DOMAIN, 0, 0).unwrap();

        assert_eq!(v.poll(fd, 0x145), 0x145);
        assert_eq!(v.write(fd, b"co"), Ok(2));
        assert_eq!(v.write(alias, b"dex\nignored"), Ok(11));
        assert_eq!(v.uts_name(false), b"codex");
        assert_eq!(v.pread(fd, 2, 4).unwrap(), b"x\n");
        assert_eq!(v.poll(alias, 0x147), 0x4b);
        assert_eq!(v.poll(fd, 0), 0);
        assert_eq!(v.poll(independent, 0), 8);
        assert_eq!(v.poll(independent, 0), 0);
        assert_eq!(v.poll(domain, 0), 0);

        // Linux consumes the input count for a write past the string, while
        // keeping the shared offset and the name in place.
        assert_eq!(v.write(alias, b"more"), Ok(4));
        assert_eq!(v.seek(fd, 0, 1), Ok(13));
        assert_eq!(v.uts_name(false), b"codex");
        assert_eq!(v.pwrite(fd, b"X\0Y", 2), Ok(3));
        assert_eq!(v.uts_name(false), b"coX");
        assert_eq!(v.pwrite(fd, &[b'z'; 70], 0), Ok(70));
        assert_eq!(v.uts_name(false), vec![b'z'; 64]);

        let fresh = v.open_at(AT_FDCWD, HOST, 0, 0).unwrap();
        assert_eq!(v.poll(fresh, 0), 0);
        v.credentials.euid = 1000;
        assert_eq!(v.open_at(AT_FDCWD, HOST, 2, 0), Err(Errno(13)));
        assert_eq!(v.pwrite(fd, b"denied", 0), Err(Errno(13)));
        assert_eq!(v.poll(fresh, 0), 0);
    }

    #[test]
    fn uts_epoll_error_has_a_new_edge_for_each_change() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        let fd = v.open_at(AT_FDCWD, HOST, 0, 0).unwrap();
        let ep = v.epoll_create(0).unwrap();
        v.epoll_ctl(ep, 1, fd, 0x80000000, 17).unwrap();
        for _ in 0..3 {
            v.set_uts_name(false, b"same").unwrap();
            assert_eq!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(), [(8, 17)]);
        }
        assert!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap().is_empty());
    }

    #[test]
    fn inherited_uts_fd_uses_callers_namespace_and_guest_wide_table_events() {
        let mut parent = Vfs::default();
        parent.set_runtime_info(1, RuntimeInfo::default());
        let fd = parent.open_at(AT_FDCWD, HOST, 2, 0).unwrap();
        let mut child = parent.clone();
        child.unshare_uts().unwrap();
        let target = child
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let work = FileWork::from_vfs(
            &child,
            target,
            FileCommand::Write {
                bytes: b"child".to_vec(),
                offset: Some(0),
            },
        );
        let FileOutcome::Complete(reply) = std::thread::spawn(move || work.run()).join().unwrap()
        else {
            panic!("UTS write did not complete on the worker");
        };
        assert!(matches!(reply.result, Ok(FileValue::Count(5))));
        assert_eq!(child.pread(fd, 64, 0).unwrap(), b"child\n");
        assert_eq!(parent.pread(fd, 64, 0).unwrap(), b"trames\n");
        assert_eq!(parent.poll(fd, 2), 10);
        assert_eq!(child.poll(fd, 2), 0);

        let mut other = Vfs::default();
        other.set_runtime_info(1, RuntimeInfo::default());
        let unrelated = other.open_at(AT_FDCWD, HOST, 0, 0).unwrap();
        child.set_uts_name(false, b"again").unwrap();
        assert_eq!(other.poll(unrelated, 0), 0);
        assert_eq!(parent.poll(fd, 0), 8);
    }
}
