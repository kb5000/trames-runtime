// SPDX-License-Identifier: GPL-3.0-or-later
//! Original filesystem/Files resources for dynamic process observations.
//! No owner VFS, namespace Rc, or accepted descriptor number is transferred.
use super::*;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

static NEXT_VIEW: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(super) struct Observation {
    fields: ProcRefresh,
    target: u32,
    enumerate: bool,
    namespace: u64,
    binding: u64,
}
/// Original PID ancestry carried by the common walker, cwd and directory OFDs.
/// Parent scopes survive `..`; absolute links start another walk at its root.
pub(super) struct ProcPath {
    root: Vec<u8>,
    namespace: u64,
    pub target: Arc<dyn ProcTask>,
    parent: Option<Arc<ProcPath>>,
}
impl ProcPath {
    pub fn at(self: &Arc<Self>, key: &[u8], namespace: u64) -> Option<Arc<Self>> {
        if namespace == self.namespace && mounts::below(key, &self.root) {
            Some(self.clone())
        } else {
            self.parent.as_ref()?.at(key, namespace)
        }
    }
}
pub(super) struct ProcNode {
    pub path: Vec<u8>,
    pub binding: Option<Arc<ProcPath>>,
}
/// Directory inode/mount identity for proc path observation. This is physical
/// metadata retention, not a namespace control or an extra fs_struct/mount use.
#[derive(Clone)]
pub struct ProcDirectory {
    pub(super) node: NodeRef,
    pub(super) mount: Arc<mounts::MountData>,
}

pub struct ProcQuery<'a> {
    pub path: &'a [u8],
    pub demand: ProcRefresh,
    pub namespace: &'a PidNamespace,
    pub reader: u32,
    pub enumerate: bool,
    pub content: bool,
    pub retained: Option<&'a Arc<dyn ProcTask>>,
}
impl<'a> ProcQuery<'a> {
    pub fn new(
        path: &'a [u8],
        demand: ProcRefresh,
        namespace: &'a PidNamespace,
        reader: u32,
    ) -> Self {
        Self {
            path,
            demand,
            namespace,
            reader,
            enumerate: false,
            content: true,
            retained: None,
        }
    }
}

/// An original PID resource, retained independently of numeric lookup. A
/// ProcSource::task result must not strongly retain a task's Files table: an
/// opened proc file can itself belong to that table. Kernel ProcPid uses only
/// a weak binding to its current task, including nonleader exec transfers.
pub trait ProcTask: Send + Sync {
    fn identity(&self) -> u64;
    fn pid(&self) -> u32;
    fn observe(&self, demand: ProcRefresh, residency: Option<usize>) -> Option<ProcessInfo>;
    fn memory_report(&self) -> Option<trames_memory::MemoryReport>;
    fn present(&self) -> bool {
        self.observe(ProcRefresh::Metadata, None).is_some()
    }
    fn threads(&self) -> Vec<Arc<dyn ProcTask>> {
        Vec::new()
    }
}

#[derive(Default)]
pub struct ProcCounters {
    per_cpu: [AtomicU64; 32],
    last_task: [AtomicU64; 32],
    pub switches: AtomicU64,
}
impl ProcCounters {
    pub fn ticks(&self, cpus: usize) -> Vec<u64> {
        self.per_cpu[..cpus.min(32)]
            .iter()
            .map(|time| time.load(Ordering::Relaxed) / 10_000_000)
            .collect()
    }
    fn account(&self, elapsed: Duration, cpu: usize) {
        if let Some(time) = self.per_cpu.get(cpu) {
            time.fetch_add(
                elapsed.as_nanos().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
        }
    }
}

/// The existing owner and source resolver consume the same dynamic provider.
/// Returned control projections are constructed on the calling thread; a
/// provider must retain only original Send + Sync resources.
pub trait ProcSource: Send + Sync {
    fn available(&self, _demand: ProcRefresh) -> bool {
        true
    }
    fn observe(&self, query: ProcQuery<'_>) -> RuntimeInfo;
    fn task(&self, _pid: u32) -> Option<Arc<dyn ProcTask>> {
        None
    }
}

impl Vfs {
    pub(super) fn proc_description_path(&self, open: &OpenDescription) -> Option<ResolvedPath> {
        let (key, binding) = if let Some(proc) = open.node.as_ref().and_then(|n| n.proc_node.get())
        {
            (proc.path.clone(), proc.binding.clone())
        } else if let FdKind::Node(key) = &open.kind {
            (key.clone(), None)
        } else {
            return None;
        };
        Some(ResolvedPath {
            key,
            proc_binding: binding,
            mount: self.mount_for_path(open.mount.as_ref()),
        })
    }
    pub(super) fn proc_directory_readlink(&self, path: &ResolvedPath) -> Result<Option<Vec<u8>>> {
        let Some(file) = self.proc_directory_node_normalized(path)? else {
            return Ok(None);
        };
        self.proc_directory_display(&ProcDirectory {
            node: file.node.clone(),
            mount: file.mount.as_ref().ok_or(Errno(2))?.shared.clone(),
        })
        .map(Some)
    }
    pub fn proc_directories(&self) -> (Option<ProcDirectory>, Option<ProcDirectory>) {
        self.context.paths.directories()
    }
    pub(super) fn proc_directory_display(&self, directory: &ProcDirectory) -> Result<Vec<u8>> {
        let mount = self.mount_for_path(Some(&OpenMount::Shared(directory.mount.clone())));
        let path = self.location(&directory.node, &mount)?;
        self.path_visible(&path).or_else(|_| {
            let mount = mount.ok_or(Errno(2))?;
            let mut root = mount.clone();
            loop {
                let next = root.parent.borrow().as_ref().map(|a| a.parent.clone());
                let Some(next) = next else {
                    break;
                };
                root = next;
            }
            mounts::mount_absolute(&mount, &path.key, &root).ok_or(Errno(2))
        })
    }
    pub(super) fn bind_proc_path(&self, path: &mut ResolvedPath) -> Result<()> {
        if !self.uses_pseudo(path) {
            return Ok(());
        }
        let Some(source) = self.pseudo.borrow().source.clone() else {
            return Ok(());
        };
        let Some(rest) = path.strip_prefix(b"/proc/") else {
            return Ok(());
        };
        let namespace = self.proc_namespace(path);
        let parent = path
            .proc_binding
            .as_ref()
            .and_then(|p| p.at(path, namespace.id()));
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let numeric = |part: &[u8]| std::str::from_utf8(part).ok()?.parse::<u32>().ok();
        let pid = match parts.as_slice() {
            [pid] => numeric(pid),
            [_, b"task", tid] => numeric(tid),
            _ => return Ok(()),
        };
        let Some(pid) = pid.and_then(|pid| namespace.global(pid)) else {
            return Ok(());
        };
        if parent.as_ref().is_some_and(|p| p.root == path.key) {
            return Ok(());
        }
        let target = if parts.len() == 3 {
            match &parent {
                Some(parent) => parent
                    .target
                    .threads()
                    .into_iter()
                    .find(|task| task.pid() == pid),
                None => source.task(pid),
            }
        } else {
            source.task(pid)
        };
        let Some(target) = target else {
            return if parent.is_some() {
                Err(Errno(2))
            } else {
                Ok(())
            };
        };
        path.proc_binding = Some(Arc::new(ProcPath {
            root: path.key.clone(),
            namespace: namespace.id(),
            target,
            parent,
        }));
        Ok(())
    }
    pub(super) fn proc_path_identity<P: PathArg + ?Sized>(&self, path: &P) -> u64 {
        let Some(rest) = path.key().strip_prefix(b"/proc/") else {
            return 0;
        };
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let pid = if parts.get(1) == Some(&b"task".as_slice()) {
            parts.get(2)
        } else {
            parts.first()
        }
        .and_then(|part| std::str::from_utf8(part).ok())
        .and_then(|part| part.parse::<u32>().ok());
        if pid.is_none() {
            return 0;
        }
        let pseudo = self.pseudo.borrow();
        self.proc_runtime(path, &pseudo.runtime)
            .processes
            .iter()
            .find(|task| Some(task.pid) == pid)
            .map_or(0, |task| task.identity)
    }
    pub fn set_proc_source(&self, source: Arc<dyn ProcSource>) {
        let mut pseudo = self.pseudo.borrow_mut();
        pseudo.source = Some(source);
        pseudo.enabled = true;
        drop(pseudo);
        self.begin_proc_query();
    }
    pub(super) fn begin_proc_query(&self) {
        self.source_observed.set(None);
    }
    pub(super) fn refresh_proc_source<P: PathArg + ?Sized>(&self, path: &P) -> Result<()> {
        self.refresh_proc_source_with(path, false)
    }
    pub(super) fn refresh_proc_source_with<P: PathArg + ?Sized>(
        &self,
        path: &P,
        enumerate: bool,
    ) -> Result<()> {
        let Some(source) = self.pseudo.borrow().source.clone() else {
            return Ok(());
        };
        let key = path.key();
        if !matches!(key, b"/proc" | b"/sys")
            && !key.starts_with(b"/proc/")
            && !key.starts_with(b"/sys/")
        {
            return Ok(());
        }
        let demand = ProcRefresh::for_path(key).lookup();
        let namespace = self.proc_namespace(path);
        let binding = path.proc_binding().and_then(|p| p.at(key, namespace.id()));
        let identity = binding.as_ref().map_or(0, |p| p.target.identity());
        let parts: Vec<_> = key.split(|b| *b == b'/').collect();
        let target = if parts.get(3) == Some(&b"task".as_slice()) {
            parts.get(4)
        } else {
            parts.get(2)
        }
        .and_then(|part| std::str::from_utf8(part).ok())
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
        if self.source_observed.get().is_some_and(|observed| {
            observed.target == target
                && observed.binding == identity
                && observed.namespace == namespace.id()
                && observed.fields.includes(demand)
                && (!enumerate || observed.enumerate)
        }) {
            return Ok(());
        }
        if !source.available(demand) {
            return match &self.query {
                Some(query) => query.defer(),
                None => Ok(()), // Legacy embedding provides joined host accounting.
            };
        }
        let mut query = ProcQuery::new(key, demand, namespace, self.pid);
        query.enumerate = enumerate;
        query.content = false;
        query.retained = binding.as_ref().map(|p| &p.target);
        let runtime = source.observe(query);
        self.pseudo.borrow_mut().runtime = runtime;
        self.source_observed.set(Some(Observation {
            fields: demand,
            target,
            enumerate,
            namespace: namespace.id(),
            binding: identity,
        }));
        Ok(())
    }
}

#[derive(Clone)]
pub struct ProcResources {
    fs: FsHandle,
    paths: fs_context::PathSource,
    files: SharedFiles,
    nodes: std::sync::Weak<SharedCell<pseudo::PseudoNodes>>,
    namespaces: SharedNamespaceSnapshot,
}
impl Vfs {
    pub fn proc_resources(&self) -> ProcResources {
        ProcResources {
            fs: self.fs.clone(),
            paths: self.path_source(),
            files: self.shared_files(),
            nodes: Arc::downgrade(&self.pseudo.borrow().nodes),
            namespaces: self.namespace_snapshot().shared(),
        }
    }
}
impl ProcResources {
    fn view(&self, lease: &linux_namespace::NamespaceProjection) -> Vfs {
        let mut view = Vfs::empty(self.fs.clone());
        self.paths.install(&mut view.context);
        view.mounts = lease._mount.clone();
        if let Some(namespace) = &view.mounts {
            *view.mount_registry.borrow_mut() = namespace
                .0
                .borrow()
                .mounts
                .iter()
                .map(Arc::downgrade)
                .collect();
        }
        if let Some(nodes) = self.nodes.upgrade() {
            let mut pseudo = view.pseudo.borrow_mut();
            pseudo.nodes = nodes;
            pseudo.enabled = true;
        }
        view
    }
    pub fn observe(&self, info: &mut ProcessInfo, demand: ProcRefresh) {
        if demand.directories() {
            (info.cwd_directory, info.root_directory) = self.paths.directories();
        }
        if !demand.paths() && !demand.namespaces() && !demand.descriptors() {
            info.namespaces = self.namespaces.metadata();
            return;
        }
        let (mut namespaces, mut lease) = self.namespaces.project();
        let view = self.view(&lease);
        let paths = view.context.paths.borrow();
        namespaces.root = paths.root_mount.as_ref().map(|mount| {
            (
                Arc::downgrade(mount),
                Arc::downgrade(paths.root_node.as_ref().unwrap_or(&mount.root)),
            )
        });
        Rc::get_mut(&mut lease)
            .expect("fresh namespace projection")
            ._root = paths.root_mount.clone();
        if demand.paths() {
            info.cwd = view.cwd().unwrap_or_else(|_| b"/".to_vec());
            if let Some(file) = info
                .executable_file
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
            {
                info.executable = view.executable_display(&file);
            }
        }
        if demand.descriptors() {
            info.fds = view.source_fd_snapshot(&self.files);
        }
        info.namespaces = namespaces;
        info.namespace_projection = Some(lease);
    }
}

impl Vfs {
    pub(super) fn source_fd_snapshot(&self, files: &SharedFiles) -> Vec<FdInfo> {
        files
            .proc_descriptions()
            .iter()
            .map(|m| {
                self.fd_info(
                    m.fd,
                    &m.descriptor.open.borrow(),
                    m.descriptor.cloexec.get(),
                    m.descriptor.open.downgrade(),
                    Some(m),
                )
            })
            .collect()
    }
    pub(super) fn fd_info(
        &self,
        fd: u32,
        o: &OpenDescription,
        cloexec: bool,
        open: OpenWeak,
        metadata: Option<&fd_table::ProcDescriptor>,
    ) -> FdInfo {
        let observed_mount = metadata
            .and_then(|m| m.mount.as_ref())
            .map(|mount| OpenMount::Shared(mount.clone()))
            .or_else(|| o.mount.clone());
        let node = o.node.clone().or_else(|| {
            if matches!(o.kind, FdKind::Terminal) {
                self.node(b"/dev/pts/0").ok()
            } else {
                None
            }
        });
        let inode = node.as_ref().map_or_else(
            || {
                o.namespace.as_ref().map_or_else(
                    || o.pipe.as_ref().map_or(o.id, |p| p.pipe.inode),
                    linux_namespace::NamespaceHandle::id,
                )
            },
            |n| n.borrow().inode,
        );
        let target = if let Some(label) = metadata.and_then(|m| m.label.as_ref()) {
            label.clone()
        } else if let Some(ns) = &o.namespace {
            ns.label()
        } else {
            match &o.kind {
                FdKind::Node(path) => o
                    .node
                    .as_ref()
                    .and_then(|n| {
                        self.location(n, &self.mount_for_path(observed_mount.as_ref()))
                            .map(|p| self.path_visible(&p).unwrap_or(p.key))
                            .ok()
                    })
                    .unwrap_or_else(|| {
                        let mut p = path.clone();
                        p.extend_from_slice(b" (deleted)");
                        p
                    }),
                FdKind::Terminal if o.pty.is_some() => {
                    let end = o.pty.as_ref().expect("PTY");
                    if end.master {
                        b"/dev/ptmx".to_vec()
                    } else {
                        format!("/dev/pts/{}", end.pair.number).into_bytes()
                    }
                }
                FdKind::Terminal => node
                    .as_ref()
                    .and_then(|n| self.path_of(n).ok())
                    .unwrap_or_else(|| b"/dev/pts/0".to_vec()),
                FdKind::Anonymous if o.native_image.is_some() => {
                    b"anon_inode:[trames-image]".to_vec()
                }
                FdKind::Anonymous => o
                    .anonymous
                    .as_ref()
                    .expect("anonymous description")
                    .name()
                    .to_vec(),
                FdKind::Socket => format!("socket:[{inode}]").into_bytes(),
                FdKind::PipeRead | FdKind::PipeWrite => format!("pipe:[{inode}]").into_bytes(),
                FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => {
                    format!("pipe:[{inode}]").into_bytes()
                }
            }
        };
        FdInfo {
            signal_mask: match o.anonymous {
                Some(events::Anonymous::Signal(ref mask)) => Some(mask.get()),
                _ => None,
            },
            fd,
            target,
            position: o.current_position(),
            flags: o.flags.get() | if cloexec { O_CLOEXEC } else { 0 },
            inode,
            mount_id: observed_mount.as_ref().map_or(
                if o.namespace.is_some() || metadata.is_some_and(|m| m.namespace) {
                    17
                } else if matches!(o.kind, FdKind::Terminal) {
                    4
                } else {
                    1
                },
                |m| m.id,
            ),
            socket: o.socket.as_ref().and_then(|s| s.info()),
            open,
        }
    }
}

// The process image is published at actual task/image/credential changes.
// Live paths and descriptor membership are retained resources, never these
// copied fields. Payloads are cloned only for an observation that consumes them.
macro_rules! process_metadata {
    ($($name:ident: $ty:ty,)*) => {
        #[derive(Clone)]
        struct ProcessMetadata { $( $name: $ty, )* }
        impl ProcessMetadata {
            fn capture(info: &ProcessInfo) -> Self {
                Self { $( $name: info.$name.clone(), )* }
            }
            fn project(&self) -> ProcessInfo {
                ProcessInfo { $( $name: self.$name.clone(), )* ..Default::default() }
            }
        }
    }
}
process_metadata! {
    pid: u32,
    processor: u32,
    nice: i32,
    scheduler: u32,
    affinity: u64,
    tgid: u32,
    parent: u32,
    group: u32,
    session: u32,
    state: char,
    credentials: Credentials,
    namespace_ids: [Vec<u32>; 4],
    command: Vec<u8>,
    cgroup: Vec<u8>,
    nondumpable: bool,
    seccomp: u32,
    seccomp_filters: usize,
    executable: Vec<u8>,
    executable_file: Option<std::sync::Weak<ExecutableFile>>,
    mapped_bytes: usize,
    virtual_bytes: u64,
    user_ticks: u64,
    start_ticks: u64,
    terminal: bool,
    terminal_number: u32,
    file_size_limits: Option<(u64, u64)>,
    core_limits: Option<(u64, u64)>,
    nofile_limits: Option<(u64, u64)>,
    address_space_limit: Option<u64>,
    oom: std::sync::Weak<OomTask>,
    pending: u64,
    shared_pending: u64,
    blocked: u64,
    ignored: u64,
    caught: u64,
}
struct ProcessImage {
    metadata: ProcessMetadata,
    resources: ProcResources,
    arguments: Vec<Vec<u8>>,
    environment: Vec<Vec<u8>>,
    auxiliary: Vec<u8>,
    maps: Vec<u8>,
    memory: Option<trames_memory::MemoryReport>,
}
/// Stable original process-view identity. It contains no owner-local weak Rc,
/// and swapping an image cannot redirect a retained view to a reused PID.
pub struct ProcessView {
    image: std::sync::RwLock<Option<Arc<ProcessImage>>>,
    identity: u64,
    cpu: AtomicU32,
    time: AtomicU64,
    state: AtomicU32,
    counters: std::sync::OnceLock<Arc<ProcCounters>>,
}
impl Default for ProcessView {
    fn default() -> Self {
        Self {
            image: Default::default(),
            identity: NEXT_VIEW.fetch_add(1, Ordering::Relaxed),
            cpu: Default::default(),
            time: Default::default(),
            state: Default::default(),
            counters: Default::default(),
        }
    }
}
impl ProcessView {
    pub fn identity(&self) -> u64 {
        self.identity
    }
    pub fn bind_counters(&self, counters: &Arc<ProcCounters>) {
        self.counters.get_or_init(|| counters.clone());
    }
    pub fn account(&self, elapsed: Duration, cpu: usize) {
        self.cpu.store(cpu as u32, Ordering::Relaxed);
        self.time.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        if let Some(counters) = self.counters.get() {
            counters.account(elapsed, cpu);
        }
    }
    pub fn dispatched(&self, cpu: usize) {
        self.cpu.store(cpu as u32, Ordering::Relaxed);
        self.waiting(false);
        if let Some(counters) = self.counters.get() {
            if let Some(last) = counters.last_task.get(cpu) {
                if last.swap(self.identity, Ordering::Relaxed) != self.identity {
                    counters.switches.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    pub fn publish_time(&self, elapsed: Duration) {
        self.time.fetch_max(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }
    pub fn waiting(&self, waiting: bool) {
        self.state
            .store(if waiting { b'S' } else { b'R' } as u32, Ordering::Relaxed);
    }
    pub fn memory_report(&self) -> Option<trames_memory::MemoryReport> {
        self.image.read().unwrap().as_ref()?.memory.clone()
    }
    pub fn publish(&self, info: &ProcessInfo, resources: ProcResources) {
        self.publish_with_memory(info, resources, None);
    }
    pub fn publish_with_memory(
        &self,
        info: &ProcessInfo,
        resources: ProcResources,
        memory: Option<trames_memory::MemoryReport>,
    ) {
        let image = Arc::new(ProcessImage {
            metadata: ProcessMetadata::capture(info),
            resources,
            arguments: info.arguments.clone(),
            environment: info.environment.clone(),
            auxiliary: info.auxiliary.clone(),
            maps: info.maps.clone(),
            memory,
        });
        *self.image.write().unwrap() = Some(image);
    }
    pub fn observe(&self, demand: ProcRefresh) -> Option<ProcessInfo> {
        self.observe_with_residency(demand, None)
    }
    pub fn observe_with_residency(
        &self,
        demand: ProcRefresh,
        residency: Option<usize>,
    ) -> Option<ProcessInfo> {
        let image = self.image.read().unwrap().clone()?;
        let mut info = image.metadata.project();
        info.identity = self.identity;
        let time = self.time.load(Ordering::Relaxed);
        if time != 0 {
            info.user_ticks = time / 10_000_000;
            info.processor = self.cpu.load(Ordering::Relaxed);
        }
        if let Some(state) =
            char::from_u32(self.state.load(Ordering::Relaxed)).filter(|c| *c != '\0')
        {
            info.state = state;
        }
        if demand.arguments() {
            info.arguments = image.arguments.clone();
        }
        if demand.environment() {
            info.environment = image.environment.clone();
        }
        if demand.auxiliary() {
            info.auxiliary = image.auxiliary.clone();
        }
        if demand.mappings() {
            info.maps = image.maps.clone();
        }
        if let Some(memory) = &image.memory {
            info.virtual_bytes = memory.virtual_bytes();
            if demand.residency() {
                info.mapped_bytes = residency.unwrap_or_else(|| memory.resident_bytes());
            }
            if demand.mappings() {
                info.maps = memory.maps().to_vec();
            }
        }
        image.resources.observe(&mut info, demand);
        Some(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::PAGE_SIZE;
    #[test]
    fn process_resources_keep_live_files_paths_and_original_executable_on_another_thread() {
        fn shared<T: Send + Sync>() {}
        shared::<ProcResources>();
        shared::<SharedNamespaceSnapshot>();
        shared::<ExecutableFile>();
        shared::<ProcessView>();
        let mut owner = Vfs::default();
        owner
            .import_file(b"/program", b"ELF-original".to_vec())
            .unwrap();
        owner.chmod_at(AT_FDCWD, b"/program", 0o755).unwrap();
        let executable = owner.executable_file_at(AT_FDCWD, b"/program", 0).unwrap();
        let original = owner.open_at(AT_FDCWD, b"/program", 0, 0).unwrap();
        let resources = owner.proc_resources();
        owner.mkdir_at(AT_FDCWD, b"/cwd", 0o755).unwrap();
        owner.chdir(b"/cwd").unwrap();
        owner
            .rename_at(AT_FDCWD, b"/program", AT_FDCWD, b"/renamed", 0)
            .unwrap();
        owner.close(original).unwrap();
        let reused = owner.open_at(AT_FDCWD, b"/renamed", 0, 0).unwrap();
        assert_eq!(original, reused);
        owner.seek(reused, 3, 0).unwrap();
        owner.fd_flags_snapshot().fcntl(reused, 2, 1).unwrap();
        let remote_executable = executable.clone();
        std::thread::spawn(move || {
            let mut info = ProcessInfo::default();
            resources.observe(
                &mut info,
                ProcRefresh::Descriptors.merge(ProcRefresh::Paths),
            );
            assert_eq!(info.cwd, b"/cwd");
            let fd = info.fds.iter().find(|fd| fd.fd == reused).unwrap();
            assert_eq!(fd.target, b"/renamed");
            assert_eq!(fd.position, 3);
            assert_ne!(fd.flags & O_CLOEXEC, 0);
            assert_eq!(remote_executable.bytes().unwrap(), b"ELF-original");
            assert!(linux_namespace::snapshot_label(&info.namespaces, b"mnt").is_some());
        })
        .join()
        .unwrap();
    }
    #[test]
    fn proc_observer_does_not_retain_a_dead_fs_struct_or_its_mount_uses() {
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/used", 0o755).unwrap();
        owner
            .mount(None, b"/used", Some(b"tmpfs"), 0, None)
            .unwrap();
        let mut target = owner.clone();
        target.chdir(b"/used").unwrap();
        let source = target.proc_resources();
        let mut observed = ProcessInfo::default();
        source.observe(&mut observed, ProcRefresh::Directories);
        assert!(observed.cwd_directory.is_some());
        assert_eq!(owner.umount(b"/used", 0), Err(Errno(16)));
        drop(target);
        owner.umount(b"/used", 0).unwrap();
        source.observe(&mut observed, ProcRefresh::Directories);
        assert!(observed.cwd_directory.is_none());
    }
    #[test]
    fn namespace_observer_sees_real_mount_updates_without_retaining_busy_references() {
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/mount", 0o755).unwrap();
        let source = owner.proc_resources();
        let observe = || {
            let mut info = ProcessInfo::default();
            source.observe(&mut info, ProcRefresh::Namespaces);
            mounts::table_text(&info.namespaces, true)
        };
        assert!(!observe().windows(7).any(|w| w == b" /mount"));
        owner
            .mount(None, b"/mount", Some(b"tmpfs"), 0, None)
            .unwrap();
        assert!(observe().windows(7).any(|w| w == b" /mount"));
        let mut retained = ProcessInfo::default();
        source.observe(&mut retained, ProcRefresh::Namespaces);
        owner.umount(b"/mount", 0).unwrap();
        assert!(!observe().windows(7).any(|w| w == b" /mount"));
        assert!(
            mounts::table_text(&retained.namespaces, true)
                .windows(7)
                .any(|w| w == b" /mount"),
            "an immutable observation can finish after detach without becoming a mount use"
        );
    }
    #[test]
    fn namespace_observers_do_not_replace_real_file_exec_mapping_or_cwd_uses() {
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/mount", 0o755).unwrap();
        owner
            .mount(None, b"/mount", Some(b"tmpfs"), 0, None)
            .unwrap();
        let source = owner.proc_resources();
        let mut retained = ProcessInfo::default();
        source.observe(&mut retained, ProcRefresh::Namespaces);
        let fd = owner
            .open_at(AT_FDCWD, b"/mount/file", 0x42, 0o755)
            .unwrap();
        owner.truncate_fd(fd, PAGE_SIZE).unwrap();
        let accepted = owner.shared_files().lookup(fd).unwrap().unwrap();
        let alias = owner.dup(fd, 32, false).unwrap();
        assert_eq!(owner.umount(b"/mount", 0), Err(Errno(16)));
        let executable = owner
            .executable_file_at(AT_FDCWD, b"/mount/file", 0)
            .unwrap();
        let pages = owner.mapping_pages(fd, 0, PAGE_SIZE, false, false).unwrap();
        owner.close(fd).unwrap();
        owner.close(alias).unwrap();
        std::thread::spawn(move || drop(accepted)).join().unwrap();
        assert_eq!(owner.umount(b"/mount", 0), Err(Errno(16)));
        drop(executable);
        assert_eq!(
            owner.umount(b"/mount", 0),
            Err(Errno(16)),
            "read-only mappings retain their original OFD use"
        );
        drop(pages);
        owner.chdir(b"/mount").unwrap();
        assert_eq!(owner.umount(b"/mount", 0), Err(Errno(16)));
        owner.chdir(b"/").unwrap();
        owner.umount(b"/mount", 0).unwrap();
        drop(retained);
    }
    #[test]
    fn namespace_observation_on_a_worker_does_not_make_umount_busy() {
        use std::{sync::mpsc, time::Duration};
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/mount", 0o755).unwrap();
        owner
            .mount(None, b"/mount", Some(b"tmpfs"), 0, None)
            .unwrap();
        let source = owner.proc_resources();
        let (ready, observed) = mpsc::channel();
        let (finish, resume) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut info = ProcessInfo::default();
            source.observe(&mut info, ProcRefresh::Namespaces);
            ready.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(5)).unwrap();
            mounts::table_text(&info.namespaces, true)
        });
        let observed = observed.recv_timeout(Duration::from_secs(5));
        let result = owner.umount(b"/mount", 0);
        let _ = finish.send(());
        let text = worker.join().unwrap();
        observed.unwrap();
        assert_eq!(result, Ok(()));
        assert!(text.windows(7).any(|w| w == b" /mount"));
    }
    #[test]
    fn proc_directory_magic_uses_target_inodes_across_chroot_rename_and_aliases() {
        struct Source(Vec<Arc<ProcessView>>);
        impl ProcSource for Source {
            fn observe(&self, query: ProcQuery<'_>) -> RuntimeInfo {
                RuntimeInfo {
                    processes: self
                        .0
                        .iter()
                        .filter_map(|p| p.observe(query.demand))
                        .collect(),
                    ..Default::default()
                }
            }
        }
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/jail", 0o755).unwrap();
        owner.mkdir_at(AT_FDCWD, b"/jail/work", 0o755).unwrap();
        owner.import_file(b"/outside", b"outside".to_vec()).unwrap();
        owner
            .import_file(b"/jail/inside", b"inside".to_vec())
            .unwrap();
        owner
            .symlink_at(b"/proc/2/root", AT_FDCWD, b"/remote")
            .unwrap();
        let mut target = owner.clone();
        target.chdir(b"/jail/work").unwrap();
        target.chroot(b"/jail").unwrap();
        target.set_process_context(2);
        let root = target.stat_at(AT_FDCWD, b"/").unwrap();
        let cwd = target.stat_at(AT_FDCWD, b".").unwrap();
        let reader = Arc::new(ProcessView::default());
        let subject = Arc::new(ProcessView::default());
        reader.publish(
            &ProcessInfo {
                pid: 1,
                tgid: 1,
                ..Default::default()
            },
            owner.proc_resources(),
        );
        subject.publish(
            &ProcessInfo {
                pid: 2,
                tgid: 2,
                cwd: b"/wrong-display-path".to_vec(),
                ..Default::default()
            },
            target.proc_resources(),
        );
        owner.set_proc_source(Arc::new(Source(vec![reader, subject.clone()])));
        let queries = owner.path_queries();
        assert_ne!(root[8..16], owner.stat_at(AT_FDCWD, b"/").unwrap()[8..16]);
        assert_eq!(
            queries.stat_at(AT_FDCWD, b"/proc/2/root", false),
            Some(Ok(root))
        );
        assert_eq!(
            queries.stat_at(AT_FDCWD, b"/proc/2/cwd", false),
            Some(Ok(cwd))
        );
        assert_eq!(
            queries.readlink_at(AT_FDCWD, b"/proc/2/root"),
            Some(Ok(b"/jail".to_vec()))
        );
        assert_eq!(
            queries.readlink_at(AT_FDCWD, b"/proc/2/cwd"),
            Some(Ok(b"/jail/work".to_vec()))
        );
        assert_eq!(
            queries.stat_at(AT_FDCWD, b"/proc/2/root/outside", false),
            Some(Err(Errno(2)))
        );
        let fd = queries
            .open_at_resolve(
                AT_FDCWD,
                b"/remote/inside",
                0,
                0,
                0,
                &DirectFiles::default(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(owner.read(fd, 16).unwrap(), b"inside");
        for (path, expected) in [(b"/proc/2/root".as_slice(), root), (b"/proc/2/cwd", cwd)] {
            let fd = queries
                .open_at_resolve(AT_FDCWD, path, O_DIRECTORY, 0, 0, &DirectFiles::default())
                .expect("directory magic opens on the worker")
                .unwrap();
            assert_eq!(owner.stat_fd(fd).unwrap(), expected);
            assert!(!owner.getdents(fd, 4096).unwrap().is_empty());
            owner.close(fd).unwrap();
        }
        assert_eq!(
            queries.open_at_resolve(
                AT_FDCWD,
                b"/proc/2/root",
                O_NOFOLLOW | O_DIRECTORY,
                0,
                0,
                &DirectFiles::default(),
            ),
            Some(Err(Errno(20)))
        );
        assert_eq!(
            queries.open_at_resolve(
                AT_FDCWD,
                b"/remote",
                O_DIRECTORY,
                0,
                2,
                &DirectFiles::default(),
            ),
            Some(Err(Errno(40)))
        );
        target
            .rename_at(AT_FDCWD, b"/work", AT_FDCWD, b"/moved", 0)
            .unwrap();
        assert_eq!(
            queries.readlink_at(AT_FDCWD, b"/proc/2/cwd"),
            Some(Ok(b"/jail/moved".to_vec()))
        );
        assert_eq!(
            queries.stat_at(AT_FDCWD, b"/proc/2/cwd", false),
            Some(Ok(target.stat_at(AT_FDCWD, b".").unwrap()))
        );
        owner.credentials = Credentials::user(1000, 1000);
        subject.publish(
            &ProcessInfo {
                pid: 2,
                tgid: 2,
                credentials: Credentials::user(2000, 2000),
                ..Default::default()
            },
            target.proc_resources(),
        );
        assert_eq!(
            owner
                .path_queries()
                .stat_at(AT_FDCWD, b"/remote/inside", false),
            Some(Err(Errno(13)))
        );
    }
    #[test]
    fn retained_view_tracks_its_original_image_instead_of_a_reused_number() {
        let owner = Vfs::default();
        let original = Arc::new(ProcessView::default());
        original.publish(
            &ProcessInfo {
                pid: 42,
                command: b"first".to_vec(),
                arguments: vec![b"first".to_vec()],
                ..Default::default()
            },
            owner.proc_resources(),
        );
        let reused = ProcessView::default();
        reused.publish(
            &ProcessInfo {
                pid: 42,
                command: b"different".to_vec(),
                ..Default::default()
            },
            owner.proc_resources(),
        );
        let remote = original.clone();
        std::thread::spawn(move || {
            assert_eq!(
                remote.observe(ProcRefresh::Arguments).unwrap().arguments,
                vec![b"first".to_vec()]
            );
            assert!(remote
                .observe(ProcRefresh::Metadata)
                .unwrap()
                .arguments
                .is_empty());
        })
        .join()
        .unwrap();
        original.publish(
            &ProcessInfo {
                pid: 42,
                command: b"exec".to_vec(),
                ..Default::default()
            },
            owner.proc_resources(),
        );
        assert_eq!(
            original.observe(ProcRefresh::Metadata).unwrap().command,
            b"exec"
        );
        assert_eq!(
            reused.observe(ProcRefresh::Metadata).unwrap().command,
            b"different"
        );
    }
    #[test]
    fn source_resolver_reads_current_executable_and_fd_identity_through_real_proc_mounts() {
        struct Source(Arc<ProcessView>);
        impl ProcSource for Source {
            fn observe(&self, query: ProcQuery<'_>) -> RuntimeInfo {
                let demand = query.demand;
                RuntimeInfo {
                    processes: self.0.observe(demand).into_iter().collect(),
                    cpu_count: 4,
                    ..Default::default()
                }
            }
        }
        let mut owner = Vfs::default();
        owner.import_file(b"/program", b"ELF".to_vec()).unwrap();
        owner.chmod_at(AT_FDCWD, b"/program", 0o755).unwrap();
        let executable = owner.executable_file_at(AT_FDCWD, b"/program", 0).unwrap();
        let fd = owner.open_at(AT_FDCWD, b"/program", 0, 0).unwrap();
        let process = Arc::new(ProcessView::default());
        process.publish(
            &ProcessInfo {
                pid: 1,
                tgid: 1,
                executable_file: Some(Arc::downgrade(&executable)),
                ..Default::default()
            },
            owner.proc_resources(),
        );
        owner.set_proc_source(Arc::new(Source(process)));
        let queries = owner.path_queries();
        assert_eq!(
            queries.readlink_at(AT_FDCWD, b"/proc/self/exe"),
            Some(Ok(b"/program".to_vec()))
        );
        let inode = owner.stat_fd(fd).unwrap()[8..16].to_vec();
        let stat = queries
            .stat_at(AT_FDCWD, b"/proc/self/exe", false)
            .unwrap()
            .unwrap();
        assert_eq!(&stat[8..16], inode);
        owner
            .rename_at(AT_FDCWD, b"/program", AT_FDCWD, b"/renamed", 0)
            .unwrap();
        assert_eq!(
            queries.readlink_at(AT_FDCWD, b"/proc/self/exe"),
            Some(Ok(b"/renamed".to_vec()))
        );
        let path = format!("/proc/self/fd/{fd}");
        assert_eq!(
            queries.readlink_at(AT_FDCWD, path.as_bytes()),
            Some(Ok(b"/renamed".to_vec()))
        );
        owner.seek(fd, 2, 0).unwrap();
        let reopened = queries
            .open_at_resolve(AT_FDCWD, path.as_bytes(), 0, 0, 0, &DirectFiles::default())
            .expect("source FD reopen stays on its execution worker")
            .unwrap();
        assert_eq!(owner.read(reopened, 8).unwrap(), b"ELF");
        assert_eq!(owner.seek(fd, 0, 1).unwrap(), 2, "fresh OFD offset");
        owner.close(reopened).unwrap();
        owner.unlink_at(AT_FDCWD, b"/renamed", false).unwrap();
        // Preserve the existing original-label fallback for an unlinked inode;
        // a live dentry-name model is separate from process-view ownership.
        assert_eq!(
            queries.readlink_at(AT_FDCWD, b"/proc/self/exe"),
            Some(Ok(b"/program (deleted)".to_vec()))
        );
        let stat = queries
            .stat_at(AT_FDCWD, b"/proc/self/exe", false)
            .unwrap()
            .unwrap();
        assert_eq!(&stat[8..16], inode);
        let reopened = queries
            .open_at_resolve(
                AT_FDCWD,
                b"/proc/self/exe",
                0,
                0,
                0,
                &DirectFiles::default(),
            )
            .expect("deleted executable inode remains usable on the worker")
            .unwrap();
        assert_eq!(owner.read(reopened, 8).unwrap(), b"ELF");
        owner.close(reopened).unwrap();
        owner.close(fd).unwrap();
        assert_eq!(
            queries.readlink_at(AT_FDCWD, path.as_bytes()),
            Some(Err(Errno(2)))
        );
        let [input, output] = owner.pipe(0).unwrap();
        let alias = format!("/proc/self/fd/{output}");
        let reopened = queries
            .open_at_resolve(AT_FDCWD, alias.as_bytes(), 1, 0, 0, &DirectFiles::default())
            .expect("source pipe reopen publishes in the original Files")
            .unwrap();
        owner.close(output).unwrap();
        owner.write(reopened, b"pipe").unwrap();
        assert_eq!(owner.read(input, 8).unwrap(), b"pipe");
        owner.close(reopened).unwrap();
        assert_eq!(owner.read(input, 8).unwrap(), b"", "last writer closes");
        owner.close(input).unwrap();
    }

    #[test]
    fn namespace_descriptors_retain_original_nsfs_identity_and_mount_authority() {
        struct Source(Arc<ProcessView>);
        impl ProcSource for Source {
            fn observe(&self, query: ProcQuery<'_>) -> RuntimeInfo {
                RuntimeInfo {
                    processes: self.0.observe(query.demand).into_iter().collect(),
                    ..Default::default()
                }
            }
        }
        let mut owner = Vfs::default();
        let mut info = ProcessInfo {
            pid: 1,
            tgid: 1,
            namespaces: owner.namespace_snapshot(),
            ..Default::default()
        };
        owner.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![info.clone()],
                ..Default::default()
            },
        );
        let fd = owner.open_at(AT_FDCWD, b"/proc/self/ns/mnt", 0, 0).unwrap();
        info.fds = owner.fd_snapshot();
        owner.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![info.clone()],
                ..Default::default()
            },
        );
        let expected = owner.stat_fd(fd).unwrap();
        let process = Arc::new(ProcessView::default());
        process.publish(&info, owner.proc_resources());
        owner.set_proc_source(Arc::new(Source(process)));
        let queries = owner.path_queries();
        assert_eq!(
            queries.stat_at(AT_FDCWD, b"/proc/self/ns/mnt", false),
            Some(Ok(expected))
        );
        assert_eq!(
            queries.stat_at(AT_FDCWD, format!("/proc/self/fd/{fd}").as_bytes(), false),
            Some(Ok(expected))
        );
        assert_eq!(queries.stat_fd_with_mount(fd).unwrap().unwrap().0, expected);
        let link = queries
            .stat_at(AT_FDCWD, b"/proc/self/ns/mnt", true)
            .unwrap()
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(link[16..20].try_into().unwrap()) & 0o170000,
            0o120000
        );
        assert!(
            owner.shared_files().lookup(fd).is_some(),
            "original namespace is a transferable shared capability"
        );
    }
    #[test]
    fn worker_namespace_open_rights_and_bound_alias_enter_the_original_live_table() {
        fn shared<T: Send + Sync>() {}
        shared::<MountNamespace>();
        shared::<linux_namespace::NamespaceHandle>();
        struct Source(Arc<ProcessView>);
        impl ProcSource for Source {
            fn observe(&self, query: ProcQuery<'_>) -> RuntimeInfo {
                RuntimeInfo {
                    processes: self.0.observe(query.demand).into_iter().collect(),
                    ..Default::default()
                }
            }
        }
        // The receiving namespace is older, so Linux permits the nsfs bind.
        let mut receiver = Vfs::default();
        let mut owner = Vfs::default();
        let original = Arc::downgrade(&owner.mounts.as_ref().unwrap().0);
        let info = ProcessInfo {
            pid: 1,
            tgid: 1,
            ..Default::default()
        };
        let process = Arc::new(ProcessView::default());
        process.publish(&info, owner.proc_resources());
        owner.set_proc_source(Arc::new(Source(process)));
        let queries = owner.path_queries();
        let factory = owner.descriptor_factory();
        let (fd, rights) = std::thread::spawn(move || {
            let fd = queries
                .open_at_resolve(
                    AT_FDCWD,
                    b"/proc/1/ns/mnt",
                    0,
                    0,
                    0,
                    &DirectFiles::default(),
                )
                .expect("worker nsfs admission")
                .unwrap();
            let rights = factory.send_local_rights(&[fd]).unwrap().unwrap();
            (fd, rights)
        })
        .join()
        .unwrap();
        owner.close(fd).unwrap();
        // A projected copy captured at open would miss this later mount.
        owner.mkdir_at(AT_FDCWD, b"/late", 0o755).unwrap();
        owner
            .mount(None, b"/late", Some(b"tmpfs"), 0, None)
            .unwrap();
        let proof = owner
            .open_at(AT_FDCWD, b"/late/proof", 0x41, 0o644)
            .unwrap();
        owner.write(proof, b"original").unwrap();
        owner.close(proof).unwrap();
        let factory = receiver.descriptor_factory();
        let (received, cut) =
            std::thread::spawn(move || factory.receive_local_rights(rights, 1, true))
                .join()
                .unwrap();
        assert!(!cut);
        let fd = received[0];
        receiver.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    fds: receiver.fd_snapshot(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        receiver.import_file(b"/ns-alias", Vec::new()).unwrap();
        receiver
            .mount(
                Some(format!("/proc/self/fd/{fd}").as_bytes()),
                b"/ns-alias",
                None,
                4096,
                None,
            )
            .unwrap();
        let queries = receiver.path_queries();
        let bound = std::thread::spawn(move || {
            queries
                .open_at_resolve(AT_FDCWD, b"/ns-alias", 0, 0, 0, &DirectFiles::default())
                .expect("bound nsfs worker admission")
                .unwrap()
        })
        .join()
        .unwrap();
        receiver.close(fd).unwrap();
        receiver.setns(bound, CLONE_NEWNS).unwrap();
        receiver.close(bound).unwrap();
        drop(owner);
        assert!(Arc::ptr_eq(
            &receiver.mounts.as_ref().unwrap().0,
            &original.upgrade().unwrap()
        ));
        let proof = receiver.open_at(AT_FDCWD, b"/late/proof", 0, 0).unwrap();
        assert_eq!(receiver.read(proof, 32).unwrap(), b"original");
        receiver.close(proof).unwrap();
        // Repeated setns/registration does not accumulate weak registry entries.
        let mounts = receiver.mounts.as_ref().unwrap().0.borrow().mounts.clone();
        receiver.register_mounts(&mounts).unwrap();
        let count = receiver.mount_registry.borrow().len();
        for _ in 0..32 {
            receiver.register_mounts(&mounts).unwrap();
        }
        assert_eq!(receiver.mount_registry.borrow().len(), count);
        drop(mounts);
        drop(receiver);
        assert!(
            original.upgrade().is_none(),
            "last real namespace lease releases the table"
        );
    }
    #[test]
    fn source_opens_mount_and_sysctl_controls_with_original_ofds_and_permissions() {
        struct Source(Arc<ProcessView>);
        impl ProcSource for Source {
            fn observe(&self, query: ProcQuery<'_>) -> RuntimeInfo {
                RuntimeInfo {
                    processes: self.0.observe(query.demand).into_iter().collect(),
                    ..Default::default()
                }
            }
        }
        fn run(work: FileWork) -> Result<FileValue> {
            assert!(!work.host_work());
            let FileOutcome::Complete(reply) = work.run() else {
                panic!("original control must finish on the execution worker")
            };
            reply.result
        }
        let mut owner = Vfs::default();
        let oom = Arc::new(OomTask::default());
        let view = Arc::new(ProcessView::default());
        view.publish(
            &ProcessInfo {
                pid: 1,
                tgid: 1,
                oom: Arc::downgrade(&oom),
                ..Default::default()
            },
            owner.proc_resources(),
        );
        owner.set_proc_source(Arc::new(Source(view)));
        let paths = owner.path_queries();
        let (mount, net, oomfd) = std::thread::spawn(move || {
            let files = DirectFiles::default();
            let open = |path: &[u8], flags| {
                paths
                    .open_at_resolve(AT_FDCWD, path, flags, 0, 0, &files)
                    .unwrap()
                    .unwrap()
            };
            (
                open(b"/proc/self/mountinfo", 0),
                // runc writes sysctls with O_TRUNC. Control files ignore that
                // open flag; it must not become a regular-file truncate job.
                open(b"/proc/sys/net/ipv4/ip_unprivileged_port_start", 2 | 0x200),
                open(b"/proc/self/oom_score_adj", 2 | 0x200),
            )
        })
        .join()
        .unwrap();
        let file = |fd| {
            owner
                .shared_files()
                .lookup(fd)
                .unwrap()
                .unwrap()
                .file_target()
                .unwrap()
        };
        let mount_target = file(mount);
        let net_target = file(net);
        let oom_target = file(oomfd);
        let write = FileWork::from_vfs(
            &owner,
            net_target.clone(),
            FileCommand::Write {
                bytes: b"1234\n".to_vec(),
                offset: None,
            },
        );
        assert!(matches!(
            std::thread::spawn(move || run(write)).join().unwrap(),
            Ok(FileValue::Count(5))
        ));
        assert_eq!(owner.network.unprivileged_port(), 1234);
        assert_eq!(owner.seek(net, 0, 1), Ok(5));
        owner.unshare_net().unwrap();
        owner.seek(net, 0, 0).unwrap();
        assert_eq!(owner.read(net, 10).unwrap(), b"1234\n");
        assert_eq!(owner.network.unprivileged_port(), 1024);
        owner.credentials = Credentials::user(1000, 1000);
        let denied = FileWork::from_vfs(
            &owner,
            net_target,
            FileCommand::Write {
                bytes: b"0".to_vec(),
                offset: Some(0),
            },
        );
        assert!(matches!(
            std::thread::spawn(move || run(denied)).join().unwrap(),
            Err(Errno(13))
        ));
        let write = FileWork::from_vfs(
            &owner,
            oom_target,
            FileCommand::Write {
                bytes: b"200".to_vec(),
                offset: None,
            },
        );
        assert!(matches!(
            std::thread::spawn(move || run(write)).join().unwrap(),
            Ok(FileValue::Count(3))
        ));
        assert_eq!(owner.read(oomfd, 16).unwrap(), b"200\n");
        let read = FileWork::from_vfs(
            &owner,
            mount_target,
            FileCommand::Read {
                count: 65536,
                offset: Some(0),
            },
        );
        owner.close(mount).unwrap();
        owner.credentials = Credentials::default();
        let replacement = owner
            .open_at(AT_FDCWD, b"/replacement", 0x42, 0o600)
            .unwrap();
        assert_eq!(replacement, mount);
        let Ok(FileValue::Bytes(text)) = std::thread::spawn(move || run(read)).join().unwrap()
        else {
            panic!("mount body")
        };
        assert!(String::from_utf8_lossy(&text).contains(" - proc "));
        assert_eq!(owner.pread(replacement, 8, 0).unwrap(), b"");
    }
}
