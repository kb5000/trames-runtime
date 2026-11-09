// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted proc files retain original PID/mm resources, never a Files table.
//! Rendering uses a private control island and the same pseudo-file algorithms.
use super::*;
use std::sync::Mutex;

pub(super) struct ProcFile {
    path: Vec<u8>,
    mount: Option<Arc<mounts::MountData>>,
    source: Arc<dyn ProcSource>,
    target: Option<Arc<dyn ProcTask>>,
    memory: Option<trames_memory::MemoryReport>,
    saved: Option<Vec<u8>>,
    payload: Option<Payload>,
    readers: Mutex<Readers>,
    renderer: Mutex<PathQueries>,
}

// The type-erased source preserves the existing ProcFile capability boundary;
// its original publication has no Files root. PID bindings and fdinfo retain
// only their existing weak task/open capabilities.
pub(super) struct PublishedGlobal(pub(super) Arc<SharedCell<pseudo::PseudoFs>>);
impl ProcSource for PublishedGlobal {
    fn observe(&self, query: ProcQuery<'_>) -> RuntimeInfo {
        // Do not hold the original publication lock across provider callbacks.
        let source = self.0.borrow().source.clone();
        if let Some(source) = source.filter(|s| s.available(query.demand)) {
            source.observe(query)
        } else {
            self.0.borrow().runtime.clone()
        }
    }
}
#[derive(Clone, Copy)]
enum Payload {
    CommandLine,
    Environment,
}
#[derive(Default)]
struct Readers {
    memory: Option<trames_memory::MemoryReport>,
    pages: BTreeMap<u64, trames_memory::MemoryRead>,
}
pub(super) enum ProcRead {
    Complete(Result<Vec<u8>>),
    Waiting(Vec<trames_memory::MemoryRead>),
}
impl ProcFile {
    pub fn live_payload(&self) -> bool {
        self.payload.is_some()
    }
    fn payload_memory(&self) -> Result<Option<trames_memory::MemoryReport>> {
        match self.payload {
            Some(Payload::Environment) => Ok(self.memory.clone()),
            Some(Payload::CommandLine) => {
                let target = self.target.as_ref().unwrap();
                if !target.present() {
                    return Err(Errno(3));
                }
                Ok(target.memory_report())
            }
            None => unreachable!("image payload only"),
        }
    }
    fn image_read(
        &self,
        ranges: trames_memory::ImageRanges,
        offset: u64,
        count: usize,
        read: impl FnMut(u64, &mut [u8]) -> Option<usize>,
    ) -> Option<Vec<u8>> {
        let image = crate::ProcImage(ranges);
        match self.payload.unwrap() {
            Payload::CommandLine => image.command_line(offset, count, read),
            Payload::Environment => image.environment(offset, count, read),
        }
    }
    pub fn read_local(
        &self,
        offset: u64,
        count: usize,
        caller: &impl trames_memory::CpuMemory,
    ) -> Option<Result<Vec<u8>>> {
        self.payload?;
        let memory = match self.payload_memory() {
            Ok(memory) => memory,
            Err(error) => return Some(Err(error)),
        };
        let Some(memory) = memory.filter(|m| m.alive()) else {
            return Some(Ok(Vec::new()));
        };
        if caller.proc_address_space() != Some(memory.identity()) {
            return None;
        }
        let ranges = memory.image_ranges()?;
        self.image_read(ranges, offset, count, |a, out| {
            crate::ProcImage::local_reader(caller, a, out)
        })
        .map(Ok)
    }
    pub fn read_payload(&self, offset: u64, count: usize) -> ProcRead {
        let memory = match self.payload_memory() {
            Ok(memory) => memory,
            Err(error) => return ProcRead::Complete(Err(error)),
        };
        let Some(memory) = memory.filter(|m| m.alive()) else {
            return ProcRead::Complete(Ok(Vec::new()));
        };
        let Some(ranges) = memory.image_ranges() else {
            return ProcRead::Complete(Ok(Vec::new()));
        };
        let mut readers = self.readers.lock().unwrap();
        if readers
            .memory
            .as_ref()
            .is_none_or(|old| !old.same_resource(&memory))
        {
            readers.pages.clear();
            readers.memory = Some(memory.clone());
        }
        let mut missing = Vec::new();
        let bytes = self.image_read(ranges, offset, count, |address, out| {
            let base = address & !(trames_memory::PAGE_SIZE - 1);
            let page = match readers.pages.entry(base) {
                std::collections::btree_map::Entry::Occupied(page) => page.into_mut(),
                std::collections::btree_map::Entry::Vacant(page) => {
                    page.insert(memory.prepare_read_page(base)?)
                }
            };
            match page.try_read_chunk(address, out) {
                Some(Ok(n)) => Some(n),
                Some(Err(_)) => Some(0),
                None => {
                    // Discover the rest of this read's pages in the same pass.
                    // These placeholder bytes are preparation advice only: the
                    // entire owned result is discarded before any output/f_pos.
                    missing.push(page.clone());
                    out.fill(0);
                    Some(out.len())
                }
            }
        });
        if !missing.is_empty() {
            memory.request_reads(&missing);
            return ProcRead::Waiting(missing);
        }
        ProcRead::Complete(Ok(bytes.expect("admitted original mm reader")))
    }
    pub fn read(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        if self.payload.is_some() {
            return match self.read_payload(offset, count) {
                ProcRead::Complete(result) => result,
                ProcRead::Waiting(_) => Err(Errno(11)),
            };
        }
        let text = self.text()?;
        let start = offset.min(text.len() as u64) as usize;
        Ok(text[start..text.len().min(start.saturating_add(count))].to_vec())
    }
    fn text(&self) -> Result<Vec<u8>> {
        if let Some(saved) = &self.saved {
            return Ok(saved.clone());
        }
        if self.memory.as_ref().is_some_and(|memory| !memory.alive()) {
            if self.target.as_ref().is_some_and(|task| !task.present()) {
                return Err(Errno(3));
            }
            return Ok(Vec::new());
        }
        let renderer = self.renderer.lock().unwrap();
        let view = renderer.view.borrow();
        let path = ResolvedPath {
            proc_binding: None,
            key: self.path.clone(),
            mount: self
                .mount
                .as_ref()
                .map(|m| Mount::query_projection(m.clone(), &mut BTreeMap::new())),
        };
        let mut query = ProcQuery::new(
            &self.path,
            ProcRefresh::for_path(&self.path),
            view.proc_namespace(&path),
            view.pid,
        );
        query.retained = self.target.as_ref();
        let mut runtime = self.source.observe(query);
        if self.target.as_ref().is_some_and(|target| {
            !runtime
                .processes
                .iter()
                .any(|task| task.identity == target.identity())
        }) {
            return Err(Errno(3));
        }
        if let Some(memory) = &self.memory {
            for task in &mut runtime.processes {
                if self
                    .target
                    .as_ref()
                    .is_some_and(|target| target.identity() == task.identity)
                {
                    task.maps = memory.maps().to_vec();
                }
            }
        }
        view.pseudo.borrow_mut().runtime = runtime;
        match view.pseudo_content(&path)? {
            Some((Content::File(data), _)) => data.read_at(0, data.len() as usize),
            _ => Err(Errno(3)),
        }
    }
}
impl Vfs {
    pub(super) fn published_global(
        &self,
        path: &[u8],
    ) -> Option<Arc<SharedCell<pseudo::PseudoFs>>> {
        if path != b"/sys" && !path.starts_with(b"/sys/") {
            let tail = path.strip_prefix(b"/proc")?;
            if !tail.is_empty() && !tail.starts_with(b"/") {
                return None;
            }
            let first = tail
                .strip_prefix(b"/")
                .unwrap_or(tail)
                .split(|&b| b == b'/')
                .next()
                .unwrap_or_default();
            if matches!(first, b"self" | b"thread-self")
                || first.first().is_some_and(u8::is_ascii_digit)
            {
                return None;
            }
        }
        self.pseudo.borrow().publication.clone()
    }
    pub(super) fn proc_runtime_file(&self, path: &ResolvedPath) -> Option<Arc<ProcFile>> {
        if !self.uses_pseudo(path) || !self.pseudo_readonly(path) {
            return None;
        }
        let source = self.pseudo.borrow().source.clone();
        let demand = ProcRefresh::for_path(path);
        // Live guest bytes still require an actual read capability. Loaded
        // argv/environment metadata must never silently become their authority.
        if source.as_ref().is_some_and(|s| !s.available(demand)) {
            return None;
        }
        let parts: Vec<_> = path
            .strip_prefix(b"/proc/")
            .unwrap_or_default()
            .split(|b| *b == b'/')
            .collect();
        let local_pid = if parts.get(1) == Some(&b"task".as_slice()) {
            parts.get(2)
        } else {
            parts.first()
        }
        .and_then(|part| std::str::from_utf8(part).ok())
        .and_then(|part| part.parse::<u32>().ok());
        let target = match local_pid {
            Some(pid) => {
                let pid = self.proc_namespace(path).global(pid)?;
                Some(
                    path.proc_binding
                        .as_ref()
                        .and_then(|p| p.at(path, self.proc_namespace(path).id()))
                        .map(|p| p.target.clone())
                        .or_else(|| source.as_ref()?.task(pid))?,
                )
            }
            None => None,
        };
        // Published global proc/sys metadata already has an original shared
        // authority. It does not grant a guest-mm capability for numeric PID
        // files, cmdline, environment, maps or saved auxv.
        if source.is_none()
            && (local_pid.is_some()
                || demand.arguments()
                || demand.environment()
                || demand.mappings()
                || demand.auxiliary())
        {
            return None;
        }
        let payload = if demand.arguments() {
            Some(Payload::CommandLine)
        } else if demand.environment() {
            Some(Payload::Environment)
        } else {
            None
        };
        let memory = if demand.mappings() || payload.is_some() {
            let memory = target.as_ref()?.memory_report();
            if payload.is_some()
                && memory
                    .as_ref()
                    .is_some_and(|m| m.image_ranges().is_none() || !m.supports_reads())
            {
                return None; // legacy synthetic fixtures without an actual image
            }
            if demand.mappings() {
                Some(memory?)
            } else {
                memory
            }
        } else {
            None
        };
        let saved = if demand.auxiliary() {
            let mut query = ProcQuery::new(path, demand, self.proc_namespace(path), self.pid);
            query.retained = target.as_ref();
            Some(
                source
                    .as_ref()?
                    .observe(query)
                    .processes
                    .into_iter()
                    .find(|info| {
                        target
                            .as_ref()
                            .is_some_and(|task| task.identity() == info.identity)
                    })?
                    .auxiliary,
            )
        } else {
            None
        };
        // A renderer needs text/resource capabilities, not cwd/root or the
        // opener's live Files. In particular OFD -> renderer -> Files -> OFD
        // must never form a last-close cycle.
        let mut view = Vfs::empty(self.fs.clone());
        view.uts = self.uts.clone();
        view.network = self.network.clone();
        view.root_network = self.root_network.clone();
        view.pid = self.pid;
        view.pid_ns = self.pid_ns.clone();
        view.cgroups = self.cgroups.clone();
        view.cgroup_namespace = self.cgroup_namespace.clone();
        view.query = Some(path_queries::Authority::file_root(&view));
        {
            let original = self.pseudo.borrow();
            let mut pseudo = view.pseudo.borrow_mut();
            pseudo.enabled = true;
            pseudo.source = source.clone();
            pseudo.boot_id = original.boot_id.clone();
            pseudo.video_device = original.video_device.clone();
        }
        Some(Arc::new(ProcFile {
            path: path.key.clone(),
            mount: path.mount.as_ref().map(|m| m.shared.clone()),
            source: source.unwrap_or_else(|| {
                Arc::new(PublishedGlobal(
                    self.pseudo
                        .borrow()
                        .publication
                        .clone()
                        .unwrap_or_else(|| self.pseudo.clone()),
                ))
            }),
            target,
            memory,
            saved,
            payload,
            readers: Default::default(),
            renderer: Mutex::new(PathQueries {
                view: RefCell::new(view),
            }),
        }))
    }
}

#[cfg(test)]
mod published_tests {
    use super::*;
    use std::time::Duration;
    fn bytes(outcome: FileOutcome) -> Vec<u8> {
        let FileOutcome::Complete(reply) = outcome else {
            panic!("global metadata needs no owner/layout/byte wait")
        };
        let FileValue::Bytes(bytes) = reply.result.unwrap() else {
            panic!("metadata bytes")
        };
        bytes
    }
    fn read(owner: &Vfs, file: FileTarget) -> Vec<u8> {
        bytes(
            FileWork::from_vfs(
                owner,
                file,
                FileCommand::Read {
                    count: 16384,
                    offset: Some(0),
                },
            )
            .run(),
        )
    }
    #[test]
    fn all_published_global_metadata_uses_the_original_resource_on_source() {
        let mut owner = Vfs::default();
        owner.set_runtime_info(
            1,
            RuntimeInfo {
                cpu_count: 4,
                uptime: Duration::from_secs(123),
                memory_limit: 128 << 20,
                ..Default::default()
            },
        );
        let paths = owner.path_queries();
        for path in [
            b"/proc/version".as_slice(),
            b"/proc/cpuinfo",
            b"/proc/meminfo",
            b"/proc/uptime",
            b"/proc/stat",
            b"/sys/devices/system/cpu/online",
        ] {
            let solo = owner.open_at(AT_FDCWD, path, 0, 0).unwrap();
            let fd = paths
                .open_at_resolve(AT_FDCWD, path, 0, 0, 0, &DirectFiles::default())
                .expect("published global provider is retained")
                .unwrap();
            let target = owner
                .shared_files()
                .lookup(fd)
                .unwrap()
                .unwrap()
                .file_target()
                .expect("original metadata FileTarget");
            assert_eq!(
                read(&owner, target),
                owner.pread(solo, 16384, 0).unwrap(),
                "{}",
                String::from_utf8_lossy(path)
            );
            owner.close(fd).unwrap();
            owner.close(solo).unwrap();
        }
    }
    #[test]
    fn retained_global_file_observes_publication_and_live_provider_without_files_cycle() {
        struct Live(std::sync::Weak<SharedCell<pseudo::PseudoFs>>);
        impl ProcSource for Live {
            fn observe(&self, _: ProcQuery<'_>) -> RuntimeInfo {
                // Provider callbacks can reenter the original publication.
                let _root = self.0.upgrade().unwrap().borrow().enabled;
                RuntimeInfo {
                    cpu_count: 9,
                    ..Default::default()
                }
            }
        }
        let mut owner = Vfs::default();
        owner.set_runtime_info(
            1,
            RuntimeInfo {
                cpu_count: 2,
                ..Default::default()
            },
        );
        let original = Arc::downgrade(&owner.pseudo);
        let paths = owner.path_queries();
        let fd = paths
            .open_at_resolve(
                AT_FDCWD,
                b"/sys/devices/system/cpu/online",
                0,
                0,
                0,
                &DirectFiles::default(),
            )
            .unwrap()
            .unwrap();
        let target = owner
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        assert_eq!(read(&owner, target.clone()), b"0-1\n");
        owner.set_runtime_info(
            1,
            RuntimeInfo {
                cpu_count: 6,
                ..Default::default()
            },
        );
        assert_eq!(read(&owner, target.clone()), b"0-5\n");
        owner.set_proc_source(Arc::new(Live(original.clone())));
        assert_eq!(read(&owner, target.clone()), b"0-8\n");
        let work = FileWork::from_vfs(
            &owner,
            target.clone(),
            FileCommand::Read {
                count: 64,
                offset: Some(0),
            },
        );
        owner.close(fd).unwrap();
        drop(paths);
        drop(owner);
        assert!(original.upgrade().is_some());
        assert_eq!(bytes(work.run()), b"0-8\n");
        drop(target);
        assert!(
            original.upgrade().is_none(),
            "last close must release the original publication"
        );
    }
    #[test]
    fn published_metadata_does_not_invent_live_pid_memory_or_override_explicit_exclusion() {
        struct Excluded;
        impl ProcSource for Excluded {
            fn available(&self, _: ProcRefresh) -> bool {
                false
            }
            fn observe(&self, _: ProcQuery<'_>) -> RuntimeInfo {
                panic!("unavailable original provider")
            }
        }
        let mut owner = Vfs::default();
        owner.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    arguments: vec![b"metadata-only".to_vec()],
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let paths = owner.path_queries();
        for path in [
            b"/proc/1/cmdline".as_slice(),
            b"/proc/1/environ",
            b"/proc/1/maps",
            b"/proc/1/auxv",
        ] {
            assert!(
                paths
                    .open_at_resolve(AT_FDCWD, path, 0, 0, 0, &DirectFiles::default())
                    .is_none(),
                "numeric PID metadata is not a live mm capability"
            );
        }
        owner.set_proc_source(Arc::new(Excluded));
        assert!(owner
            .path_queries()
            .open_at_resolve(AT_FDCWD, b"/proc/version", 0, 0, 0, &DirectFiles::default())
            .is_none());
        let fd = owner.open_at(AT_FDCWD, b"/proc/version", 0, 0).unwrap();
        assert!(owner.pread(fd, 8, 0).unwrap().starts_with(b"Linux"));
    }
}
