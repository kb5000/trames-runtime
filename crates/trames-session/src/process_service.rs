// SPDX-License-Identifier: GPL-3.0-or-later
//! In-epoch services: coordinator-owned FD state, caller-owned concurrent bytes.
//! Ordinary I/O uses caller Views. New private-anonymous intervals may be
//! published through the append-only mapping authority while peers execute.
use super::*;

#[derive(Default)]
pub(super) struct DiskEpoch<C: Cpu> {
    pending: Vec<Option<PendingDiskRead<C>>>,
    syncs: Vec<Option<PendingDiskSync<C>>>,
    reads: usize,
    pub(super) in_flight: usize,
    pub(super) waiting: std::collections::VecDeque<Box<crate::workers::Request<C>>>,
}
impl<C: Cpu> DiskEpoch<C> {
    fn insert_sync(&mut self, pending: PendingDiskSync<C>) -> usize {
        self.in_flight += 1;
        if let Some(index) = self.syncs.iter().position(Option::is_none) {
            self.syncs[index] = Some(pending);
            index
        } else {
            self.syncs.push(Some(pending));
            self.syncs.len() - 1
        }
    }
    fn insert(&mut self, pending: PendingDiskRead<C>) -> usize {
        self.in_flight += 1;
        self.reads += 1;
        if let Some(index) = self.pending.iter().position(Option::is_none) {
            self.pending[index] = Some(pending);
            index
        } else {
            self.pending.push(Some(pending));
            self.pending.len() - 1
        }
    }
    fn take(&mut self, id: usize) -> PendingDiskRead<C> {
        let pending = self.pending[id].take().expect("submitted disk read");
        self.in_flight -= 1;
        self.reads -= 1;
        pending
    }
}
struct PendingDiskSync<C: Cpu> {
    request: Box<crate::workers::Request<C>>,
    _sync: trames_vfs::DiskSync,
}
pub(super) struct PendingDiskRead<C: Cpu> {
    request: Box<crate::workers::Request<C>>,
    read: trames_vfs::DiskRead,
    parts: ReadParts,
}

enum ReadParts {
    Scalar(u64),
    Vector(Vec<(u64, usize)>),
}
impl ReadParts {
    fn scatter(
        &self,
        memory: &mut impl trames_memory::CpuMemory,
        bytes: &[u8],
    ) -> Result<(), Errno> {
        match self {
            Self::Scalar(address) => Linux::scatter(memory, &[(*address, bytes.len())], bytes),
            Self::Vector(parts) => Linux::scatter(memory, parts, bytes),
        }
    }
}

impl<C: Cpu> Kernel<C> {
    pub(super) fn epoch_request(
        &mut self,
        mut request: Box<crate::workers::Request<C>>,
        disk: &mut DiskEpoch<C>,
        io: &mut impl GuestOutput,
    ) -> bool {
        let bulk = matches!(request.number, 65 | 69)
            || matches!(request.number, 63 | 67) && request.args[2] >= 16 * 1024;
        // Most services have no pending disk conflict or bulk-read admission.
        // Keep their single process lookup and original helpers intact.
        if disk.in_flight == 0 && !bulk && !matches!(request.number, 82 | 83) {
            let value = self.service_request(&mut request, io);
            request.respond(value);
            return value.is_some();
        }
        let Some(p) = self.processes.get(&request.pid) else {
            request.respond(None);
            return false;
        };
        if disk.pending.iter().flatten().any(|pending| {
            pending
                .read
                .conflicts(&p.linux.vfs, request.args[0] as u32, request.number)
        }) {
            disk.waiting.push_back(request);
            return true;
        }
        // Small reads remain inline: a host queue roundtrip would cost more
        // than their cached read. Memory/mapped files retain the old helpers.
        let a = request.args;
        if matches!(request.number, 82 | 83)
            && p.seccomp.allows(request.number, request.pc, request.args)
            && !p.linux.trace
            && matches!(p.state, State::Ready)
        {
            match p.linux.vfs.prepare_disk_sync(a[0] as u32, request.number == 83) {
                Ok(Some((sync, job))) => {
                    if disk.in_flight >= self.cpu_count {
                        disk.waiting.push_back(request);
                        return true;
                    }
                    let id = disk.insert_sync(PendingDiskSync { request, _sync: sync });
                    self.workers.disk_sync(id, job);
                    return true;
                }
                Err(e) => { request.respond(Some(error(e))); return true; }
                Ok(None) => {}
            }
        }
        if matches!(request.number, 63 | 65 | 67 | 69)
            && p.seccomp.allows(request.number, request.pc, request.args)
            && !p.linux.trace
            && matches!(p.state, State::Ready)
            && (matches!(request.number, 65 | 69) || a[2] >= 16 * 1024)
            && p.linux.vfs.disk_read_candidate(a[0] as u32)
        {
            let prepare = || -> Result<_, Errno> {
                if request.number == 69 && a[3] > i64::MAX as u64 {
                    return Err(Errno(22));
                }
                let (parts, count) = if matches!(request.number, 65 | 69) {
                    let (parts, count) = Linux::readv_parts(request.memory(), a)?;
                    (ReadParts::Vector(parts), count)
                } else {
                    let count = a[2].min(trames_linux::MAX_WRITE as u64) as usize;
                    Linux::check(request.memory(), a[1], count, trames_memory::Access::Write)?;
                    (ReadParts::Scalar(a[1]), count)
                };
                if count < 16 * 1024 {
                    return Ok(None);
                }
                let offset = matches!(request.number, 67 | 69).then_some(a[3]);
                Ok(p.linux
                    .vfs
                    .prepare_disk_read(a[0] as u32, count, offset)?
                    .map(|(read, job)| (read, job, parts)))
            };
            match prepare() {
                Ok(Some((read, job, parts))) => {
                    if disk.in_flight >= self.cpu_count {
                        // Slot-free callers must not create unbounded 1 MiB
                        // buffers. Preparation above has no byte/OFD effects;
                        // metadata-only waiters retry admission on completion.
                        disk.waiting.push_back(request);
                        return true;
                    }
                    let id = disk.insert(PendingDiskRead::<C> {
                        request,
                        read,
                        parts,
                    });
                    self.disk_reads += 1;
                    self.peak_disk_reads = self.peak_disk_reads.max(disk.reads);
                    self.workers.disk_read(id, job);
                    return true;
                }
                Err(e) => {
                    request.respond(Some(error(e)));
                    return true;
                }
                Ok(None) => {}
            }
        }
        let value = self.service_request(&mut request, io);
        request.respond(value);
        value.is_some()
    }
    pub(super) fn finish_disk_read(
        &mut self,
        id: usize,
        result: Result<Vec<u8>, Errno>,
        disk: &mut DiskEpoch<C>,
    ) {
        let mut pending = disk.take(id);
        let began = self.profile_syscalls.then(Instant::now);
        let result = pending.read.finish(result).and_then(|bytes| {
            self.disk_read_bytes += bytes.len() as u64;
            let count = bytes.len() as u64;
            let copied = pending.parts.scatter(pending.request.memory_mut(), &bytes);
            self.workers.recycle_disk_buffer(bytes);
            copied.map(|()| count)
        });
        if let Some(began) = began {
            self.syscall_total += began.elapsed();
        }
        pending.request.respond(Some(result.unwrap_or_else(error)));
    }
    pub(super) fn finish_disk_sync(&mut self, id: usize, result: Result<(), Errno>, disk: &mut DiskEpoch<C>) {
        let pending = disk.syncs[id].take().expect("submitted disk sync");
        disk.in_flight -= 1;
        pending.request.respond(Some(result.map_or_else(error, |()| 0)));
    }
    pub(super) fn resume_disk_waiters(
        &mut self,
        disk: &mut DiskEpoch<C>,
        io: &mut impl GuestOutput,
    ) -> bool {
        // One pass preserves arrival order among conflicting operations, while
        // independent descriptors can resume. A caller can own only one request.
        let count = disk.waiting.len();
        for _ in 0..count {
            let request = disk.waiting.pop_front().expect("waiting request");
            if !self.epoch_request(request, disk, io) {
                return false;
            }
        }
        true
    }
    pub(super) fn service_request(
        &mut self,
        request: &mut crate::workers::Request<C>,
        io: &mut impl GuestOutput,
    ) -> Option<u64> {
        let p = self.processes.get_mut(&request.pid)?;
        // The worker already evaluated its immutable epoch filter. Recheck
        // here before any VFS effects, using the actual post-SVC PC/arguments.
        // Installation/TSYNC cannot change authority until all CPUs join.
        if !p.seccomp.allows(request.number, request.pc, request.args)
            || p.linux.trace
            || !matches!(p.state, State::Ready)
        {
            return None;
        }
        let a = request.args;
        if request.number == 222 && p.seccomp.mode() == 0 {
            let began = Instant::now();
            let result = p.linux.mmap_additive(a, &mut p.memory)?;
            self.parallel_memory_time += began.elapsed();
            self.vm_local_syscalls += 1;
            // Every result is final, including errors. No mapping effect can
            // fall back/replay through a later joined request.
            return Some(result.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
        }
        match request.number {
            25 if matches!(a[1], 1 | 3) => {}
            62 | 80 => {
                let kind = p.linux.vfs.fd_kind(a[0] as u32);
                // Dynamic proc endpoints require a joined process snapshot.
                if matches!(&kind, Ok(FdKind::Node(path)) if path == b"/proc" || path.starts_with(b"/proc/") || path == b"/sys" || path.starts_with(b"/sys/"))
                {
                    return None;
                }
            }
            63..=70 | 82 | 83 => {
                // Start with streams that cannot modify mapped file backing,
                // transfer FD rights, acquire a terminal, or queue guest signals.
                // Ordinary files join only when retained inode/backing state
                // requires it. The cached bitmap is merely an RPC candidate.
                let write = matches!(request.number, 64 | 66 | 68 | 70);
                let admitted = match p.linux.vfs.epoch_io(a[0] as u32, write) {
                    Some(trames_vfs::EpochIo::Stream) => matches!(request.number, 63..=66),
                    // RLIMIT_FSIZE can queue SIGXFSZ. Keep its complete existing
                    // signal path joined; no effects before this decision.
                    Some(trames_vfs::EpochIo::File) => {
                        !write || p.file_size_limit.get().0 == u64::MAX
                    }
                    None => false,
                };
                if !admitted {
                    return None;
                }
            }
            _ => return None,
        }
        p.linux.vfs.set_process_context(request.pid);
        p.linux.vfs.set_lock_owner(p.tgid);
        p.linux.vfs.set_file_size_limit(p.file_size_limit.get().0);
        let began = self.profile_syscalls.then(Instant::now);
        let number = request.number;
        let result = match number {
            63 => p.linux.read(a, request.memory_mut(), io),
            64 => p
                .linux
                .write_scratch(a, request.memory(), io, &mut self.service_write_buffer),
            65 => p.linux.readv(a, request.memory_mut(), io),
            66 => p
                .linux
                .writev_scratch(a, request.memory(), io, &mut self.service_write_buffer),
            67 | 68 => p.linux.positioned_scratch(
                a,
                request.memory_mut(),
                number == 68,
                &mut self.service_write_buffer,
            ),
            69 | 70 => p.linux.positioned_vector_scratch(
                a,
                request.memory_mut(),
                number == 70,
                &mut self.service_write_buffer,
            ),
            82 | 83 => p
                .linux
                .vfs
                .sync_fd(a[0] as u32, request.number == 83)
                .map(|()| 0),
            number => p.linux.fd_query(number, a, request.memory_mut()),
        };
        if let Some(began) = began {
            self.syscall_total += began.elapsed();
        }
        match result {
            // Both return before effects on these admitted streams. Let the
            // original joined path install waits/timeouts and deliver SIGPIPE.
            Err(Errno(11))
                if p.linux
                    .vfs
                    .flags(a[0] as u32)
                    .is_ok_and(|f| f & O_NONBLOCK == 0) =>
            {
                None
            }
            Err(Errno(32)) if matches!(request.number, 64 | 66) => None,
            Err(Errno(38 | 95)) => None,
            other => Some(other.unwrap_or_else(error)),
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Process = crate::process::Process<Cpu>;
    type Kernel = crate::process::Kernel<Cpu>;
    type Work = crate::workers::Work<Cpu>;
    type Request = crate::workers::Request<Cpu>;

    use super::*;
    use crate::workers::{Control, Event};
    use std::sync::Arc;
    use trames_memory::{CpuMemory, Permissions, PAGE_SIZE};

    fn pending(
        mut p: Box<Process>,
        number: u32,
        a: [u64; 6],
    ) -> (Kernel, Box<Request>, Arc<Control>) {
        p.memory
            .write_array(0x4000, 0xd4000001u32.to_le_bytes())
            .unwrap();
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        let mut cpu = Cpu::new(0x4000, 0);
        cpu.set_x(8, number as u64);
        put_args(&mut cpu, a);
        let snapshot = crate::worker_syscalls::Snapshot {
            seccomp: p.seccomp.clone(),
            identities: [0; 7],
            started: Instant::now(),
            processor: 0,
            profile: false,
            streams: p.linux.vfs.stream_descriptors(),
            files: p.linux.vfs.file_descriptors(),
            fd_flags: p.linux.vfs.fd_flags_snapshot(),
            umask: p.linux.vfs.umask_capability(),
            actions: p.signals.actions.shared(),
            program_break: p.linux.program_break(),
            uts: None,
            direct: Default::default(),
            futex: Default::default(),
        };
        let memory = p.memory.parallel_view(&mut Default::default()).unwrap();
        let control = Arc::new(Control::new(100));
        let mut k = super::super::tests::kernel();
        k.processes.insert(1, p);
        k.workers.ensure(0).unwrap();
        k.workers
            .dispatch(
                0,
                Work {
                    gpu: None,
                    pid: 1,
                    cpu,
                    memory: Some(Box::new(memory)),
                    control: control.clone(),
                    syscalls: Some(snapshot),
                },
            )
            .unwrap();
        let Some(Event::Service(request)) =
            k.workers.event_timeout(Duration::from_secs(5)).unwrap()
        else {
            panic!("missing in-epoch request");
        };
        (k, request, control)
    }
    fn finish(
        k: &mut Kernel,
        request: Box<Request>,
        control: Arc<Control>,
        value: Option<u64>,
    ) -> crate::workers::Done<Cpu> {
        control.stop();
        request.respond(value);
        let done = k.workers.complete().unwrap();
        assert_eq!(done.instructions, 1);
        assert_eq!(done.serviced_syscalls, u64::from(value.is_some()));
        k.processes
            .get_mut(&1)
            .unwrap()
            .memory
            .commit_parallel()
            .unwrap();
        done
    }
    fn disk_process() -> (std::path::PathBuf, Box<Process>, u32) {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "trames-epoch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut p = super::super::tests::process();
        p.linux.vfs = trames_vfs::Vfs::open_disk(&path, Default::default()).unwrap();
        p.linux
            .vfs
            .import_file(b"/data", vec![0xa5; 32768])
            .unwrap();
        let fd = p.linux.vfs.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
        p.memory.map(0x10000, 32768, Permissions::RW).unwrap();
        (path, p, fd)
    }
    #[test]
    fn disk_slots_bound_in_flight_reads_and_resume_metadata_only_waiters() {
        let (path, p, fd) = disk_process();
        let mut peer = super::super::tests::process();
        peer.linux.vfs = p.linux.vfs.clone();
        peer.memory.map(0x10000, 32768, Permissions::RW).unwrap();
        let args = [fd as u64, 0x10000, 32768, 0, 0, 0];
        let (mut k, request, control) = pending(p, 67, args);
        k.cpu_count = 1;
        let mut disk = DiskEpoch::default();
        let mut io = trames_linux::CapturedOutput::default();
        assert!(k.epoch_request(request, &mut disk, &mut io));
        let Some(Event::DiskRead(id, result)) =
            k.workers.event_timeout(Duration::from_secs(5)).unwrap()
        else {
            panic!("missing disk completion");
        };
        // Hold the first result uncommitted while another independent pread
        // arrives. It must queue without submitting another buffer/job.
        let (mut peer_kernel, mut request, peer_control) = pending(peer, 67, args);
        request.pid = 2;
        k.processes
            .insert(2, peer_kernel.processes.remove(&1).unwrap());
        assert!(k.epoch_request(request, &mut disk, &mut io));
        assert_eq!(
            (
                disk.in_flight,
                disk.waiting.len(),
                k.disk_reads,
                k.peak_disk_reads
            ),
            (1, 1, 1, 1)
        );
        control.stop();
        peer_control.stop();
        k.finish_disk_read(id, result, &mut disk);
        assert!(k.resume_disk_waiters(&mut disk, &mut io));
        assert_eq!(
            (
                disk.in_flight,
                disk.waiting.len(),
                k.disk_reads,
                k.peak_disk_reads
            ),
            (1, 0, 2, 1)
        );
        let mut first = None;
        while first.is_none() || disk.in_flight != 0 {
            match k.workers.event_timeout(Duration::from_secs(5)).unwrap() {
                Some(Event::DiskRead(id, result)) => k.finish_disk_read(id, result, &mut disk),
                Some(Event::Done(done)) => first = Some(done),
                _ => panic!("missing disk/CPU completion"),
            }
        }
        let second = peer_kernel
            .workers
            .complete_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert_eq!((first.unwrap().cpu.x(0), second.cpu.x(0)), (32768, 32768));
        assert_eq!(
            k.processes
                .get_mut(&1)
                .unwrap()
                .linux
                .vfs
                .seek(fd, 0, 1)
                .unwrap(),
            0
        );
        for process in k.processes.values_mut() {
            process.memory.commit_parallel().unwrap();
            assert_eq!(
                process.memory.read_array::<32768>(0x10000).unwrap(),
                [0xa5; 32768]
            );
        }
        drop(peer_kernel);
        drop(k);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn disk_scalar_vector_and_positioned_reads_complete_once_after_stop() {
        for number in [63, 65, 67, 69] {
            let (path, mut p, fd) = disk_process();
            p.memory
                .write_array(0x2000, 0x10000u64.to_le_bytes())
                .unwrap();
            p.memory.write_array(0x2008, 8192u64.to_le_bytes()).unwrap();
            p.memory
                .write_array(0x2010, 0x12000u64.to_le_bytes())
                .unwrap();
            p.memory
                .write_array(0x2018, 24576u64.to_le_bytes())
                .unwrap();
            let vector = matches!(number, 65 | 69);
            let a = [
                fd as u64,
                if vector { 0x2000 } else { 0x10000 },
                if vector { 2 } else { 32768 },
                0,
                0,
                0,
            ];
            let (mut k, request, control) = pending(p, number, a);
            let mut disk = DiskEpoch::default();
            assert!(k.epoch_request(
                request,
                &mut disk,
                &mut trames_linux::CapturedOutput::default()
            ));
            assert_eq!(disk.in_flight, 1);
            control.stop();
            let Some(Event::DiskRead(id, result)) =
                k.workers.event_timeout(Duration::from_secs(5)).unwrap()
            else {
                panic!("missing host completion")
            };
            k.finish_disk_read(id, result, &mut disk);
            let done = k
                .workers
                .complete_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            assert_eq!(done.cpu.x(0), 32768);
            assert_eq!(done.instructions, 1);
            assert_eq!(done.serviced_syscalls, 1);
            let p = k.processes.get_mut(&1).unwrap();
            p.memory.commit_parallel().unwrap();
            assert_eq!(
                p.memory.read_array::<32768>(0x10000).unwrap(),
                [0xa5; 32768]
            );
            assert_eq!(
                p.linux.vfs.seek(fd, 0, 1).unwrap(),
                if number < 67 { 32768 } else { 0 }
            );
            drop(k);
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test]
    fn repeated_disk_reads_reuse_owned_buffers_and_pending_slots() {
        let (path, mut p, fd) = disk_process();
        // Restore x0 after each pread result, then request the next read.
        for (i, instruction) in [0xd2800000u32 | (fd << 5), 0xd4000001, 0x17fffffe]
            .into_iter()
            .enumerate()
        {
            p.memory
                .write_array(0x4004 + i as u64 * 4, instruction.to_le_bytes())
                .unwrap();
        }
        let (mut k, mut request, control) = pending(p, 67, [fd as u64, 0x10000, 32768, 0, 0, 0]);
        let mut disk = DiskEpoch::default();
        let mut allocation = None;
        for i in 0..12 {
            assert!(k.epoch_request(
                request,
                &mut disk,
                &mut trames_linux::CapturedOutput::default()
            ));
            assert_eq!(disk.pending.len(), 1);
            let Some(Event::DiskRead(id, result)) =
                k.workers.event_timeout(Duration::from_secs(5)).unwrap()
            else {
                panic!("missing completion")
            };
            assert_eq!(id, 0);
            let pointer = result.as_ref().unwrap().as_ptr();
            assert_eq!(*allocation.get_or_insert(pointer), pointer);
            if i == 11 {
                control.stop();
            }
            k.finish_disk_read(id, result, &mut disk);
            assert_eq!(disk.in_flight, 0);
            if i == 11 {
                break;
            }
            let Some(Event::Service(next)) =
                k.workers.event_timeout(Duration::from_secs(5)).unwrap()
            else {
                panic!("missing next request")
            };
            request = next;
        }
        let done = k
            .workers
            .complete_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert_eq!(done.serviced_syscalls, 12);
        assert_eq!(done.cpu.x(0), 32768);
        drop(k);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn pending_disk_read_allows_pipe_service_and_defers_shared_offset() {
        for conflict in [false, true] {
            let (path, p, fd) = disk_process();
            let mut peer = super::super::tests::process();
            peer.linux.vfs = p.linux.vfs.clone();
            let [r, w] = peer.linux.vfs.pipe(0).unwrap();
            peer.linux.vfs.write(w, b"ok").unwrap();
            let (mut k, request, control) = pending(p, 63, [fd as u64, 0x10000, 16384, 0, 0, 0]);
            let mut disk = DiskEpoch::default();
            let mut io = trames_linux::CapturedOutput::default();
            assert!(k.epoch_request(request, &mut disk, &mut io));
            // The host job may already have finished. Deliberately retain its
            // uncommitted completion to exercise an outstanding operation.
            let Some(Event::DiskRead(id, result)) =
                k.workers.event_timeout(Duration::from_secs(5)).unwrap()
            else {
                panic!("missing disk completion")
            };
            let args = [if conflict { fd } else { r } as u64, 0x2000, 2, 0, 0, 0];
            let (mut peer_kernel, mut request, peer_control) = pending(peer, 63, args);
            request.pid = 2;
            k.processes
                .insert(2, peer_kernel.processes.remove(&1).unwrap());
            peer_control.stop();
            assert!(k.epoch_request(request, &mut disk, &mut io));
            assert_eq!(disk.waiting.len(), usize::from(conflict));
            if !conflict {
                let done = peer_kernel
                    .workers
                    .complete_timeout(Duration::from_secs(5))
                    .unwrap()
                    .unwrap();
                assert_eq!(done.cpu.x(0), 2);
                assert_eq!(disk.in_flight, 1);
            }
            control.stop();
            k.finish_disk_read(id, result, &mut disk);
            assert!(k.resume_disk_waiters(&mut disk, &mut io));
            if conflict {
                let done = peer_kernel
                    .workers
                    .complete_timeout(Duration::from_secs(5))
                    .unwrap()
                    .unwrap();
                assert_eq!(done.cpu.x(0), 2);
                assert_eq!(k.processes[&1].linux.vfs.flags(fd).unwrap() & 3, 2);
            }
            assert_eq!(
                k.workers
                    .complete_timeout(Duration::from_secs(5))
                    .unwrap()
                    .unwrap()
                    .cpu
                    .x(0),
                16384
            );
            let position = k
                .processes
                .get_mut(&1)
                .unwrap()
                .linux
                .vfs
                .seek(fd, 0, 1)
                .unwrap();
            assert_eq!(position, 16384 + if conflict { 2 } else { 0 });
            drop(peer_kernel);
            drop(k);
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test]
    fn regular_scalar_vector_and_positioned_services_share_the_original_abi() {
        for number in 63..=70u32 {
            let mut p = super::super::tests::process();
            p.linux
                .vfs
                .import_file(b"/file", b"abcdefgh".to_vec())
                .unwrap();
            let fd = p
                .linux
                .vfs
                .open_at(trames_vfs::AT_FDCWD, b"/file", 2, 0)
                .unwrap();
            let vector = matches!(number, 65 | 66 | 69 | 70);
            let positioned = number >= 67;
            let write = number % 2 == 0;
            p.memory.write(0x2200, b"XY").unwrap();
            p.memory.write(0x2210, b"ZW").unwrap();
            for (at, value) in [(0x2100, 0x2200), (0x2108, 2), (0x2110, 0x2210), (0x2118, 2)] {
                p.memory
                    .write_array(at, (value as u64).to_le_bytes())
                    .unwrap();
            }
            if positioned {
                p.linux.vfs.seek(fd, 5, 0).unwrap();
            }
            let args = [fd as u64, if vector { 0x2100 } else { 0x2200 }, 2, 2, 0, 0];
            let (mut k, mut request, control) = pending(p, number, args);
            let value =
                k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
            let count = if vector { 4 } else { 2 };
            assert_eq!(value, Some(count));
            let done = finish(&mut k, request, control, value);
            assert_eq!(done.cpu.x(0), count);
            let p = k.processes.get_mut(&1).unwrap();
            assert_eq!(
                p.linux.vfs.seek(fd, 0, 1).unwrap(),
                if positioned { 5 } else { count }
            );
            let start = if positioned { 2 } else { 0 };
            let mut expected = b"abcdefgh".to_vec();
            if write {
                expected[start..start + count as usize].copy_from_slice(&b"XYZW"[..count as usize]);
            } else {
                assert_eq!(
                    p.memory.read_array::<2>(0x2200).unwrap(),
                    expected[start..start + 2]
                );
                if vector {
                    assert_eq!(
                        p.memory.read_array::<2>(0x2210).unwrap(),
                        expected[start + 2..start + 4]
                    );
                }
            }
            assert_eq!(p.linux.vfs.pread(fd, 8, 0).unwrap(), expected);
        }
    }
    #[test]
    fn regular_file_sync_services_use_the_original_vfs_path() {
        for sync in [82, 83] {
            let mut p = super::super::tests::process();
            p.linux.vfs.import_file(b"/file", b"x".to_vec()).unwrap();
            let fd = p
                .linux
                .vfs
                .open_at(trames_vfs::AT_FDCWD, b"/file", 2, 0)
                .unwrap();
            let (mut k, mut request, control) = pending(p, sync, [fd as u64, 0, 0, 0, 0, 0]);
            let value =
                k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
            assert_eq!(value, Some(0));
            finish(&mut k, request, control, value);
        }
    }
    #[test]
    fn pending_disk_sync_allows_pipe_service_and_completes_once_after_stop() {
        for sync in [82, 83] {
            let (path, p, fd) = disk_process();
            let mut peer = super::super::tests::process();
            peer.linux.vfs = p.linux.vfs.clone();
            let [r, w] = peer.linux.vfs.pipe(0).unwrap();
            peer.linux.vfs.write(w, b"ok").unwrap();
            let (mut k, request, control) = pending(p, sync, [fd as u64, 0, 0, 0, 0, 0]);
            let mut disk = DiskEpoch::default();
            let mut io = trames_linux::CapturedOutput::default();
            assert!(k.epoch_request(request, &mut disk, &mut io));
            assert_eq!(disk.in_flight, 1);
            let Some(Event::DiskSync(id, result)) = k.workers.event_timeout(Duration::from_secs(5)).unwrap()
            else { panic!("missing disk sync") };
            assert_eq!(result, Ok(()));
            // Retain completion while serving an unrelated caller: the sync
            // caller is still parked, without occupying coordinator execution.
            let (mut peer_kernel, mut request, peer_control) = pending(peer, 63, [r as u64, 0x2000, 2, 0, 0, 0]);
            request.pid = 2;
            k.processes.insert(2, peer_kernel.processes.remove(&1).unwrap());
            peer_control.stop();
            assert!(k.epoch_request(request, &mut disk, &mut io));
            assert_eq!(disk.in_flight, 1);
            let peer_done = peer_kernel.workers.complete().unwrap();
            assert_eq!(peer_done.cpu.x(0), 2);
            control.stop();
            k.finish_disk_sync(id, result, &mut disk);
            assert_eq!(disk.in_flight, 0);
            let done = k.workers.complete().unwrap();
            assert_eq!((done.cpu.x(0), done.serviced_syscalls), (0, 1));
            k.processes.get_mut(&1).unwrap().memory.commit_parallel().unwrap();
            k.processes.get_mut(&2).unwrap().memory.commit_parallel().unwrap();
            drop((k, peer_kernel));
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test]
    fn mapped_file_bytes_are_shared_but_io_waits_for_metadata_publication() {
        let mut p = super::super::tests::process();
        p.linux.vfs.import_file(b"/file", b"old".to_vec()).unwrap();
        let fd = p
            .linux
            .vfs
            .open_at(trames_vfs::AT_FDCWD, b"/file", 2, 0)
            .unwrap();
        let pages = p
            .linux
            .vfs
            .mapping_pages(fd, 0, PAGE_SIZE, true, true)
            .unwrap();
        p.memory
            .map_backed(0x6000, pages, true, Permissions::RW, true)
            .unwrap();
        let args = [fd as u64, 0x2000, 3, 0, 0, 0];
        let (mut k, mut request, control) = pending(p, 63, args);
        request.memory_mut().write(0x6000, b"new").unwrap();
        assert_eq!(k.processes[&1].linux.vfs.pread(fd, 3, 0).unwrap(), b"new");
        let value = k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
        assert_eq!(value, None);
        let done = finish(&mut k, request, control, value);
        let mut p = k.processes.remove(&1).unwrap();
        p.cpu = done.cpu;
        k.call(
            1,
            &mut p,
            63,
            args,
            &mut trames_linux::CapturedOutput::default(),
        );
        assert_eq!(p.memory.read_array::<3>(0x2000).unwrap(), *b"new");
        assert_eq!(p.linux.vfs.seek(fd, 0, 1).unwrap(), 3);
    }
    #[test]
    fn finite_file_limit_keeps_sigxfsz_on_the_joined_path_without_effects() {
        let mut p = super::super::tests::process();
        p.linux.vfs.import_file(b"/file", b"old".to_vec()).unwrap();
        let fd = p
            .linux
            .vfs
            .open_at(trames_vfs::AT_FDCWD, b"/file", 2, 0)
            .unwrap();
        p.file_size_limit.set((0, 0));
        let args = [fd as u64, 0x2000, 1, 0, 0, 0];
        let (mut k, mut request, control) = pending(p, 64, args);
        let value = k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
        assert_eq!(value, None);
        let done = finish(&mut k, request, control, value);
        let mut p = k.processes.remove(&1).unwrap();
        p.cpu = done.cpu;
        k.call(
            1,
            &mut p,
            64,
            args,
            &mut trames_linux::CapturedOutput::default(),
        );
        assert_eq!(p.cpu.x(0), error(Errno(27)));
        assert!(p.signals.pending.contains_key(&25));
        assert_eq!(p.linux.vfs.pread(fd, 3, 0).unwrap(), b"old");
    }
    #[test]
    fn vector_read_preflights_every_output_before_consuming_file_input() {
        let mut p = super::super::tests::process();
        p.linux.vfs.import_file(b"/file", b"abcd".to_vec()).unwrap();
        let fd = p
            .linux
            .vfs
            .open_at(trames_vfs::AT_FDCWD, b"/file", 0, 0)
            .unwrap();
        for (at, value) in [(0x2100, 0x2200), (0x2108, 2), (0x2110, 0x9000), (0x2118, 2)] {
            p.memory
                .write_array(at, (value as u64).to_le_bytes())
                .unwrap();
        }
        let (mut k, mut request, control) = pending(p, 65, [fd as u64, 0x2100, 2, 0, 0, 0]);
        let value = k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
        assert_eq!(value, Some(error(Errno(14))));
        finish(&mut k, request, control, value);
        assert_eq!(
            k.processes
                .get_mut(&1)
                .unwrap()
                .linux
                .vfs
                .seek(fd, 0, 1)
                .unwrap(),
            0
        );
    }
    #[test]
    fn private_cow_stores_do_not_prevent_reading_the_unchanged_file() {
        let mut p = super::super::tests::process();
        p.linux.vfs.import_file(b"/file", b"old".to_vec()).unwrap();
        let fd = p
            .linux
            .vfs
            .open_at(trames_vfs::AT_FDCWD, b"/file", 2, 0)
            .unwrap();
        let pages = p
            .linux
            .vfs
            .mapping_pages(fd, 0, PAGE_SIZE, false, true)
            .unwrap();
        p.memory
            .map_backed(0x6000, pages, false, Permissions::RW, true)
            .unwrap();
        let (mut k, mut request, control) = pending(p, 63, [fd as u64, 0x2000, 3, 0, 0, 0]);
        request.memory_mut().write(0x6000, b"own").unwrap();
        let value = k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
        assert_eq!(value, Some(3));
        finish(&mut k, request, control, value);
        let p = k.processes.get_mut(&1).unwrap();
        assert_eq!(p.memory.read_array::<3>(0x6000).unwrap(), *b"own");
        assert_eq!(p.memory.read_array::<3>(0x2000).unwrap(), *b"old");
        assert_eq!(p.linux.vfs.pread(fd, 3, 0).unwrap(), b"old");
    }
    #[test]
    fn unix_stream_services_preserve_ready_blocking_nonblocking_and_sigpipe_paths() {
        for mode in 0..4 {
            let mut p = super::super::tests::process();
            let [r, w] = p
                .linux
                .vfs
                .socketpair(1, 1 | if mode == 2 { O_NONBLOCK } else { 0 }, 0)
                .unwrap();
            let number = if mode == 3 { 64 } else { 63 };
            if mode == 0 {
                p.linux.vfs.write(w, b"ab").unwrap();
            }
            if mode == 3 {
                p.linux
                    .vfs
                    .local_socket(w)
                    .unwrap()
                    .unwrap()
                    .shutdown(0)
                    .unwrap();
            }
            let args = [r as u64, 0x2000, 1, 0, 0, 0];
            let (mut k, mut request, control) = pending(p, number, args);
            let value =
                k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
            assert_eq!(
                value,
                match mode {
                    0 => Some(1),
                    2 => Some(error(Errno(11))),
                    _ => None,
                }
            );
            let done = finish(&mut k, request, control, value);
            if mode == 0 {
                assert_eq!(
                    k.processes[&1].memory.read_array::<1>(0x2000).unwrap(),
                    *b"a"
                );
            }
            if mode == 1 || mode == 3 {
                let mut p = k.processes.remove(&1).unwrap();
                p.cpu = done.cpu;
                k.call(
                    1,
                    &mut p,
                    number,
                    args,
                    &mut trames_linux::CapturedOutput::default(),
                );
                if mode == 1 {
                    assert!(matches!(p.state, State::Blocked(63, _)));
                } else {
                    assert_eq!(p.cpu.x(0), error(Errno(32)));
                    assert!(p.signals.pending.contains_key(&13));
                }
            }
        }
    }
    #[test]
    fn pipe_read_uses_the_callers_view_and_commits_once_when_a_peer_requests_stop() {
        let mut p = super::super::tests::process();
        let [r, w] = p.linux.vfs.pipe(0).unwrap();
        p.linux.vfs.write(w, b"ab").unwrap();
        let (mut k, mut request, control) = pending(p, 63, [r as u64, 0x2000, 1, 0, 0, 0]);
        let value = k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
        assert_eq!(value, Some(1));
        assert_eq!(request.memory().read_array::<1>(0x2000).unwrap(), *b"a");
        assert_eq!(
            k.processes
                .get_mut(&1)
                .unwrap()
                .linux
                .vfs
                .read(r, 1)
                .unwrap(),
            b"b"
        );
        let done = finish(&mut k, request, control, value);
        assert_eq!(done.cpu.x(0), 1);
        assert!(matches!(done.outcome, Some(SliceOutcome::Yield { .. })));
        assert_eq!(
            k.processes[&1].memory.read_array::<1>(0x2000).unwrap(),
            *b"a"
        );
    }
    #[test]
    fn stream_preflight_rejects_bad_destinations_without_consuming_input() {
        let mut p = super::super::tests::process();
        let [r, w] = p.linux.vfs.pipe(0).unwrap();
        p.linux.vfs.write(w, b"ab").unwrap();
        let (mut k, mut request, control) = pending(p, 63, [r as u64, 0x9000, 2, 0, 0, 0]);
        let value = k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
        assert_eq!(value, Some(error(Errno(14))));
        assert_eq!(
            k.processes
                .get_mut(&1)
                .unwrap()
                .linux
                .vfs
                .read(r, 2)
                .unwrap(),
            b"ab"
        );
        finish(&mut k, request, control, value);
    }
    #[test]
    fn blocking_and_sigpipe_paths_checkpoint_but_nonblocking_eagain_completes() {
        for mode in 0..3 {
            let mut p = super::super::tests::process();
            let [r, w] = p
                .linux
                .vfs
                .pipe(if mode == 1 { O_NONBLOCK } else { 0 })
                .unwrap();
            let number = if mode == 2 { 64 } else { 63 };
            let fd = if mode == 2 {
                p.linux.vfs.close(r).unwrap();
                w
            } else {
                r
            };
            let a = [fd as u64, 0x2000, 1, 0, 0, 0];
            let (mut k, mut request, control) = pending(p, number, a);
            let mut io = trames_linux::CapturedOutput::default();
            let value = k.service_request(&mut request, &mut io);
            assert_eq!(value, (mode == 1).then(|| error(Errno(11))));
            let done = finish(&mut k, request, control, value);
            if mode != 1 {
                assert!(matches!(done.outcome, Some(SliceOutcome::Syscall { .. })));
                let mut p = k.processes.remove(&1).unwrap();
                p.cpu = done.cpu;
                k.call(1, &mut p, number, a, &mut io);
                if mode == 0 {
                    assert!(matches!(p.state, State::Blocked(63, _)));
                } else {
                    assert_eq!(p.cpu.x(0), error(Errno(32)));
                    assert!(p.signals.pending.contains_key(&13));
                }
            }
        }
    }
}
