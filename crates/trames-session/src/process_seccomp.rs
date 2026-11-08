// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest classic-BPF seccomp. Immutable programs run only at syscall entry;
//! filters never reach the host kernel and add no CPU/memory hot-path work.
use super::*;
use std::sync::Arc;

const ALLOW: u32 = 0x7fff_0000;
const KILL_PROCESS: u32 = 0x8000_0000;
const ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64
const MAX_INSNS: usize = 4096;
const MAX_PATH: usize = 32768;

#[derive(Clone, Copy)]
struct Instruction {
    code: u16,
    yes: u8,
    no: u8,
    value: u32,
}
struct Filter(Vec<Instruction>);
/// Original per-task policy. Readers retain this allocation and dereference an
/// immutable published version; installing a filter never locks syscall entry.
#[derive(Clone)]
pub(crate) struct Seccomp {
    original: Arc<Policy>,
    group: trames_shared::Custody<Vec<std::sync::Weak<Policy>>>,
    captured: Option<(usize, Version)>,
    entry_value: Option<u32>,
    #[cfg(all(test, trames_interpreter_conformance))]
    evaluations: Arc<std::sync::atomic::AtomicU64>,
}
struct Binding {
    task: std::sync::Weak<trames_kernel::signal::IoTask>,
    pid: std::sync::atomic::AtomicU32,
}
pub(super) struct Policy {
    binding: std::sync::OnceLock<Binding>,
    current: std::sync::atomic::AtomicPtr<Version>,
    // Stable allocations are retained until the original task and all captured
    // consumers retire. Filter chains share tails, so retained versions consume
    // O(installed filters), not O(chain length squared). Successful installation
    // is bounded by Linux's MAX_PATH; ordinary reads allocate nothing.
    #[allow(clippy::vec_box)] // Stable addresses are the publication contract.
    versions: std::sync::Mutex<Vec<Box<Version>>>,
}
impl trames_vfs::SeccompView for Policy {
    fn seccomp(&self) -> (u32, usize) {
        // SAFETY: same stable immutable publication contract as Seccomp::version.
        let version = unsafe { &*self.current.load(std::sync::atomic::Ordering::Acquire) };
        (
            if version.strict {
                1
            } else if version.filters.is_some() {
                2
            } else {
                0
            },
            version.filters.as_ref().map_or(0, |chain| chain.count),
        )
    }
}
#[derive(Default, Clone)]
struct Version {
    strict: bool,
    filters: Option<Arc<Chain>>,
}
struct Chain {
    filter: Arc<Filter>,
    parent: Option<Arc<Chain>>,
    count: usize,
    path: usize,
}
impl Drop for Chain {
    fn drop(&mut self) {
        // A long inherited chain can have no intermediate version owners.
        // Release its unique suffix iteratively rather than on the host stack.
        let mut parent = self.parent.take();
        while let Some(node) = parent {
            match Arc::try_unwrap(node) {
                Ok(mut node) => parent = node.parent.take(),
                Err(_) => break,
            }
        }
    }
}
impl Default for Seccomp {
    fn default() -> Self {
        Self::from_version(Version::default())
    }
}
impl Seccomp {
    fn from_version(version: Version) -> Self {
        let mut version = Box::new(version);
        let current = std::sync::atomic::AtomicPtr::new(&mut *version);
        let original = Arc::new(Policy {
            binding: Default::default(),
            current,
            versions: std::sync::Mutex::new(vec![version]),
        });
        Self {
            group: trames_shared::Custody::new(vec![Arc::downgrade(&original)]),
            original,
            captured: None,
            entry_value: None,
            #[cfg(all(test, trames_interpreter_conformance))]
            evaluations: Arc::default(),
        }
    }
    fn uncaptured(&self) -> Self {
        let mut current = self.clone();
        current.captured = None;
        current.entry_value = None;
        current
    }
    pub(super) fn bind(&self, task: &Arc<trames_kernel::signal::IoTask>, pid: u32) {
        let binding = self.original.binding.get_or_init(|| Binding {
            task: Arc::downgrade(task),
            pid: std::sync::atomic::AtomicU32::new(pid),
        });
        binding.pid.store(pid, std::sync::atomic::Ordering::Relaxed);
        self.publish_status(&task.proc_view);
    }
    /// Birth and filter synchronization serialize only original policy membership.
    /// Call with parent group admission held; no task body is borrowed by TSYNC.
    pub(super) fn inherit(
        &mut self,
        parent: &Self,
        threaded: bool,
        task: &Arc<trames_kernel::signal::IoTask>,
        pid: u32,
        child_privs: &trames_vfs::capabilities::NoNewPrivs,
        parent_privs: &trames_vfs::capabilities::NoNewPrivs,
    ) {
        let mut members = parent.group.borrow_mut();
        self.replace(&parent.uncaptured());
        if parent_privs.get() {
            child_privs.set();
        }
        self.bind(task, pid);
        if threaded {
            self.group = parent.group.clone();
            members.retain(|p| p.strong_count() != 0);
            members.push(Arc::downgrade(&self.original));
        }
    }
    pub(super) fn birth_group(&self) -> trames_shared::Custody<Vec<std::sync::Weak<Policy>>> {
        self.group.clone()
    }
    pub(super) fn admit_birth(
        &self,
        target: &std::sync::Weak<dyn trames_shared::IoWake>,
        pid: u32,
    ) -> Result<trames_shared::Admission<Vec<std::sync::Weak<Policy>>>, super::tasks::AdmissionWait>
    {
        if let Some(permit) = self.group.try_admit() {
            return Ok(permit);
        }
        let signal = trames_shared::IoSignal::new(pid, target.clone());
        let subscriptions = vec![self.group.subscribe(&signal)];
        self.group.try_admit().ok_or(super::tasks::AdmissionWait {
            signal,
            subscriptions,
        })
    }
    /// One immutable policy per architectural entry. Unchanged entries perform
    /// one acquire load and no lock, allocation or filter-chain refcount update.
    pub(crate) fn capture_entry(&mut self) {
        self.entry_value = None;
        let pointer = self
            .original
            .current
            .load(std::sync::atomic::Ordering::Acquire);
        if self
            .captured
            .as_ref()
            .is_none_or(|(id, _)| *id != pointer as usize)
        {
            // SAFETY: same stable immutable allocation contract as version().
            self.captured = Some((pointer as usize, unsafe { (&*pointer).clone() }));
        }
    }
    pub(crate) fn begin_entry(&mut self, number: u32, pc: u64, args: [u64; 6]) {
        self.capture_entry();
        if self.mode() != 0 {
            self.entry_value = Some(self.decide(self.version(), number, pc, args));
        }
    }
    pub(crate) fn denied_entry(
        &self,
        number: u32,
        pc: u64,
        args: [u64; 6],
    ) -> Option<EntryDecision> {
        self.entry_value
            .filter(|value| value & 0xffff_0000 != ALLOW)
            .map(|_| self.entry_decision(number, pc, args))
    }
    fn version(&self) -> &Version {
        if let Some((_, version)) = &self.captured {
            return version;
        }
        // SAFETY: publication points only to an immutable Box in versions.
        // Boxes never move or retire while this original Arc is alive. Acquire
        // pairs with the install release; this is policy publication, not a
        // guest-byte barrier or a lock around a native/syscall body.
        unsafe {
            &*self
                .original
                .current
                .load(std::sync::atomic::Ordering::Acquire)
        }
    }
    fn publish(&self, change: impl FnOnce(&Version) -> Version) {
        let mut versions = self.original.versions.lock().unwrap();
        let mut next = Box::new(change(versions.last().unwrap()));
        let pointer = &mut *next as *mut Version;
        versions.push(next);
        self.original
            .current
            .store(pointer, std::sync::atomic::Ordering::Release);
    }
    pub(super) fn fork(&self) -> Self {
        let child = Self::from_version(self.version().clone());
        #[cfg(all(test, trames_interpreter_conformance))]
        let child = Self {
            evaluations: self.evaluations.clone(),
            ..child
        };
        child
    }
    fn replace(&self, other: &Self) {
        let version = other.version().clone();
        self.publish(|_| version);
    }
    fn set_strict(&mut self) {
        self.captured = None;
        self.entry_value = None;
        self.publish(|old| Version {
            strict: true,
            filters: old.filters.clone(),
        });
    }
    fn path(&self) -> usize {
        self.version()
            .filters
            .as_ref()
            .map_or(0, |chain| chain.path)
    }
}
/// A single immutable BPF result, bound to its exact architectural entry and
/// original policy. Accepted calls retain this decision across later installations.
pub(crate) struct EntryDecision {
    policy: Arc<Policy>,
    number: u32,
    pc: u64,
    args: [u64; 6],
    value: u32,
    strict: bool,
}
impl EntryDecision {
    pub(crate) fn fatal_signal(&self) -> i32 {
        if self.strict {
            9
        } else {
            31
        }
    }
    pub(crate) fn action(&self) -> u32 {
        self.value & 0xffff_0000
    }
    pub(crate) fn data(&self) -> u32 {
        self.value & 0xffff
    }
    pub(crate) fn allowed(&self) -> bool {
        self.value & 0xffff_0000 == ALLOW
    }
    /// These decisions have no task lifecycle or signal-delivery effects.
    pub(crate) fn completed(&self) -> Option<u64> {
        match self.value & 0xffff_0000 {
            0x0005_0000 => Some(0u64.wrapping_sub((self.value & 0xffff).min(4095) as u64)),
            0x7ff0_0000 | 0x7fc0_0000 => Some(0u64.wrapping_sub(38)),
            _ => None,
        }
    }
    fn value_for(self, policy: &Seccomp, number: u32, pc: u64, args: [u64; 6]) -> Option<u32> {
        (self.number == number
            && self.pc == pc
            && self.args == args
            && Arc::ptr_eq(&self.policy, &policy.original))
        .then_some(self.value)
    }
}
impl Seccomp {
    fn push(&mut self, filter: Arc<Filter>) {
        self.captured = None;
        self.entry_value = None;
        self.publish(|old| Version {
            strict: old.strict,
            filters: Some(Arc::new(Chain {
                count: old.filters.as_ref().map_or(0, |chain| chain.count) + 1,
                path: old.filters.as_ref().map_or(0, |chain| chain.path) + filter.0.len() + 4,
                parent: old.filters.clone(),
                filter,
            })),
        });
    }
    pub fn allows(&self, number: u32, pc: u64, args: [u64; 6]) -> bool {
        self.decision(number, pc, args) & 0xffff_0000 == ALLOW
    }
    pub fn mode(&self) -> u32 {
        let version = self.version();
        if version.strict {
            1
        } else if version.filters.is_none() {
            0
        } else {
            2
        }
    }
    pub fn count(&self) -> usize {
        self.version()
            .filters
            .as_ref()
            .map_or(0, |chain| chain.count)
    }
    fn ancestor_of(&self, other: &Self) -> bool {
        let ancestor = self.version();
        if ancestor.strict {
            return false;
        }
        let mut node = other.version().filters.as_ref();
        let count = ancestor.filters.as_ref().map_or(0, |chain| chain.count);
        while node.is_some_and(|chain| chain.count > count) {
            node = node.unwrap().parent.as_ref();
        }
        match (&ancestor.filters, node) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
    pub(crate) fn entry_decision(&self, number: u32, pc: u64, args: [u64; 6]) -> EntryDecision {
        EntryDecision {
            policy: self.original.clone(),
            number,
            pc,
            args,
            value: self.decision(number, pc, args),
            strict: self.version().strict,
        }
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn evaluations(&self) -> u64 {
        self.evaluations.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn decision(&self, number: u32, pc: u64, args: [u64; 6]) -> u32 {
        // capture_entry owns the architectural entry. Internal helpers reuse
        // its decision; a parked operation carries its accepted token separately.
        self.entry_value
            .unwrap_or_else(|| self.decide(self.version(), number, pc, args))
    }
    fn decide(&self, version: &Version, number: u32, pc: u64, args: [u64; 6]) -> u32 {
        #[cfg(all(test, trames_interpreter_conformance))]
        self.evaluations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if version.strict {
            return if matches!(number, 63 | 64 | 93 | 139) {
                ALLOW
            } else {
                0
            };
        }
        if version.filters.is_none() {
            return ALLOW;
        }
        let mut input = [0u32; 16];
        input[0] = number;
        input[1] = ARCH;
        input[2] = pc as u32;
        input[3] = (pc >> 32) as u32;
        for (i, a) in args.into_iter().enumerate() {
            input[4 + i * 2] = a as u32;
            input[5 + i * 2] = (a >> 32) as u32;
        }
        let mut decision = ALLOW;
        let mut chain = version.filters.as_ref();
        while let Some(node) = chain {
            let new = node.filter.run(&input);
            if ((new & 0xffff_0000) as i32) < ((decision & 0xffff_0000) as i32) {
                decision = new;
            }
            chain = node.parent.as_ref();
        }
        decision
    }
}
/// All supported policy controls run on the calling executor.
pub(crate) fn local_entry(number: u32, a: [u64; 6]) -> bool {
    number == 277 || number == 167 && matches!(a[0], 21 | 22)
}
pub(crate) enum Attempt {
    Complete(Result<u64, Errno>),
    Waiting(Box<Install>),
}
enum Change {
    Strict,
    Filter {
        filter: Arc<Filter>,
        sync: bool,
        no_new_privs: bool,
    },
}
/// Guest bytes and caller authority are accepted once before waiting. A retry
/// never reads an overwritten fprog, re-evaluates BPF or resolves a reused PID.
pub(crate) struct Install {
    policy: Seccomp,
    change: Change,
    namespace: trames_vfs::PidNamespace,
}
impl Install {
    pub(crate) fn ready(&self) -> bool {
        self.policy.group.available()
    }
    pub(crate) fn subscribe(
        &self,
        signal: &Arc<trames_vfs::IoSignal>,
    ) -> trames_vfs::IoSubscription {
        self.policy.group.subscribe(signal)
    }
    pub(crate) fn run(mut self) -> Attempt {
        let Some(permit) = self.policy.group.try_admit() else {
            return Attempt::Waiting(Box::new(self));
        };
        let result = self.commit(&mut permit.write());
        Attempt::Complete(result)
    }
    fn commit(&mut self, members: &mut Vec<std::sync::Weak<Policy>>) -> Result<u64, Errno> {
        match &self.change {
            Change::Strict => {
                if self.policy.mode() != 0 {
                    return Err(Errno(22));
                }
                self.policy.set_strict();
            }
            Change::Filter {
                filter,
                sync,
                no_new_privs,
            } => {
                if self.policy.version().strict {
                    return Err(Errno(22));
                }
                if self.policy.path() + filter.0.len() > MAX_PATH {
                    return Err(Errno(12));
                }
                let mut peers = Vec::new();
                if *sync {
                    members.retain(|p| p.strong_count() != 0);
                    for original in members.iter().filter_map(std::sync::Weak::upgrade) {
                        if Arc::ptr_eq(&original, &self.policy.original) {
                            continue;
                        }
                        let Some(binding) = original.binding.get() else {
                            continue;
                        };
                        let Some(task) = binding.task.upgrade().filter(|t| t.live()) else {
                            continue;
                        };
                        let mut peer = self.policy.uncaptured();
                        peer.original = original.clone();
                        if !peer.ancestor_of(&self.policy) {
                            return Ok(self
                                .namespace
                                .local(binding.pid.load(std::sync::atomic::Ordering::Relaxed))
                                as u64);
                        }
                        peers.push((peer, task));
                    }
                }
                self.policy.push(filter.clone());
                for (peer, task) in peers {
                    // Publish the monotonic flag before the filter release so
                    // a task observing the new policy also observes its NNP.
                    if *no_new_privs {
                        task.credentials().read().caps.no_new_privs.set();
                    }
                    peer.replace(&self.policy);
                    peer.publish_status(&task.proc_view);
                }
            }
        }
        if let Some(task) = self
            .policy
            .original
            .binding
            .get()
            .and_then(|b| b.task.upgrade())
        {
            self.policy.publish_status(&task.proc_view);
        }
        Ok(0)
    }
}
impl Seccomp {
    fn prepare(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &impl trames_memory::CpuMemory,
        credentials: &trames_vfs::Credentials,
        namespace: trames_vfs::PidNamespace,
    ) -> Result<Result<u64, Install>, Errno> {
        let policy = self.uncaptured();
        let a = if number == 167 {
            match a[0] {
                21 => return Ok(Ok(policy.mode() as u64)),
                22 => match a[1] {
                    1 => [0; 6],
                    2 => [1, 0, a[2], 0, 0, 0],
                    _ => return Err(Errno(22)),
                },
                _ => return Err(Errno(22)),
            }
        } else {
            a
        };
        let change = match a[0] {
            0 => {
                if a[1] != 0 || a[2] != 0 {
                    return Err(Errno(22));
                }
                Change::Strict
            }
            1 => {
                if a[1] & !1 != 0 || policy.version().strict {
                    return Err(Errno(22));
                }
                let no_new_privs = credentials.caps.no_new_privs.get();
                if !no_new_privs && !credentials.has_cap(capabilities::SYS_ADMIN) {
                    return Err(Errno(13));
                }
                Change::Filter {
                    filter: Arc::new(Filter::load(memory, a[2])?),
                    sync: a[1] & 1 != 0,
                    no_new_privs,
                }
            }
            2 => {
                if a[1] != 0 {
                    return Err(Errno(22));
                }
                Linux::check(memory, a[2], 4, Access::Read)?;
                let action = u32::from_le_bytes(memory.read_array(a[2]).map_err(|_| Errno(14))?);
                return if matches!(
                    action,
                    0 | KILL_PROCESS | 0x0003_0000 | 0x0005_0000 | 0x7ff0_0000 | ALLOW
                ) {
                    Ok(Ok(0))
                } else {
                    Err(Errno(95))
                };
            }
            _ => return Err(Errno(22)),
        };
        Ok(Err(Install {
            policy,
            change,
            namespace,
        }))
    }
    pub(crate) fn start(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &impl trames_memory::CpuMemory,
        credentials: &trames_vfs::Credentials,
        namespace: trames_vfs::PidNamespace,
    ) -> Attempt {
        match self.prepare(number, a, memory, credentials, namespace) {
            Ok(Err(install)) => install.run(),
            Ok(Ok(value)) => Attempt::Complete(Ok(value)),
            Err(e) => Attempt::Complete(Err(e)),
        }
    }
    // Explicit joined/debug embedding path uses the same resource implementation.
    pub(crate) fn local_call(
        &mut self,
        number: u32,
        a: [u64; 6],
        memory: &impl trames_memory::CpuMemory,
        credentials: &trames_vfs::Credentials,
        namespace: trames_vfs::PidNamespace,
    ) -> Result<u64, Errno> {
        match self.prepare(number, a, memory, credentials, namespace)? {
            Ok(value) => Ok(value),
            Err(mut install) => {
                let group = install.policy.group.clone();
                let result = install.commit(&mut group.borrow_mut());
                self.captured = None;
                self.entry_value = None;
                result
            }
        }
    }
    pub(crate) fn publish_status(&self, view: &trames_vfs::ProcessView) {
        view.bind_seccomp(self.original.clone());
    }
}
impl Filter {
    fn load(memory: &impl trames_memory::CpuMemory, address: u64) -> Result<Self, Errno> {
        Linux::check(memory, address, 16, Access::Read)?;
        let mut header = [0; 16];
        memory.read(address, &mut header).map_err(|_| Errno(14))?;
        let n = u16::from_le_bytes(header[..2].try_into().unwrap()) as usize;
        if n == 0 || n > MAX_INSNS {
            return Err(Errno(22));
        }
        let pointer = u64::from_le_bytes(header[8..16].try_into().unwrap());
        Linux::check(memory, pointer, n * 8, Access::Read)?;
        let mut bytes = vec![0; n * 8];
        memory.read(pointer, &mut bytes).map_err(|_| Errno(14))?;
        let code: Vec<_> = bytes
            .chunks_exact(8)
            .map(|i| Instruction {
                code: u16::from_le_bytes(i[..2].try_into().unwrap()),
                yes: i[2],
                no: i[3],
                value: u32::from_le_bytes(i[4..8].try_into().unwrap()),
            })
            .collect();
        Self::validate(code)
    }
    fn validate(code: Vec<Instruction>) -> Result<Self, Errno> {
        if code.is_empty()
            || code.len() > MAX_INSNS
            || !matches!(code.last().unwrap().code, 0x06 | 0x16)
        {
            return Err(Errno(22));
        }
        let mut initialized = vec![None; code.len()];
        initialized[0] = Some(0u16);
        for (pc, i) in code.iter().enumerate() {
            let mut mask = initialized[pc];
            let mut targets = vec![pc + 1];
            match i.code {
                0x00 | 0x01 | 0x80 | 0x81 | 0x07 | 0x87 => {}
                0x20 if i.value < 64 && i.value.is_multiple_of(4) => {}
                0x60 | 0x61 if i.value < 16 => {
                    if mask.is_some_and(|m| m & (1 << i.value) == 0) {
                        return Err(Errno(22));
                    }
                }
                0x02 | 0x03 if i.value < 16 => {
                    mask = mask.map(|m| m | (1 << i.value));
                }
                0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x4c | 0x44 | 0x54 | 0x5c | 0x6c
                | 0x7c | 0x84 | 0xac | 0xa4 | 0x3c | 0x9c => {}
                0x34 | 0x94 if i.value != 0 => {}
                0x64 | 0x74 if i.value < 32 => {}
                0x05 => {
                    targets = vec![pc
                        .checked_add(i.value as usize)
                        .and_then(|n| n.checked_add(1))
                        .ok_or(Errno(22))?];
                }
                0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d => {
                    targets = vec![pc + 1 + i.yes as usize, pc + 1 + i.no as usize];
                }
                0x06 | 0x16 => targets.clear(),
                _ => return Err(Errno(22)),
            }
            for target in targets {
                if target >= code.len() {
                    return Err(Errno(22));
                }
                if let Some(mask) = mask {
                    initialized[target] = Some(initialized[target].map_or(mask, |old| old & mask));
                }
            }
        }
        Ok(Self(code))
    }
    fn run(&self, input: &[u32; 16]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let mut scratch = [0u32; 16];
        while let Some(i) = self.0.get(pc) {
            pc += 1;
            match i.code {
                0x00 => a = i.value,
                0x01 => x = i.value,
                0x20 => a = input[(i.value / 4) as usize],
                0x80 => a = 64,
                0x81 => x = 64,
                0x60 => a = scratch[i.value as usize],
                0x61 => x = scratch[i.value as usize],
                0x02 => scratch[i.value as usize] = a,
                0x03 => scratch[i.value as usize] = x,
                0x07 => x = a,
                0x87 => a = x,
                0x06 => return i.value,
                0x16 => return a,
                0x05 => pc += i.value as usize,
                c if c & 7 == 4 => {
                    let v = if c & 8 != 0 { x } else { i.value };
                    a = match c & 0xf0 {
                        0x00 => a.wrapping_add(v),
                        0x10 => a.wrapping_sub(v),
                        0x20 => a.wrapping_mul(v),
                        0x30 => {
                            if v == 0 {
                                return 0;
                            } else {
                                a / v
                            }
                        }
                        0x40 => a | v,
                        0x50 => a & v,
                        0x60 => a.checked_shl(v).unwrap_or(0),
                        0x70 => a.checked_shr(v).unwrap_or(0),
                        0x80 => a.wrapping_neg(),
                        0x90 => {
                            if v == 0 {
                                return 0;
                            } else {
                                a % v
                            }
                        }
                        0xa0 => a ^ v,
                        _ => return KILL_PROCESS,
                    };
                }
                c if c & 7 == 5 => {
                    let v = if c & 8 != 0 { x } else { i.value };
                    let yes = match c & 0xf0 {
                        0x10 => a == v,
                        0x20 => a > v,
                        0x30 => a >= v,
                        0x40 => a & v != 0,
                        _ => false,
                    };
                    pc += if yes { i.yes } else { i.no } as usize;
                }
                _ => return KILL_PROCESS,
            }
        }
        KILL_PROCESS
    }
}
impl<C: Cpu> Kernel<C> {
    pub(super) fn seccomp(&mut self, p: &mut Process<C>, a: [u64; 6]) -> Result<u64, Errno> {
        p.seccomp.local_call(
            277,
            a,
            &p.memory,
            &p.linux.vfs.credentials,
            p.linux.vfs.pid_namespace().clone(),
        )
    }
    /// True means the syscall was consumed without executing its implementation.
    pub(super) fn filter_syscall(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        args: [u64; 6],
    ) -> bool {
        let decision = p
            .seccomp_entry
            .take()
            .and_then(|entry| entry.value_for(&p.seccomp, number, p.cpu.pc(), args))
            .unwrap_or_else(|| p.seccomp.decision(number, p.cpu.pc(), args));
        match decision & 0xffff_0000 {
            ALLOW => return false,
            0x0005_0000 => {
                p.cpu.set_x(0, error(Errno((decision & 0xffff).min(4095))));
                p.state = State::Ready;
            }
            0x7ff0_0000 | 0x7fc0_0000 => {
                p.cpu.set_x(0, error(Errno(38)));
                p.state = State::Ready;
            }
            0x0003_0000 => {
                // force_sig_seccomp cannot be suppressed by ignoring or
                // blocking SIGSYS; Linux forces its fatal default action.
                if p.signals.mask & (1u64 << 30) != 0 || p.signals.actions.get(31).handler == 1 {
                    self.exit(pid, p, 31);
                    return true;
                }
                // ARM64 syscall_rollback restores the original x0 argument.
                // The syscall number lives in x8 and siginfo; replacing x0
                // would corrupt the arguments inspected by a SIGSYS broker.
                p.state = State::Ready;
                p.signals.io.inbox.discard(31);
                let _ = p.signals.io.inbox.enqueue(
                    31,
                    Info {
                        sender: decision & 0xffff,
                        uid: ARCH,
                        status: number as i32,
                        code: 1,
                        timer: None,
                        fault: Some(p.cpu.pc()),
                        poll: None,
                    },
                );
                if self.deliver(pid, p).is_err() {
                    self.exit(pid, p, 31);
                }
            }
            0 => {
                let signal = if p.seccomp.version().strict { 9 } else { 31 };
                self.exit_one(pid, p, signal);
            }
            _ => self.exit(pid, p, 31), // Unknown actions fail closed, as Linux does.
        }
        true
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    #[test]
    fn entropy_fd_controls_preserve_access_and_policy_without_owner_fallback() {
        for path in [b"/dev/random".as_slice(), b"/dev/urandom"] {
            for flags in [0, 1, 2, trames_vfs::O_PATH] {
                for policy in [None, Some(ALLOW), Some(0x5002a)] {
                    let mut p = super::super::tests::process();
                    p.linux
                        .vfs
                        .set_runtime_info(1, trames_vfs::RuntimeInfo::default());
                    let fd = p.linux.vfs.open_at(-100, path, flags, 0).unwrap();
                    // A source yield makes both jobs run even if one host
                    // thread starts after the other has spent its first budget.
                    for (index, word) in [
                        0xaa1403e0u32,
                        0xd28003a8,
                        0xd4000001,
                        0xaa0003f3,
                        0xd2800f88,
                        0xd4000001,
                        0x17fffffa,
                    ]
                    .iter()
                    .enumerate()
                    {
                        p.memory
                            .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                            .unwrap();
                    }
                    p.memory
                        .protect(
                            0x4000,
                            trames_memory::PAGE_SIZE,
                            trames_memory::Permissions::RX,
                        )
                        .unwrap();
                    p.cpu.set_x(8, 29);
                    p.cpu.set_x(20, fd as u64);
                    p.cpu.set_x(1, 0x80045200);
                    p.cpu.set_x(2, u64::MAX);
                    p.signals.io.scheduling.set_affinity(3);
                    if let Some(value) = policy {
                        p.seccomp.push(Arc::new(
                            Filter::validate(vec![
                                i(0x20, 0, 0, 0),
                                i(0x15, 0, 1, 29),
                                i(6, 0, 0, value),
                                i(6, 0, 0, ALLOW),
                            ])
                            .unwrap(),
                        ));
                    }
                    let peer = p.fork();
                    peer.family.set_parent(1);
                    let mut k = super::super::tests::kernel();
                    k.cpu_count = 2;
                    k.workers = crate::workers::Pool::new(2);
                    k.per_cpu = vec![Duration::ZERO; 2];
                    k.processes.insert(1, p);
                    k.processes.insert(2, peer);
                    let expected = if policy == Some(0x5002a) {
                        -42i64
                    } else if flags & trames_vfs::O_PATH != 0 {
                        -9
                    } else {
                        -25
                    } as u64;
                    // A budget can expire before a host worker first starts.
                    // Require both guest observations, rather than assuming
                    // that one fixed epoch scheduled every task.
                    for _ in 0..8 {
                        let limit = k.instructions + 20_000;
                        assert!(k
                            .parallel_epoch(
                                &mut trames_linux::CapturedOutput::default(),
                                limit,
                                true
                            )
                            .unwrap());
                        if k.processes.values().all(|p| p.cpu.x(19) == expected) {
                            break;
                        }
                    }
                    assert!(k.syscalls > 100);
                    assert!(k.processes.values().all(|p| p.cpu.x(19) == expected),
                        "entropy FD path={path:?} flags={flags:#x} policy={policy:?} expected={expected:#x} observed={:?}",
                        k.processes.values().map(|p| (p.cpu.pc,p.cpu.x(0),p.cpu.x(1),p.cpu.x(8),p.cpu.x(19))).collect::<Vec<_>>());
                    if policy.is_some() {
                        assert_eq!(k.processes.read(&1).seccomp.evaluations(), k.syscalls);
                    }
                    assert_eq!(k.service_requests, 0);
                    assert!(
                        k.cohort_return_syscalls.is_empty(),
                        "{:?}",
                        k.cohort_return_syscalls
                    );
                    assert_eq!(k.vm_checkpoint_groups, 0);
                }
            }
        }
    }

    #[test]
    fn entropy_completes_on_sources_with_original_memory_and_one_policy_decision() {
        for policy in [None, Some(ALLOW), Some(0x5002a)] {
            for (address, count, flags, expected) in [
                (0x1800, 64, 0, 64i64),
                (0x1800, 64, 1, 64),
                (0x1800, 64, 2, 64),
                (0x1800, 64, 3, 64),
                (0x1800, 64, 1u64 << 32, 64),
                (u64::MAX, 0, 0, -14),
                (0, 0, 0, 0),
                (0, 1, 0, -14),
                (u64::MAX, 1, 0, -14),
                (u64::MAX, 1, 4, -22),
                (0x4000, 32, 0, -14),
            ] {
                let mut p = super::super::tests::process();
                // Reload x0 each time; syscall return values cannot become the
                // next output pointer. Keep the original operands in x20..22.
                for (index, word) in [
                    0xaa1403e0u32,
                    0xaa1503e1,
                    0xaa1603e2,
                    0xd28022c8,
                    0xd4000001,
                    0xaa0003f3,
                    0xd2800f88,
                    0xd4000001,
                    0x17fffff8,
                ]
                .iter()
                .enumerate()
                {
                    p.memory
                        .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.cpu.set_x(8, 278);
                p.cpu.set_x(20, address);
                p.cpu.set_x(21, count);
                p.cpu.set_x(22, flags);
                p.signals.io.scheduling.set_affinity(3);
                if let Some(value) = policy {
                    p.seccomp.push(Arc::new(
                        Filter::validate(vec![
                            i(0x20, 0, 0, 0),
                            i(0x15, 0, 1, 278),
                            i(6, 0, 0, value),
                            i(6, 0, 0, ALLOW),
                        ])
                        .unwrap(),
                    ));
                }
                let peer = p.fork();
                peer.family.set_parent(1);
                let mut k = super::super::tests::kernel();
                k.cpu_count = 2;
                k.workers = crate::workers::Pool::new(2);
                k.per_cpu = vec![Duration::ZERO; 2];
                k.processes.insert(1, p);
                k.processes.insert(2, peer);
                let expected = if policy == Some(0x5002a) {
                    -42i64
                } else {
                    expected
                } as u64;
                for _ in 0..8 {
                    let limit = k.instructions + 20_000;
                    assert!(k
                        .parallel_epoch(&mut trames_linux::CapturedOutput::default(), limit, true)
                        .unwrap());
                    if k.processes.values().all(|p| p.cpu.x(19) == expected) {
                        break;
                    }
                }
                assert!(k.syscalls > 100);
                assert!(k.processes.values().all(|p| p.cpu.x(19) == expected),
                    "entropy address={address:#x} count={count} flags={flags:#x} policy={policy:?} expected={expected:#x} observed={:?}",
                    k.processes.values().map(|p| (p.cpu.pc,p.cpu.x(19))).collect::<Vec<_>>());
                if policy.is_some() {
                    assert_eq!(k.processes.read(&1).seccomp.evaluations(), k.syscalls);
                }
                assert_eq!(k.service_requests, 0);
                assert!(
                    k.cohort_return_syscalls.is_empty(),
                    "{:?}",
                    k.cohort_return_syscalls
                );
                assert_eq!(k.vm_checkpoint_groups, 0);
            }
        }
    }

    #[test]
    fn unknown_entries_complete_on_sources_with_one_policy_decision_and_original_diagnostics() {
        for number in [99u32, 100, 293, 0x7fff_ffff, u32::MAX] {
            for policy in [None, Some(ALLOW), Some(0x5002a)] {
                let mut p = super::super::tests::process();
                let log = p.linux.vfs.kernel_log_capability();
                p.linux.command_name = b"unknown-entry-long-name".to_vec();
                p.linux.vfs.credentials = trames_vfs::Credentials::user(1234, 1234);
                for (index, word) in [0xd4000001u32, 0xaa0003f3, 0x17fffffe].iter().enumerate() {
                    p.memory
                        .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.cpu.set_x(8, number as u64);
                put_args(&mut p.cpu, [u64::MAX; 6]);
                p.signals.io.scheduling.set_affinity(3);
                if let Some(value) = policy {
                    p.seccomp
                        .push(Arc::new(Filter::validate(vec![i(6, 0, 0, value)]).unwrap()));
                }
                let mut peer = p.fork();
                peer.family.set_parent(1);
                peer.cpu.set_x(8, number as u64);
                let mut k = super::super::tests::kernel();
                k.cpu_count = 2;
                k.workers = crate::workers::Pool::new(2);
                k.per_cpu = vec![Duration::ZERO; 2];
                k.processes.insert(1, p);
                k.processes.insert(2, peer);
                assert!(k
                    .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 20_000, true)
                    .unwrap());
                assert!(k.syscalls > 100);
                let expected = if policy == Some(0x5002a) {
                    (-42i64) as u64
                } else {
                    (-38i64) as u64
                };
                for task in k.processes.values() {
                    assert_eq!(task.cpu.x(19), expected);
                }
                if policy.is_some() {
                    assert_eq!(k.processes.read(&1).seccomp.evaluations(), k.syscalls);
                }
                assert_eq!(k.service_requests, 0);
                assert!(
                    k.cohort_return_syscalls.is_empty(),
                    "{:?}",
                    k.cohort_return_syscalls
                );
                let bytes = log.syslog(3, 65536).unwrap();
                let text = String::from_utf8(bytes).unwrap();
                if policy == Some(0x5002a) {
                    assert!(!text.contains("unsupported errno=38"));
                } else {
                    assert!(
                        text.contains("unsupported errno=38 comm=\"unknown-entry-l\""),
                        "{text}"
                    );
                    assert!(text.contains("pc=0x4000"), "{text}");
                }
            }
        }
    }

    fn program(memory: &mut Memory, decision: u32) {
        memory.write_array(0x1800, 4u16.to_le_bytes()).unwrap();
        memory.write_array(0x1808, 0x1900u64.to_le_bytes()).unwrap();
        for (n, i) in [
            i(0x20, 0, 0, 0),
            i(0x15, 0, 1, 172),
            i(6, 0, 0, decision),
            i(6, 0, 0, ALLOW),
        ]
        .iter()
        .enumerate()
        {
            let mut bytes = [0; 8];
            bytes[..2].copy_from_slice(&i.code.to_le_bytes());
            bytes[2] = i.yes;
            bytes[3] = i.no;
            bytes[4..].copy_from_slice(&i.value.to_le_bytes());
            memory.write_array(0x1900 + n as u64 * 8, bytes).unwrap();
        }
    }
    fn join(parent: &Process<Cpu>, child: &mut Process<Cpu>, id: u32) {
        child.tgid = parent.tgid;
        child.share_process_context(parent);
        child.bind_signals();
        child.seccomp.inherit(
            &parent.seccomp,
            true,
            &child.signals.io,
            id,
            &child.linux.vfs.credentials.caps.no_new_privs,
            &parent.linux.vfs.credentials.caps.no_new_privs,
        );
    }
    #[test]
    fn source_tsync_updates_running_peers_and_privilege_views_without_join() {
        use super::super::tests::{kernel, process};
        for slots in [1, 2, 4] {
            let mut p = process();
            program(&mut p.memory, 0x5002a);
            let mut peer = p.fork();
            join(&p, &mut peer, 2);
            let credentials = peer.linux.vfs.credentials.clone();
            let paths = peer.linux.vfs.clone();
            let mut foreign = p.fork();
            foreign.tgid = 3;
            p.linux.vfs.credentials.caps.no_new_privs.set();
            p.bind_signals();
            p.cpu.set_x(8, 277);
            put_args(&mut p.cpu, [1, 1, 0x1800, 0, 0, 0]);
            for (n, w) in [0xd4000001u32, 0xaa0003f9, 0x14000000].iter().enumerate() {
                p.memory
                    .write_array(0x4000 + n as u64 * 4, w.to_le_bytes())
                    .unwrap();
            }
            // Repeated getpid, GET_NO_NEW_PRIVS, GET_SECCOMP on the same live CPU.
            let code = [
                0xd2801588u32,
                0xd4000001,
                0xaa0003f5,
                0xd28004e0,
                0xd2800001,
                0xd2800002,
                0xd2800003,
                0xd2800004,
                0xd28014e8,
                0xd4000001,
                0xaa0003f6,
                0xd28002a0,
                0xd4000001,
                0xaa0003f7,
                0x17fffff2,
            ];
            for (n, w) in code.iter().enumerate() {
                peer.memory
                    .write_array(0x4000 + n as u64 * 4, w.to_le_bytes())
                    .unwrap();
            }
            foreign
                .memory
                .write_array(0x4000, 0x14000000u32.to_le_bytes())
                .unwrap();
            for task in [&mut p, &mut peer, &mut foreign] {
                task.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                task.signals.io.scheduling.set_affinity((1 << slots) - 1);
            }
            let mut k = kernel();
            k.cpu_count = slots.max(2);
            k.workers = crate::workers::Pool::new(slots);
            k.per_cpu = vec![Duration::ZERO; slots.max(2)];
            k.processes.insert(1, p);
            k.processes.insert(2, peer);
            k.processes.insert(3, foreign);
            // A global instruction budget can be consumed by a runnable peer
            // before another host thread is scheduled. Wait for the complete
            // observation, not four budgets or just the first of three SVCs.
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                assert!(k
                    .parallel_epoch(
                        &mut trames_linux::CapturedOutput::default(),
                        k.instructions + 100_000,
                        true
                    )
                    .unwrap());
                let peer = k.processes.read(&2);
                if (peer.cpu.x(21), peer.cpu.x(22), peer.cpu.x(23)) == ((-42i64) as u64, 1, 2) {
                    break;
                }
                assert!(Instant::now() < deadline, "peer did not observe TSYNC");
            }
            let p = k.processes.read(&1);
            let peer = k.processes.read(&2);
            assert_eq!(p.cpu.x(25), 0);
            assert_eq!(
                (peer.cpu.x(21), peer.cpu.x(22), peer.cpu.x(23)),
                ((-42i64) as u64, 1, 2)
            );
            assert_eq!(peer.seccomp.count(), 1);
            assert!(credentials.caps.no_new_privs.get());
            assert!(paths.credentials.caps.no_new_privs.get());
            assert!(!k
                .processes
                .read(&3)
                .linux
                .vfs
                .credentials
                .caps
                .no_new_privs
                .get());
            assert_eq!(k.processes.read(&3).seccomp.mode(), 0);
            assert_eq!(k.service_requests, 0);
            assert!(
                k.cohort_return_syscalls.is_empty(),
                "{:?}",
                k.cohort_return_syscalls
            );
            // Publishing an older image cannot overwrite the live policy view.
            let mut stale = peer.info(
                2,
                k.started,
                k.memory_limits,
                0,
                trames_vfs::ProcRefresh::Metadata,
                Vec::new(),
            );
            stale.seccomp = 0;
            stale.seccomp_filters = 0;
            peer.signals
                .io
                .proc_view
                .publish(&stale, peer.linux.vfs.proc_resources());
            let info = peer
                .signals
                .io
                .proc_view
                .observe(trames_vfs::ProcRefresh::Metadata)
                .unwrap();
            assert_eq!((info.seccomp, info.seccomp_filters), (2, 1));
        }
    }
    #[test]
    fn tsync_conflicting_peer_is_all_or_nothing_and_dead_peer_is_excluded() {
        let mut p = super::super::tests::process();
        program(&mut p.memory, 0x5002a);
        p.seccomp.bind(&p.signals.io, 1);
        let mut first = p.fork();
        join(&p, &mut first, 2);
        let mut conflict = p.fork();
        join(&p, &mut conflict, 3);
        conflict
            .seccomp
            .push(Arc::new(Filter::validate(vec![i(6, 0, 0, ALLOW)]).unwrap()));
        p.linux.vfs.credentials.caps.no_new_privs.set();
        let call = |p: &mut Process<Cpu>| {
            p.seccomp.local_call(
                277,
                [1, 1, 0x1800, 0, 0, 0],
                &p.memory,
                &p.linux.vfs.credentials,
                p.linux.vfs.pid_namespace().clone(),
            )
        };
        assert_eq!(call(&mut p), Ok(3));
        assert_eq!(
            (
                p.seccomp.mode(),
                first.seccomp.mode(),
                conflict.seccomp.count()
            ),
            (0, 0, 1)
        );
        assert!(!first.linux.vfs.credentials.caps.no_new_privs.get());
        conflict.signals.io.exit();
        assert_eq!(call(&mut p), Ok(0));
        assert_eq!(
            (
                p.seccomp.count(),
                first.seccomp.count(),
                conflict.seccomp.count()
            ),
            (1, 1, 1)
        );
        assert!(first.linux.vfs.credentials.caps.no_new_privs.get());
        assert!(!first.seccomp.allows(172, 0, [0; 6]));
        assert!(conflict.seccomp.allows(172, 0, [0; 6]));
    }
    #[test]
    fn parked_install_keeps_guest_bytes_and_original_group_across_cancellation() {
        let mut p = super::super::tests::process();
        program(&mut p.memory, 0x5002a);
        p.seccomp.bind(&p.signals.io, 1);
        let mut peer = p.fork();
        join(&p, &mut peer, 2);
        let group = p.seccomp.birth_group();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let locker = std::thread::spawn(move || {
            let _guard = group.borrow_mut();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let Attempt::Waiting(work) = p.seccomp.start(
            277,
            [1, 1, 0x1800, 0, 0, 0],
            &p.memory,
            &p.linux.vfs.credentials,
            p.linux.vfs.pid_namespace().clone(),
        ) else {
            panic!("must park")
        };
        let wait = crate::run_queue::PolicyWait::new(*work);
        let wake =
            trames_shared::IoSignal::new(1, std::sync::Weak::<crate::run_queue::Epoch<Cpu>>::new());
        wait.bind(&wake);
        assert!(!wait.ready());
        // Guest overwrites the accepted program while the executor is released.
        program(&mut p.memory, KILL_PROCESS);
        release_tx.send(()).unwrap();
        locker.join().unwrap();
        assert!(wake.ready());
        assert!(wait.ready());
        // A joined/cancelled epoch consumes the same accepted object once.
        assert_eq!(wait.run(), Some(Ok(0)));
        assert_eq!(wait.run(), None);
        assert_eq!(p.seccomp.decision(172, 0, [0; 6]), 0x5002a);
        assert_eq!(peer.seccomp.decision(172, 0, [0; 6]), 0x5002a);
    }
    #[test]
    fn policy_contention_releases_the_only_slot_and_resumes_after_epoch_cancellation() {
        use super::super::tests::{kernel, process};
        let mut p = process();
        program(&mut p.memory, 0x5002a);
        for (n, w) in [0xd4000001u32, 0xaa0003f9, 0x14000000].iter().enumerate() {
            p.memory
                .write_array(0x4000 + n as u64 * 4, w.to_le_bytes())
                .unwrap();
        }
        p.memory
            .write_array(0x4f00, 0xd28009bcu32.to_le_bytes())
            .unwrap();
        p.memory
            .write_array(0x4f04, 0x14000000u32.to_le_bytes())
            .unwrap();
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu.set_x(8, 277);
        put_args(&mut p.cpu, [1, 1, 0x1800, 0, 0, 0]);
        p.signals.io.scheduling.set_affinity(1);
        let mut peer = p.fork();
        peer.tgid = 2;
        peer.cpu = Cpu::new(0x4f00, 0x9000);
        let group = p.seccomp.birth_group();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let locker = std::thread::spawn(move || {
            let _guard = group.borrow_mut();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut k = kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(1);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        assert!(k
            .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
            .unwrap());
        assert!(matches!(
            k.processes.read(&1).state,
            State::Policy(_) | State::Barrier(_)
        ));
        assert_eq!(k.processes.read(&2).cpu.x(28), 77);
        assert_eq!(k.worker_syscalls, 1);
        {
            let mut p = k.processes.get_mut(&1).unwrap();
            program(&mut p.memory, KILL_PROCESS);
        }
        release_tx.send(()).unwrap();
        locker.join().unwrap();
        assert!(k
            .parallel_epoch(
                &mut trames_linux::CapturedOutput::default(),
                k.instructions + 100_000,
                true
            )
            .unwrap());
        let p = k.processes.read(&1);
        assert_eq!(p.cpu.x(25), 0);
        assert_eq!(p.seccomp.decision(172, 0, [0; 6]), 0x5002a);
        assert_eq!(k.syscalls, 1);
        assert_eq!(k.service_requests, 0);
        assert!(k.cohort_return_syscalls.is_empty());
    }
    #[test]
    fn birth_recopies_synchronized_policy_and_keeps_nonthread_privileges_independent() {
        let mut k = super::super::tests::kernel();
        let mut p = super::super::tests::admitted_process(&k);
        k.publish_task(1, &p);
        program(&mut p.memory, 0x5002a);
        let mut before = p.fork();
        p.linux.vfs.credentials.caps.no_new_privs.set();
        assert_eq!(k.seccomp(&mut p, [1, 1, 0x1800, 0, 0, 0]), Ok(0));
        assert_eq!(before.seccomp.mode(), 0);
        join(&p, &mut before, 99);
        assert_eq!(before.seccomp.count(), 1);
        assert!(before.linux.vfs.credentials.caps.no_new_privs.get());
        let birth = super::super::birth::Birth::capture(&k);
        let threaded = birth
            .clone_task(1, &mut p, [0x100 | 0x800 | 0x10000, 0x8000, 0, 0, 0, 0])
            .unwrap();
        let child = birth
            .clone_task(1, &mut p, [17, 0x8000, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(threaded.process.seccomp.count(), 1);
        assert_eq!(child.process.seccomp.count(), 1);
        program(&mut p.memory, 0x5000d);
        assert_eq!(k.seccomp(&mut p, [1, 1, 0x1800, 0, 0, 0]), Ok(0));
        assert_eq!(threaded.process.seccomp.decision(172, 0, [0; 6]), 0x5000d);
        assert_eq!(child.process.seccomp.decision(172, 0, [0; 6]), 0x5002a);
    }
    #[test]
    fn tsync_conflict_reports_the_original_tid_in_the_callers_pid_namespace() {
        let mut k = super::super::tests::kernel();
        let mut root = super::super::tests::process();
        let mut output = trames_linux::CapturedOutput::default();
        k.syscall(
            1,
            &mut root,
            220,
            [trames_vfs::CLONE_NEWPID | 17, 0, 0, 0, 0, 0],
            &mut output,
        )
        .unwrap();
        k.processes.insert(1, root);
        let mut init = k.processes.remove(&2).unwrap();
        k.syscall(2, &mut init, 220, [0x10f00, 0, 0, 0, 0, 0], &mut output)
            .unwrap();
        k.processes
            .get_mut(&3)
            .unwrap()
            .seccomp
            .push(Arc::new(Filter::validate(vec![i(6, 0, 0, ALLOW)]).unwrap()));
        program(&mut init.memory, 0x5002a);
        assert_eq!(init.linux.vfs.visible_pid(3), 2);
        assert_eq!(k.seccomp(&mut init, [1, 1, 0x1800, 0, 0, 0]), Ok(2));
        assert_eq!(init.seccomp.count(), 0);
        assert_eq!(k.processes.read(&3).seccomp.count(), 1);
    }
    #[test]
    fn concurrent_tsync_installers_append_to_the_same_original_chain_without_lost_updates() {
        let mut p = super::super::tests::process();
        program(&mut p.memory, 0x5002a);
        p.seccomp.bind(&p.signals.io, 1);
        let mut peer = p.fork();
        join(&p, &mut peer, 2);
        let policy = p.seccomp.clone();
        let other = peer.seccomp.clone();
        let gate = Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for mut task in [p, peer] {
            let gate = gate.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..64 {
                    gate.wait();
                    assert_eq!(
                        task.seccomp.local_call(
                            277,
                            [1, 1, 0x1800, 0, 0, 0],
                            &task.memory,
                            &task.linux.vfs.credentials,
                            task.linux.vfs.pid_namespace().clone()
                        ),
                        Ok(0)
                    );
                }
                task
            }));
        }
        let tasks: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!((policy.count(), other.count()), (128, 128));
        assert!(policy.ancestor_of(&other) && other.ancestor_of(&policy));
        assert_eq!(policy.decision(172, 0, [0; 6]), 0x5002a);
        drop(tasks);
    }
    #[test]
    fn source_local_installation_refreshes_policy_and_proc_without_owner_returns() {
        use super::super::tests::{kernel, process};
        for slots in [1, 2] {
            for prctl in [false, true] {
                let mut p = process();
                let words = [
                    i(0x20, 0, 0, 0),
                    i(0x15, 0, 1, 172),
                    i(6, 0, 0, 0x5000d),
                    i(6, 0, 0, ALLOW),
                ];
                p.memory.write_array(0x1800, 4u16.to_le_bytes()).unwrap();
                p.memory
                    .write_array(0x1808, 0x1900u64.to_le_bytes())
                    .unwrap();
                for (n, i) in words.iter().enumerate() {
                    let mut bytes = [0; 8];
                    bytes[..2].copy_from_slice(&i.code.to_le_bytes());
                    bytes[2] = i.yes;
                    bytes[3] = i.no;
                    bytes[4..].copy_from_slice(&i.value.to_le_bytes());
                    p.memory.write_array(0x1900 + n as u64 * 8, bytes).unwrap();
                }
                p.memory.write_array(0x1a00, ALLOW.to_le_bytes()).unwrap();
                let mut calls = vec![(167, [21, 0, 0, 0, 0, 0], 0), (167, [38, 1, 0, 0, 0, 0], 0)];
                calls.push(if prctl {
                    (167, [22, 2, 0x1800, 0, 0, 0], 0)
                } else {
                    (277, [1, 0, 0x1800, 0, 0, 0], 0)
                });
                calls.extend([
                    (172, [0; 6], (-13i64) as u64),
                    (167, [21, 0, 0, 0, 0, 0], 2),
                    (277, [2, 0, 0x1a00, 0, 0, 0], 0),
                    (277, [1, 2, 0x1800, 0, 0, 0], (-22i64) as u64),
                    (277, [1, 0, 0, 0, 0, 0], (-14i64) as u64),
                    (277, [0; 6], (-22i64) as u64),
                ]);
                let mov = |r: u32, value: u64| {
                    [0xd2800000, 0xf2a00000, 0xf2c00000, 0xf2e00000]
                        .into_iter()
                        .enumerate()
                        .map(|(i, op)| op | (((value >> (16 * i)) as u32 & 0xffff) << 5) | r)
                        .collect::<Vec<_>>()
                };
                let mut code = mov(20, 0x1000);
                for (index, (number, args, _)) in calls.iter().enumerate() {
                    for (r, arg) in args.iter().enumerate() {
                        code.extend(mov(r as u32, *arg));
                    }
                    code.extend(mov(8, *number));
                    code.extend([0xd4000001, 0xf9000000 | ((index as u32) << 10) | (20 << 5)]);
                }
                code.extend(mov(28, 1));
                code.push(0x14000000);
                for (n, word) in code.iter().enumerate() {
                    p.memory
                        .write_array(0x4000 + n as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .write_array(0x4f00, 0x14000000u32.to_le_bytes())
                    .unwrap();
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.signals.io.scheduling.set_affinity((1 << slots) - 1);
                let mut peer = p.fork();
                peer.tgid = 2;
                peer.family.set_parent(1);
                peer.cpu = Cpu::new(0x4f00, 0x9000);
                let mut k = kernel();
                k.cpu_count = 2;
                k.workers = crate::workers::Pool::new(slots);
                k.per_cpu = vec![Duration::ZERO; 2];
                p.signals.io.proc_view.publish(
                    &p.info(
                        1,
                        k.started,
                        k.memory_limits,
                        0,
                        trames_vfs::ProcRefresh::Metadata,
                        Vec::new(),
                    ),
                    p.linux.vfs.proc_resources(),
                );
                k.processes.insert(1, p);
                k.processes.insert(2, peer);
                for _ in 0..16 {
                    assert!(k
                        .parallel_epoch(
                            &mut trames_linux::CapturedOutput::default(),
                            k.instructions + 100_000,
                            true
                        )
                        .unwrap());
                    if k.processes.read(&1).cpu.x(28) == 1 {
                        break;
                    }
                }
                let p = k.processes.read(&1);
                assert_eq!(p.cpu.x(28), 1);
                for (index, (_, _, expected)) in calls.iter().enumerate() {
                    assert_eq!(
                        p.memory.read_u64(0x1000 + index as u64 * 8).unwrap(),
                        *expected,
                        "call={index} slots={slots} prctl={prctl}"
                    );
                }
                assert_eq!(p.seccomp.count(), 1);
                assert_eq!(k.processes.read(&2).seccomp.mode(), 0);
                let info = p
                    .signals
                    .io
                    .proc_view
                    .observe(trames_vfs::ProcRefresh::Metadata)
                    .unwrap();
                assert_eq!((info.seccomp, info.seccomp_filters), (2, 1));
                assert_eq!(k.syscalls, calls.len() as u64);
                assert_eq!(k.syscalls, k.worker_syscalls);
                assert_eq!(k.service_requests, 0);
                assert!(
                    k.cohort_return_syscalls.is_empty(),
                    "{:?}",
                    k.cohort_return_syscalls
                );
            }
        }
    }

    #[test]
    fn source_seccomp_trap_enters_original_arm64_frame_without_owner_return() {
        use super::super::tests::{kernel, process};
        for slots in [1, 2] {
            let mut p = process();
            p.memory
                .write_array(0x4000, 0xd4000001u32.to_le_bytes())
                .unwrap();
            p.memory
                .write_array(0x4004, 0x14000000u32.to_le_bytes())
                .unwrap();
            p.memory
                .write_array(0x5000, 0xd28009bcu32.to_le_bytes())
                .unwrap(); // mov x28,77
            p.memory
                .write_array(0x5004, 0x14000000u32.to_le_bytes())
                .unwrap();
            p.memory
                .protect(
                    0x4000,
                    2 * trames_memory::PAGE_SIZE,
                    trames_memory::Permissions::RX,
                )
                .unwrap();
            let args = [0x1234, 2, 3, 4, 5, 6];
            put_args(&mut p.cpu, args);
            p.cpu.set_x(8, 56);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, 0x30055)]).unwrap(),
            ));
            p.signals.actions.set(
                31,
                Action {
                    handler: 0x5000,
                    flags: 4,
                    ..Default::default()
                },
            );
            p.signals.io.scheduling.set_affinity((1 << slots) - 1);
            let mut peer = p.fork();
            peer.tgid = 2;
            peer.family.set_parent(1);
            peer.cpu = Cpu::new(0x4004, 0x9000);
            let mut k = kernel();
            k.cpu_count = 2;
            k.workers = crate::workers::Pool::new(slots);
            k.per_cpu = vec![Duration::ZERO; 2];
            k.processes.insert(1, p);
            k.processes.insert(2, peer);
            assert!(k
                .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                .unwrap());
            let p = k.processes.read(&1);
            assert_eq!(p.cpu.x(28), 77);
            assert_eq!(p.cpu.x(0), 31);
            let sp = p.cpu.sp;
            for (index, arg) in args.iter().enumerate() {
                assert_eq!(
                    p.memory.read_u64(sp + 312 + index as u64 * 8).unwrap(),
                    *arg
                );
            }
            assert_eq!(p.memory.read_u64(sp + 312 + 8 * 8).unwrap(), 56);
            assert_eq!(
                u32::from_le_bytes(p.memory.read_array(sp + 24).unwrap()),
                56
            );
            assert_eq!(
                u32::from_le_bytes(p.memory.read_array(sp + 28).unwrap()),
                ARCH
            );
            assert_eq!(
                u32::from_le_bytes(p.memory.read_array(sp + 4).unwrap()),
                0x55
            );
            assert_eq!(k.worker_syscalls, 1);
            assert_eq!(k.service_requests, 0);
            assert!(k.cohort_return_syscalls.is_empty());
        }
    }

    #[test]
    fn source_seccomp_fatal_actions_use_original_thread_or_group_without_owner_return() {
        use super::super::tests::{kernel, process};
        for (action, handler, mask, strict) in [
            (0, 0, 0, false),
            (KILL_PROCESS, 0, 0, false),
            (0x1234_0000, 0, 0, false),
            (0x30055, 1, 0, false),
            (0x30055, 0x5000, 1 << 30, false),
            (0, 0, 0, true),
        ] {
            let mut subject = process();
            subject.tgid = 2;
            subject.family.set_parent(1);
            subject
                .memory
                .write_array(0x4000, 0xd4000001u32.to_le_bytes())
                .unwrap();
            subject
                .memory
                .write_array(0x4004, 0x14000000u32.to_le_bytes())
                .unwrap();
            subject
                .memory
                .protect(
                    0x4000,
                    trames_memory::PAGE_SIZE,
                    trames_memory::Permissions::RX,
                )
                .unwrap();
            subject.cpu.set_x(8, 172);
            subject.signals.actions.set_handler(31, handler);
            subject.signals.mask = mask;
            if strict {
                subject.seccomp.set_strict();
            } else {
                subject.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, action)]).unwrap(),
                ));
            }
            subject.signals.io.scheduling.set_affinity(3);
            let peer_memory = subject.memory.share();
            let mut peer = subject.fork_with_memory(peer_memory);
            peer.tgid = 2;
            peer.family = subject.family.clone();
            peer.children = subject.children.clone();
            peer.wait_event = subject.wait_event.clone();
            peer.share_process_context(&subject);
            peer.cpu = Cpu::new(0x4004, 0x9000);
            let mut foreign = process();
            foreign
                .memory
                .write_array(0x4000, 0x14000000u32.to_le_bytes())
                .unwrap();
            foreign
                .memory
                .protect(
                    0x4000,
                    trames_memory::PAGE_SIZE,
                    trames_memory::Permissions::RX,
                )
                .unwrap();
            foreign.signals.io.scheduling.set_affinity(3);
            let mut k = kernel();
            k.cpu_count = 2;
            k.workers = crate::workers::Pool::new(2);
            k.per_cpu = vec![Duration::ZERO; 2];
            k.processes.insert(1, foreign);
            k.processes.insert(2, subject);
            k.processes.insert(3, peer);
            for _ in 0..4 {
                assert!(k
                    .parallel_epoch(
                        &mut trames_linux::CapturedOutput::default(),
                        k.instructions + 100_000,
                        true
                    )
                    .unwrap());
                if matches!(k.processes.read(&2).state, State::Zombie(_)) {
                    break;
                }
            }
            let signal = if strict { 9 } else { 31 };
            assert!(
                matches!(k.processes.read(&2).state,State::Zombie(s) if s==signal),
                "action={action:x} strict={strict}"
            );
            assert_eq!(
                k.processes
                    .get(&3)
                    .is_none_or(|p| matches!(p.state, State::Zombie(_))),
                action != 0,
                "action={action:x}"
            );
            assert!(matches!(k.processes.read(&1).state, State::Ready));
            assert_eq!(k.service_requests, 0);
            assert!(
                k.cohort_return_syscalls.is_empty(),
                "{:?}",
                k.cohort_return_syscalls
            );
        }
    }

    #[test]
    fn original_policy_readers_do_not_wait_for_the_publication_mutex() {
        let policy = Seccomp::default();
        let mut reader = policy.clone();
        let publication = policy.original.versions.lock().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            reader.capture_entry();
            send.send(reader.allows(172, 0, [0; 6])).unwrap();
        });
        let result = receive.recv_timeout(Duration::from_secs(2));
        drop(publication);
        thread.join().unwrap();
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn inherited_long_policy_chain_drops_without_recursive_host_stack_use() {
        std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let mut parent = Seccomp::default();
                let filter = Arc::new(Filter::validate(vec![i(6, 0, 0, ALLOW)]).unwrap());
                for _ in 0..6500 {
                    parent.push(filter.clone());
                }
                let child = parent.fork();
                drop(parent);
                assert_eq!(child.count(), 6500);
                assert!(child.allows(172, 0, [0; 6]));
                drop(child);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn credential_subsystem_refreshes_future_calls_without_owner_returns() {
        use super::super::tests::{kernel, process};
        for slots in [1, 2] {
            for filtered in [false, true] {
                let mut p = process();
                p.linux
                    .vfs
                    .open_at(AT_FDCWD, b"/root-only", 0x42, 0o600)
                    .unwrap();
                p.memory.write(0x1800, b"/root-only\0").unwrap();
                p.memory
                    .write_array(0x1900, 0x20080522u32.to_le_bytes())
                    .unwrap();
                p.memory.write_array(0x1904, 0u32.to_le_bytes()).unwrap();
                p.memory.write_array(0x1a00, 17u32.to_le_bytes()).unwrap();
                let calls: Vec<(u64, [u64; 6], u64)> = vec![
                    (144, [1001, 0, 0, 0, 0, 0], 0),
                    (159, [1, 0x1a00, 0, 0, 0, 0], 0),
                    (167, [8, 1, 0, 0, 0, 0], 0),
                    (146, [1000, 0, 0, 0, 0, 0], 0),
                    (174, [0; 6], 1000),
                    (175, [0; 6], 1000),
                    (176, [0; 6], 1001),
                    (177, [0; 6], 1001),
                    (151, [u32::MAX as u64, 0, 0, 0, 0, 0], 1000),
                    (152, [u32::MAX as u64, 0, 0, 0, 0, 0], 1001),
                    (158, [1, 0x1a10, 0, 0, 0, 0], 1),
                    (90, [0x1900, 0x1910, 0, 0, 0, 0], 0),
                    (56, [(-100i64) as u64, 0x1800, 0, 0, 0, 0], (-13i64) as u64),
                    (161, [0x1800, 4, 0, 0, 0, 0], (-1i64) as u64),
                    (116, [10, 0, 0, 0, 0, 0], (-1i64) as u64),
                    (129, [2, 0, 0, 0, 0, 0], (-1i64) as u64),
                    (261, [2, 7, 0, 0x1b00, 0, 0], (-1i64) as u64),
                    (
                        97,
                        [trames_vfs::CLONE_NEWUTS, 0, 0, 0, 0, 0],
                        (-1i64) as u64,
                    ),
                    (146, [0; 6], (-1i64) as u64),
                    (167, [3, 0, 0, 0, 0, 0], 0),
                    (167, [38, 1, 0, 0, 0, 0], 0),
                    (167, [39, 0, 0, 0, 0, 0], 1),
                ];
                let mov = |r: u32, value: u64| {
                    [0xd2800000, 0xf2a00000, 0xf2c00000, 0xf2e00000]
                        .into_iter()
                        .enumerate()
                        .map(|(i, op)| op | (((value >> (16 * i)) as u32 & 0xffff) << 5) | r)
                        .collect::<Vec<_>>()
                };
                let mut code = mov(20, 0x1000);
                for (index, (number, args, _)) in calls.iter().enumerate() {
                    for (r, arg) in args.iter().enumerate() {
                        code.extend(mov(r as u32, *arg));
                    }
                    code.extend(mov(8, *number));
                    code.extend([0xd4000001, 0xf9000000 | ((index as u32) << 10) | (20 << 5)]);
                }
                code.extend(mov(28, 1));
                code.push(0x14000000);
                assert!(code.len() * 4 < 0xf00);
                for (i, word) in code.iter().enumerate() {
                    p.memory
                        .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .write_array(0x4f00, 0x14000000u32.to_le_bytes())
                    .unwrap();
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.signals.io.scheduling.set_affinity((1 << slots) - 1);
                if filtered {
                    p.seccomp
                        .push(Arc::new(Filter::validate(vec![i(6, 0, 0, ALLOW)]).unwrap()));
                }
                let mut peer = p.fork();
                peer.tgid = 2;
                peer.family.set_parent(1);
                peer.cpu = Cpu::new(0x4f00, 0x9000);
                let mut k = kernel();
                k.cpu_count = 2;
                k.workers = crate::workers::Pool::new(2);
                k.per_cpu = vec![Duration::ZERO; 2];
                k.processes.insert(1, p);
                k.processes.insert(2, peer);
                for _ in 0..16 {
                    assert!(k
                        .parallel_epoch(
                            &mut trames_linux::CapturedOutput::default(),
                            k.instructions + 100_000,
                            true
                        )
                        .unwrap());
                    if k.processes.read(&1).cpu.x(28) == 1 {
                        break;
                    }
                }
                let p = &k.processes.read(&1);
                assert_eq!(p.cpu.x(28), 1, "slots={slots} filtered={filtered}");
                for (index, (number, _, expected)) in calls.iter().enumerate() {
                    assert_eq!(
                        p.memory.read_u64(0x1000 + index as u64 * 8).unwrap(),
                        *expected,
                        "call {index}: {number} slots={slots} filtered={filtered}"
                    );
                }
                assert_eq!(
                    p.memory.read_array::<4>(0x1a10).unwrap(),
                    17u32.to_le_bytes()
                );
                assert_eq!(p.memory.read_array::<4>(0x1910).unwrap(), [0; 4]);
                assert_eq!(p.linux.vfs.credentials.uid, 1000);
                assert_eq!(k.processes.read(&2).linux.vfs.credentials.uid, 0);
                assert_eq!(k.syscalls, calls.len() as u64);
                assert_eq!(k.service_requests, 0);
                assert!(
                    k.cohort_return_syscalls.is_empty(),
                    "{:?}",
                    k.cohort_return_syscalls
                );
                if filtered {
                    assert_eq!(p.seccomp.evaluations(), calls.len() as u64);
                }
            }
        }
    }

    #[test]
    fn resource_limit_loops_and_seccomp_denials_retire_on_workers_without_owner_returns() {
        use super::super::tests::{kernel, process};
        for decision in [0x7fff0000, 0x5007b] {
            let mut p = process();
            p.signals.io.scheduling.set_affinity(3);
            // getrlimit(7, 0x1000), repeated 1000 times, then owner exit boundary.
            let code = [
                0xd28000e0u32,
                0xd2820001,
                0xd2801468,
                0xd4000001,
                0xf1000529,
                0x54ffff61,
                0x14000000,
            ];
            for (i, word) in code.into_iter().enumerate() {
                p.memory
                    .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
            p.memory
                .protect(
                    0x4000,
                    trames_memory::PAGE_SIZE,
                    trames_memory::Permissions::RX,
                )
                .unwrap();
            p.cpu.set_x(9, 1000);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
            ));
            let evaluations = p.seccomp.evaluations.clone();
            let mut peer = p.fork();
            peer.vm_id = 2;
            peer.tgid = 2;
            let mut k = kernel();
            k.cpu_count = 2;
            k.workers = crate::workers::Pool::new(2);
            k.per_cpu = vec![Duration::ZERO; 2];
            k.processes.insert(1, p);
            k.processes.insert(2, peer);
            // A faster spinner may exhaust one epoch's instruction allowance
            // before its peer finishes. Resume the same tasks, without running
            // an owner syscall, until both fixed workloads have completed.
            for _ in 0..32 {
                let allowance = k.instructions + 100_000;
                assert!(k
                    .parallel_epoch(
                        &mut trames_linux::CapturedOutput::default(),
                        allowance,
                        true
                    )
                    .unwrap());
                if k.processes.values().all(|p| p.cpu.x(9) == 0) {
                    break;
                }
            }
            assert!(k.processes.values().all(|p| p.cpu.x(9) == 0));
            assert_eq!(k.service_requests, 0);
            assert_eq!(evaluations.load(std::sync::atomic::Ordering::Relaxed), 2000);
            assert!(!k.cohort_return_syscalls.contains_key(&163));
            assert!(k.worker_syscalls >= 2000);
            for p in k.processes.values() {
                assert_eq!(
                    p.memory.read_u64(0x1000).unwrap(),
                    if decision == 0x7fff0000 {
                        trames_vfs::MAX_FDS as u64
                    } else {
                        0
                    }
                );
            }
        }
    }
    #[test]
    fn child_wait_filters_execute_once_on_the_source_workers() {
        use super::super::tests::{kernel, process};
        for number in [95u32, 260] {
            for decision in [ALLOW, 0x5000d] {
                let mut p = process();
                p.signals.io.scheduling.set_affinity(3);
                let args = if number == 260 {
                    [u32::MAX as u64, 0, 1, 0, 0, 0]
                } else {
                    [0, 0, 0, 5, 0, 0]
                };
                let mut words = Vec::new();
                for (reg, value) in args.into_iter().enumerate() {
                    words.push(if value == u32::MAX as u64 {
                        0x92800000 | reg as u32
                    } else {
                        0xd2800000 | ((value as u32) << 5) | reg as u32
                    });
                }
                words.extend([
                    0xd2800008 | (number << 5),
                    0xd4000001,
                    0xf1000529,
                    0x54000001 | ((-9i32 as u32 & 0x7ffff) << 5),
                    0x14000000,
                ]);
                for (i, word) in words.into_iter().enumerate() {
                    p.memory
                        .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.cpu.set_x(9, 1000);
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
                ));
                let evaluations = p.seccomp.evaluations.clone();
                let mut thread = p.fork();
                thread.children = p.children.clone();
                thread.wait_event = p.wait_event.clone();
                let mut child = p.fork();
                child.tgid = 42;
                child.family.set_parent(1);
                child.state = State::Sleep(Instant::now() + Duration::from_secs(60), 0);
                let mut k = kernel();
                k.cpu_count = 2;
                k.workers = crate::workers::Pool::new(2);
                k.per_cpu = vec![Duration::ZERO; 2];
                k.processes.insert(1, p);
                k.processes.insert(2, thread);
                k.processes.insert(42, child);
                for _ in 0..32 {
                    let allowance = k.instructions + 100_000;
                    assert!(k
                        .parallel_epoch(
                            &mut trames_linux::CapturedOutput::default(),
                            allowance,
                            true
                        )
                        .unwrap());
                    if [1, 2]
                        .into_iter()
                        .all(|id| k.processes.read(&id).cpu.x(9) == 0)
                    {
                        break;
                    }
                }
                for id in [1, 2] {
                    assert_eq!(k.processes.read(&id).cpu.x(9), 0);
                    assert_eq!(
                        k.processes.read(&id).cpu.x(0),
                        if decision == ALLOW {
                            0
                        } else {
                            0u64.wrapping_sub(13)
                        }
                    );
                }
                assert_eq!(evaluations.load(std::sync::atomic::Ordering::Relaxed), 2000);
                assert!(!k.cohort_return_syscalls.contains_key(&number));
                assert_eq!(k.service_requests, 0);
            }
        }
    }

    use trames_cpu::Cpu;
    type Kernel = crate::process::Kernel<Cpu>;

    use super::*;
    #[test]
    fn filtered_socket_controls_remain_joined_and_never_run_in_snapshot_invoke() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            p.linux
                .vfs
                .configure_network(trames_vfs::NetworkMode::Loopback)
                .unwrap();
            let fd = p.linux.vfs.socket(2, 1, 0).unwrap();
            p.memory.write_array(0x1000, 4u32.to_le_bytes()).unwrap();
            p.cpu.set_x(8, 209);
            put_args(&mut p.cpu, [fd as u64, 6, 1, 0x1100, 0x1000, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5000d })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                owner_syscalls: false,
                diagnostics: None,
                membarrier_registered: None,
                vfork_release: None,
                native_space: None,
                namespaces: None,
                exit_files: None,
                exit_context: None,
                children: Default::default(),
                limits: None,
                timers: None,

                saved_wait_mask: Default::default(),
                io_signals: Default::default(),
                io_routes: Default::default(),
                io_wake: None,
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                cpus: 4,
                profile: false,

                fd_flags: p.linux.vfs.fd_flags_snapshot(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: trames_linux::DirectSyscalls::default()
                    .with_network(p.linux.vfs.direct_network()),
                futex: Default::default(),
            };
            assert!(!snapshot.admit(&p.cpu));
            assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), None);
            assert_eq!(p.seccomp.evaluations(), 0);
            let mut k = super::super::tests::kernel();
            k.call(
                1,
                &mut p,
                209,
                [fd as u64, 6, 1, 0x1100, 0x1000, 0],
                &mut trames_linux::CapturedOutput::default(),
            );
            assert_eq!(p.seccomp.evaluations(), 1);
            assert_eq!(p.cpu.x(0), if allowed { 0 } else { error(Errno(13)) });
        }
    }

    #[test]
    fn complete_socket_controls_use_workers_and_one_filter_decision() {
        for virtual_socket in [false, true] {
            for number in [200u32, 201, 202, 203, 204, 205, 208, 209, 210, 242] {
                for decision in [None, Some(ALLOW), Some(0x5007b)] {
                    let mut p = super::super::tests::process();
                    if virtual_socket {
                        p.linux
                            .vfs
                            .configure_local_fabric(trames_vfs::NetworkMode::Loopback)
                            .unwrap();
                    } else {
                        p.linux
                            .vfs
                            .configure_network(trames_vfs::NetworkMode::Loopback)
                            .unwrap();
                    }
                    let fd = p
                        .linux
                        .vfs
                        .socket(2, 1 | trames_vfs::O_NONBLOCK, 0)
                        .unwrap();
                    let socket = p.linux.vfs.socket_fd(fd).unwrap();
                    let mut endpoint = "127.0.0.1:0".parse().unwrap();
                    if matches!(number, 201 | 202 | 242) {
                        socket.bind(endpoint).unwrap();
                        if number != 201 {
                            socket.listen(4).unwrap();
                        }
                    }
                    let _listener = if number == 203 {
                        let listener = p
                            .linux
                            .vfs
                            .socket(2, 1 | trames_vfs::O_NONBLOCK, 0)
                            .unwrap();
                        let socket = p.linux.vfs.socket_fd(listener).unwrap();
                        socket.bind(endpoint).unwrap();
                        socket.listen(4).unwrap();
                        endpoint = socket.local_addr().unwrap();
                        Some(socket)
                    } else {
                        None
                    };
                    p.memory
                        .write(0x1000, &trames_net::encode_address(endpoint))
                        .unwrap();
                    p.memory.write(0x1100, &1u32.to_le_bytes()).unwrap();
                    p.memory.write(0x1200, &16u32.to_le_bytes()).unwrap();
                    let args = match number {
                        200 | 203 => [fd, 0x1000, 16, 0, 0, 0],
                        201 => [fd, 4, 0, 0, 0, 0],
                        202 | 242 => [fd, 0, 0, 0, 0, 0],
                        204 | 205 => [fd, 0x1300, 0x1200, 0, 0, 0],
                        208 => [fd, 6, 1, 0x1100, 4, 0],
                        209 => [fd, 6, 1, 0x1100, 0x1200, 0],
                        _ => [fd, 2, 0, 0, 0, 0],
                    };
                    let mov = |rd: u32, value: u32| 0xd2800000u32 | (value << 5) | rd;
                    let mut code: Vec<_> = args
                        .into_iter()
                        .enumerate()
                        .map(|(i, a)| mov(i as u32, a))
                        .collect();
                    code.extend([mov(8, number), 0xd4000001]);
                    code.push(0x14000000 | ((-(code.len() as i32) as u32) & 0x03ffffff));
                    for (i, word) in code.into_iter().enumerate() {
                        p.memory
                            .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                            .unwrap();
                    }
                    p.memory
                        .protect(
                            0x4000,
                            trames_memory::PAGE_SIZE,
                            trames_memory::Permissions::RX,
                        )
                        .unwrap();
                    p.cpu = Cpu::new(0x4000, 0);
                    p.signals.io.scheduling.set_affinity(3);
                    if let Some(decision) = decision {
                        p.seccomp.push(Arc::new(
                            Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
                        ));
                    }
                    let peer = p.fork();
                    peer.family.set_parent(1);
                    let mut k = super::super::tests::kernel();
                    k.cpu_count = 2;
                    k.workers = crate::workers::Pool::new(2);
                    k.per_cpu = vec![Duration::ZERO; 2];
                    k.processes.insert(1, p);
                    k.processes.insert(2, peer);
                    assert!(k
                        .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                        .unwrap());
                    if decision.is_some() {
                        assert_eq!(
                            k.processes.read(&1).seccomp.evaluations(),
                            k.syscalls,
                            "{virtual_socket} {number}"
                        );
                    }
                    if decision != Some(0x5007b) {
                        assert!(
                            k.worker_socket_syscalls > 100,
                            "{virtual_socket} {number}: {}",
                            k.worker_socket_syscalls
                        );
                        assert_eq!(k.service_requests, 0, "{virtual_socket} {number}");
                        assert!(k.parallel_rounds <= 4, "{virtual_socket} {number}");
                    } else {
                        assert_eq!(k.worker_socket_syscalls, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn accepted_mapping_decision_retains_original_entry_across_policy_publication() {
        let mut policy = Seccomp::default();
        policy.push(Arc::new(Filter::validate(vec![i(6, 0, 0, ALLOW)]).unwrap()));
        let args = [0x8000, trames_memory::PAGE_SIZE, 0, 0, 0, 0];
        assert_eq!(
            policy
                .entry_decision(215, 0x4004, args)
                .value_for(&policy, 215, 0x4004, args),
            Some(ALLOW)
        );
        assert!(policy
            .entry_decision(215, 0x4004, args)
            .value_for(&policy, 233, 0x4004, args)
            .is_none());
        assert!(policy
            .entry_decision(215, 0x4004, args)
            .value_for(&policy, 215, 0x4008, args)
            .is_none());
        let mut changed = args;
        changed[1] += trames_memory::PAGE_SIZE;
        assert!(policy
            .entry_decision(215, 0x4004, args)
            .value_for(&policy, 215, 0x4004, changed)
            .is_none());
        let mut p = super::super::tests::process();
        p.cpu.pc = 0x4004;
        p.seccomp = policy.clone();
        p.seccomp_entry = Some(policy.entry_decision(215, p.cpu.pc, args));
        p.seccomp.push(Arc::new(
            Filter::validate(vec![i(6, 0, 0, 0x0005_000d)]).unwrap(),
        ));
        let mut kernel = super::super::tests::kernel();
        kernel.call(
            1,
            &mut p,
            215,
            args,
            &mut trames_linux::CapturedOutput::default(),
        );
        assert_eq!(
            p.cpu.x(0),
            0,
            "accepted entry is not evaluated against a later policy"
        );
        assert!(p.memory.read_array::<1>(0x8000).is_err());
        assert!(p.seccomp_entry.is_none());
        let other = policy.fork();
        assert!(
            policy
                .entry_decision(215, 0x4004, args)
                .value_for(&other, 215, 0x4004, args)
                .is_none(),
            "same filter does not confer original task identity"
        );
    }
    #[test]
    fn general_admission_does_not_evaluate_filtered_membership_entries() {
        for decision in [ALLOW, 0x5007b] {
            let mut p = super::super::tests::process();
            let [fd, _] = p.linux.vfs.pipe(0).unwrap();
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                owner_syscalls: false,
                diagnostics: None,
                membarrier_registered: None,
                vfork_release: None,
                native_space: None,
                namespaces: None,
                exit_files: None,
                exit_context: None,
                children: Default::default(),
                limits: None,
                timers: None,

                saved_wait_mask: Default::default(),
                io_signals: Default::default(),
                io_routes: Default::default(),
                io_wake: None,
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                cpus: 4,
                profile: false,

                fd_flags: p.linux.vfs.fd_flags_snapshot(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: trames_linux::DirectSyscalls::default()
                    .with_membership(p.linux.vfs.shared_files()),
                futex: Default::default(),
            };
            for (number, args) in [
                (23, [fd as u64, 0, 0, 0, 0, 0]),
                (24, [fd as u64, 200, 0, 0, 0, 0]),
                (57, [fd as u64, 0, 0, 0, 0, 0]),
                (25, [fd as u64, 0, 160, 0, 0, 0]),
                (25, [fd as u64, 1030, 160, 0, 0, 0]),
            ] {
                p.cpu.set_x(8, number as u64);
                put_args(&mut p.cpu, args);
                assert!(!snapshot.admit(&p.cpu));
                assert_eq!(p.linux.vfs.flags(160), Err(Errno(9)));
                assert_eq!(p.linux.vfs.flags(200), Err(Errno(9)));
                assert!(p.linux.vfs.flags(fd).is_ok());
            }
            assert_eq!(snapshot.direct.fd_control_completed(), 0);
        }
    }
    #[test]
    fn timer_controls_apply_entry_policy_once_before_inputs() {
        for number in [102, 103, 107, 108, 109, 110, 111] {
            for decision in [ALLOW, 0x5007b] {
                let mut p = super::super::tests::process();
                for (i, word) in [0xd4000001u32, 0xaa0003f3, 0x14000000]
                    .into_iter()
                    .enumerate()
                {
                    p.memory
                        .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.memory.write_array(0x8000, 3600u64.to_le_bytes()).unwrap();
                p.memory
                    .write_array(0x8200, 0x8220u64.to_le_bytes())
                    .unwrap();
                p.memory.write_array(0x8208, 8u64.to_le_bytes()).unwrap();
                p.memory
                    .write_array(0x8220, (1u64 << 11).to_le_bytes())
                    .unwrap();
                p.signals.io_directory.publish(&p.signals.io, 1, 1, 1, 0, 0);
                let timers = Arc::new(trames_kernel::timers::Timers::default());
                timers
                    .call(
                        107,
                        [1, 0, 0x8300, 0, 0, 0],
                        &mut p.memory,
                        Instant::now(),
                        1,
                        &p.signals.io_directory,
                        p.linux.vfs.pid_namespace(),
                    )
                    .unwrap();
                let id = p.memory.read_u64(0x8300).unwrap();
                p.memory.write_array(0x8000, [0u8; 32]).unwrap();
                let output = if decision == ALLOW { 0x8000 } else { u64::MAX };
                let args = match number {
                    102 => [0, output, 0, 0, 0, 0],
                    103 => [0, output, 0, 0, 0, 0],
                    107 => [1, 0, output, 0, 0, 0],
                    108 => [id, output, 0, 0, 0, 0],
                    109 | 111 => [id, 0, 0, 0, 0, 0],
                    110 => [id, 0, output, 0, 0, 0],
                    _ => unreachable!(),
                };
                p.cpu = Cpu::new(0x4000, 0);
                p.cpu.set_x(8, number);
                put_args(&mut p.cpu, args);
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
                ));
                let snapshot = crate::worker_syscalls::Snapshot {
                    owner_syscalls: false,
                    diagnostics: None,
                    membarrier_registered: None,
                    vfork_release: None,
                    native_space: None,
                    namespaces: None,
                    exit_files: None,
                    exit_context: None,
                    children: Default::default(),
                    limits: None,
                    timers: Some(timers),

                    saved_wait_mask: Default::default(),
                    io_signals: p.signals.io.clone(),
                    io_routes: trames_kernel::signal::IoRoutes {
                        directory: p.signals.io_directory.clone(),
                        ..Default::default()
                    },
                    io_wake: None,
                    seccomp: p.seccomp.clone(),
                    identities: [0; 7],
                    started: Instant::now(),
                    processor: 0,
                    cpus: 4,
                    profile: false,

                    fd_flags: Default::default(),
                    umask: Default::default(),
                    actions: p.signals.actions.shared(),
                    program_break: p.linux.program_break(),
                    uts: None,
                    futex: Default::default(),
                    direct: trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors()),
                };
                let task = snapshot.io_signals.clone();
                let control = Arc::new(crate::workers::Control::new(1000));
                let epoch = crate::run_queue::Epoch::new(control.clone());
                epoch.add(crate::run_queue::Job::new(
                    crate::workers::Work {
                        task: None,
                        pid: 1,
                        cpu: std::mem::take(&mut p.cpu),
                        memory: Some(Box::new(
                            p.memory.parallel_view(&mut Default::default()).unwrap(),
                        )),
                        control,
                        syscalls: Some(snapshot),
                        gpu: None,
                        audio: None,
                    },
                    1,
                    0,
                    None,
                ));
                let mut pool = crate::workers::Pool::new(1);
                pool.ensure(0).unwrap();
                pool.launch(0, epoch.clone()).unwrap();
                assert!(matches!(
                    pool.event_timeout(Duration::from_secs(5)).unwrap(),
                    Some(crate::workers::Event::EpochStopped(0))
                ));
                let done = epoch.drain().pop().unwrap();
                p.memory.commit_parallel().unwrap();
                p.cpu = done.cpu;
                assert_eq!(p.seccomp.evaluations(), 1);
                if decision == ALLOW {
                    assert_eq!(p.cpu.x(19), 0);
                    assert_eq!(done.io_waits, 0);
                    assert_eq!(done.serviced_syscalls, 0);
                    assert_eq!(task.context.lock().unwrap().wait_mask, None);
                    assert_eq!(task.mask(), 0);
                } else {
                    assert!(
                        done.seccomp_entry.is_none(),
                        "pure denial completes on its worker"
                    );
                    assert!(matches!(done.outcome, Some(SliceOutcome::Yield { .. })));
                    assert_eq!(done.syscalls, 1);
                    assert_eq!(p.cpu.x(19), error(Errno(123)));
                    assert_eq!(p.seccomp.evaluations(), 1);
                    assert_eq!(task.mask(), 0);
                }
            }
        }
    }
    #[test]
    fn masked_event_waits_apply_entry_policy_once_before_inputs_and_across_parking() {
        for number in [22, 72, 73, 441] {
            for decision in [ALLOW, 0x5007b] {
                let mut p = super::super::tests::process();
                let ep = p.linux.vfs.epoll_create(0).unwrap();
                for (i, word) in [0xd4000001u32, 0xaa0003f3, 0x14000000]
                    .into_iter()
                    .enumerate()
                {
                    p.memory
                        .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.memory.write_array(0x8000, 3600u64.to_le_bytes()).unwrap();
                p.memory
                    .write_array(0x8200, 0x8220u64.to_le_bytes())
                    .unwrap();
                p.memory.write_array(0x8208, 8u64.to_le_bytes()).unwrap();
                p.memory
                    .write_array(0x8220, (1u64 << 11).to_le_bytes())
                    .unwrap();
                let mask = if decision == ALLOW { 0x8220 } else { u64::MAX };
                let args = match number {
                    72 => [
                        0,
                        0,
                        0,
                        0,
                        0x8000,
                        if decision == ALLOW { 0x8200 } else { u64::MAX },
                    ],
                    73 => [0, 0, 0x8000, mask, 8, 0],
                    22 => [ep as u64, 0x8300, 1, 3600000, mask, 8],
                    _ => [ep as u64, 0x8300, 1, 0x8000, mask, 8],
                };
                p.cpu = Cpu::new(0x4000, 0);
                p.cpu.set_x(8, number);
                put_args(&mut p.cpu, args);
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
                ));
                let snapshot = crate::worker_syscalls::Snapshot {
                    owner_syscalls: false,
                    diagnostics: None,
                    membarrier_registered: None,
                    vfork_release: None,
                    native_space: None,
                    namespaces: None,
                    exit_files: None,
                    exit_context: None,
                    children: Default::default(),
                    limits: None,
                    timers: None,

                    saved_wait_mask: Default::default(),
                    io_signals: Default::default(),
                    io_routes: Default::default(),
                    io_wake: None,
                    seccomp: p.seccomp.clone(),
                    identities: [0; 7],
                    started: Instant::now(),
                    processor: 0,
                    cpus: 4,
                    profile: false,

                    fd_flags: Default::default(),
                    umask: Default::default(),
                    actions: p.signals.actions.shared(),
                    program_break: p.linux.program_break(),
                    uts: None,
                    futex: Default::default(),
                    direct: trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors()),
                };
                let task = snapshot.io_signals.clone();
                let control = Arc::new(crate::workers::Control::new(1000));
                let epoch = crate::run_queue::Epoch::new(control.clone());
                epoch.add(crate::run_queue::Job::new(
                    crate::workers::Work {
                        task: None,
                        pid: 1,
                        cpu: std::mem::take(&mut p.cpu),
                        memory: Some(Box::new(
                            p.memory.parallel_view(&mut Default::default()).unwrap(),
                        )),
                        control,
                        syscalls: Some(snapshot),
                        gpu: None,
                        audio: None,
                    },
                    1,
                    0,
                    None,
                ));
                let mut pool = crate::workers::Pool::new(1);
                pool.ensure(0).unwrap();
                pool.launch(0, epoch.clone()).unwrap();
                if decision == ALLOW {
                    epoch.expire_parked_io(1);
                }
                assert!(matches!(
                    pool.event_timeout(Duration::from_secs(5)).unwrap(),
                    Some(crate::workers::Event::EpochStopped(0))
                ));
                let done = epoch.drain().pop().unwrap();
                p.memory.commit_parallel().unwrap();
                p.cpu = done.cpu;
                assert_eq!(p.seccomp.evaluations(), 1);
                if decision == ALLOW {
                    assert_eq!(p.cpu.x(19), 0);
                    assert_eq!(done.io_waits, 1);
                    assert_eq!(done.serviced_syscalls, 0);
                    assert_eq!(task.context.lock().unwrap().wait_mask, None);
                    assert_eq!(task.mask(), 0);
                } else {
                    assert!(
                        done.seccomp_entry.is_none(),
                        "pure denial completes on its worker"
                    );
                    assert!(matches!(done.outcome, Some(SliceOutcome::Yield { .. })));
                    assert_eq!(done.syscalls, 1);
                    assert_eq!(p.cpu.x(19), error(Errno(123)));
                    assert_eq!(p.seccomp.evaluations(), 1);
                    assert_eq!(task.mask(), 0);
                }
            }
        }
    }
    #[test]
    fn filtered_sleeps_wait_on_workers_and_denials_retain_the_exact_entry() {
        for number in [101, 115] {
            for decision in [ALLOW, 0x5007b] {
                let mut p = super::super::tests::process();
                for (offset, word) in [0xd4000001u32, 0xaa0003f3, 0x14000000]
                    .into_iter()
                    .enumerate()
                {
                    p.memory
                        .write_array(0x4000 + offset as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.memory.write_array(0x8000, 0u64.to_le_bytes()).unwrap();
                p.memory
                    .write_array(0x8008, 100_000u64.to_le_bytes())
                    .unwrap();
                let args = if number == 101 {
                    [0x8000, 0, 0, 0, 0, 0]
                } else {
                    [1, 0, 0x8000, 0, 0, 0]
                };
                p.cpu = Cpu::new(0x4000, 0);
                p.cpu.set_x(8, number);
                put_args(&mut p.cpu, args);
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
                ));
                let snapshot = crate::worker_syscalls::Snapshot {
                    owner_syscalls: false,
                    diagnostics: None,
                    membarrier_registered: None,
                    vfork_release: None,
                    native_space: None,
                    namespaces: None,
                    exit_files: None,
                    exit_context: None,
                    children: Default::default(),
                    limits: None,
                    timers: None,

                    saved_wait_mask: Default::default(),
                    io_signals: Default::default(),
                    io_routes: Default::default(),
                    io_wake: None,
                    seccomp: p.seccomp.clone(),
                    identities: [0; 7],
                    started: Instant::now(),
                    processor: 0,
                    cpus: 4,
                    profile: false,

                    fd_flags: Default::default(),
                    umask: Default::default(),
                    actions: p.signals.actions.shared(),
                    program_break: p.linux.program_break(),
                    uts: None,
                    direct: Default::default(),
                    futex: Default::default(),
                };
                let control = Arc::new(crate::workers::Control::new(1000));
                let epoch = crate::run_queue::Epoch::new(control.clone());
                epoch.add(crate::run_queue::Job::new(
                    crate::workers::Work {
                        task: None,
                        audio: None,
                        gpu: None,
                        pid: 1,
                        cpu: std::mem::take(&mut p.cpu),
                        memory: Some(Box::new(
                            p.memory.parallel_view(&mut Default::default()).unwrap(),
                        )),
                        control,
                        syscalls: Some(snapshot),
                    },
                    1,
                    0,
                    None,
                ));
                let mut pool = crate::workers::Pool::new(1);
                pool.ensure(0).unwrap();
                pool.launch(0, epoch.clone()).unwrap();
                assert!(matches!(
                    pool.event_timeout(Duration::from_secs(5)).unwrap(),
                    Some(crate::workers::Event::EpochStopped(0))
                ));
                let done = epoch.drain().pop().unwrap();
                assert_eq!(p.seccomp.evaluations(), 1);
                p.memory.commit_parallel().unwrap();
                p.cpu = done.cpu;
                if decision == ALLOW {
                    assert_eq!((done.waits, done.resumes, done.syscalls), (1, 1, 1));
                    assert_eq!((p.cpu.x(19), p.cpu.x(8)), (0, number));
                    assert!(done.seccomp_entry.is_none());
                } else {
                    assert_eq!(done.waits, 0);
                    assert!(
                        done.seccomp_entry.is_none(),
                        "pure denial completes on its worker"
                    );
                    assert!(matches!(done.outcome, Some(SliceOutcome::Yield { .. })));
                    assert_eq!(done.syscalls, 1);
                    assert_eq!(p.cpu.x(19), error(Errno(123)));
                    assert_eq!(p.seccomp.evaluations(), 1);
                    assert_eq!(p.cpu.x(0), error(Errno(123)));
                    assert!(matches!(p.state, State::Ready));
                }
            }
        }
    }

    #[test]
    fn filtered_fd_workers_complete_shared_operations_and_preserve_deferred_decisions() {
        for (number, kind, decision) in [
            (23, 0, ALLOW),
            (24, 0, ALLOW),
            (25, 0, ALLOW),
            (57, 0, ALLOW),
            (23, 1, ALLOW),
            (57, 1, ALLOW),
            (23, 2, ALLOW),
            (57, 2, ALLOW),
            (23, 0, 0x5007b),
            (57, 0, 0x5007b),
        ] {
            let mut p = super::super::tests::process();
            let [shared, _] = p.linux.vfs.pipe(0).unwrap();
            let owner = false; // All three original OFDs are now complete shared resources.
            let fd = match kind {
                0 => shared,
                1 => 0,
                _ => p.linux.vfs.epoll_create(0).unwrap(),
            };
            let args = match number {
                24 => [fd as u64, 200, 0, 0, 0, 0],
                25 => [fd as u64, 1030, 160, 0, 0, 0],
                _ => [fd as u64, 0, 0, 0, 0, 0],
            };
            p.memory
                .write_array(0x4000, 0xd4000001u32.to_le_bytes())
                .unwrap();
            p.memory
                .write_array(0x4004, 0x14000000u32.to_le_bytes())
                .unwrap();
            p.memory
                .protect(
                    0x4000,
                    trames_memory::PAGE_SIZE,
                    trames_memory::Permissions::RX,
                )
                .unwrap();
            p.cpu = Cpu::new(0x4000, 0);
            p.cpu.set_x(8, number);
            put_args(&mut p.cpu, args);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                owner_syscalls: false,
                diagnostics: None,
                membarrier_registered: None,
                vfork_release: None,
                native_space: None,
                namespaces: None,
                exit_files: None,
                exit_context: None,
                children: Default::default(),
                limits: None,
                timers: None,

                saved_wait_mask: Default::default(),
                io_signals: Default::default(),
                io_routes: Default::default(),
                io_wake: None,
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                cpus: 4,
                profile: false,

                fd_flags: p.linux.vfs.fd_flags_snapshot(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: trames_linux::DirectSyscalls::default()
                    .with_membership(p.linux.vfs.shared_files())
                    .with_lock_context(p.linux.vfs.record_lock_context(1)),
                futex: Default::default(),
            };
            let work = crate::workers::Work {
                task: None,
                audio: None,
                pid: 1,
                cpu: std::mem::take(&mut p.cpu),
                memory: Some(Box::new(
                    p.memory.parallel_view(&mut Default::default()).unwrap(),
                )),
                control: Arc::new(crate::workers::Control::new(1000)),
                syscalls: Some(snapshot),
                gpu: None,
            };
            let mut pool = crate::workers::Pool::new(1);
            pool.ensure(0).unwrap();
            pool.dispatch(0, work).unwrap();
            let done = pool.complete().unwrap();
            assert_eq!(p.seccomp.evaluations(), 1, "one entry decision");
            p.memory.commit_parallel().unwrap();
            p.cpu = done.cpu;
            if owner && decision == ALLOW {
                assert!(matches!(done.outcome, Some(SliceOutcome::Syscall { .. })));
                assert!(p.linux.vfs.flags(fd).is_ok(), "no deferred FD effect");
                p.seccomp_entry = Some(done.seccomp_entry.expect("exact deferred entry"));
                super::super::tests::kernel().call(
                    1,
                    &mut p,
                    number as u32,
                    args,
                    &mut trames_linux::CapturedOutput::default(),
                );
                assert_eq!(p.seccomp.evaluations(), 1, "owner must consume decision");
                assert!(p.seccomp_entry.is_none());
            } else {
                assert!(matches!(done.outcome, Some(SliceOutcome::Yield { .. })));
                assert!(done.seccomp_entry.is_none());
                assert_eq!(done.syscalls, 1);
                assert_eq!(done.fd_syscalls, u64::from(decision == ALLOW));
            }
            if decision != ALLOW {
                assert_eq!(p.cpu.x(0), error(Errno(123)));
                assert!(p.linux.vfs.flags(fd).is_ok());
            } else if number == 57 {
                assert_eq!(p.linux.vfs.flags(fd), Err(Errno(9)));
            } else {
                assert!(p.linux.vfs.flags(p.cpu.x(0) as u32).is_ok());
            }
        }
    }
    #[test]
    fn filtered_epoll_and_inotify_controls_keep_one_decision_and_original_fallbacks() {
        for (number, nested, decision) in [
            (21, false, ALLOW),
            (21, true, ALLOW),
            (21, false, 0x5007b),
            (27, false, ALLOW),
            (27, false, 0x5007b),
        ] {
            let mut p = super::super::tests::process();
            let event = p.linux.vfs.eventfd(0, 0).unwrap();
            let ep = p.linux.vfs.epoll_create(0).unwrap();
            let child = p.linux.vfs.epoll_create(0).unwrap();
            p.linux.vfs.epoll_ctl(child, 1, event, 1, 100).unwrap();
            let watched = if nested { child } else { event };
            p.linux.vfs.epoll_ctl(ep, 1, watched, 1, 7).unwrap();
            p.linux.vfs.import_file(b"/file", b"data".to_vec()).unwrap();
            let notify = p.linux.vfs.inotify_init(trames_vfs::O_NONBLOCK).unwrap();
            p.memory.write(0x1234, b"/file\0").unwrap();
            p.memory.write_array(0x1800, 1u32.to_le_bytes()).unwrap();
            p.memory.write_array(0x1808, 42u64.to_le_bytes()).unwrap();
            let fd = if number == 21 { ep } else { notify };
            let words = [0xd2800000u32 | (fd << 5), 0xd4000001, 0x17fffffe];
            for (index, word) in words.into_iter().enumerate() {
                p.memory
                    .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
            p.memory
                .protect(
                    0x4000,
                    trames_memory::PAGE_SIZE,
                    trames_memory::Permissions::RX,
                )
                .unwrap();
            p.cpu = Cpu::new(0x4000, 0);
            p.cpu.set_x(8, number);
            if number == 21 {
                p.cpu.set_x(1, 3);
                p.cpu.set_x(2, watched as u64);
                p.cpu.set_x(3, 0x1800);
            } else {
                p.cpu.set_x(1, 0x1234);
                p.cpu.set_x(2, 2);
            }
            p.signals.io.scheduling.set_affinity(3);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
            ));
            let peer = p.fork();
            peer.family.set_parent(1);
            let mut kernel = super::super::tests::kernel();
            kernel.cpu_count = 2;
            kernel.workers = crate::workers::Pool::new(2);
            kernel.per_cpu = vec![Duration::ZERO; 2];
            kernel.processes.insert(1, p);
            kernel.processes.insert(2, peer);
            assert!(kernel
                .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                .unwrap());
            assert_eq!(
                kernel.processes.read(&1).seccomp.evaluations(),
                kernel.syscalls
            );
            assert_eq!(kernel.service_requests, 0);
            let direct = decision == ALLOW && !nested;
            if number == 21 {
                assert_eq!(kernel.worker_fd_syscalls > 100, direct);
                let v = &mut kernel.processes.get_mut(&1).unwrap().linux.vfs;
                v.write(event, &1u64.to_le_bytes()).unwrap();
                assert_eq!(
                    v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(),
                    vec![(1, if decision == ALLOW { 42 } else { 7 })]
                );
            } else {
                assert_eq!(kernel.worker_file_syscalls > 100, direct);
                let v = &mut kernel.processes.get_mut(&1).unwrap().linux.vfs;
                let file = v.open_at(-100, b"/file", 2, 0).unwrap();
                v.write(file, b"x").unwrap();
                if direct {
                    assert!(!v.read(notify, 4096).unwrap().is_empty());
                } else {
                    assert_eq!(v.read(notify, 4096), Err(Errno(11)));
                }
            }
        }
    }
    #[test]
    fn credential_entries_apply_one_policy_decision_before_identity_effects() {
        use super::super::tests::{kernel, process};
        for allowed in [false, true] {
            for (number, args) in [
                (143, [1000, 1000, 0]),
                (144, [1000, 0, 0]),
                (145, [1000, 1000, 0]),
                (146, [1000, 0, 0]),
                (147, [1000, 1000, 1000]),
                (149, [1000, 1000, 1000]),
                (151, [1000, 0, 0]),
                (152, [1000, 0, 0]),
                (159, [0, 0, 0]),
                (167, [38, 1, 0]),
            ] {
                let mut p = process();
                let mut original = p.linux.vfs.credentials.clone();
                original.caps.no_new_privs = original.caps.no_new_privs.fork();
                p.memory
                    .write_array(0x4000, 0xd4000001u32.to_le_bytes())
                    .unwrap();
                p.memory
                    .write_array(0x4004, 0x14000000u32.to_le_bytes())
                    .unwrap();
                p.memory
                    .write_array(0x4500, 0x14000000u32.to_le_bytes())
                    .unwrap();
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.cpu.set_x(8, number);
                for (i, arg) in args.iter().enumerate() {
                    p.cpu.set_x(i, *arg);
                }
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })])
                        .unwrap(),
                ));
                let memory = p.memory.share();
                let mut peer = p.fork_with_memory(memory);
                peer.tgid = 2;
                peer.cpu = Cpu::new(0x4500, 0x9000);
                let mut k = kernel();
                k.cpu_count = 2;
                k.workers = crate::workers::Pool::new(2);
                k.per_cpu = vec![Duration::ZERO; 2];
                k.processes.insert(1, p);
                k.processes.insert(2, peer);
                assert!(k
                    .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                    .unwrap());
                let p = &k.processes.read(&1);
                let peer = &k.processes.read(&2);
                let expected = if !allowed {
                    error(Errno(123))
                } else if number == 268 {
                    error(Errno(9))
                } else {
                    0
                };
                assert_eq!(p.cpu.x(0), expected);
                assert_eq!(p.seccomp.evaluations(), 1);
                assert_eq!(k.service_requests, 0);
                if allowed {
                    assert!(!k.cohort_return_syscalls.contains_key(&(number as u32)));
                    assert_eq!(*p.signals.io.credentials().read(), p.linux.vfs.credentials);
                } else {
                    assert_eq!(p.linux.vfs.credentials, original);
                    assert!(p.linux.vfs.dumpable() != 0);
                }
                assert_eq!(peer.linux.vfs.credentials, original);
            }
        }
    }
    #[test]
    fn task_namespace_entries_apply_one_policy_decision_before_resource_effects() {
        use super::super::tests::{kernel, process};
        for allowed in [false, true] {
            for (number, args) in [
                (97, [0x600, 0, 0]),
                (268, [900, 0, 0]),
                (436, [0, u32::MAX as u64, 2]),
                (436, [0, u32::MAX as u64, 0]),
                (436, [0, u32::MAX as u64, 4]),
            ] {
                let mut p = process();
                let fd = p.linux.vfs.eventfd(0, 0).unwrap();
                p.memory
                    .write_array(0x4000, 0xd4000001u32.to_le_bytes())
                    .unwrap();
                p.memory
                    .write_array(0x4004, 0x14000000u32.to_le_bytes())
                    .unwrap();
                p.memory
                    .write_array(0x4500, 0x14000000u32.to_le_bytes())
                    .unwrap();
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.cpu.set_x(8, number);
                for (i, arg) in args.iter().enumerate() {
                    p.cpu.set_x(i, *arg);
                }
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })])
                        .unwrap(),
                ));
                let memory = p.memory.share();
                let mut peer = p.fork_with_memory(memory);
                peer.tgid = 2;
                peer.cpu = Cpu::new(0x4500, 0x9000);
                let mut k = kernel();
                k.cpu_count = 2;
                k.workers = crate::workers::Pool::new(2);
                k.per_cpu = vec![Duration::ZERO; 2];
                k.processes.insert(1, p);
                k.processes.insert(2, peer);
                assert!(k
                    .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                    .unwrap());
                let p = &k.processes.read(&1);
                let peer = &k.processes.read(&2);
                let expected = if !allowed {
                    error(Errno(123))
                } else if number == 268 {
                    error(Errno(9))
                } else {
                    0
                };
                assert_eq!(p.cpu.x(0), expected);
                assert_eq!(p.seccomp.evaluations(), 1);
                assert_eq!(k.service_requests, 0);
                let detached = allowed && (number == 97 || number == 436 && args[2] & 2 != 0);
                assert_eq!(
                    p.linux.vfs.shares_descriptors_with(&peer.linux.vfs),
                    !detached
                );
                assert_eq!(
                    p.linux.vfs.shares_context_with(&peer.linux.vfs),
                    !(allowed && number == 97)
                );
                if allowed && number == 436 {
                    if args[2] == 4 {
                        assert_ne!(p.linux.vfs.flags(fd).unwrap() & trames_vfs::O_CLOEXEC, 0);
                        assert_ne!(peer.linux.vfs.flags(fd).unwrap() & trames_vfs::O_CLOEXEC, 0);
                    } else {
                        assert_eq!(p.linux.vfs.flags(fd), Err(Errno(9)));
                        assert_eq!(peer.linux.vfs.flags(fd).is_ok(), detached);
                    }
                } else {
                    assert!(p.linux.vfs.flags(fd).is_ok());
                }
            }
        }
    }
    #[test]
    fn task_namespace_switch_refreshes_all_source_consumers_without_owner_returns() {
        use super::super::tests::{kernel, process};
        for slots in [1, 2] {
            for filtered in [false, true] {
                let mut p = process();
                p.linux.vfs.mkdir_at(AT_FDCWD, b"/private", 0o755).unwrap();
                p.linux.vfs.set_runtime_info(
                    1,
                    trames_vfs::RuntimeInfo {
                        processes: vec![trames_vfs::ProcessInfo {
                            pid: 1,
                            tgid: 1,
                            namespaces: p.linux.vfs.namespace_snapshot(),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                );
                let uts = p
                    .linux
                    .vfs
                    .open_at(AT_FDCWD, b"/proc/self/ns/uts", 0, 0)
                    .unwrap();
                let old_fd = p.linux.vfs.eventfd(5, 0).unwrap();
                p.memory.write(0x1200, b"/private\0").unwrap();
                p.memory.write(0x1300, b"source").unwrap();
                let flags = 0x600
                    | trames_vfs::CLONE_NEWUTS
                    | trames_vfs::CLONE_NEWNET
                    | trames_vfs::CLONE_NEWIPC
                    | trames_vfs::CLONE_NEWCGROUP
                    | trames_vfs::CLONE_NEWNS;
                let calls = [
                    (97, [flags, 0, 0]),
                    (49, [0x1200, 0, 0]),
                    (166, [0o077, 0, 0]),
                    (57, [old_fd as u64, 0, 0]),
                    (19, [11, 0, 0]),
                    (161, [0x1300, 6, 0]),
                    (160, [0x2000, 0, 0]),
                    (268, [uts as u64, trames_vfs::CLONE_NEWUTS, 0]),
                    (160, [0x2400, 0, 0]),
                ];
                let mov = |r: u32, value: u64| {
                    [
                        0xd2800000 | ((value as u32 & 0xffff) << 5) | r,
                        0xf2a00000 | (((value as u32 >> 16) & 0xffff) << 5) | r,
                    ]
                };
                let mut code = mov(20, 0x1000).to_vec();
                for (index, (number, args)) in calls.iter().enumerate() {
                    for (r, arg) in args.iter().enumerate() {
                        code.extend(mov(r as u32, *arg));
                    }
                    code.extend(mov(8, *number));
                    code.extend([0xd4000001, 0xf9000000 | ((index as u32) << 10) | (20 << 5)]);
                }
                code.extend(mov(28, 1));
                code.push(0x14000000);
                for (i, word) in code.iter().enumerate() {
                    p.memory
                        .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .write_array(0x4500, 0x14000000u32.to_le_bytes())
                    .unwrap();
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.signals.io.scheduling.set_affinity((1 << slots) - 1);
                if filtered {
                    p.seccomp
                        .push(Arc::new(Filter::validate(vec![i(6, 0, 0, ALLOW)]).unwrap()));
                }
                let shared_memory = p.memory.share();
                let mut peer = p.fork_with_memory(shared_memory);
                peer.tgid = 2;
                peer.cpu = Cpu::new(0x4500, 0x9000);
                peer.family.set_parent(1);
                let mut k = kernel();
                k.cpu_count = 2;
                k.workers = crate::workers::Pool::new(2);
                k.per_cpu = vec![Duration::ZERO; 2];
                k.processes.insert(1, p);
                k.processes.insert(2, peer);
                for _ in 0..16 {
                    assert!(k
                        .parallel_epoch(
                            &mut trames_linux::CapturedOutput::default(),
                            k.instructions + 100_000,
                            true
                        )
                        .unwrap());
                    if k.processes.read(&1).cpu.x(28) == 1 {
                        break;
                    }
                }
                let p = &k.processes.read(&1);
                let peer = &k.processes.read(&2);
                assert_eq!(p.cpu.x(28), 1, "slots={slots} filtered={filtered}");
                for index in [0, 1, 3, 5, 6, 7, 8] {
                    assert_eq!(
                        p.memory.read_u64(0x1000 + index * 8).unwrap(),
                        0,
                        "call {index}"
                    );
                }
                assert_eq!(p.memory.read_u64(0x1010).unwrap(), 0o022);
                assert_eq!(p.memory.read_array::<6>(0x2041).unwrap(), *b"source");
                assert_eq!(p.memory.read_array::<6>(0x2441).unwrap(), *b"trames");
                assert_eq!(p.linux.vfs.cwd().unwrap(), b"/private");
                assert_eq!(peer.linux.vfs.cwd().unwrap(), b"/");
                assert_eq!(p.linux.vfs.umask(), 0o077);
                assert_eq!(peer.linux.vfs.umask(), 0o022);
                assert!(!p.linux.vfs.shares_descriptors_with(&peer.linux.vfs));
                let fresh = p.memory.read_u64(0x1020).unwrap() as u32;
                assert_eq!(
                    p.linux
                        .vfs
                        .shared_files()
                        .lookup(fresh)
                        .unwrap()
                        .unwrap()
                        .direct_byte()
                        .unwrap()
                        .read(8)
                        .unwrap(),
                    11u64.to_le_bytes()
                );
                assert_eq!(
                    peer.linux
                        .vfs
                        .shared_files()
                        .lookup(old_fd)
                        .unwrap()
                        .unwrap()
                        .direct_byte()
                        .unwrap()
                        .read(8)
                        .unwrap(),
                    5u64.to_le_bytes()
                );
                assert_eq!(k.syscalls, calls.len() as u64);
                assert_eq!(k.service_requests, 0);
                assert!(!k.cohort_return_syscalls.contains_key(&97));
                assert!(!k.cohort_return_syscalls.contains_key(&268));
                if filtered {
                    assert_eq!(p.seccomp.evaluations(), calls.len() as u64);
                }
            }
        }
    }
    #[test]
    fn namespace_mutations_stay_on_workers_with_one_filter_decision() {
        for slots in [1, 2] {
            for decision in [ALLOW, 0x5007b] {
                let mut p = super::super::tests::process();
                p.memory.write(0x1234, b"/worker-namespace\0").unwrap();
                let mov = |rd: u32, value: u32| 0xd2800000u32 | (value << 5) | rd;
                let mut code = Vec::new();
                for (number, flags) in [(34, 0o700), (35, 0x200)] {
                    code.extend([
                        0x92800c60,
                        mov(1, 0x1234),
                        mov(2, flags),
                        mov(8, number),
                        0xd4000001,
                    ]);
                }
                code.push(0x14000000 | ((-(code.len() as i32) as u32) & 0x03ffffff));
                for (index, word) in code.into_iter().enumerate() {
                    p.memory
                        .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.cpu = Cpu::new(0x4000, 0);
                p.signals.io.scheduling.set_affinity((1 << slots) - 1);
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
                ));
                let peer = p.fork();
                peer.family.set_parent(1);
                let mut kernel = super::super::tests::kernel();
                kernel.cpu_count = 2;
                kernel.workers = crate::workers::Pool::new(2);
                kernel.per_cpu = vec![Duration::ZERO; 2];
                kernel.processes.insert(1, p);
                kernel.processes.insert(2, peer);
                assert!(kernel
                    .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                    .unwrap());
                assert!(kernel.syscalls > 0);
                assert_eq!(
                    kernel.processes.read(&1).seccomp.evaluations(),
                    kernel.syscalls
                );
                assert_eq!(kernel.service_requests, 0);
                if decision == ALLOW {
                    assert!(
                        kernel.syscalls > 100,
                        "slots={slots} calls={}",
                        kernel.syscalls
                    );
                    assert_eq!(
                        kernel.worker_file_syscalls, kernel.syscalls,
                        "slots={slots}"
                    );
                } else {
                    assert_eq!(kernel.worker_file_syscalls, 0);
                    assert_eq!(
                        kernel
                            .processes
                            .read(&1)
                            .linux
                            .vfs
                            .stat_at(AT_FDCWD, b"/worker-namespace"),
                        Err(Errno(2))
                    );
                }
            }
        }
    }
    #[test]
    fn mount_transactions_stay_on_workers_with_one_filter_decision() {
        for slots in [1, 2] {
            for decision in [ALLOW, 0x5007b] {
                let mut p = super::super::tests::process();
                p.linux
                    .vfs
                    .mkdir_at(AT_FDCWD, b"/worker-mount", 0o755)
                    .unwrap();
                p.memory.write(0x1234, b"/worker-mount\0").unwrap();
                p.memory.write(0x1300, b"tmpfs\0").unwrap();
                let mov = |rd: u32, value: u32| 0xd2800000u32 | (value << 5) | rd;
                let mut code = vec![
                    mov(0, 0x1300),
                    mov(1, 0x1234),
                    mov(2, 0x1300),
                    mov(3, 0),
                    mov(4, 0),
                    mov(8, 40),
                    0xd4000001,
                    mov(0, 0x1234),
                    mov(1, 2),
                    mov(8, 39),
                    0xd4000001,
                ];
                code.push(0x14000000 | ((-(code.len() as i32) as u32) & 0x03ffffff));
                for (index, word) in code.into_iter().enumerate() {
                    p.memory
                        .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.cpu = Cpu::new(0x4000, 0);
                p.signals.io.scheduling.set_affinity((1 << slots) - 1);
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
                ));
                let mut peer = p.fork();
                peer.linux.vfs.unshare_mounts().unwrap();
                peer.family.set_parent(1);
                let mut kernel = super::super::tests::kernel();
                kernel.cpu_count = 2;
                kernel.workers = crate::workers::Pool::new(2);
                kernel.per_cpu = vec![Duration::ZERO; 2];
                kernel.processes.insert(1, p);
                kernel.processes.insert(2, peer);
                assert!(kernel
                    .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                    .unwrap());
                assert!(kernel.syscalls > 0);
                assert_eq!(
                    kernel.processes.read(&1).seccomp.evaluations(),
                    kernel.syscalls
                );
                assert_eq!(kernel.service_requests, 0);
                if decision == ALLOW {
                    assert!(
                        kernel.syscalls > 100,
                        "slots={slots} calls={}",
                        kernel.syscalls
                    );
                    assert_eq!(
                        kernel.worker_file_syscalls, kernel.syscalls,
                        "slots={slots}"
                    );
                } else {
                    assert_eq!(kernel.worker_file_syscalls, 0);
                    let vfs = &kernel.processes.read(&1).linux.vfs;
                    assert_eq!(
                        vfs.stat_at(AT_FDCWD, b"/worker-mount").unwrap()[..8],
                        vfs.stat_at(AT_FDCWD, b"/").unwrap()[..8]
                    );
                }
            }
        }
    }
    #[test]
    fn filtered_path_queries_complete_or_defer_with_one_entry_decision() {
        for (path, decision, direct) in [
            (b"/file\0".as_slice(), ALLOW, true),
            (b"/proc/self/status\0", ALLOW, false),
            (b"/file\0", 0x5007b, false),
        ] {
            let mut p = super::super::tests::process();
            p.linux
                .vfs
                .import_file(b"/file", b"bytes".to_vec())
                .unwrap();
            p.linux
                .vfs
                .set_runtime_info(1, trames_vfs::RuntimeInfo::default());
            p.memory.write(0x1234, path).unwrap();
            p.memory.write(0x1800, &[0x55; 128]).unwrap();
            for (index, word) in [0x92800c60u32, 0xd28009e8, 0xd4000001, 0x17fffffd]
                .into_iter()
                .enumerate()
            {
                p.memory
                    .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
            p.memory
                .protect(
                    0x4000,
                    trames_memory::PAGE_SIZE,
                    trames_memory::Permissions::RX,
                )
                .unwrap();
            p.cpu = Cpu::new(0x4000, 0);
            p.cpu.set_x(1, 0x1234);
            p.cpu.set_x(2, 0x1800);
            p.signals.io.scheduling.set_affinity(3);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
            ));
            let mut kernel = super::super::tests::kernel();
            kernel.cpu_count = 2;
            kernel.workers = crate::workers::Pool::new(2);
            kernel.per_cpu = vec![Duration::ZERO; 2];
            let peer = p.fork();
            peer.family.set_parent(1);
            kernel.processes.insert(1, p);
            kernel.processes.insert(2, peer);
            assert!(kernel
                .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                .unwrap());
            assert!(kernel.syscalls > 0);
            assert_eq!(
                kernel.processes.read(&1).seccomp.evaluations(),
                kernel.syscalls,
                "{path:?}"
            );
            if direct {
                assert!(
                    kernel.worker_file_syscalls > 100,
                    "worker={} files={} syscalls={}",
                    kernel.worker_syscalls,
                    kernel.worker_file_syscalls,
                    kernel.syscalls
                );
                assert_eq!(kernel.service_requests, 0);
            } else {
                assert_eq!(kernel.worker_file_syscalls, 0);
            }
            if decision != ALLOW {
                for p in kernel.processes.values() {
                    assert_eq!(p.memory.read_array::<128>(0x1800).unwrap(), [0x55; 128]);
                }
            }
        }
    }
    #[test]
    fn filtered_open_publication_and_close_preserve_single_entry_decisions() {
        for (path, decision, direct) in [
            (b"/worker-open\0".as_slice(), ALLOW, true),
            (b"/proc/self/status\0".as_slice(), ALLOW, false),
            (b"/worker-open\0".as_slice(), 0x5007b, false),
        ] {
            let mut p = super::super::tests::process();
            p.linux
                .vfs
                .set_runtime_info(1, trames_vfs::RuntimeInfo::default());
            p.memory.write(0x1234, path).unwrap();
            let code = [
                0x92800c60u32,
                0xd2824681,
                0xd2800842,
                0xd2803003,
                0xd2800708,
                0xd4000001,
                0xd2800728,
                0xd4000001,
                0x17fffff8,
            ];
            for (index, word) in code.into_iter().enumerate() {
                p.memory
                    .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
            p.memory
                .protect(
                    0x4000,
                    trames_memory::PAGE_SIZE,
                    trames_memory::Permissions::RX,
                )
                .unwrap();
            p.cpu = Cpu::new(0x4000, 0);
            p.signals.io.scheduling.set_affinity(3);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
            ));
            let peer = p.fork();
            peer.family.set_parent(1);
            let mut kernel = super::super::tests::kernel();
            kernel.cpu_count = 2;
            kernel.workers = crate::workers::Pool::new(2);
            kernel.per_cpu = vec![Duration::ZERO; 2];
            kernel.processes.insert(1, p);
            kernel.processes.insert(2, peer);
            assert!(kernel
                .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                .unwrap());
            assert!(kernel.syscalls > 0);
            assert_eq!(
                kernel.processes.read(&1).seccomp.evaluations(),
                kernel.syscalls
            );
            if direct {
                assert!(kernel.worker_file_syscalls > 100);
                assert_eq!(kernel.service_requests, 0);
                assert!(kernel
                    .processes
                    .read(&1)
                    .linux
                    .vfs
                    .stat_at(trames_vfs::AT_FDCWD, b"/worker-open")
                    .is_ok());
            } else {
                assert_eq!(kernel.worker_file_syscalls, 0);
            }
            if decision != ALLOW {
                assert!(kernel
                    .processes
                    .read(&1)
                    .linux
                    .vfs
                    .stat_at(trames_vfs::AT_FDCWD, b"/worker-open")
                    .is_err());
            }
        }
    }
    #[test]
    fn shared_resource_creation_and_close_complete_on_workers_with_one_seccomp_decision() {
        for number in [19u32, 26, 59, 85, 198, 280] {
            for decision in [None, Some(ALLOW), Some(0x5007b)] {
                let mut p = super::super::tests::process();
                p.memory.write(0x1800, &[0; 8]).unwrap();
                let mov = |rd: u32, value: u32| 0xd2800000u32 | (value << 5) | rd;
                if number == 198 {
                    p.linux
                        .vfs
                        .configure_network(trames_vfs::NetworkMode::Loopback)
                        .unwrap();
                }
                if number == 280 {
                    let mut attr = [0u8; 152];
                    attr[..4].copy_from_slice(&15u32.to_le_bytes());
                    attr[4..8].copy_from_slice(&2u32.to_le_bytes());
                    attr[8..16].copy_from_slice(&0x1a00u64.to_le_bytes());
                    attr[16..24].copy_from_slice(&0x1b00u64.to_le_bytes());
                    p.memory.write(0x1900, &attr).unwrap();
                    p.memory
                        .write(
                            0x1a00,
                            &[0xb7, 0, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0],
                        )
                        .unwrap();
                    p.memory.write(0x1b00, b"GPL\0").unwrap();
                }
                let initial = if number == 280 {
                    5
                } else if number == 198 {
                    2
                } else if number == 59 {
                    0x1800
                } else if number == 85 {
                    1
                } else {
                    0
                };
                let mut code = vec![
                    mov(0, initial),
                    mov(
                        1,
                        if number == 280 {
                            0x1900
                        } else {
                            u32::from(number == 198)
                        },
                    ),
                    mov(2, if number == 280 { 152 } else { 0 }),
                    mov(8, number),
                    0xd4000001,
                ];
                if number == 59 {
                    code.extend([
                        mov(9, 0x1800),
                        0xb9400120,
                        mov(8, 57),
                        0xd4000001,
                        0xb9400520,
                        mov(8, 57),
                        0xd4000001,
                    ]);
                } else {
                    code.extend([mov(8, 57), 0xd4000001]);
                }
                code.push(0x14000000 | ((-(code.len() as i32) as u32) & 0x03ffffff));
                for (i, word) in code.into_iter().enumerate() {
                    p.memory
                        .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                p.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                p.cpu = Cpu::new(0x4000, 0);
                p.signals.io.scheduling.set_affinity(3);
                if let Some(decision) = decision {
                    p.seccomp.push(Arc::new(
                        Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
                    ));
                }
                let peer = p.fork();
                peer.family.set_parent(1);
                let mut kernel = super::super::tests::kernel();
                kernel.cpu_count = 2;
                kernel.workers = crate::workers::Pool::new(2);
                kernel.per_cpu = vec![Duration::ZERO; 2];
                kernel.processes.insert(1, p);
                kernel.processes.insert(2, peer);
                assert!(kernel
                    .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
                    .unwrap());
                assert!(kernel.syscalls > 0);
                if decision.is_some() {
                    assert_eq!(
                        kernel.processes.read(&1).seccomp.evaluations(),
                        kernel.syscalls,
                        "syscall {number}"
                    );
                }
                if decision != Some(0x5007b) {
                    assert!(
                        kernel.worker_fd_syscalls > 100,
                        "syscall {number}: {}",
                        kernel.worker_fd_syscalls
                    );
                    assert_eq!(kernel.service_requests, 0);
                    assert!(kernel.parallel_rounds <= 4);
                } else {
                    assert_eq!(kernel.worker_fd_syscalls, 0);
                    for p in kernel.processes.values() {
                        assert_eq!(p.linux.vfs.fd_snapshot().len(), 3);
                    }
                }
            }
        }
    }
    #[test]
    fn allowed_filtered_dup_close_loops_do_not_checkpoint_peer_cpus() {
        let mut p = super::super::tests::process();
        let [fd, _] = p.linux.vfs.pipe(0).unwrap();
        let code = [
            0xd2800000u32 | (fd << 5), // mov x0, original FD
            0xd28002e8,                // mov x8, dup
            0xd4000001,
            0xd2800728, // mov x8, close
            0xd4000001,
            0x17fffffb, // loop
        ];
        for (index, word) in code.into_iter().enumerate() {
            p.memory
                .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.signals.io.scheduling.set_affinity(15);
        p.seccomp
            .push(Arc::new(Filter::validate(vec![i(6, 0, 0, ALLOW)]).unwrap()));
        let mut kernel = super::super::tests::kernel();
        kernel.cpu_count = 4;
        kernel.workers = crate::workers::Pool::new(4);
        kernel.per_cpu = vec![Duration::ZERO; 4];
        for id in 2..=4 {
            let peer = p.fork();
            peer.family.set_parent(1);
            kernel.processes.insert(id, peer);
        }
        kernel.processes.insert(1, p);
        for _ in 0..4 {
            assert!(kernel
                .parallel_round(&mut trames_linux::CapturedOutput::default(), 100_000)
                .unwrap());
            if kernel.worker_syscalls > 100 {
                break;
            }
        }
        assert!(kernel.worker_syscalls > 100);
        assert_eq!(
            kernel.syscalls, kernel.worker_syscalls,
            "shared FD calls must not join peers"
        );
        for p in kernel.processes.values() {
            assert!(p.linux.vfs.flags(fd).is_ok());
            assert!(
                p.linux.vfs.fd_snapshot().len() <= 6,
                "at most one in-flight duplicate per task"
            );
        }
    }
    #[test]
    fn private_shared_futex_wait_wake_and_requeue_require_an_allow_decision() {
        let table = crate::futex::Futexes::default();
        let wait = table
            .wait((0, 7, 0x1000), 3, 1, || Ok::<_, ()>(()))
            .unwrap();
        let mut snapshot = crate::worker_syscalls::Snapshot {
            owner_syscalls: false,
            diagnostics: None,
            membarrier_registered: None,
            vfork_release: None,
            native_space: None,
            namespaces: None,
            exit_files: None,
            exit_context: None,
            children: Default::default(),
            limits: None,
            timers: None,

            saved_wait_mask: Default::default(),
            io_signals: Default::default(),
            io_routes: Default::default(),
            io_wake: None,
            seccomp: Default::default(),
            identities: [0; 7],
            started: Instant::now(),
            processor: 0,
            cpus: 4,
            profile: false,

            fd_flags: Default::default(),
            umask: Default::default(),
            actions: Default::default(),
            program_break: Default::default(),
            uts: None,
            direct: Default::default(),
            futex: crate::futex::Authority::new(table, 7),
        };
        let mut cpu = Cpu::new(0x4004, 0);
        cpu.set_x(8, 98);
        for op in [0, 9, 1, 10, 3, 4, 128, 137, 129, 138, 131, 132] {
            put_args(&mut cpu, [0x1000, op, 1, 1, 0x1004, 1]);
            for decision in [ALLOW, 0x50007, 0x30009, 0, KILL_PROCESS] {
                snapshot.seccomp = Seccomp::default();
                snapshot.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
                ));
                assert_eq!(snapshot.admit(&cpu), decision == ALLOW);
                assert!(!wait.woken());
            }
            snapshot.seccomp.set_strict();
            assert!(!snapshot.admit(&cpu));
        }
    }

    #[test]
    fn allowed_filtered_identity_calls_continue_on_workers_without_peer_checkpoints() {
        for (number, decision) in [
            (172u32, ALLOW),
            (96, ALLOW),
            (96, 0x5007b),
            (167, ALLOW),
            (167, 0x5007b),
        ] {
            let mut p = super::super::tests::process();
            let code = if number == 167 {
                vec![
                    0xd2800020,
                    0xd2800461,
                    0xd2800008 | (number << 5),
                    0xd4000001,
                    0x17fffffc,
                ]
            } else {
                vec![0xd2800008u32 | (number << 5), 0xd4000001, 0x17ffffff]
            };
            for (index, word) in code.into_iter().enumerate() {
                p.memory
                    .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
            p.memory
                .protect(
                    0x4000,
                    trames_memory::PAGE_SIZE,
                    trames_memory::Permissions::RX,
                )
                .unwrap();
            p.cpu = Cpu::new(0x4000, 0);
            p.signals.io.scheduling.set_affinity(15);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
            ));
            let mut kernel = super::super::tests::kernel();
            kernel.cpu_count = 4;
            kernel.workers = crate::workers::Pool::new(4);
            kernel.per_cpu = vec![Duration::ZERO; 4];
            for id in 2..=4 {
                let peer = p.fork();
                peer.family.set_parent(1);
                kernel.processes.insert(id, peer);
            }
            kernel.processes.insert(1, p);
            // Host scheduling and instrumentation can end a round after just one
            // syscall per task. Assert guest progress, not a host-time throughput.
            for _ in 0..128 {
                assert!(kernel
                    .parallel_round(&mut trames_linux::CapturedOutput::default(), 100_000)
                    .unwrap());
                assert_eq!(
                    kernel.syscalls, kernel.worker_syscalls,
                    "identity queries must not checkpoint"
                );
                if kernel.worker_syscalls > 100 {
                    break;
                }
            }
            assert!(
            kernel.worker_syscalls > 100,
            "allowed calls must stay on their workers: worker={} owner={} instructions={} tasks={:?}",
            kernel.worker_syscalls, kernel.syscalls, kernel.instructions,
            kernel.processes.iter().map(|(id,p)| (id,p.cpu.pc,p.cpu.x(8),p.cpu.x(0))).collect::<Vec<_>>()
        );
            assert_eq!(
                kernel.syscalls, kernel.worker_syscalls,
                "identity queries must not checkpoint"
            );
            if number == 167 {
                assert!(kernel
                    .processes
                    .values()
                    .all(|p| p.parentage.death_signal() == if decision == ALLOW { 35 } else { 0 }));
            }
            if number == 96 {
                assert_eq!(
                    kernel
                        .processes
                        .values()
                        .any(|p| p.linux.clear_tid_address() != 0),
                    decision == ALLOW
                );
            }
        }
    }
    #[test]
    fn worker_filter_snapshots_keep_pc_arguments_and_immutable_installation_order() {
        let mut current = Seccomp::default();
        current.push(Arc::new(
            Filter::validate(vec![
                i(0x20, 0, 0, 8), // post-SVC PC low word
                i(0x15, 0, 4, 0x4004),
                i(0x20, 0, 0, 60), // sixth argument high word
                i(0x15, 0, 2, 7),
                i(0x06, 0, 0, ALLOW | 19),
                i(0x06, 0, 0, KILL_PROCESS),
                i(0x06, 0, 0, 0x30007),
            ])
            .unwrap(),
        ));
        let args = [1, 2, 3, 4, 5, 7 << 32];
        let mut worker = current.clone();
        worker.capture_entry();
        let forked = current.fork();
        current.push(Arc::new(
            Filter::validate(vec![i(6, 0, 0, 0x50009)]).unwrap(),
        ));
        // Installation cannot alter an already captured entry. The same worker
        // observes publication at its next entry without joining an epoch.
        std::thread::spawn(move || {
            assert!(worker.allows(113, 0x4004, args));
            assert!(!worker.allows(113, 0x4008, args));
            assert!(!worker.allows(113, 0x4004, [0; 6]));
            worker.capture_entry();
            assert!(!worker.allows(113, 0x4004, args));
            assert!(
                forked.allows(113, 0x4004, args),
                "fork has its own policy slot"
            );
        })
        .join()
        .unwrap();
        assert!(!current.allows(113, 0x4004, args));
        let mut strict = Seccomp::default();
        strict.set_strict();
        assert!(strict.allows(63, 0, [0; 6]));
        assert!(!strict.allows(113, 0, [0; 6]));
    }
    #[test]
    fn strict_allowed_reads_use_worker_local_shared_resources() {
        let mut p = super::super::tests::process();
        let [read, write] = p.linux.vfs.pipe(O_NONBLOCK).unwrap();
        p.linux.vfs.write(write, b"abcdefgh").unwrap();
        p.memory
            .write_array(0x4000, 0xd4000001u32.to_le_bytes())
            .unwrap();
        p.memory
            .write_array(0x4004, 0x14000000u32.to_le_bytes())
            .unwrap();
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.cpu.set_x(8, 63);
        put_args(&mut p.cpu, [read as u64, 0x1000, 4, 0, 0, 0]);
        p.signals.io.scheduling.set_affinity(3);
        p.seccomp.set_strict();
        let peer = p.fork();
        peer.family.set_parent(1);
        let mut kernel = super::super::tests::kernel();
        kernel.cpu_count = 2;
        kernel.workers = crate::workers::Pool::new(2);
        kernel.per_cpu = vec![Duration::ZERO; 2];
        kernel.processes.insert(1, p);
        kernel.processes.insert(2, peer);
        assert!(kernel
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 100_000)
            .unwrap());
        // A peer may reach the shared budget before the other is scheduled;
        // an epoch ending is not a filter rejection. At least one actual read
        // must complete on its worker, without an RPC or checkpoint.
        assert!(kernel.worker_direct_syscalls > 0);
        assert_eq!(kernel.serviced_syscalls, 0);
        assert_eq!(kernel.service_requests, 0);
        let mut received: Vec<_> = kernel
            .processes
            .values()
            .filter(|p| p.cpu.x(0) == 4)
            .map(|p| p.memory.read_array::<4>(0x1000).unwrap())
            .collect();
        received.sort();
        assert_eq!(received, [*b"abcd", *b"efgh"][..received.len()]);
    }
    #[test]
    fn denied_filtered_reads_do_not_issue_services_or_consume_pipe_bytes() {
        let mut p = super::super::tests::process();
        let [read, write] = p.linux.vfs.pipe(O_NONBLOCK).unwrap();
        p.linux.vfs.write(write, b"unchanged").unwrap();
        p.memory.write_array(0x1000, [0x5a; 8]).unwrap();
        p.memory
            .write_array(0x4000, 0xd4000001u32.to_le_bytes())
            .unwrap();
        p.memory
            .write_array(0x4004, 0x17ffffffu32.to_le_bytes())
            .unwrap();
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.cpu.set_x(8, 63);
        put_args(&mut p.cpu, [read as u64, 0x1000, 8, 0, 0, 0]);
        p.signals.io.scheduling.set_affinity(3);
        p.seccomp.push(Arc::new(
            Filter::validate(vec![i(6, 0, 0, 0x5007b)]).unwrap(),
        ));
        let peer = p.fork();
        peer.family.set_parent(1);
        let mut kernel = super::super::tests::kernel();
        kernel.cpu_count = 2;
        kernel.workers = crate::workers::Pool::new(2);
        kernel.per_cpu = vec![Duration::ZERO; 2];
        kernel.processes.insert(1, p);
        kernel.processes.insert(2, peer);
        assert!(kernel
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 100_000)
            .unwrap());
        assert_eq!(kernel.service_requests, 0);
        assert!(kernel.syscalls > 0);
        for p in kernel.processes.values() {
            assert_eq!(p.memory.read_array::<8>(0x1000), Ok([0x5a; 8]));
            if p.cpu.pc == 0x4004 {
                assert_eq!(p.cpu.x(0), error(Errno(123)));
            }
        }
        assert_eq!(
            kernel
                .processes
                .get_mut(&1)
                .unwrap()
                .linux
                .vfs
                .read(read, 9)
                .unwrap(),
            b"unchanged"
        );
    }

    #[test]
    fn worker_fd_status_controls_obey_seccomp_before_atomic_effects() {
        for allowed in [false, true] {
            for (number, command, argument, bit) in [
                (25, 4, O_NONBLOCK as u64, O_NONBLOCK),
                (29, 0x5421, 0x1000, O_NONBLOCK),
                (25, 2, 1, trames_vfs::O_CLOEXEC),
            ] {
                let mut p = super::super::tests::process();
                let [fd, _] = p.linux.vfs.pipe(0).unwrap();
                p.memory.write_array(0x1000, 1u32.to_le_bytes()).unwrap();
                p.cpu.set_x(8, number);
                put_args(&mut p.cpu, [fd as u64, command, argument, 0, 0, 0]);
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })])
                        .unwrap(),
                ));
                let snapshot = crate::worker_syscalls::Snapshot {
                    owner_syscalls: false,
                    diagnostics: None,
                    membarrier_registered: None,
                    vfork_release: None,
                    native_space: None,
                    namespaces: None,
                    exit_files: None,
                    exit_context: None,
                    children: Default::default(),
                    limits: None,
                    timers: None,

                    saved_wait_mask: Default::default(),
                    io_signals: Default::default(),
                    io_routes: Default::default(),
                    io_wake: None,
                    seccomp: p.seccomp.clone(),
                    identities: [0; 7],
                    started: Instant::now(),
                    processor: 0,
                    cpus: 4,
                    profile: false,

                    fd_flags: p.linux.vfs.fd_flags_snapshot(),
                    umask: p.linux.vfs.umask_capability(),
                    actions: p.signals.actions.shared(),
                    program_break: p.linux.program_break(),
                    uts: None,
                    direct: Default::default(),
                    futex: Default::default(),
                };
                assert_eq!(snapshot.admit(&p.cpu), allowed);
                if allowed {
                    assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0));
                }
                assert_eq!(p.linux.vfs.flags(fd).unwrap() & bit != 0, allowed);
            }
        }
    }
    #[test]
    fn worker_flock_checks_seccomp_and_defers_blocking_conversion_before_effects() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            let fd = p.linux.vfs.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
            let other = p.linux.vfs.open_at(-100, b"/lock", 2, 0).unwrap();
            p.cpu.set_x(8, 32);
            put_args(&mut p.cpu, [fd as u64, 6, 0, 0, 0, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let mut epoch = trames_vfs::FileEpoch::default();
            let snapshot = crate::worker_syscalls::Snapshot {
                owner_syscalls: false,
                diagnostics: None,
                membarrier_registered: None,
                vfork_release: None,
                native_space: None,
                namespaces: None,
                exit_files: None,
                exit_context: None,
                children: Default::default(),
                limits: None,
                timers: None,

                saved_wait_mask: Default::default(),
                io_signals: Default::default(),
                io_routes: Default::default(),
                io_wake: None,
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                cpus: 4,
                profile: false,

                fd_flags: Default::default(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
                    .with_files(epoch.capture(&p.linux.vfs, true)),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0));
            }
            assert_eq!(
                p.linux.vfs.flock(other, 6),
                if allowed { Err(Errno(11)) } else { Ok(()) }
            );
            p.linux.vfs.flock(other, 8).unwrap();
            p.linux.vfs.flock(fd, 5).unwrap();
            p.linux.vfs.flock(other, 5).unwrap();
            p.cpu.set_x(1, 2); // A blocking conversion must not drop the SH lock.
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), None);
            assert_eq!(p.linux.vfs.flock(other, 6), Err(Errno(11)));
            epoch.finish();
        }
    }

    #[test]
    fn worker_brk_queries_obey_seccomp_and_mapping_changes_defer() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            p.cpu.set_x(8, 214);
            put_args(&mut p.cpu, [0; 6]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                owner_syscalls: false,
                diagnostics: None,
                membarrier_registered: None,
                vfork_release: None,
                native_space: None,
                namespaces: None,
                exit_files: None,
                exit_context: None,
                children: Default::default(),
                limits: None,
                timers: None,

                saved_wait_mask: Default::default(),
                io_signals: Default::default(),
                io_routes: Default::default(),
                io_wake: None,
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                cpus: 4,
                profile: false,

                fd_flags: Default::default(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: Default::default(),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0xa000));
            }
            let before = p.linux.heap_context();
            p.cpu.set_x(0, 0xb000);
            assert!(!snapshot.admit(&p.cpu));
            assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), None);
            assert_eq!(p.linux.heap_context(), before);
        }
    }

    #[test]
    fn worker_sigaction_queries_and_mutations_use_one_exact_entry_decision() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            p.signals.actions.set_handler(10, 0x5000);
            p.cpu.set_x(8, 134);
            put_args(&mut p.cpu, [10, 0, 0x1000, 8, 0, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                owner_syscalls: false,
                diagnostics: None,
                membarrier_registered: None,
                vfork_release: None,
                native_space: None,
                namespaces: None,
                exit_files: None,
                exit_context: None,
                children: Default::default(),
                limits: None,
                timers: None,

                saved_wait_mask: Default::default(),
                io_signals: Default::default(),
                io_routes: Default::default(),
                io_wake: None,
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                cpus: 4,
                profile: false,

                fd_flags: Default::default(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: Default::default(),
                futex: Default::default(),
            };
            assert!(!snapshot.admit(&p.cpu));
            assert_eq!(snapshot.task_entry(&p.cpu).unwrap().allowed(), allowed);
            if allowed {
                assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0));
            }
            assert_eq!(
                p.memory.read_u64(0x1000).unwrap(),
                if allowed { 0x5000 } else { 0 }
            );
            p.cpu.set_x(1, 0x1100);
            assert!(!snapshot.admit(&p.cpu));
            assert_eq!(snapshot.task_entry(&p.cpu).unwrap().allowed(), allowed);
            if allowed {
                assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0));
            }
            assert_eq!(
                p.signals.actions.get(10).handler,
                if allowed { 0 } else { 0x5000 }
            );
            assert_eq!(p.seccomp.evaluations(), 2);
        }
    }
    #[test]
    fn worker_uts_filters_mutation_and_reads_live_namespace() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            p.memory.write_array(0x1000, *b"worker").unwrap();
            p.cpu.set_x(8, 161);
            put_args(&mut p.cpu, [0x1000, 6, 0, 0, 0, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                owner_syscalls: false,
                diagnostics: None,
                membarrier_registered: None,
                vfork_release: None,
                native_space: None,
                namespaces: None,
                exit_files: None,
                exit_context: None,
                children: Default::default(),
                limits: None,
                timers: None,

                saved_wait_mask: Default::default(),
                io_signals: Default::default(),
                io_routes: Default::default(),
                io_wake: None,
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                cpus: 4,
                profile: false,

                fd_flags: Default::default(),
                umask: Default::default(),
                actions: Default::default(),
                program_break: Default::default(),
                uts: Some(p.linux.vfs.uts_capability()),
                direct: Default::default(),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                let mut view = p.memory.parallel_view(&mut Default::default()).unwrap();
                assert_eq!(snapshot.invoke(&p.cpu, &mut view), Some(0));
                assert_eq!(p.linux.vfs.uts_name(false), b"worker");
                p.linux.vfs.set_uts_name(false, b"visible").unwrap();
                p.cpu.set_x(8, 160);
                put_args(&mut p.cpu, [0x1000, 0, 0, 0, 0, 0]);
                assert!(snapshot.admit(&p.cpu));
                assert_eq!(snapshot.invoke(&p.cpu, &mut view), Some(0));
                assert_eq!(
                    trames_memory::CpuMemory::read_array::<8>(&view, 0x1000 + 65).unwrap(),
                    *b"visible\0"
                );
            } else {
                assert_eq!(p.linux.vfs.uts_name(false), b"trames");
            }
        }
    }
    #[test]
    fn worker_syslog_checks_filter_authority_and_output_before_clear() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            p.linux.vfs.log(4, "worker syslog retained");
            p.memory
                .map(0x20000, 4096, trames_memory::Permissions::RW)
                .unwrap();
            p.cpu.set_x(8, 116);
            put_args(&mut p.cpu, [4, 0x20000, 4096, 0, 0, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                owner_syscalls: false,
                diagnostics: None,
                membarrier_registered: None,
                vfork_release: None,
                native_space: None,
                namespaces: None,
                exit_files: None,
                exit_context: None,
                children: Default::default(),
                limits: None,
                timers: None,

                saved_wait_mask: Default::default(),
                io_signals: Default::default(),
                io_routes: Default::default(),
                io_wake: None,
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                cpus: 4,
                profile: false,

                fd_flags: Default::default(),
                umask: Default::default(),
                actions: Default::default(),
                program_break: Default::default(),
                uts: None,
                direct: trames_linux::DirectSyscalls::default()
                    .with_kernel_log(p.linux.vfs.kernel_log_capability()),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                let mut view = p.memory.parallel_view(&mut Default::default()).unwrap();
                put_args(&mut p.cpu, [2, 0x20000, 4096, 0, 0, 0]);
                assert!(snapshot.admit(&p.cpu));
                put_args(&mut p.cpu, [4, 0x20fff, 2, 0, 0, 0]);
                assert_eq!(snapshot.invoke(&p.cpu, &mut view), Some(error(Errno(14))));
                assert!(!p.linux.vfs.syslog(3, 4096).unwrap().is_empty());
                put_args(&mut p.cpu, [4, 0x20000, 4096, 0, 0, 0]);
                let length = snapshot.invoke(&p.cpu, &mut view).unwrap();
                assert!(length > 0 && length < 4096);
                let mut bytes = vec![0; length as usize];
                trames_memory::CpuMemory::read(&view, 0x20000, &mut bytes).unwrap();
                assert!(String::from_utf8(bytes)
                    .unwrap()
                    .contains("worker syslog retained"));
                assert!(p.linux.vfs.syslog(3, 4096).unwrap().is_empty());
            } else {
                assert!(!p.linux.vfs.syslog(3, 4096).unwrap().is_empty());
            }
        }
    }
    #[test]
    fn worker_umask_checks_seccomp_and_shares_only_its_fs_domain() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            let shared = p.linux.vfs.clone_with_resources(false, true);
            let fork = p.linux.vfs.clone();
            p.cpu.set_x(8, 166);
            put_args(&mut p.cpu, [0o1077, 0, 0, 0, 0, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                owner_syscalls: false,
                diagnostics: None,
                membarrier_registered: None,
                vfork_release: None,
                native_space: None,
                namespaces: None,
                exit_files: None,
                exit_context: None,
                children: Default::default(),
                limits: None,
                timers: None,

                saved_wait_mask: Default::default(),
                io_signals: Default::default(),
                io_routes: Default::default(),
                io_wake: None,
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                cpus: 4,
                profile: false,

                fd_flags: Default::default(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: Default::default(),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0o022));
            }
            assert_eq!(shared.umask(), if allowed { 0o077 } else { 0o022 });
            assert_eq!(fork.umask(), 0o022);
        }
    }
    #[test]
    fn worker_record_locks_obey_seccomp_before_query_or_commit() {
        for allowed in [false, true] {
            for command in [5, 6] {
                let mut p = super::super::tests::process();
                let fd = p
                    .linux
                    .vfs
                    .open_at(trames_vfs::AT_FDCWD, b"/lock", 0x42, 0o600)
                    .unwrap();
                let mut bytes = [0; 32];
                bytes[..2].copy_from_slice(&1u16.to_le_bytes());
                bytes[16..24].copy_from_slice(&1u64.to_le_bytes());
                p.memory.write_array(0x1000, bytes).unwrap();
                p.cpu.set_x(8, 25);
                put_args(&mut p.cpu, [fd as u64, command, 0x1000, 0, 0, 0]);
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })])
                        .unwrap(),
                ));
                let mut epoch = trames_vfs::FileEpoch::default();
                let snapshot = crate::worker_syscalls::Snapshot {
                    owner_syscalls: false,
                    diagnostics: None,
                    membarrier_registered: None,
                    vfork_release: None,
                    native_space: None,
                    namespaces: None,
                    exit_files: None,
                    exit_context: None,
                    children: Default::default(),
                    limits: None,
                    timers: None,

                    saved_wait_mask: Default::default(),
                    io_signals: Default::default(),
                    io_routes: Default::default(),
                    io_wake: None,
                    seccomp: p.seccomp.clone(),
                    identities: [0; 7],
                    started: Instant::now(),
                    processor: 0,
                    cpus: 4,
                    profile: false,

                    fd_flags: p.linux.vfs.fd_flags_snapshot(),
                    umask: p.linux.vfs.umask_capability(),
                    actions: p.signals.actions.shared(),
                    program_break: p.linux.program_break(),
                    uts: None,
                    direct: trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
                        .with_files(epoch.capture(&p.linux.vfs, true))
                        .with_lock_context(p.linux.vfs.record_lock_context(p.tgid)),
                    futex: Default::default(),
                };
                assert_eq!(snapshot.admit(&p.cpu), allowed);
                if allowed {
                    assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0));
                }
                if command == 6 {
                    let mut other = p.linux.vfs.normalize_lock(fd, 1, 0, 0, 1).unwrap();
                    other.owner = 99;
                    assert_eq!(
                        p.linux
                            .vfs
                            .record_lock_conflict(fd, other)
                            .unwrap()
                            .is_some(),
                        allowed
                    );
                } else {
                    assert_eq!(
                        p.memory.read_array::<2>(0x1000).unwrap(),
                        (if allowed { 2u16 } else { 1u16 }).to_le_bytes()
                    );
                }
                epoch.finish();
            }
        }
    }
    #[test]
    fn filtered_identity_denials_complete_on_workers_without_owner_returns() {
        let mut p = super::super::tests::process();
        for (index, word) in [0xd2801588u32, 0xd4000001, 0x17ffffff]
            .into_iter()
            .enumerate()
        {
            p.memory
                .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.signals.io.scheduling.set_affinity(3);
        p.seccomp.push(Arc::new(
            Filter::validate(vec![i(6, 0, 0, 0x5007b)]).unwrap(),
        ));
        let peer = p.fork();
        peer.family.set_parent(1);
        let mut kernel = super::super::tests::kernel();
        kernel.cpu_count = 2;
        kernel.workers = crate::workers::Pool::new(2);
        kernel.per_cpu = vec![Duration::ZERO; 2];
        kernel.processes.insert(1, p);
        kernel.processes.insert(2, peer);
        assert!(kernel
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 100_000)
            .unwrap());
        assert_eq!(kernel.worker_syscalls, kernel.syscalls);
        assert_eq!(kernel.service_requests, 0);
        assert!(kernel.cohort_return_syscalls.is_empty());
        assert!(kernel.syscalls > 0);
        for p in kernel.processes.values().filter(|p| p.cpu.pc == 0x4008) {
            assert_eq!(p.cpu.x(0), error(Errno(123)));
        }
    }
    #[test]
    fn seccomp_trap_preserves_aarch64_arguments_in_the_signal_context() {
        for number in [56, 78] {
            let mut p = super::super::tests::process();
            let mut kernel = super::super::tests::kernel();
            let args = [
                AT_FDCWD as i64 as u64,
                0x1234,
                0xa0000,
                0x5678,
                0x9abc,
                0xdef0,
            ];
            put_args(&mut p.cpu, args);
            p.cpu.set_x(8, number as u64);
            p.cpu.pc = 0x4004;
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, 0x30055)]).unwrap(),
            ));
            p.signals.actions.set(
                31,
                Action {
                    handler: 0x5000,
                    flags: 4,
                    ..Action::default()
                },
            );
            assert!(kernel.filter_syscall(1, &mut p, number, args));
            assert_eq!(p.cpu.pc, 0x5000);
            let sp = p.cpu.sp;
            assert_eq!(p.cpu.x(0), 31);
            for (index, arg) in args.into_iter().enumerate() {
                assert_eq!(p.memory.read_u64(sp + 312 + index as u64 * 8).unwrap(), arg);
            }
            assert_eq!(p.memory.read_u64(sp + 312 + 8 * 8).unwrap(), number as u64);
            assert_eq!(
                u32::from_le_bytes(p.memory.read_array(sp + 24).unwrap()),
                number
            );
            assert_eq!(
                u32::from_le_bytes(p.memory.read_array(sp + 28).unwrap()),
                ARCH
            );
            assert_eq!(
                u32::from_le_bytes(p.memory.read_array(sp + 4).unwrap()),
                0x55
            );
            // The broker can set its result in x0 and resume after SVC.
            write_u64(&mut p.memory, sp + 312, error(Errno(13))).unwrap();
            Kernel::sigreturn(&mut p).unwrap();
            assert_eq!(p.cpu.x(0), error(Errno(13)));
            assert_eq!(p.cpu.x(1), args[1]);
            assert_eq!(p.cpu.x(8), number as u64);
            assert_eq!(p.cpu.pc, 0x4004);
        }
    }
    #[test]
    fn ignored_or_blocked_sigsys_cannot_suppress_a_forced_seccomp_trap() {
        for (handler, mask) in [(1, 0), (0x5000, 1u64 << 30)] {
            let mut p = super::super::tests::process();
            let mut kernel = super::super::tests::kernel();
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, 0x30055)]).unwrap(),
            ));
            p.signals.actions.set_handler(31, handler);
            p.signals.mask = mask;
            assert!(kernel.filter_syscall(1, &mut p, 173, [0; 6]));
            assert!(matches!(p.state, State::Zombie(31)));
        }
    }
    fn i(code: u16, yes: u8, no: u8, value: u32) -> Instruction {
        Instruction {
            code,
            yes,
            no,
            value,
        }
    }
    #[test]
    fn filter_loads_arch_arguments_and_verifies_all_paths() {
        let f = Filter::validate(vec![
            i(0x20, 0, 0, 4),
            i(0x15, 1, 0, ARCH),
            i(0x06, 0, 0, KILL_PROCESS),
            i(0x20, 0, 0, 20),
            i(0x15, 0, 1, 7),
            i(0x06, 0, 0, 0x50001),
            i(0x06, 0, 0, ALLOW),
        ])
        .unwrap();
        let mut input = [0; 16];
        input[1] = ARCH;
        input[5] = 7;
        assert_eq!(f.run(&input), 0x50001);
        input[5] = 8;
        assert_eq!(f.run(&input), ALLOW);
        input[1] = 0;
        assert_eq!(f.run(&input), KILL_PROCESS);
        for bad in [
            vec![i(0x20, 0, 0, 64), i(6, 0, 0, ALLOW)],
            vec![i(0x05, 0, 0, u32::MAX), i(6, 0, 0, ALLOW)],
            vec![i(0x60, 0, 0, 0), i(6, 0, 0, ALLOW)],
            vec![i(0x34, 0, 0, 0), i(6, 0, 0, ALLOW)],
            vec![
                i(0x15, 0, 1, 1),
                i(2, 0, 0, 0),
                i(0x60, 0, 0, 0),
                i(6, 0, 0, ALLOW),
            ],
        ] {
            assert!(Filter::validate(bad).is_err());
        }
    }
    #[test]
    fn stacked_filters_keep_restrictions_and_newest_equal_action_data() {
        let a = Arc::new(Filter::validate(vec![i(6, 0, 0, 0x50001)]).unwrap());
        let b = Arc::new(Filter::validate(vec![i(6, 0, 0, 0x50002)]).unwrap());
        let mut ancestor = Seccomp::default();
        ancestor.push(a);
        let mut current = ancestor.fork();
        current.push(b);
        assert!(ancestor.ancestor_of(&current));
        assert!(!current.ancestor_of(&ancestor));
        assert_eq!(current.decision(172, 0, [0; 6]), 0x50002);
    }
}
