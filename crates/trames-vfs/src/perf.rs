// SPDX-License-Identifier: GPL-3.0-or-later
//! Software perf OFDs over the original task's execution clock. No host PMU,
//! process image, Files root, guest pointer or numeric target PID is retained.
use super::*;
use std::sync::atomic::AtomicU64;
mod accounting;
mod context;
mod inheritance;
pub(crate) mod metadata;
mod output;
mod quota;
mod ring;
mod sample;
mod settings;
pub(super) use accounting::{Accounts, Policy};
pub use context::{Domain, Execution, Scope};
pub use sample::Sample;
pub(super) use settings::{Setting, Settings};

#[derive(Clone, Copy, Default)]
struct Stamp {
    cpu: u64,
    enabled: u64,
}
impl Stamp {
    fn max(self, other: Self) -> Self {
        Self {
            cpu: self.cpu.max(other.cpu),
            enabled: self.enabled.max(other.enabled),
        }
    }
}
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct Clock(Arc<ClockData>);
struct ClockData {
    time: Arc<crate::proc_time::Time>,
    terminal: parking_lot::Mutex<Option<Stamp>>,
    enabled_time: Option<Arc<crate::proc_time::Time>>,
    groups: parking_lot::Mutex<Registry>,
    sampling: std::sync::atomic::AtomicBool,
    active: std::sync::atomic::AtomicBool,
    metadata: std::sync::atomic::AtomicBool,
    history: parking_lot::Mutex<BTreeMap<u64, metadata::Seen>>,
    cpu: std::sync::atomic::AtomicU32,
    filters: parking_lot::Mutex<BTreeMap<u32, Clock>>,
    wall: Option<std::time::Instant>,
    filter: Option<u32>,
    wake_domain: Option<Arc<std::sync::atomic::AtomicUsize>>,
}
#[derive(Default)]
struct Registry {
    revision: u64,
    groups: Vec<std::sync::Weak<parking_lot::Mutex<Group>>>,
    inherited: Vec<Arc<parking_lot::Mutex<Group>>>,
}
impl Clock {
    pub(super) fn new(time: &Arc<crate::proc_time::Time>) -> Self {
        Self(Arc::new(ClockData {
            time: time.clone(),
            terminal: Default::default(),
            enabled_time: None,
            groups: Default::default(),
            sampling: Default::default(),
            active: Default::default(),
            metadata: Default::default(),
            history: Default::default(),
            cpu: std::sync::atomic::AtomicU32::new(u32::MAX),
            filters: Default::default(),
            wall: None,
            filter: None,
            wake_domain: None,
        }))
    }
    fn read(&self) -> Stamp {
        self.read_at(std::time::Instant::now())
    }
    fn read_at(&self, at: std::time::Instant) -> Stamp {
        if let Some(terminal) = *self.0.terminal.lock() {
            return terminal;
        }
        let cpu = self.0.wall.map_or_else(
            || self.0.time.read_at(at),
            |origin| at.saturating_duration_since(origin),
        );
        Stamp {
            cpu: cpu.as_nanos().min((u64::MAX - 1) as u128) as u64,
            enabled: self
                .0
                .enabled_time
                .as_ref()
                .map_or(cpu, |time| time.read_at(at))
                .as_nanos()
                .min((u64::MAX - 1) as u128) as u64,
        }
    }
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(super) fn retire(&self) {
        let final_time = self.read();
        let fresh = {
            let mut terminal = self.0.terminal.lock();
            if terminal.is_some() {
                false
            } else {
                *terminal = Some(final_time);
                true
            }
        };
        // Freeze the parent before collecting children: a concurrent/new
        // filter inherits terminal state instead of reviving an exited task.
        let filters: Vec<_> = self.0.filters.lock().values().cloned().collect();
        for clock in filters {
            clock.retire();
        }
        if fresh {
            let groups: Vec<_> = self
                .0
                .groups
                .lock()
                .groups
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .collect();
            let mut changes = Vec::new();
            for group in groups {
                let mut group = group.lock();
                group.settle(final_time);
                group.detach_all();
                group.publish_userpages();
                changes.extend(
                    group
                        .members
                        .values()
                        .map(|counter| counter.changed.clone()),
                );
            }
            for changed in changes {
                changed.notify_atomic();
            }
        }
    }
    pub(super) fn sample(&self, context: impl FnOnce(std::time::Instant) -> Sample) {
        if !self.0.sampling.load(Ordering::Relaxed) || self.0.terminal.lock().is_some() {
            return;
        }
        let (groups, revision): (Vec<_>, _) = {
            let mut registry = self.0.groups.lock();
            registry.groups.retain(|group| group.strong_count() != 0);
            (
                registry
                    .groups
                    .iter()
                    .filter_map(std::sync::Weak::upgrade)
                    .collect(),
                registry.revision,
            )
        };
        let now = std::time::Instant::now();
        let context = context(now);
        let source = self.read_at(now);
        let mut changes = Vec::new();
        let mut active = false;
        for group in groups {
            let mut group = group.lock();
            changes.extend(group.sample(source, &context));
            active |= group
                .members
                .values()
                .any(|counter| counter.running && counter.config != 9 && counter.attr.period != 0);
        }
        if !active {
            let registry = self.0.groups.lock();
            if registry.revision == revision {
                self.0.sampling.store(false, Ordering::Relaxed);
            }
        }
        // Exclusive subscriptions may inspect the event synchronously. Never
        // notify while holding a group, mapping or ring producer transaction.
        for changed in changes {
            changed.notify_atomic();
        }
    }
    fn register(&self, group: &Arc<parking_lot::Mutex<Group>>, new: bool, sample: bool) {
        let mut registry = self.0.groups.lock();
        registry.revision = registry.revision.wrapping_add(1);
        registry.groups.retain(|group| group.strong_count() != 0);
        if new {
            registry.groups.push(Arc::downgrade(group));
        }
        if !self.0.active.swap(true, Ordering::Relaxed) {
            if let Some(domain) = &self.0.wake_domain {
                domain.fetch_add(1, Ordering::Relaxed);
            }
        }
        if sample {
            self.0.sampling.store(true, Ordering::Relaxed);
        }
    }
}

#[derive(Clone)]
pub struct Attr {
    config: u64,
    metadata: u64,
    format: u64,
    disabled: bool,
    pinned: bool,
    exclusive: bool,
    period: u64,
    sample_type: u64,
    wakeup: u32,
    watermark: bool,
    sample_id_all: bool,
    inherit: bool,
    inherit_thread: bool,
    enable_on_exec: bool,
    remove_on_exec: bool,
    frequency: Option<u64>,
    exclude_user: bool,
    exclude_kernel: bool,
}
pub enum AttrInput {
    Value(Attr),
    SizeError,
}
impl Attr {
    /// copy_struct_from_user-compatible size negotiation, including a zero
    /// legacy size and zero-filled future tails. No event/FD effects yet.
    pub fn read(memory: &mut impl trames_memory::CpuMemory, address: u64) -> Result<Self> {
        match Self::import(memory, address)? {
            AttrInput::Value(attr) => Ok(attr),
            AttrInput::SizeError => {
                let size = address.checked_add(4).ok_or(Errno(14))?;
                let _ = memory.write_array(size, 136u32.to_le_bytes());
                Err(Errno(7))
            }
        }
    }
    pub fn import(memory: &impl trames_memory::CpuMemory, address: u64) -> Result<AttrInput> {
        let size_at = address.checked_add(4).ok_or(Errno(14))?;
        let supplied = u32::from_le_bytes(memory.read_array::<4>(size_at).map_err(|_| Errno(14))?);
        let size = if supplied == 0 { 64 } else { supplied as usize };
        let expected = 136usize;
        if !(64..=4096).contains(&size) {
            return Ok(AttrInput::SizeError);
        }
        let mut bytes = [0; 136];
        memory
            .read(address, &mut bytes[..size.min(expected)])
            .map_err(|_| Errno(14))?;
        let mut offset = expected;
        let mut tail = [0; 64];
        while offset < size {
            let count = (size - offset).min(tail.len());
            memory
                .read(
                    address.checked_add(offset as u64).ok_or(Errno(14))?,
                    &mut tail[..count],
                )
                .map_err(|_| Errno(14))?;
            if tail[..count].iter().any(|byte| *byte != 0) {
                return Ok(AttrInput::SizeError);
            }
            offset += count;
        }
        let word = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let kind = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let config = word(8);
        let flags = word(40);
        let format = word(32);
        if flags >> 38 != 0
            || format & !31 != 0
            || bytes[110..112]
                .iter()
                .chain(&bytes[116..120])
                .any(|&b| b != 0)
        {
            return Err(Errno(22));
        }
        if flags & (1 << 35) != 0 && flags & 2 == 0
            || flags & (1 << 36) != 0 && flags & (1 << 12) != 0
        {
            return Err(Errno(22));
        }
        if kind != 1 {
            return Err(Errno(2));
        }
        if !matches!(config, 0..=6 | 9) {
            return Err(Errno(2));
        }
        // Admit only sample fields with a real software producer. Inherited
        // contexts and user/kernel separation still have their own producers.
        const SUPPORTED_FLAGS: u64 = 1
            | 2
            | 4
            | 8
            | (1 << 4)
            | (1 << 5)
            | (1 << 6)
            | (1 << 7)
            | (1 << 10)
            | (1 << 12)
            | (1 << 14)
            | (1 << 18)
            | (1 << 20)
            | (1 << 35)
            | (1 << 36)
            | (1 << 8)
            | (1 << 9)
            | (1 << 11)
            | (1 << 13)
            | (1 << 17)
            | (1 << 23)
            | (1 << 24)
            | (1 << 25)
            // These subscribe to guest dynamic kernel symbols/BPF programs.
            // Neither resource can currently be created, so the streams are empty.
            | (1 << 29)
            | (1 << 30);
        let period = word(16);
        let sample_type = word(24);
        if period >> 63 != 0 || sample_type >> 25 != 0 {
            return Err(Errno(22));
        }
        if flags & !SUPPORTED_FLAGS != 0
            || sample_type & !sample::SUPPORTED != 0
            || bytes[52..92]
                .iter()
                .chain(&bytes[96..expected])
                .any(|&b| b != 0)
            || if flags & (1 << 25) != 0 {
                i32::from_le_bytes(bytes[92..96].try_into().unwrap()) != 1
            } else {
                bytes[92..96] != [0; 4]
            }
        {
            return Err(Errno(95));
        }
        let frequency = flags & (1 << 10) != 0;
        let requested_frequency = frequency.then_some(period);
        let period = if frequency && period != 0 && matches!(config, 0 | 1) {
            (1_000_000_000 / period).max(1)
        } else if frequency && period != 0 {
            1
        } else {
            period
        };
        Ok(AttrInput::Value(Self {
            config,
            metadata: flags & ((1 << 8) | (1 << 9) | (1 << 13) | (1 << 17) | (1 << 23) | (1 << 24)),
            format,
            disabled: flags & 1 != 0,
            pinned: flags & 4 != 0,
            exclusive: flags & 8 != 0,
            period,
            sample_type,
            wakeup: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
            watermark: flags & (1 << 14) != 0,
            sample_id_all: flags & (1 << 18) != 0,
            inherit: flags & 2 != 0,
            inherit_thread: flags & (1 << 35) != 0,
            enable_on_exec: flags & (1 << 12) != 0,
            remove_on_exec: flags & (1 << 36) != 0,
            frequency: requested_frequency,
            exclude_user: flags & (1 << 4) != 0,
            exclude_kernel: flags & (1 << 5) != 0,
        }))
    }
}

struct Counter {
    leader: u64,
    config: u64,
    enabled: bool,
    running: bool,
    value: u64,
    time: u64,
    enabled_time: u64,
    attr: Attr,
    remaining: u64,
    refresh: Option<u64>,
    exhausted: bool,
    throttled: bool,
    sample_at: u64,
    sample_value: u64,
    lost: Arc<AtomicU64>,
    output: Arc<output::Output>,
    namespace: PidNamespace,
    changed: Arc<Readiness>,
    closed_at: Arc<parking_lot::Mutex<Option<Stamp>>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    family: Option<Arc<inheritance::Family>>,
    branch: Option<Arc<inheritance::Branch>>,
    settings: Arc<Settings>,
}
struct Group {
    source: Stamp,
    members: BTreeMap<u64, Counter>,
}
impl Group {
    fn settle(&mut self, source: Stamp) {
        // A mapping can release the final Event while a sampler owns this
        // group. Drop only publishes its close timestamp; reap at this shared
        // resource boundary, including leader detachment at the actual time.
        let mut events = Vec::new();
        for (&id, counter) in &self.members {
            let at = *counter.closed_at.lock();
            if let Some(at) = at {
                events.push((at, id, None));
            }
            if let Some(branch) = &counter.branch {
                events.extend(
                    branch
                        .commands
                        .lock()
                        .drain(..)
                        .map(|(at, request)| (at, id, Some(request))),
                );
            }
        }
        events.sort_by_key(|&(at, _, _)| at.enabled);
        let source = source.max(events.last().map_or(Stamp::default(), |event| event.0));
        for (at, id, request) in events {
            self.advance(at);
            if let Some(request) = request {
                if let Some(counter) = self.members.get_mut(&id) {
                    counter.control(request);
                }
            } else {
                if let Some(counter) = self.members.remove(&id) {
                    counter.retire_branch();
                }
                for (&member, counter) in &mut self.members {
                    if counter.leader == id {
                        counter.leader = member;
                    }
                }
            }
            self.sync();
        }
        self.advance(source);
    }
    fn advance(&mut self, source: Stamp) {
        // A live assignment may finish after a reader observed its clock. The
        // completed projection must not move the baseline backward and count
        // the same execution interval again on the next read.
        let source = source.max(self.source);
        let delta = source.cpu - self.source.cpu;
        let enabled_delta = source.enabled - self.source.enabled;
        for counter in self.members.values_mut() {
            if counter.running {
                if matches!(counter.config, 0 | 1) {
                    counter.value = counter.value.wrapping_add(delta);
                }
                counter.time = counter.time.saturating_add(delta);
                counter.enabled_time = counter.enabled_time.saturating_add(enabled_delta);
                if matches!(counter.config, 0 | 1) && counter.attr.period != 0 {
                    counter.remaining = counter.remaining.saturating_sub(delta);
                }
            }
            counter.publish_branch();
        }
        self.source = source;
    }
    fn sync(&mut self) {
        let running: Vec<_> = self
            .members
            .iter()
            .map(|(&id, counter)| {
                (
                    id,
                    counter.connected.load(Ordering::Relaxed)
                        && counter.enabled
                        && self.members[&counter.leader].enabled,
                )
            })
            .collect();
        for (id, running) in running {
            self.members.get_mut(&id).unwrap().running = running;
        }
    }
    fn words(&self, id: u64, format: u64) -> Vec<u64> {
        let counter = &self.members[&id];
        let grouped = format & 8 != 0;
        let members = self
            .members
            .iter()
            .filter(|(_, member)| member.leader == counter.leader);
        let (value, enabled, time, _) = counter.totals();
        let mut words = vec![if grouped {
            members.clone().count() as u64
        } else {
            value
        }];
        if format & 1 != 0 {
            words.push(enabled);
        }
        if format & 2 != 0 {
            words.push(time);
        }
        let mut append = |id: u64, counter: &Counter| {
            let (value, _, _, lost) = counter.totals();
            if grouped {
                words.push(value);
            }
            if format & 4 != 0 {
                words.push(counter.primary_id(id));
            }
            if format & 16 != 0 {
                words.push(lost);
            }
        };
        if grouped {
            for (&id, counter) in members {
                append(id, counter);
            }
        } else {
            append(id, counter);
        }
        words
    }
}
pub struct Event {
    id: u64,
    clock: Clock,
    format: u64,
    group: Arc<parking_lot::Mutex<Group>>,
    cpus: usize,
    attr: Attr,
    changed: Arc<Readiness>,
    output: Arc<output::Output>,
    closed_at: Arc<parking_lot::Mutex<Option<Stamp>>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    family: Option<Arc<inheritance::Family>>,
}
impl Event {
    #[cfg(test)]
    fn new(attr: Attr, clock: Clock, leader: Option<&Arc<Self>>) -> Result<Arc<Self>> {
        Self::in_namespace(
            attr,
            clock,
            leader,
            None,
            PidNamespace::default(),
            1,
            Arc::default(),
        )
    }
    fn in_namespace(
        mut attr: Attr,
        clock: Clock,
        leader: Option<&Arc<Self>>,
        output: Option<&Arc<Self>>,
        namespace: PidNamespace,
        cpus: usize,
        settings: Arc<Settings>,
    ) -> Result<Arc<Self>> {
        if clock.0.terminal.lock().is_some() {
            return Err(Errno(3));
        }
        // Linux software clocks convert frequency once in PMU init and clear
        // attr.freq. A later IOC_PERIOD therefore takes nanoseconds.
        if matches!(attr.config, 0 | 1) {
            attr.frequency = None;
        }
        if output.is_some_and(|event| !clock.output_compatible(&event.clock)) {
            return Err(Errno(22));
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let changed: Arc<Readiness> = Arc::default();
        let closed_at = Arc::new(parking_lot::Mutex::new(None));
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let family = attr.inherit.then(|| Arc::new(inheritance::Family::new(id)));
        let destination = output::Output::new(changed.clone());
        let group = if let Some(leader) = leader {
            if !clock.same(&leader.clock)
                || attr.pinned
                || attr.exclusive
                || attr.inherit != leader.attr.inherit
                || !leader.connected.load(Ordering::Relaxed)
            {
                return Err(Errno(22));
            }
            leader.group.clone()
        } else {
            Arc::new(parking_lot::Mutex::new(Group {
                source: clock.read(),
                members: BTreeMap::new(),
            }))
        };
        {
            let mut state = group.lock();
            state.settle(clock.read());
            if leader.is_some_and(|leader| state.members[&leader.id].leader != leader.id) {
                return Err(Errno(22));
            }
            let leader_id = leader.map_or(id, |leader| leader.id);
            let members = state
                .members
                .values()
                .filter(|counter| counter.leader == leader_id)
                .count()
                + 1;
            if sample::size(&attr, members) > u16::MAX as usize
                || state
                    .members
                    .values()
                    .filter(|counter| counter.leader == leader_id)
                    .any(|counter| sample::size(&counter.attr, members) > u16::MAX as usize)
            {
                return Err(Errno(22));
            }
            if let Some(output) = output {
                destination.redirect(Some(&output.output))?;
            }
            state.members.insert(
                id,
                Counter {
                    leader: leader.map_or(id, |leader| leader.id),
                    config: attr.config,
                    enabled: !attr.disabled,
                    running: false,
                    value: 0,
                    time: 0,
                    enabled_time: 0,
                    remaining: attr.period.max(if matches!(attr.config, 0 | 1) {
                        settings.minimum_period()
                    } else {
                        1
                    }),
                    refresh: None,
                    exhausted: false,
                    throttled: false,
                    sample_at: 0,
                    sample_value: 0,
                    attr: attr.clone(),
                    lost: Arc::new(AtomicU64::new(0)),
                    output: destination.clone(),
                    namespace: namespace.clone(),
                    changed: changed.clone(),
                    closed_at: closed_at.clone(),
                    connected: connected.clone(),
                    family: family.clone(),
                    branch: None,
                    settings: settings.clone(),
                },
            );
            state.sync();
        }
        if attr.metadata != 0 {
            clock.0.metadata.store(true, Ordering::Relaxed);
        }
        clock.register(&group, leader.is_none(), attr.period != 0);
        let event = Arc::new(Self {
            id,
            clock,
            format: attr.format,
            group,
            cpus,
            attr,
            changed,
            output: destination,
            closed_at,
            connected,
            family,
        });
        if event.clock.0.terminal.lock().is_some() {
            return Err(Errno(3));
        }
        Ok(event)
    }
    pub fn id(&self) -> u64 {
        self.id
    }
    pub(super) fn read(&self, count: usize) -> Result<Vec<u8>> {
        self.refresh_children();
        let mut state = self.group.lock();
        state.settle(self.clock.read());
        let words = state.words(self.id, self.format);
        state.publish_userpages();
        if count < words.len() * 8 {
            return Err(Errno(28));
        }
        Ok(words.into_iter().flat_map(u64::to_le_bytes).collect())
    }
    pub fn ioctl(
        &self,
        request: u32,
        argument: u64,
        memory: &mut impl trames_memory::CpuMemory,
    ) -> Result<u64> {
        match request {
            0x2400 | 0x2401 | 0x2403 => {
                if argument & !1 != 0 {
                    return Err(Errno(22));
                }
                let mut state = self.group.lock();
                state.settle(self.clock.read());
                let leader = state.members[&self.id].leader;
                for (&id, counter) in &mut state.members {
                    if argument & 1 != 0 && counter.leader == leader || id == self.id {
                        counter.control(request);
                        if let Some(family) = &counter.family {
                            family.control(request);
                        }
                    }
                }
                state.sync();
                state.publish_userpages();
                if request == 0x2400 {
                    self.clock.register(&self.group, false, true);
                }
                Ok(0)
            }
            0x80082407 => {
                memory
                    .write_array(argument, self.id.to_le_bytes())
                    .map_err(|_| Errno(14))?;
                Ok(0)
            }
            0x2402 => {
                let mut state = self.group.lock();
                state.settle(self.clock.read());
                let counter = state.members.get_mut(&self.id).unwrap();
                if counter.attr.inherit || counter.attr.period == 0 || argument == 0 {
                    return Err(Errno(22));
                }
                counter.refresh = Some(counter.refresh.unwrap_or(0).saturating_add(argument));
                counter.exhausted = false;
                counter.enabled = true;
                state.sync();
                state.publish_userpages();
                self.clock.register(&self.group, false, true);
                Ok(0)
            }
            0x40082404 => {
                let period =
                    u64::from_le_bytes(memory.read_array(argument).map_err(|_| Errno(14))?);
                let mut state = self.group.lock();
                state.settle(self.clock.read());
                let counter = state.members.get_mut(&self.id).unwrap();
                if period == 0 || period >> 63 != 0 || counter.attr.period == 0 {
                    return Err(Errno(22));
                }
                if counter.attr.frequency.is_some() {
                    if period > counter.settings.get(Setting::MaxSampleRate) as u64 {
                        return Err(Errno(22));
                    }
                    counter.attr.frequency = Some(period);
                    counter.attr.period = 1;
                } else {
                    counter.attr.period = period;
                }
                counter.remaining = counter.attr.period.max(if matches!(counter.config, 0 | 1) {
                    counter.settings.minimum_period()
                } else {
                    1
                });
                Ok(0)
            }
            0x40042409 => {
                let ring = self.output.capture().ok_or(Errno(22))?;
                if ring.size() == 0 {
                    return Err(Errno(22));
                }
                ring.pause(argument != 0);
                Ok(0)
            }
            _ => Err(Errno(25)),
        }
    }
}
impl Drop for Event {
    fn drop(&mut self) {
        *self.closed_at.lock() = Some(self.clock.read());
        if let Some(family) = &self.family {
            family.close();
        }
    }
}
impl DirectPoll for Event {
    fn identity(&self) -> usize {
        self as *const Self as usize
    }
    fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        self.poll_with(events, true)
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.changed.subscribe(signal)
    }
}
impl Event {
    pub(super) fn peek(&self, events: u16) -> (u16, [u64; 2]) {
        self.poll_with(events, false)
    }
    fn poll_with(&self, events: u16, consume: bool) -> (u16, [u64; 2]) {
        let terminal = !self.connected.load(Ordering::Relaxed)
            && self.family.as_ref().is_none_or(|family| !family.live());
        if terminal {
            return (16, [1, 0]);
        }
        self.output.poll(events, consume)
    }
}
impl DescriptorFactory {
    pub fn perf_event(
        &self,
        attr: Attr,
        clock: Clock,
        leader: Option<&Arc<Event>>,
        cloexec: bool,
    ) -> Result<u32> {
        self.perf_event_for_cpus(attr, clock, leader, cloexec, 1)
    }
    pub fn perf_event_for_cpus(
        &self,
        attr: Attr,
        clock: Clock,
        leader: Option<&Arc<Event>>,
        cloexec: bool,
        cpus: usize,
    ) -> Result<u32> {
        self.perf_event_configured(attr, clock, leader, None, cloexec, cpus)
    }
    pub fn perf_event_configured(
        &self,
        attr: Attr,
        clock: Clock,
        leader: Option<&Arc<Event>>,
        output: Option<&Arc<Event>>,
        cloexec: bool,
        cpus: usize,
    ) -> Result<u32> {
        self.check_perf_attr(&attr)?;
        self.reserve_perf()?
            .publish(attr, clock, leader, output, cloexec, cpus)
    }
    pub fn reserve_perf(&self) -> Result<Reservation<'_>> {
        Ok(Reservation {
            slot: self.files.reserve()?,
            factory: self,
        })
    }
}
/// A private descriptor slot, held while the original group/task are resolved.
/// User input has already completed; this reservation never needs a worker.
pub struct Reservation<'a> {
    slot: fd_table::ReservedFd,
    factory: &'a DescriptorFactory,
}
impl Reservation<'_> {
    pub fn publish(
        self,
        attr: Attr,
        clock: Clock,
        leader: Option<&Arc<Event>>,
        output: Option<&Arc<Event>>,
        cloexec: bool,
        cpus: usize,
    ) -> Result<u32> {
        let factory = self.factory;
        let settings = factory
            .credentials
            .user_namespace
            .overflow()
            .1
            .settings
            .clone();
        let event = Event::in_namespace(
            attr,
            clock,
            leader,
            output,
            factory.pid_namespace.clone(),
            cpus,
            settings,
        )?;
        let description = events::anonymous_descriptor(
            factory.open_id(),
            if cloexec { O_CLOEXEC } else { 0 },
            events::Anonymous::Perf(event),
        );
        self.slot.publish(description, None)
    }
}

impl FdFlags {
    pub fn perf_event(&self, fd: u32) -> Result<Option<Arc<Event>>> {
        self.descriptor_control(fd)?.perf_event()
    }
}
impl Vfs {
    pub fn perf_event(&self, fd: u32) -> Result<Option<Arc<Event>>> {
        self.descriptor_control(fd)?.perf_event()
    }
}

#[cfg(test)]
#[path = "perf_tests.rs"]
mod tests;
