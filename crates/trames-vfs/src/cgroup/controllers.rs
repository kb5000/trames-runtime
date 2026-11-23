// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(super) const PIDS: u8 = 1;
pub(super) const CPU: u8 = 2;
pub(super) const CPUSET: u8 = 4;
pub(super) const MEMORY: u8 = 8;
pub(super) const CONTROLLERS: [(&str, u8); 4] = [
    ("cpuset", CPUSET),
    ("cpu", CPU),
    ("memory", MEMORY),
    ("pids", PIDS),
];

const CPU_FILES: &[(&str, u32)] = &[("cpu.max", 0o644), ("cpu.weight", 0o644)];
const CPUSET_FILES: &[(&str, u32)] = &[
    ("cpuset.cpus", 0o644),
    ("cpuset.cpus.effective", 0o444),
    ("cpuset.mems", 0o644),
    ("cpuset.mems.effective", 0o444),
];
const MEMORY_FILES: &[(&str, u32)] = &[
    ("memory.current", 0o444),
    ("memory.max", 0o644),
    ("memory.high", 0o644),
    ("memory.events", 0o444),
    ("memory.events.local", 0o444),
    ("memory.oom.group", 0o644),
];

#[derive(Default)]
pub(super) struct ControllerChange {
    pub events: Vec<Arc<ControlEvents>>,
    pub nodes: Vec<NodeRef>,
    pub reschedule: Vec<Arc<Member>>,
}

pub(super) struct CpuBandwidth(Mutex<Bandwidth>);
struct Bandwidth {
    quota: std::time::Duration,
    period: std::time::Duration,
    expires: Option<std::time::Instant>,
    used: std::time::Duration,
}
impl CpuBandwidth {
    fn new(quota: u64, period: u64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Bandwidth {
            quota: std::time::Duration::from_micros(quota),
            period: std::time::Duration::from_micros(period),
            expires: None,
            used: std::time::Duration::ZERO,
        })))
    }
    pub(super) fn charge(
        &self,
        now: std::time::Instant,
        elapsed: std::time::Duration,
    ) -> Option<std::time::Instant> {
        let mut policy = self.0.lock().unwrap();
        let start = now.checked_sub(elapsed).unwrap_or(now);
        if policy.expires.is_none_or(|deadline| deadline <= now) {
            let first = policy.expires.map_or(start, |deadline| deadline.max(start));
            policy.used = now.saturating_duration_since(first).min(policy.period);
            policy.expires = Some(first + policy.period);
            if policy.expires.is_some_and(|deadline| deadline <= now) {
                policy.expires = Some(now + policy.period);
            }
        } else {
            policy.used = policy.used.saturating_add(elapsed);
        }
        if policy.used >= policy.quota {
            policy.expires
        } else {
            None
        }
    }
}

pub struct CpuShare {
    weight: AtomicU32,
    service: AtomicU64,
}
impl Default for CpuShare {
    fn default() -> Self {
        Self {
            weight: AtomicU32::new(100),
            service: AtomicU64::new(0),
        }
    }
}
impl CpuShare {
    pub fn service(&self) -> u64 {
        self.service.load(Ordering::Relaxed)
    }
    pub fn start(&self, floor: u64) {
        self.service.fetch_max(floor, Ordering::Relaxed);
    }
    pub fn account(&self, elapsed: std::time::Duration) {
        let service = elapsed.as_nanos() / u128::from(self.weight.load(Ordering::Relaxed));
        self.service
            .fetch_add(service.min(u64::MAX as u128) as u64, Ordering::Relaxed);
    }
}

pub(super) struct CpuSettings {
    pub quota: Option<u64>,
    pub period: u64,
    pub weight: u32,
    pub share: Arc<CpuShare>,
    pub bandwidth: Option<Arc<CpuBandwidth>>,
}
impl Default for CpuSettings {
    fn default() -> Self {
        Self {
            quota: None,
            period: 100_000,
            weight: 100,
            share: Arc::default(),
            bandwidth: None,
        }
    }
}
impl CpuSettings {
    pub fn set_limit(&mut self, text: &str) -> Result<()> {
        let mut fields = text.split_whitespace();
        let quota = match fields.next().ok_or(Errno(22))? {
            "max" => None,
            number => Some(
                number
                    .parse::<u64>()
                    .ok()
                    .filter(|&quota| quota >= 1_000)
                    .ok_or(Errno(22))?,
            ),
        };
        let period = fields
            .next()
            .map(|period| {
                period
                    .parse::<u64>()
                    .ok()
                    .filter(|period| (1_000..=1_000_000).contains(period))
                    .ok_or(Errno(22))
            })
            .transpose()?
            .unwrap_or(self.period);
        if fields.next().is_some() {
            return Err(Errno(22));
        }
        if self.quota != quota || self.period != period {
            self.bandwidth = quota.map(|quota| CpuBandwidth::new(quota, period));
            self.quota = quota;
            self.period = period;
        }
        Ok(())
    }
    pub fn set_weight(&mut self, text: &str) -> Result<()> {
        let weight = text.parse::<u32>().map_err(|_| Errno(22))?;
        if !(1..=10_000).contains(&weight) {
            return Err(Errno(34));
        }
        self.weight = weight;
        self.share.weight.store(weight, Ordering::Relaxed);
        Ok(())
    }
}

pub(super) fn list(mask: u8) -> String {
    let mut names = CONTROLLERS
        .iter()
        .filter_map(|(name, bit)| (mask & bit != 0).then_some(*name))
        .peekable();
    if names.peek().is_none() {
        return String::new();
    }
    let mut text = names.collect::<Vec<_>>().join(" ");
    text.push('\n');
    text
}

pub(super) fn possible_cpus(cpus: usize) -> u64 {
    u64::MAX >> (64 - cpus.clamp(1, 64))
}

pub(super) fn parse_mask(text: &str, possible: u64) -> Result<u64> {
    let mut mask = 0;
    for part in text.split(',') {
        let (first, last) = part.split_once('-').unwrap_or((part, part));
        let first = first.parse::<u32>().map_err(|_| Errno(22))?;
        let last = last.parse::<u32>().map_err(|_| Errno(22))?;
        if first > last || last >= u64::BITS {
            return Err(Errno(34));
        }
        mask |= (u64::MAX << first) & (u64::MAX >> (63 - last));
    }
    if mask & !possible != 0 {
        return Err(Errno(34));
    }
    Ok(mask)
}
pub(super) fn format_mask(mask: u64) -> String {
    let mut remaining = mask;
    let mut ranges = Vec::new();
    while remaining != 0 {
        let start = remaining.trailing_zeros();
        let count = (remaining >> start).trailing_ones();
        let last = start + count - 1;
        ranges.push(if start == last {
            start.to_string()
        } else {
            format!("{start}-{last}")
        });
        remaining &= !(u64::MAX >> (64 - count) << start);
    }
    format!("{}\n", ranges.join(","))
}
pub(super) fn memory_limit(text: &str) -> Result<usize> {
    if text == "max" {
        return Ok(usize::MAX);
    }
    let shift = match text.as_bytes().last() {
        Some(b'k' | b'K') => 10,
        Some(b'm' | b'M') => 20,
        Some(b'g' | b'G') => 30,
        Some(b't' | b'T') => 40,
        _ => 0,
    };
    let number = if shift == 0 {
        text
    } else {
        &text[..text.len() - 1]
    };
    let bytes = number
        .parse::<usize>()
        .map_err(|_| Errno(22))?
        .checked_mul(1usize << shift)
        .ok_or(Errno(34))?;
    Ok(bytes & !(trames_memory::PAGE_SIZE as usize - 1))
}

pub(super) fn limit_text(limit: usize) -> String {
    if limit == usize::MAX {
        "max\n".to_owned()
    } else {
        format!("{limit}\n")
    }
}

impl Cgroups {
    pub(super) fn available_controllers(&self, id: u64) -> u8 {
        self.groups[&id]
            .parent
            .map_or(PIDS | CPU | CPUSET | MEMORY, |parent| {
                self.groups[&parent].subtree
            })
    }
    pub(super) fn memory_at(&self, id: u64) -> Option<Arc<trames_memory::MemoryCgroup>> {
        self.groups[&id]
            .location
            .ancestors
            .iter()
            .find_map(|id| self.groups[id].memory.clone())
    }
    pub(super) fn effective_cpus(&self, id: u64, possible: u64) -> u64 {
        self.groups[&id]
            .location
            .ancestors
            .iter()
            .rev()
            .fold(possible, |mask, id| {
                self.groups[id].cpus.map_or(mask, |cpus| {
                    let allowed = mask & cpus;
                    if allowed == 0 {
                        mask
                    } else {
                        allowed
                    }
                })
            })
    }
    pub(super) fn publish_bandwidth(&self, task: &Member) -> bool {
        let group = &self.groups[&task.group()];
        let cpu = group
            .location
            .ancestors
            .iter()
            .find(|&&id| self.available_controllers(id) & CPU != 0)
            .expect("root provides the CPU controller");
        let share = &self.groups[cpu].cpu.share;
        {
            let mut previous = task.share.borrow_mut();
            if !Arc::ptr_eq(&previous, share) {
                *previous = share.clone();
            }
        }
        let bandwidth: Vec<_> = self.groups[&task.group()]
            .location
            .ancestors
            .iter()
            .filter_map(|id| self.groups[id].cpu.bandwidth.clone())
            .collect();
        let limited = !bandwidth.is_empty();
        let mut previous = task.bandwidth.borrow_mut();
        if previous.len() == bandwidth.len()
            && previous
                .iter()
                .zip(&bandwidth)
                .all(|(a, b)| Arc::ptr_eq(a, b))
        {
            return false;
        }
        *previous = bandwidth.into();
        task.cpu_limited.store(limited, Ordering::Relaxed);
        true
    }

    pub(super) fn publish_cpuset(&self) -> Vec<Arc<Member>> {
        self.tasks
            .values()
            .filter_map(|task| {
                let cpus = self.effective_cpus(task.group(), u64::MAX);
                (task.cpus.swap(cpus, Ordering::Relaxed) != cpus).then(|| task.clone())
            })
            .collect()
    }
    pub(super) fn cpu_usage(&self, id: u64) -> u64 {
        self.tasks
            .values()
            .filter(|task| self.groups[&task.group()].location.ancestors.contains(&id))
            .fold(self.groups[&id].cpu_usage, |used, task| {
                used.saturating_add(task.cpu_delta())
            })
    }
    pub(super) fn settle_cpu(&mut self, task: &Member) {
        let elapsed = task.cpu_clock();
        let delta = elapsed.saturating_sub(task.cpu_base.fetch_max(elapsed, Ordering::Relaxed));
        let location = self.groups[&task.group()].location.clone();
        for id in &location.ancestors {
            self.groups.get_mut(id).unwrap().cpu_usage += delta;
        }
    }
    pub(super) fn change_controllers(
        &mut self,
        id: u64,
        text: &str,
        owner: (u32, u32),
    ) -> Result<ControllerChange> {
        let old = self.groups[&id].subtree;
        let mut next = old;
        let available = self.available_controllers(id);
        for token in text.split_whitespace() {
            let (operator, name) = token.split_at_checked(1).ok_or(Errno(22))?;
            let bit = CONTROLLERS
                .iter()
                .find_map(|(ctrl, bit)| (*ctrl == name).then_some(*bit))
                .ok_or(Errno(22))?;
            match operator {
                "+" if available & bit != 0 => next |= bit,
                "+" => return Err(Errno(2)),
                "-" => next &= !bit,
                _ => return Err(Errno(22)),
            }
        }
        let changed = next ^ old;
        if changed == 0 {
            return Ok(ControllerChange::default());
        }
        let children: Vec<_> = self
            .groups
            .iter()
            .filter_map(|(&key, group)| (group.parent == Some(id)).then_some(key))
            .collect();
        if children
            .iter()
            .any(|child| self.groups[child].subtree & (old & !next) != 0)
            || id != ROOT && next & !old != 0 && self.tasks.values().any(|task| task.group() == id)
        {
            return Err(Errno(16));
        }
        self.groups.get_mut(&id).unwrap().subtree = next;
        let mut events = Vec::new();
        let mut nodes = Vec::new();
        for child in children {
            for (_, bit) in CONTROLLERS {
                if changed & bit != 0 {
                    let (retired, removed) =
                        self.install_controller(child, bit, next & bit != 0, owner);
                    events.extend(retired);
                    nodes.extend(removed);
                }
            }
        }
        if changed & MEMORY != 0 {
            for task in self.tasks.values() {
                task.memory.set(self.memory_at(task.group()));
            }
        }
        let mut reschedule = if changed & CPUSET != 0 {
            self.publish_cpuset()
        } else {
            Vec::new()
        };
        if changed & CPU != 0 {
            reschedule.extend(
                self.tasks
                    .values()
                    .filter(|task| self.publish_bandwidth(task))
                    .cloned(),
            );
        }
        Ok(ControllerChange {
            events,
            nodes,
            reschedule,
        })
    }
    pub(super) fn install_controller(
        &mut self,
        id: u64,
        bit: u8,
        enable: bool,
        owner: (u32, u32),
    ) -> (Vec<Arc<ControlEvents>>, Vec<NodeRef>) {
        let files = match bit {
            PIDS => return self.install_pids(id, enable, owner),
            CPU => {
                self.groups.get_mut(&id).unwrap().cpu = CpuSettings::default();
                CPU_FILES
            }
            CPUSET => {
                let group = self.groups.get_mut(&id).unwrap();
                group.cpus = None;
                group.mems = None;
                CPUSET_FILES
            }
            MEMORY => {
                let parent = self.groups[&id].parent.expect("controllers below root");
                let memory =
                    enable.then(|| trames_memory::MemoryCgroup::new(self.memory_at(parent)));
                self.groups.get_mut(&id).unwrap().memory = memory;
                MEMORY_FILES
            }
            _ => unreachable!("known controller"),
        };
        self.install_files(id, files, enable, owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn cpu_quota_is_shared_until_the_period_expires() {
        let quota = CpuBandwidth::new(1_000, 10_000);
        let start = Instant::now();
        let half = Duration::from_micros(500);
        let period = Duration::from_millis(10);
        assert_eq!(quota.charge(start + half, half), None);
        assert_eq!(quota.charge(start + half * 2, half), Some(start + period));
        assert_eq!(quota.charge(start + period, Duration::ZERO), None);
    }
}
