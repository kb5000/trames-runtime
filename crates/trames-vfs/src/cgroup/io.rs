// SPDX-License-Identifier: GPL-3.0-or-later
//! Original-device hierarchical admission. Waiting requests consume no credit
//! and park on the existing executor's deadline/configuration readiness.
use crate::{Errno, Result};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use trames_shared::{IoSignal, IoSubscription, Readiness};
mod context;
#[cfg(test)]
mod interface_tests;
pub(crate) use context::{admit, complete, limited, Context, Scope, Target};

pub(super) const DEVICE: (u32, u32) = (253, 1);
const SECOND: u128 = 1_000_000_000;
const INITIAL_BYTES: u64 = 128 * 1024;

#[derive(Default)]
struct Bucket {
    rate: Option<u64>,
    credit: u128,
    capacity: u128,
    updated: Option<Instant>,
}
impl Bucket {
    fn refill(&mut self, now: Instant) {
        if let (Some(rate), Some(before)) = (self.rate, self.updated) {
            self.credit = self.capacity.min(
                self.credit.saturating_add(
                    now.saturating_duration_since(before)
                        .as_nanos()
                        .saturating_mul(u128::from(rate)),
                ),
            );
        }
        self.updated = Some(self.updated.map_or(now, |before| before.max(now)));
    }
    fn configure(&mut self, rate: Option<u64>, bytes: bool, now: Instant) {
        if self.rate == rate {
            return;
        }
        self.refill(now);
        let was_unlimited = self.rate.is_none();
        self.rate = rate;
        let burst = rate.map_or(0, |rate| {
            if bytes {
                (rate / 10).clamp(1, INITIAL_BYTES)
            } else {
                1
            }
        });
        self.capacity = u128::from(burst) * SECOND;
        self.credit = if was_unlimited {
            self.capacity
        } else {
            self.credit.min(self.capacity)
        };
    }
    fn delay(&mut self, units: u64, now: Instant) -> Option<Duration> {
        let rate = self.rate?;
        self.refill(now);
        let cost = u128::from(units) * SECOND;
        // A large original request can accumulate enough credit without a
        // reservation in a global queue. Growing capacity grants no free burst.
        self.capacity = self.capacity.max(cost);
        let nanos = cost.saturating_sub(self.credit).div_ceil(u128::from(rate));
        (nanos != 0).then(|| {
            Duration::new(
                (nanos / SECOND).min(u128::from(u64::MAX)) as u64,
                (nanos % SECOND) as u32,
            )
        })
    }
    fn debit(&mut self, units: u64) {
        if self.rate.is_some() {
            self.credit -= u128::from(units) * SECOND;
        }
    }
    fn refund(&mut self, units: u64, now: Instant) {
        self.refill(now);
        self.credit = self
            .capacity
            .min(self.credit.saturating_add(u128::from(units) * SECOND));
    }
}
#[derive(Default)]
struct Direction {
    bytes: Bucket,
    operations: Bucket,
}
impl Direction {
    fn delay(&mut self, bytes: u64, now: Instant) -> Option<Duration> {
        self.bytes
            .delay(bytes, now)
            .into_iter()
            .chain(self.operations.delay(1, now))
            .max()
    }
    fn debit(&mut self, bytes: u64) {
        self.bytes.debit(bytes);
        self.operations.debit(1);
    }
    fn refund(&mut self, bytes: u64, operation: bool, now: Instant) {
        self.bytes.refund(bytes, now);
        if operation {
            self.operations.refund(1, now);
        }
    }
}
#[derive(Default)]
struct Policy {
    read: Direction,
    write: Direction,
}
impl Policy {
    fn direction(&mut self, write: bool) -> &mut Direction {
        if write {
            &mut self.write
        } else {
            &mut self.read
        }
    }
    fn limited(&self) -> bool {
        self.read.bytes.rate.is_some()
            || self.read.operations.rate.is_some()
            || self.write.bytes.rate.is_some()
            || self.write.operations.rate.is_some()
    }
}
#[derive(Default)]
struct Stats {
    rbytes: AtomicU64,
    wbytes: AtomicU64,
    rios: AtomicU64,
    wios: AtomicU64,
}
struct Device {
    policy: Mutex<Policy>,
    limited: AtomicBool,
    stats: Stats,
    changed: Arc<Readiness>,
    online: AtomicBool,
}
impl Default for Device {
    fn default() -> Self {
        Self {
            policy: Mutex::default(),
            limited: AtomicBool::new(false),
            stats: Stats::default(),
            changed: Arc::default(),
            online: AtomicBool::new(true),
        }
    }
}

pub(crate) struct Group {
    parent: Option<Arc<Self>>,
    // Construct once in root-to-leaf order; ordinary unlimited IO clones one
    // slice and updates counters without acquiring controller or topology locks.
    chain: Arc<[Arc<Device>]>,
}
/// Includes admitted backend requests, whose permits retain devices directly
/// after the original Group and its accepted contexts have been dropped.
pub(super) struct Reference(std::sync::Weak<Device>);
impl Reference {
    pub fn live(&self) -> bool {
        self.0.strong_count() != 0
    }
}
pub(crate) struct Wait {
    group: Arc<Group>,
    bytes: u64,
    write: bool,
    #[cfg(test)]
    pub deadline: Instant,
}
impl Wait {
    pub fn ready(&self, now: Instant) -> bool {
        self.group.delay(self.bytes, self.write, now).is_none()
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.group
            .chain
            .iter()
            .map(|device| device.changed.subscribe(signal))
            .collect()
    }
    pub fn deadline(&self, now: Instant) -> Instant {
        self.group
            .delay(self.bytes, self.write, now)
            .map_or(now, |delay| deadline(now, delay))
    }
}
impl trames_shared::ResourceWait for Wait {
    fn ready(&self) -> bool {
        self.ready(Instant::now())
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.subscribe(signal)
    }
    fn deadline(&self) -> Option<Instant> {
        Some(self.deadline(Instant::now()))
    }
}
pub(crate) struct Permit {
    chain: Arc<[Arc<Device>]>,
    debited: Vec<usize>,
    bytes: u64,
    write: bool,
    completed: bool,
}
fn deadline(now: Instant, delay: Duration) -> Instant {
    now.checked_add(delay)
        .unwrap_or_else(|| now + Duration::from_secs(u32::MAX.into()))
}
impl Group {
    pub(super) fn reference(&self) -> Reference {
        Reference(Arc::downgrade(
            self.chain.last().expect("original IO group"),
        ))
    }
    pub fn new(parent: Option<&Arc<Self>>) -> Arc<Self> {
        let mut chain = parent.map_or_else(Vec::new, |parent| parent.chain.to_vec());
        chain.push(Arc::default());
        Arc::new(Self {
            parent: parent.cloned(),
            chain: chain.into(),
        })
    }
    pub fn online(self: &Arc<Self>) -> Option<Arc<Self>> {
        let mut group = Some(self);
        while let Some(current) = group {
            if current.chain.last().unwrap().online.load(Relaxed) {
                return Some(current.clone());
            }
            group = current.parent.as_ref();
        }
        None
    }
    pub fn limited(&self) -> bool {
        self.chain.iter().any(|device| device.limited.load(Relaxed))
    }
    fn delay(&self, bytes: u64, write: bool, now: Instant) -> Option<Duration> {
        self.chain
            .iter()
            .filter(|device| device.limited.load(Relaxed))
            .filter_map(|device| {
                device
                    .policy
                    .lock()
                    .unwrap()
                    .direction(write)
                    .delay(bytes, now)
            })
            .max()
    }
    #[cfg(test)]
    pub fn admit(
        self: &Arc<Self>,
        bytes: u64,
        write: bool,
        now: Instant,
    ) -> std::result::Result<Permit, Wait> {
        self.admit_with_clock(bytes, write, || now)
    }
    pub(super) fn admit_with_clock(
        self: &Arc<Self>,
        bytes: u64,
        write: bool,
        clock: impl FnOnce() -> Instant,
    ) -> std::result::Result<Permit, Wait> {
        let nodes: Vec<_> = self
            .chain
            .iter()
            .enumerate()
            .filter(|(_, device)| device.limited.load(Relaxed))
            .collect();
        // One stable lock order across hierarchical preflight and debit. No
        // ancestor loses credit if a child cannot admit this actual backend IO.
        let mut locks: Vec<_> = nodes
            .iter()
            .map(|(_, device)| device.policy.lock().unwrap())
            .collect();
        // Unlimited IO still records its exact original hierarchical stats,
        // but has no token deadline for which a host clock is needed.
        let now = (!nodes.is_empty()).then(clock);
        if let Some(_delay) = locks
            .iter_mut()
            .filter_map(|policy| policy.direction(write).delay(bytes, now.unwrap()))
            .max()
        {
            return Err(Wait {
                group: self.clone(),
                bytes,
                write,
                #[cfg(test)]
                deadline: deadline(now.unwrap(), _delay),
            });
        }
        for policy in &mut locks {
            policy.direction(write).debit(bytes);
        }
        Ok(Permit {
            chain: self.chain.clone(),
            debited: nodes.iter().map(|(index, _)| *index).collect(),
            bytes,
            write,
            completed: false,
        })
    }
    pub fn set_max(&self, text: &str) -> Result<()> {
        let mut fields = text.split_whitespace();
        let (major, minor) = fields
            .next()
            .and_then(|field| field.split_once(':'))
            .ok_or(Errno(22))?;
        let device = (
            major.parse::<u32>().map_err(|_| Errno(22))?,
            minor.parse::<u32>().map_err(|_| Errno(22))?,
        );
        if device != DEVICE {
            return Err(Errno(19));
        }
        let mut updates = [None; 4];
        for field in fields {
            let (key, value) = field.split_once('=').ok_or(Errno(22))?;
            let index = match key {
                "rbps" => 0,
                "wbps" => 1,
                "riops" => 2,
                "wiops" => 3,
                _ => return Err(Errno(22)),
            };
            let value = if value == "max" {
                u64::MAX
            } else {
                number(value)?
            };
            if value == 0 {
                return Err(Errno(34));
            }
            let unlimited = if index < 2 {
                u64::MAX
            } else {
                u64::from(u32::MAX)
            };
            updates[index] = Some((value < unlimited).then_some(value));
        }
        let device = self.chain.last().expect("original IO group");
        let mut policy = device.policy.lock().unwrap();
        if !device.online.load(Relaxed) {
            return Err(Errno(19));
        }
        let now = Instant::now();
        for (index, update) in updates.into_iter().enumerate() {
            if let Some(rate) = update {
                let direction = if index % 2 == 0 {
                    &mut policy.read
                } else {
                    &mut policy.write
                };
                if index < 2 {
                    direction.bytes.configure(rate, true, now);
                } else {
                    direction.operations.configure(rate, false, now);
                }
            }
        }
        device.limited.store(policy.limited(), Relaxed);
        drop(policy);
        device.changed.notify_atomic();
        Ok(())
    }
    pub fn format_max(&self) -> String {
        let policy = self
            .chain
            .last()
            .expect("original IO group")
            .policy
            .lock()
            .unwrap();
        if !policy.limited() {
            return String::new();
        }
        let text =
            |rate: Option<u64>| rate.map_or_else(|| "max".to_owned(), |rate| rate.to_string());
        format!(
            "{}:{} rbps={} wbps={} riops={} wiops={}\n",
            DEVICE.0,
            DEVICE.1,
            text(policy.read.bytes.rate),
            text(policy.write.bytes.rate),
            text(policy.read.operations.rate),
            text(policy.write.operations.rate)
        )
    }
    pub fn format_stat(&self) -> String {
        let stats = &self.chain.last().expect("original IO group").stats;
        let (rbytes, wbytes, rios, wios) = (
            stats.rbytes.load(Relaxed),
            stats.wbytes.load(Relaxed),
            stats.rios.load(Relaxed),
            stats.wios.load(Relaxed),
        );
        if rios == 0 && wios == 0 {
            return String::new();
        }
        format!(
            "{}:{} rbytes={rbytes} wbytes={wbytes} rios={rios} wios={wios} dbytes=0 dios=0\n",
            DEVICE.0, DEVICE.1
        )
    }
    pub fn retire_state(&self) {
        let device = self.chain.last().expect("original IO group");
        let mut policy = device.policy.lock().unwrap();
        device.online.store(false, Relaxed);
        *policy = Policy::default();
        device.limited.store(false, Relaxed);
    }
    pub fn notify(&self) {
        let device = self.chain.last().expect("original IO group");
        device.changed.notify_atomic();
    }
    #[cfg(test)]
    pub fn retire(&self) {
        self.retire_state();
        self.notify();
    }
}
// Match the kernel's unsigned decimal prefix conversion, including its max
// sentinels and IOPS clamp. Invalid updates are parsed before any policy edit.
fn number(text: &str) -> Result<u64> {
    let negative = text.starts_with('-');
    let digits = text
        .strip_prefix('+')
        .or_else(|| text.strip_prefix('-'))
        .unwrap_or(text);
    let end = digits
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(digits.len());
    if end == 0 {
        return Err(Errno(22));
    }
    let Ok(value) = digits[..end].parse::<u64>() else {
        return Ok(u64::MAX);
    };
    Ok(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}
impl Permit {
    pub fn complete(mut self, bytes: u64) {
        self.complete_with_clock(bytes, Instant::now);
    }
    #[cfg(test)]
    fn complete_at(&mut self, bytes: u64, now: Instant) {
        self.complete_with_clock(bytes, || now);
    }
    fn complete_with_clock(&mut self, bytes: u64, clock: impl FnOnce() -> Instant) {
        debug_assert!(bytes <= self.bytes);
        for device in &*self.chain {
            let (count, operations) = if self.write {
                (&device.stats.wbytes, &device.stats.wios)
            } else {
                (&device.stats.rbytes, &device.stats.rios)
            };
            count.fetch_add(bytes, Relaxed);
            operations.fetch_add(1, Relaxed);
        }
        if bytes != self.bytes && !self.debited.is_empty() {
            let now = clock();
            for &index in &self.debited {
                self.chain[index]
                    .policy
                    .lock()
                    .unwrap()
                    .direction(self.write)
                    .refund(self.bytes - bytes, false, now);
                self.chain[index].changed.notify_atomic();
            }
        }
        self.completed = true;
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if !self.completed {
            for &index in &self.debited {
                self.chain[index]
                    .policy
                    .lock()
                    .unwrap()
                    .direction(self.write)
                    .refund(self.bytes, true, Instant::now());
                self.chain[index].changed.notify_atomic();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fully_completed_io_does_not_wait_for_an_unrelated_policy_update() {
        let group = Group::new(None);
        group.set_max("253:1 wiops=1").unwrap();
        let permit = admitted(&group, 4096, true, Instant::now());
        let policy = group.chain.last().unwrap().policy.lock().unwrap();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            permit.complete(4096);
            send.send(()).unwrap();
        });
        let completed = receive.recv_timeout(Duration::from_secs(1)).is_ok();
        drop(policy);
        worker.join().unwrap();
        assert!(completed, "full completion has no credit to refund");
        assert!(group.format_stat().contains("wbytes=4096 "));
        assert!(group.format_stat().contains("wios=1 "));
    }
    fn admitted(group: &Arc<Group>, bytes: u64, write: bool, now: Instant) -> Permit {
        group
            .admit(bytes, write, now)
            .unwrap_or_else(|_| panic!("expected actual IO admission"))
    }
    fn waiting(group: &Arc<Group>, bytes: u64, write: bool, now: Instant) -> Wait {
        group
            .admit(bytes, write, now)
            .err()
            .expect("expected resource wait")
    }
    #[test]
    fn waiting_and_cancelled_io_do_not_consume_hierarchical_credit() {
        let parent = Group::new(None);
        let child = Group::new(Some(&parent));
        parent.set_max("253:1 rbps=1000").unwrap();
        child.set_max("253:1 rbps=10000 riops=10").unwrap();
        let now = Instant::now();
        let wait = waiting(&child, 1000, false, now);
        assert!(wait.deadline > now);
        drop(wait);
        let permit = admitted(&child, 100, false, now);
        drop(permit); // cancelled before its backend call: refund bytes and IOPS
        admitted(&child, 100, false, now).complete(100);
        assert!(child
            .format_stat()
            .contains("rbytes=100 wbytes=0 rios=1 wios=0"));
        assert!(parent
            .format_stat()
            .contains("rbytes=100 wbytes=0 rios=1 wios=0"));
    }
    #[test]
    fn large_requests_accumulate_real_credit_and_partial_completion_refunds_bytes() {
        let group = Group::new(None);
        group.set_max("253:1 rbps=4096").unwrap();
        let now = Instant::now();
        let wait = waiting(&group, 8192, false, now);
        assert!(wait.deadline.duration_since(now) > Duration::from_secs(1));
        assert!(!wait.ready(now));
        let due = wait.deadline;
        let mut permit = admitted(&group, 8192, false, due);
        permit.complete_at(4096, due);
        let mut refund = admitted(&group, 4096, false, due);
        refund.complete_at(4096, due);
        assert!(group
            .format_stat()
            .contains("rbytes=8192 wbytes=0 rios=2 wios=0"));
    }
    #[test]
    fn ancestor_and_child_limits_are_checked_before_any_debit() {
        let parent = Group::new(None);
        let child = Group::new(Some(&parent));
        parent.set_max("253:1 rbps=10000").unwrap();
        child.set_max("253:1 riops=1").unwrap();
        let now = Instant::now();
        let mut first = admitted(&child, 100, false, now);
        first.complete_at(100, now);
        let wait = waiting(&child, 900, false, now);
        // The waiting child must not reserve the parent's remaining 900 bytes.
        let sibling = Group::new(Some(&parent));
        let mut sibling_io = admitted(&sibling, 900, false, now);
        sibling_io.complete_at(900, now);
        let due = wait.deadline;
        assert!(wait.ready(due));
        let mut second = admitted(&child, 900, false, due);
        second.complete_at(900, due);
        assert!(parent.format_stat().contains("rbytes=1900"));
        assert!(child.format_stat().contains("rbytes=1000"));
    }
    #[test]
    fn invalid_policy_is_atomic_and_original_group_retirement_releases_waiters() {
        struct Wake;
        impl trames_shared::IoWake for Wake {
            fn wake_io(&self, _: &Arc<IoSignal>) {}
        }
        let group = Group::new(None);
        group
            .set_max("253:1 rbps=1000 wiops=18446744073709551615")
            .unwrap();
        let original = group.format_max();
        assert_eq!(group.set_max("253:1 wbps=10 rbps=0"), Err(Errno(34)));
        assert_eq!(group.format_max(), original);
        assert_eq!(group.set_max("253:2 rbps=10"), Err(Errno(19)));
        let now = Instant::now();
        let wait = waiting(&group, 8192, false, now);
        let wake: Arc<dyn trames_shared::IoWake> = Arc::new(Wake);
        let signal = IoSignal::new(1, Arc::downgrade(&wake));
        let _subscriptions = wait.subscribe(&signal);
        group.retire();
        assert!(signal.ready());
        assert!(wait.ready(now));
        assert_eq!(group.format_max(), "");
        admitted(&group, 8192, false, now).complete(8192);
    }
}
