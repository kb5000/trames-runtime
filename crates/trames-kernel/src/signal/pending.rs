// SPDX-License-Identifier: GPL-3.0-or-later
use super::Info;
use std::collections::{BTreeMap, VecDeque};
use trames_vfs::Errno;

#[derive(Default)]
pub struct Pending(BTreeMap<u32, VecDeque<RetainedInfo>>);
/// Keep sender translations alive through dequeue and ABI conversion, not just
/// while the signal is queued. No reference to the sender's task is retained.
#[derive(Clone)]
pub struct RetainedInfo {
    observed: bool,
    info: Info,
    _sender: Option<trames_vfs::PidReference>,
}
impl RetainedInfo {
    pub(super) fn debugger(info: Info) -> Self {
        Self {
            info,
            observed: false,
            _sender: None,
        }
    }
}
impl std::ops::Deref for RetainedInfo {
    type Target = Info;
    fn deref(&self) -> &Info {
        &self.info
    }
}
impl std::ops::DerefMut for RetainedInfo {
    fn deref_mut(&mut self) -> &mut Info {
        &mut self.info
    }
}
impl Pending {
    pub fn enqueue(&mut self, sig: u32, info: Info) -> Result<(), Errno> {
        self.enqueue_retained(sig, info, None)
    }
    pub(super) fn enqueue_retained(
        &mut self,
        sig: u32,
        info: Info,
        sender: Option<trames_vfs::PidReference>,
    ) -> Result<(), Errno> {
        if sig < 32 && self.0.contains_key(&sig) {
            return Ok(()); // Standard signals coalesce, preserving the first info.
        }
        if sig >= 32 && self.0.values().map(VecDeque::len).sum::<usize>() >= 4096 {
            return Err(Errno(11));
        }
        self.0.entry(sig).or_default().push_back(RetainedInfo {
            observed: false,
            info,
            _sender: sender,
        });
        Ok(())
    }
    /// POSIX timers own one queued record per timer, including for standard
    /// signals. A preceding kill or a different timer retains its FIFO position.
    pub(super) fn enqueue_timer(&mut self, sig: u32, info: Info) -> Result<(), Errno> {
        if self.0.values().map(VecDeque::len).sum::<usize>() >= 4096 {
            return Err(Errno(11));
        }
        self.0.entry(sig).or_default().push_back(RetainedInfo {
            observed: false,
            info,
            _sender: None,
        });
        Ok(())
    }
    /// The tracee already selected this delivery. Put its exact sender and
    /// payload ahead of signals arriving while the tracer held the stop.
    pub(super) fn resume_observed(&mut self, sig: u32, mut info: RetainedInfo) {
        info.observed = true;
        self.restore(sig, info);
    }
    /// A selected delivery deferred on user-copy keeps its exact observation,
    /// sender lease and queue position, without a second enqueue admission.
    pub(super) fn restore(&mut self, sig: u32, info: RetainedInfo) {
        self.0.entry(sig).or_default().push_front(info);
    }

    pub(super) fn remove_for_trace(&mut self, sig: u32) -> Option<RetainedInfo> {
        if self.0.get(&sig)?.front()?.observed {
            return None;
        }
        self.remove(&sig)
    }

    pub fn remove(&mut self, sig: &u32) -> Option<RetainedInfo> {
        let q = self.0.get_mut(sig)?;
        let info = q.pop_front();
        if q.is_empty() {
            self.0.remove(sig);
        }
        info
    }
    pub fn discard(&mut self, sig: u32) {
        self.0.remove(&sig);
    }
    pub fn clear(&mut self) {
        self.0.clear();
    }
    pub fn bits(&self) -> u64 {
        self.0.keys().fold(0, |b, s| b | (1 << (s - 1)))
    }
    pub fn contains_key(&self, sig: &u32) -> bool {
        self.0.contains_key(sig)
    }
    pub fn next(&self, mask: u64) -> Option<u32> {
        let mut bits = self.bits() & mask;
        // Linux prioritizes synchronous-class signal numbers even when their
        // source is kill(), before selecting the lowest remaining number.
        const SYNCHRONOUS: u64 = (1 << 3) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 10) | (1 << 30);
        if bits & SYNCHRONOUS != 0 {
            bits &= SYNCHRONOUS;
        }
        (bits != 0).then(|| bits.trailing_zeros() + 1)
    }
    pub fn values(&self) -> impl Iterator<Item = &Info> {
        self.0.values().flatten().map(|queued| &queued.info)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&u32, &Info)> {
        self.0
            .iter()
            .map(|(sig, q)| (sig, &q.front().expect("nonempty signal queue").info))
    }
    pub fn timer_mut(&mut self, sig: u32, id: i32) -> Option<&mut Info> {
        self.0
            .get_mut(&sig)?
            .iter_mut()
            .find(|i| i.timer.is_some_and(|t| t.0 == id))
            .map(|queued| &mut queued.info)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl std::ops::Index<&u32> for Pending {
    type Output = Info;
    fn index(&self, sig: &u32) -> &Info {
        &self.0[sig].front().unwrap().info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deferred_delivery_restores_fifo_and_preserves_trace_observation() {
        let mut q = Pending::default();
        q.enqueue(
            34,
            Info {
                sender: 11,
                ..Default::default()
            },
        )
        .unwrap();
        let first = q.remove(&34).unwrap();
        q.enqueue(
            34,
            Info {
                sender: 22,
                ..Default::default()
            },
        )
        .unwrap();
        q.restore(34, first);
        let first = q
            .remove_for_trace(34)
            .expect("deferred delivery still needs its original trace point");
        assert_eq!(first.sender, 11);
        q.resume_observed(34, first);
        let first = q.remove(&34).unwrap();
        q.restore(34, first);
        assert!(
            q.remove_for_trace(34).is_none(),
            "an observed delivery is not traced twice"
        );
        assert_eq!(q.remove(&34).unwrap().sender, 11);
        assert_eq!(q.remove(&34).unwrap().sender, 22);
        assert!(q.is_empty());
    }
    #[test]
    fn realtime_budget_preserves_fifo_and_cannot_drop_sigkill() {
        let mut q = Pending::default();
        let info = |sender| Info {
            user: None,
            sender,
            uid: 123,
            status: 0,
            code: 0,
            timer: None,
            fault: None,
            poll: None,
        };
        for i in 0..4096 {
            q.enqueue(34, info(i)).unwrap();
        }
        assert_eq!(q.enqueue(34, info(9999)), Err(Errno(11)));
        q.enqueue(9, info(1)).unwrap();
        q.enqueue(9, info(2)).unwrap();
        assert_eq!(q.remove(&9).unwrap().sender, 1);
        assert!(!q.contains_key(&9));
        for i in 0..4096 {
            assert_eq!(q.remove(&34).unwrap().sender, i);
        }
        assert!(q.is_empty());
    }
}
