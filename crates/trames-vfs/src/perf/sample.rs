// SPDX-License-Identifier: GPL-3.0-or-later
//! Samples come from the original CPU actor at an actual execution boundary.
use super::*;

pub(super) const SUPPORTED: u64 =
    1 | 2 | 4 | 8 | 16 | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 16);
pub struct Sample {
    pub ip: u64,
    pub pid: u32,
    pub tid: u32,
    pub time: u64,
    pub cpu: u32,
}
pub(super) fn size(attr: &Attr, members: usize) -> usize {
    let mut size = 8 + (attr.sample_type & !16).count_ones() as usize * 8;
    if attr.sample_type & 16 != 0 {
        let suffix = usize::from(attr.format & 4 != 0) + usize::from(attr.format & 16 != 0);
        let words = 1
            + usize::from(attr.format & 1 != 0)
            + usize::from(attr.format & 2 != 0)
            + if attr.format & 8 != 0 {
                members * (1 + suffix)
            } else {
                suffix
            };
        size += words * 8;
    }
    size
}
pub(super) fn header(bytes: &mut [u8], kind: u32, misc: u16) {
    let len = u16::try_from(bytes.len()).expect("bounded software sample");
    bytes[..4].copy_from_slice(&kind.to_le_bytes());
    bytes[4..6].copy_from_slice(&misc.to_le_bytes());
    bytes[6..8].copy_from_slice(&len.to_le_bytes());
}
pub(super) struct Identity<'a> {
    pub(super) id: u64,
    pub(super) stream: u64,
    pub(super) namespace: &'a PidNamespace,
    pub(super) attr: &'a Attr,
}
impl Identity<'_> {
    fn task_id(&self, sample: &Sample, out: &mut Vec<u8>) {
        out.extend(self.namespace.local(sample.pid).to_le_bytes());
        out.extend(self.namespace.local(sample.tid).to_le_bytes());
    }
    pub(super) fn sample_id(&self, sample: &Sample, out: &mut Vec<u8>) {
        if !self.attr.sample_id_all {
            return;
        }
        let kind = self.attr.sample_type;
        if kind & 2 != 0 {
            self.task_id(sample, out);
        }
        if kind & 4 != 0 {
            out.extend(sample.time.to_le_bytes());
        }
        if kind & (1 << 6) != 0 {
            out.extend(self.id.to_le_bytes());
        }
        if kind & (1 << 9) != 0 {
            out.extend(self.stream.to_le_bytes());
        }
        if kind & (1 << 7) != 0 {
            out.extend(sample.cpu.to_le_bytes());
            out.extend([0; 4]);
        }
        if kind & (1 << 16) != 0 {
            out.extend(self.id.to_le_bytes());
        }
    }
    pub(super) fn sample_record(&self, sample: &Sample, period: u64, values: Vec<u64>) -> Vec<u8> {
        let kind = self.attr.sample_type;
        let mut out = vec![0; 8];
        if kind & (1 << 16) != 0 {
            out.extend(self.id.to_le_bytes());
        }
        if kind & 1 != 0 {
            out.extend(sample.ip.to_le_bytes());
        }
        if kind & 2 != 0 {
            self.task_id(sample, &mut out);
        }
        if kind & 4 != 0 {
            out.extend(sample.time.to_le_bytes());
        }
        if kind & 8 != 0 {
            out.extend(0u64.to_le_bytes());
        }
        if kind & (1 << 6) != 0 {
            out.extend(self.id.to_le_bytes());
        }
        if kind & (1 << 9) != 0 {
            out.extend(self.stream.to_le_bytes());
        }
        if kind & (1 << 7) != 0 {
            out.extend(sample.cpu.to_le_bytes());
            out.extend([0; 4]);
        }
        if kind & (1 << 8) != 0 {
            out.extend(period.to_le_bytes());
        }
        if kind & 16 != 0 {
            for value in values {
                out.extend(value.to_le_bytes());
            }
        }
        header(&mut out, 9, 2); // PERF_RECORD_SAMPLE, PERF_RECORD_MISC_USER
        out
    }
}
impl Group {
    pub(super) fn publish_userpages(&self) {
        for counter in self.members.values() {
            if counter.branch.is_none() {
                if let Some(ring) = counter.output.capture_owned() {
                    ring.userpage(counter.value, counter.time);
                }
            }
        }
    }
    pub(super) fn sample(&mut self, source: u64, context: &Sample) -> Vec<Arc<Readiness>> {
        self.settle(source);
        let due: Vec<_> = self
            .members
            .iter()
            .filter_map(|(&id, counter)| {
                (counter.running
                    && counter.config != 9
                    && counter.attr.period != 0
                    && counter.remaining == 0)
                    .then_some(id)
            })
            .collect();
        let mut changes = Vec::new();
        for id in due {
            let counter = &self.members[&id];
            if counter.attr.exclude_user {
                let counter = self.members.get_mut(&id).unwrap();
                counter.remaining = counter.attr.period.max(counter.settings.minimum_period());
                continue;
            }
            if let Some(ring) = counter.output.capture() {
                let values = if counter.attr.sample_type & 16 != 0 {
                    self.words(id, counter.attr.format)
                } else {
                    Vec::new()
                };
                let source = Identity {
                    id: counter.primary_id(id),
                    stream: id,
                    namespace: &counter.namespace,
                    attr: &counter.attr,
                };
                let record = source.sample_record(context, counter.attr.period, values);
                if ring.output(&record, context, true, &source, &counter.lost) {
                    changes.extend(ring.waiters());
                }
            }
            let counter = self.members.get_mut(&id).unwrap();
            // A delayed software timer has one real sampled IP. Re-arm from
            // this actual boundary rather than fabricating past samples.
            counter.remaining = counter.attr.period.max(counter.settings.minimum_period());
            if let Some(remaining) = &mut counter.refresh {
                *remaining = remaining.saturating_sub(1);
                if *remaining == 0 {
                    counter.enabled = false;
                    counter.exhausted = true;
                    counter.output.hangup();
                    changes.push(counter.changed.clone());
                }
            }
            counter.publish_branch();
        }
        self.sync();
        self.publish_userpages();
        changes
    }
}
