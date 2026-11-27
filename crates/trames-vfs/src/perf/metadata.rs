// SPDX-License-Identifier: GPL-3.0-or-later
//! Sideband records describe actual guest identities, names and mapped bytes.
use super::*;
use std::sync::RwLock;

#[derive(Clone)]
pub(crate) struct ImageSource(
    pub(crate) Arc<RwLock<Option<Arc<crate::proc_source::ProcessImage>>>>,
    pub(crate) Arc<AtomicU64>,
);
#[derive(Clone)]
pub(crate) struct Image {
    pub identity: u64,
    pub exec: u64,
    pub pid: u32,
    pub tid: u32,
    pub parent: u32,
    pub comm: Vec<u8>,
    pub maps: Arc<[u8]>,
}
pub(super) struct Seen {
    comm: Vec<u8>,
    maps: Arc<[u8]>,
    exec: u64,
    tid: u32,
}
impl ImageSource {
    pub fn current(&self) -> Option<Image> {
        let image = self.0.read().unwrap().clone()?;
        Some(Image {
            identity: image.identity,
            exec: self.1.load(Ordering::Relaxed),
            pid: image.metadata.tgid,
            tid: image.metadata.pid,
            parent: image.metadata.parent,
            comm: image
                .resources
                .name
                .as_ref()
                .map_or_else(|| image.legacy_command.clone(), TaskName::get),
            maps: image.memory.as_ref().map_or_else(
                || Arc::from(image.maps.as_slice()),
                trames_memory::MemoryReport::maps,
            ),
        })
    }
}
fn output(
    counter: &Counter,
    id: u64,
    context: &Sample,
    kind: u32,
    misc: u16,
    mut payload: Vec<u8>,
) -> Vec<Arc<Readiness>> {
    let Some(ring) = counter.output.capture() else {
        return Vec::new();
    };
    let identity = sample::Identity {
        id: counter.primary_id(id),
        stream: id,
        namespace: &counter.namespace,
        attr: &counter.attr,
    };
    let mut record = vec![0; 8];
    record.append(&mut payload);
    identity.sample_id(context, &mut record);
    if record.len() > u16::MAX as usize {
        return Vec::new();
    }
    sample::header(&mut record, kind, misc);
    if ring.output(&record, context, false, &identity, &counter.lost) {
        ring.waiters()
    } else {
        Vec::new()
    }
}
pub(super) fn throttle(
    counter: &Counter,
    id: u64,
    context: &Sample,
    kind: u32,
) -> Vec<Arc<Readiness>> {
    output(
        counter,
        id,
        context,
        kind,
        0,
        [context.time, counter.primary_id(id), id]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect(),
    )
}
fn map_fields(mut line: &[u8]) -> Option<[&[u8]; 6]> {
    let mut result = [&[][..]; 6];
    for field in &mut result[..5] {
        let length = line
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(line.len());
        if length == 0 {
            return None;
        }
        *field = &line[..length];
        line = &line[length..];
        while line.first().is_some_and(u8::is_ascii_whitespace) {
            line = &line[1..];
        }
    }
    result[5] = line;
    Some(result)
}
fn nul(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend(bytes.iter().copied().take_while(|byte| *byte != 0));
    out.push(0);
    while out.len() % 8 != 0 {
        out.push(0);
    }
}
impl Clock {
    pub(crate) fn family_record(&self, kind: u32, context: &Sample, parent: u32, parent_tid: u32) {
        self.task_record(kind, context, parent, parent_tid);
        let filtered = self.0.filters.lock().get(&context.cpu).cloned();
        if let Some(filtered) = filtered {
            filtered.task_record(kind, context, parent, parent_tid);
        }
    }
    pub(crate) fn metadata(&self, image: &Image, context: &Sample) {
        if !self.0.metadata.load(Ordering::Relaxed) || !self.0.active.load(Ordering::Relaxed) {
            return;
        }
        let epoch = image.exec;
        let (comm, maps, exec) = {
            let mut history = self.0.history.lock();
            let previous = history.get(&image.identity);
            let exec = previous.map_or(epoch != 0, |old| old.exec != epoch);
            let comm = previous.is_none_or(|old| old.comm != image.comm) || exec;
            let maps = if previous.is_some_and(|old| Arc::ptr_eq(&old.maps, &image.maps) && !exec) {
                Vec::new()
            } else {
                let old = previous
                    .filter(|_| !exec)
                    .map(|old| old.maps.as_ref())
                    .unwrap_or_default();
                image
                    .maps
                    .split(|b| *b == b'\n')
                    .filter(|line| {
                        !line.is_empty()
                            && !old.split(|b| *b == b'\n').any(|before| before == *line)
                    })
                    .map(<[u8]>::to_vec)
                    .collect()
            };
            history.insert(
                image.identity,
                Seen {
                    comm: image.comm.clone(),
                    maps: image.maps.clone(),
                    exec: epoch,
                    tid: image.tid,
                },
            );
            (comm, maps, exec)
        };
        let mut changed = Vec::new();
        for group in self.groups() {
            let mut group = group.lock();
            group.settle(self.read());
            for (&id, counter) in group.members.iter().filter(|(_, counter)| counter.running) {
                let flags = counter.attr.metadata;
                let ids = || {
                    let mut out = counter.namespace.local(image.pid).to_le_bytes().to_vec();
                    out.extend(counter.namespace.local(image.tid).to_le_bytes());
                    out
                };
                if comm && flags & (1 << 9) != 0 {
                    let mut payload = ids();
                    nul(&image.comm, &mut payload);
                    changed.extend(output(
                        counter,
                        id,
                        context,
                        3,
                        if exec { 1 << 13 } else { 0 },
                        payload,
                    ));
                }
                if flags & ((1 << 8) | (1 << 17) | (1 << 23)) == 0 {
                    continue;
                }
                for line in &maps {
                    let Some(fields) = map_fields(line) else {
                        continue;
                    };
                    let hex = |bytes: &[u8]| {
                        std::str::from_utf8(bytes)
                            .ok()
                            .and_then(|text| u64::from_str_radix(text, 16).ok())
                    };
                    let Some(dash) = fields[0].iter().position(|b| *b == b'-') else {
                        continue;
                    };
                    let (Some(start), Some(end), Some(offset)) = (
                        hex(&fields[0][..dash]),
                        hex(&fields[0][dash + 1..]),
                        hex(fields[2]),
                    ) else {
                        continue;
                    };
                    let permissions = fields[1];
                    let executable = permissions.contains(&b'x');
                    if if executable {
                        flags & ((1 << 8) | (1 << 23)) == 0
                    } else {
                        flags & (1 << 17) == 0
                    } {
                        continue;
                    }
                    let mut payload = ids();
                    for value in [start, end - start, offset] {
                        payload.extend(value.to_le_bytes());
                    }
                    let mmap2 = flags & (1 << 23) != 0;
                    if mmap2 {
                        let mut dev = fields[3].split(|b| *b == b':');
                        for _ in 0..2 {
                            payload.extend(
                                (dev.next().and_then(hex).unwrap_or(0) as u32).to_le_bytes(),
                            );
                        }
                        let inode = std::str::from_utf8(fields[4])
                            .ok()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);
                        payload.extend(inode.to_le_bytes());
                        payload.extend(0u64.to_le_bytes());
                        let prot = u32::from(permissions.contains(&b'r'))
                            | (u32::from(permissions.contains(&b'w')) * 2)
                            | (u32::from(executable) * 4);
                        payload.extend(prot.to_le_bytes());
                        payload.extend(
                            (if permissions.contains(&b's') {
                                1u32
                            } else {
                                2u32
                            })
                            .to_le_bytes(),
                        );
                    }
                    nul(
                        if fields[5].is_empty() {
                            b"//anon"
                        } else {
                            fields[5]
                        },
                        &mut payload,
                    );
                    changed.extend(output(
                        counter,
                        id,
                        context,
                        if mmap2 { 10 } else { 1 },
                        2,
                        payload,
                    ));
                }
            }
        }
        for changed in changed {
            changed.notify_atomic();
        }
    }
    pub(crate) fn task_record(&self, kind: u32, context: &Sample, parent: u32, parent_tid: u32) {
        if kind == 4 {
            self.0
                .history
                .lock()
                .retain(|_, seen| seen.tid != context.tid);
        }
        if !self.0.metadata.load(Ordering::Relaxed) {
            return;
        }
        let mut changed = Vec::new();
        for group in self.groups() {
            let mut group = group.lock();
            group.settle(self.read());
            for (&id, counter) in group
                .members
                .iter()
                .filter(|(_, counter)| counter.running && counter.attr.metadata & (1 << 13) != 0)
            {
                let mut payload = Vec::new();
                for value in [context.pid, parent, context.tid, parent_tid] {
                    payload.extend(counter.namespace.local(value).to_le_bytes());
                }
                payload.extend(context.time.to_le_bytes());
                changed.extend(output(counter, id, context, kind, 0, payload));
            }
        }
        for changed in changed {
            changed.notify_atomic();
        }
    }
}
impl Domain {
    pub(crate) fn task_record(
        &self,
        kind: u32,
        context: &Sample,
        parent: u32,
        parent_tid: u32,
        group: Option<&CgroupTask>,
    ) {
        if self.active.load(Ordering::Relaxed) == 0 {
            return;
        }
        let clocks = {
            let cpus = self.cpus.lock();
            let Some(cpu) = cpus.get(&context.cpu) else {
                return;
            };
            std::iter::once(cpu.clock.clone())
                .chain(
                    cpu.groups
                        .iter()
                        .filter(|(scope, _)| group.is_some_and(|group| scope.0.contains(group)))
                        .filter_map(|(_, clock)| clock.upgrade().map(Clock)),
                )
                .collect::<Vec<_>>()
        };
        for clock in clocks {
            clock.task_record(kind, context, parent, parent_tid);
        }
    }
}
