// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux sync_file and software timelines, on the original files_struct.
//! Points notify existing waiters after the timeline unlocks. No thread, polling
//! loop, copied FD number or guest memory borrow survives an ioctl.
use super::*;
use std::sync::{Mutex, OnceLock, Weak};
use trames_memory::CpuMemory;
#[cfg(test)]
#[path = "sync_file_tests.rs"]
mod tests;

const CREATE: u32 = 0xc0285700;
const INC: u32 = 0x40045701;
const MERGE: u32 = 0xc0303e03;
const INFO: u32 = 0xc0383e04;

fn later(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}
struct Point {
    context: u64,
    origin: std::time::Instant,
    value: u32,
    finished: OnceLock<(i32, u64)>,
    ready: Arc<Readiness>,
}
impl Point {
    fn status(&self) -> i32 {
        self.finished.get().map_or(0, |v| v.0)
    }
    fn finish(&self, status: i32) {
        if self
            .finished
            .set((status, self.origin.elapsed().as_nanos() as u64))
            .is_ok()
        {
            self.ready.notify_atomic();
        }
    }
}
#[derive(Default)]
struct Timeline {
    value: u32,
    points: Vec<Weak<Point>>,
}
enum Kind {
    Timeline(Mutex<Timeline>),
    Fence(Vec<Arc<Point>>),
}
pub struct File {
    origin: std::time::Instant,
    identity: u64,
    name: [u8; 32],
    kind: Kind,
    ready: Arc<Readiness>,
    links: OnceLock<(Arc<IoSignal>, Vec<IoSubscription>)>,
}
impl File {
    pub(super) fn timeline(origin: std::time::Instant) -> Arc<Self> {
        Arc::new(Self {
            origin,
            identity: trames_memory::new_backing_identity(),
            name: [0; 32],
            kind: Kind::Timeline(Mutex::default()),
            ready: Arc::default(),
            links: OnceLock::new(),
        })
    }
    fn fence(name: [u8; 32], points: Vec<Arc<Point>>) -> Arc<Self> {
        let file = Arc::new(Self {
            origin: points[0].origin,
            identity: trames_memory::new_backing_identity(),
            name,
            kind: Kind::Fence(points),
            ready: Arc::default(),
            links: OnceLock::new(),
        });
        let target: Arc<dyn IoWake> = file.clone();
        let signal = IoSignal::new(0, Arc::downgrade(&target));
        let Kind::Fence(points) = &file.kind else {
            unreachable!()
        };
        let subscriptions = points.iter().map(|p| p.ready.subscribe(&signal)).collect();
        let _ = file.links.set((signal, subscriptions));
        file
    }
    pub(super) fn is_fence(&self) -> bool {
        matches!(self.kind, Kind::Fence(_))
    }
    fn point(&self, value: u32) -> Arc<Point> {
        let Kind::Timeline(state) = &self.kind else {
            unreachable!()
        };
        let mut state = state.lock().unwrap();
        state.points.retain(|p| p.strong_count() != 0);
        if let Some(point) = state
            .points
            .iter()
            .filter_map(Weak::upgrade)
            .find(|p| p.value == value)
        {
            return point;
        }
        let point = Arc::new(Point {
            context: self.identity,
            origin: self.origin,
            value,
            finished: OnceLock::new(),
            ready: Arc::default(),
        });
        let signaled = !later(value, state.value);
        if !signaled {
            state.points.push(Arc::downgrade(&point));
        }
        drop(state);
        if signaled {
            point.finish(1);
        }
        point
    }
    fn increment(&self, mut amount: u32) {
        let Kind::Timeline(state) = &self.kind else {
            unreachable!()
        };
        loop {
            let step = amount.min(i32::MAX as u32);
            let mut state = state.lock().unwrap();
            state.value = state.value.wrapping_add(step);
            let value = state.value;
            let mut finished = Vec::new();
            state.points.retain(|p| {
                let Some(point) = p.upgrade() else {
                    return false;
                };
                if !later(point.value, value) {
                    finished.push(point);
                    false
                } else {
                    true
                }
            });
            drop(state);
            for point in finished {
                point.finish(1);
            }
            amount -= step;
            if amount == 0 {
                break;
            }
        }
    }
    fn status(&self) -> i32 {
        let Kind::Fence(points) = &self.kind else {
            return 0;
        };
        let mut status = 1;
        for point in points {
            let value = point.status();
            if value == 0 {
                return 0;
            }
            if status > 0 {
                status = value;
            }
        }
        status
    }
    pub(super) fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let status = self.status();
        (
            if status != 0 { events & 1 } else { 0 },
            [u64::from(status != 0), 0],
        )
    }
    pub(super) fn poll_handle(self: &Arc<Self>) -> Arc<dyn DirectPoll> {
        Arc::new(Poll {
            file: Arc::downgrade(self),
            identity: self.identity as usize,
            ready: self.ready.clone(),
        })
    }
    pub fn ioctl(
        &self,
        factory: &DescriptorFactory,
        cmd: u32,
        address: u64,
        memory: &mut impl CpuMemory,
    ) -> Result<u64> {
        match (&self.kind, cmd) {
            (Kind::Timeline(_), CREATE) => {
                let reserved = factory.files.reserve()?;
                let mut data = memory.read_array::<40>(address).map_err(|_| Errno(14))?;
                let point = self.point(u32::from_le_bytes(data[..4].try_into().unwrap()));
                let mut name: [u8; 32] = data[4..36].try_into().unwrap();
                name[31] = 0;
                let file = Self::fence(name, vec![point]);
                data[36..40].copy_from_slice(&(reserved.number() as i32).to_le_bytes());
                memory.write(address, &data).map_err(|_| Errno(14))?;
                reserved.publish(
                    events::anonymous_descriptor(
                        factory.open_id(),
                        O_CLOEXEC,
                        events::Anonymous::Sync(file),
                    ),
                    None,
                )?;
            }
            (Kind::Timeline(_), INC) => {
                self.increment(u32::from_le_bytes(
                    memory.read_array::<4>(address).map_err(|_| Errno(14))?,
                ));
            }
            (Kind::Fence(points), MERGE) => {
                let reserved = factory.files.reserve()?;
                let mut data = memory.read_array::<48>(address).map_err(|_| Errno(14))?;
                if data[40..48] != [0; 8] {
                    return Err(Errno(22));
                }
                let fd = u32::from_le_bytes(data[32..36].try_into().unwrap());
                let other = factory
                    .files
                    .lookup(fd)
                    .unwrap_or(Err(Errno(22)))
                    .map_err(|_| Errno(22))?;
                let Some(events::SharedControl::Sync(other)) = &other.open.control else {
                    return Err(Errno(22));
                };
                let Kind::Fence(other) = &other.kind else {
                    return Err(Errno(22));
                };
                let mut merged = BTreeMap::<u64, Arc<Point>>::new();
                for point in points.iter().chain(other) {
                    if point.status() != 0 {
                        continue;
                    }
                    let entry = merged.entry(point.context).or_insert_with(|| point.clone());
                    if later(point.value, entry.value) {
                        *entry = point.clone();
                    }
                }
                let points = if merged.is_empty() {
                    vec![self.completed_point()]
                } else {
                    merged.into_values().collect()
                };
                let mut name: [u8; 32] = data[..32].try_into().unwrap();
                name[31] = 0;
                let file = Self::fence(name, points);
                data[36..40].copy_from_slice(&(reserved.number() as i32).to_le_bytes());
                memory.write(address, &data).map_err(|_| Errno(14))?;
                reserved.publish(
                    events::anonymous_descriptor(
                        factory.open_id(),
                        O_CLOEXEC,
                        events::Anonymous::Sync(file),
                    ),
                    None,
                )?;
            }
            (Kind::Fence(points), INFO) => {
                let mut data = memory.read_array::<56>(address).map_err(|_| Errno(14))?;
                if data[36..40] != [0; 4] || data[44..48] != [0; 4] {
                    return Err(Errno(22));
                }
                let count = u32::from_le_bytes(data[40..44].try_into().unwrap()) as usize;
                if count != 0 {
                    if count < points.len() {
                        return Err(Errno(22));
                    }
                    let pointer = u64::from_le_bytes(data[48..56].try_into().unwrap());
                    for (i, point) in points.iter().enumerate() {
                        let mut info = [0; 80];
                        info[..7].copy_from_slice(b"trames\0");
                        info[32..40].copy_from_slice(b"sw_sync\0");
                        info[64..68].copy_from_slice(&point.status().to_le_bytes());
                        info[72..80].copy_from_slice(
                            &point.finished.get().map_or(0, |v| v.1).to_le_bytes(),
                        );
                        let target = pointer.checked_add((i * 80) as u64).ok_or(Errno(14))?;
                        memory.write(target, &info).map_err(|_| Errno(14))?;
                    }
                }
                data[..32].copy_from_slice(&self.name);
                data[32..36].copy_from_slice(&self.status().to_le_bytes());
                data[40..44].copy_from_slice(&(points.len() as u32).to_le_bytes());
                memory.write(address, &data).map_err(|_| Errno(14))?;
            }
            _ => return Err(Errno(25)),
        }
        Ok(0)
    }
    fn completed_point(&self) -> Arc<Point> {
        let point = Arc::new(Point {
            context: trames_memory::new_backing_identity(),
            origin: self.origin,
            value: 0,
            finished: OnceLock::new(),
            ready: Arc::default(),
        });
        point.finish(1);
        point
    }
}
impl Drop for File {
    fn drop(&mut self) {
        if let Kind::Timeline(state) = &mut self.kind {
            for point in state
                .get_mut()
                .unwrap()
                .points
                .iter()
                .filter_map(Weak::upgrade)
            {
                point.finish(-2);
            }
        }
    }
}
impl IoWake for File {
    fn wake_io(&self, signal: &Arc<IoSignal>) {
        // This signal relays multiple point transitions rather than admitting
        // one parked guest request. Rearm before notifying the actual waiters.
        signal.reset();
        self.ready.notify_atomic();
    }
}
struct Poll {
    file: Weak<File>,
    identity: usize,
    ready: Arc<Readiness>,
}
impl DirectPoll for Poll {
    fn identity(&self) -> usize {
        self.identity
    }
    fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        self.file
            .upgrade()
            .map_or((0x18, [u64::MAX, 0]), |f| f.poll(events))
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.ready.subscribe(signal)
    }
}
impl Vfs {
    pub fn sync_file(&self, fd: u32) -> Result<Option<Arc<File>>> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        Ok(match &open.control {
            Some(events::SharedControl::Sync(file)) => Some(file.clone()),
            _ => None,
        })
    }
}
