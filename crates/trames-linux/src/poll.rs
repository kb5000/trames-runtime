// SPDX-License-Identifier: GPL-3.0-or-later
//! ppoll on retained shared resources. Unsupported descriptors defer before output.
use crate::state::Linux;
use std::sync::Arc;
use std::time::Instant;
use trames_memory::{Access, CpuMemory};
use trames_vfs::{DirectFd, DirectFds, Errno, IoSignal, IoSubscription};

pub(crate) struct Poll {
    entries: Vec<(u64, u16, Option<DirectFd>)>,
}
impl Poll {
    pub fn prepare(
        fds: &DirectFds,
        memory: &impl CpuMemory,
        a: [u64; 6],
    ) -> Option<Result<Self, Errno>> {
        if a[1] > 256 {
            return Some(Err(Errno(22)));
        }
        if let Err(e) = Linux::check(memory, a[0], a[1] as usize * 8, Access::Write) {
            return Some(Err(e));
        }
        let mut entries = Vec::with_capacity(a[1] as usize);
        for i in 0..a[1] {
            let address = a[0] + i * 8;
            let bytes = match memory.read_array::<8>(address) {
                Ok(b) => b,
                Err(_) => return Some(Err(Errno(14))),
            };
            let fd = i32::from_le_bytes(bytes[..4].try_into().unwrap());
            let events = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
            let resource = if fd < 0 {
                None
            } else {
                let resource = fds.get(fd as u32)?;
                if resource.is_epoll() {
                    return None;
                }
                Some(resource)
            };
            entries.push((address + 6, events, resource));
        }
        Some(Ok(Self { entries }))
    }
    pub fn check(
        &self,
        memory: &mut impl CpuMemory,
        deadline: Option<Instant>,
    ) -> Result<u64, Errno> {
        let mut count = 0;
        let mut results = Vec::with_capacity(self.entries.len());
        for &(address, events, ref fd) in &self.entries {
            let ready = fd
                .as_ref()
                .map_or(0, |fd| fd.poll_ready(events).expect("pollable resource"));
            count += u64::from(ready != 0);
            results.push((address, ready));
        }
        if count == 0 && !deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Errno(11));
        }
        for (address, ready) in results {
            memory
                .write_array(address, ready.to_le_bytes())
                .map_err(|_| Errno(14))?;
        }
        Ok(count)
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.entries
            .iter()
            .filter_map(|(_, _, fd)| fd.as_ref())
            .flat_map(|fd| fd.subscribe(signal))
            .collect()
    }
    pub fn poll_identities(&self) -> Vec<usize> {
        self.entries
            .iter()
            .filter_map(|(_, _, fd)| fd.as_ref())
            .flat_map(|fd| fd.poll_identities())
            .collect()
    }
    pub fn next_deadline(&self) -> Option<Instant> {
        self.entries
            .iter()
            .filter_map(|(_, events, fd)| {
                (events & 1 != 0)
                    .then(|| fd.as_ref().and_then(DirectFd::next_deadline))
                    .flatten()
            })
            .min()
    }
}
