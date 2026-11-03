// SPDX-License-Identifier: GPL-3.0-or-later
//! FASYNC state belongs to an OFD, not its numeric descriptor or a coordinator.
use super::*;
use std::sync::{Mutex, Weak};

pub trait AsyncOwner: Send + Sync {
    fn identity(&self) -> (u32, u32);
    fn signal(&self, signal: u32, fd: u32, band: u32);
}
pub trait AsyncOwners {
    fn resolve(&self, kind: u32, pid: u32) -> Result<Arc<dyn AsyncOwner>>;
    fn visible(&self, pid: u32) -> u32;
}
pub trait TaskSignal: Send + Sync {
    fn raise(&self, signal: u32);
}
#[derive(Default)]
pub(super) struct AsyncState {
    settings: Mutex<Settings>,
    observer: Mutex<Option<Observer>>,
}
#[derive(Default)]
struct Settings {
    owner: Option<Arc<dyn AsyncOwner>>,
    signal: u32,
    fd: u32,
}
struct Observer {
    _wake: Arc<dyn IoWake>,
    _signal: Arc<IoSignal>,
    _subscriptions: Vec<IoSubscription>,
}
struct Wake {
    state: Weak<AsyncState>,
    target: direct_io::WatchResource,
    previous: Mutex<(u16, [u64; 2])>,
}
impl IoWake for Wake {
    fn wake_io(&self, signal: &Arc<IoSignal>) {
        signal.reset();
        let (Some(state), Some(fd)) = (self.state.upgrade(), self.target.resolve()) else {
            return;
        };
        let (ready, epoch) = fd.peek_poll(5);
        let mut previous = self.previous.lock().unwrap();
        let mut changed = ready & !previous.0;
        if epoch[0] != previous.1[0] {
            changed |= ready & 3;
        }
        if epoch[1] != previous.1[1] {
            changed |= ready & 4;
        }
        *previous = (ready, epoch);
        drop(previous);
        if changed == 0 {
            return;
        }
        let settings = state.settings.lock().unwrap();
        let owner = settings.owner.clone();
        let number = settings.signal;
        let fd = settings.fd;
        drop(settings);
        if let Some(owner) = owner {
            // POLL_IN/POLL_OUT/POLL_HUP are positive si_codes, and si_band is
            // the Linux poll event mask. A zero F_SETSIG uses ordinary SIGIO.
            owner.signal(number, fd, changed as u32);
        }
    }
}
impl AsyncState {
    pub(super) fn enable(
        self: &Arc<Self>,
        fd: &DirectFd,
        number: u32,
        enabled: bool,
    ) -> Result<()> {
        let mut observer = self.observer.lock().unwrap();
        if !enabled {
            let old = observer.take();
            drop(observer);
            drop(old);
            return Ok(());
        }
        if !fd.supports_async() {
            return Err(Errno(95));
        }
        self.settings.lock().unwrap().fd = number;
        if observer.is_some() {
            return Ok(());
        }
        let wake: Arc<dyn IoWake> = Arc::new(Wake {
            state: Arc::downgrade(self),
            target: direct_io::WatchResource::notification(fd),
            previous: Mutex::new(fd.peek_poll(5)),
        });
        let signal = IoSignal::new(0, Arc::downgrade(&wake));
        let subscriptions = fd.subscribe(&signal);
        *observer = Some(Observer {
            _wake: wake,
            _signal: signal,
            _subscriptions: subscriptions,
        });
        Ok(())
    }
}
impl FdFlags {
    pub fn async_control(
        &self,
        fd: u32,
        command: u32,
        argument: u64,
        memory: &mut impl trames_memory::CpuMemory,
        owners: &impl AsyncOwners,
    ) -> Result<u64> {
        let status = self.with_flags(fd, |status, _| Ok(status.clone()))?;
        if status.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        let state = status.async_state();
        match command {
            8 | 15 => {
                let (kind, pid) = if command == 8 {
                    let pid = argument as i32;
                    if pid == i32::MIN {
                        return Err(Errno(22));
                    }
                    (if pid < 0 { 2 } else { 1 }, pid.unsigned_abs())
                } else {
                    let b = memory.read_array::<8>(argument).map_err(|_| Errno(14))?;
                    let kind = u32::from_le_bytes(b[..4].try_into().unwrap());
                    let pid = i32::from_le_bytes(b[4..].try_into().unwrap());
                    if kind > 2 || pid < 0 {
                        return Err(Errno(22));
                    }
                    (kind, pid as u32)
                };
                let owner = if pid == 0 {
                    None
                } else {
                    Some(owners.resolve(kind, pid)?)
                };
                state.settings.lock().unwrap().owner = owner;
                Ok(0)
            }
            9 | 16 => {
                let settings = state.settings.lock().unwrap();
                let (kind, pid) = settings.owner.as_ref().map_or((1, 0), |o| o.identity());
                let pid = owners.visible(pid);
                if command == 9 {
                    return Ok(if kind == 2 {
                        (-(pid as i32) as i64) as u64
                    } else {
                        pid as u64
                    });
                }
                let mut b = [0; 8];
                b[..4].copy_from_slice(&kind.to_le_bytes());
                b[4..].copy_from_slice(&pid.to_le_bytes());
                memory.write_array(argument, b).map_err(|_| Errno(14))?;
                Ok(0)
            }
            10 => {
                if argument > 64 {
                    return Err(Errno(22));
                }
                state.settings.lock().unwrap().signal = argument as u32;
                Ok(0)
            }
            11 => Ok(state.settings.lock().unwrap().signal as u64),
            _ => Err(Errno(22)),
        }
    }
    pub fn set_async(&self, fds: &DirectFds, fd: u32, enabled: bool) -> Result<u64> {
        let target = fds
            .get(fd)
            .ok_or_else(|| self.get(fd).err().unwrap_or(Errno(95)))?;
        target.set_async(fd, enabled)
    }
    pub fn set_status(&self, fds: &DirectFds, fd: u32, flags: u32) -> Result<u64> {
        fd_status::StatusFlags::validate(flags)?;
        let status = self.with_flags(fd, |status, _| Ok(status.clone()))?;
        {
            // Only this OFD's status/list invariant needs a lock. GETFL and
            // ordinary byte I/O keep their original atomic flags reads.
            let _update = status.lock_update();
            if status.get() & O_PATH != 0 {
                return Err(Errno(9));
            }
            if (status.get() | flags) & 0x2000 == 0 {
                status.store_locked(flags)?;
                return Ok(0);
            }
        }
        let target = fds.get(fd).ok_or(Errno(95))?;
        target.set_status(fd, flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Owner(Mutex<Vec<(u32, u32, u32)>>);
    impl AsyncOwner for Owner {
        fn identity(&self) -> (u32, u32) {
            (1, 42)
        }
        fn signal(&self, signal: u32, fd: u32, band: u32) {
            self.0.lock().unwrap().push((signal, fd, band));
        }
    }
    struct Routes(Arc<Owner>);
    impl AsyncOwners for Routes {
        fn resolve(&self, kind: u32, pid: u32) -> Result<Arc<dyn AsyncOwner>> {
            assert_eq!((kind, pid), (1, 42));
            Ok(self.0.clone())
        }
        fn visible(&self, pid: u32) -> u32 {
            pid
        }
    }
    #[test]
    fn async_pipe_observes_repeated_events_shares_ofd_state_and_stops_on_disable() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(0).unwrap();
        let alias = v.dup(reader, 0, false).unwrap();
        let owner = Arc::new(Owner(Mutex::default()));
        let routes = Routes(owner.clone());
        let mut memory = trames_memory::Memory::default();
        let flags = v.fd_flags_snapshot();
        let fds = v.direct_descriptors();
        flags
            .async_control(reader, 8, 42, &mut memory, &routes)
            .unwrap();
        flags
            .async_control(alias, 10, 35, &mut memory, &routes)
            .unwrap();
        flags.set_status(&fds, reader, 0x2000).unwrap();
        assert_eq!(flags.get(alias).unwrap() & 0x2000, 0x2000);
        let mut child = v.clone();
        child.close(reader).unwrap();
        v.close(reader).unwrap();
        for _ in 0..2 {
            v.write(writer, b"x").unwrap();
            assert_eq!(child.read(alias, 1).unwrap(), b"x");
        }
        assert_eq!(
            *owner.0.lock().unwrap(),
            vec![(35, reader, 1), (35, reader, 1)]
        );
        flags.set_async(&fds, alias, false).unwrap();
        v.write(writer, b"z").unwrap();
        assert_eq!(owner.0.lock().unwrap().len(), 2);
        assert_eq!(child.flags(alias).unwrap() & 0x2000, 0);
    }
}
