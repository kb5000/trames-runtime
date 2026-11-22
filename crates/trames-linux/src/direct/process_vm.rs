// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::process_memory::{copy_local, import, Vectors};
use trames_memory::{TransferError, TransferRequest, TransferTarget, PAGE_SIZE, TRANSFER_WINDOW};

struct Cursor {
    vectors: std::vec::IntoIter<(u64, u64)>,
    offset: u64,
}
impl Cursor {
    fn new(vectors: Vectors) -> Self {
        Self {
            vectors: vectors.into_iter(),
            offset: 0,
        }
    }
    fn span(&mut self) -> Result<Option<(u64, u64)>, Errno> {
        while let Some(&(base, len)) = self.vectors.as_slice().first() {
            if self.offset < len {
                return Ok(Some((
                    base.checked_add(self.offset).ok_or(Errno(14))?,
                    len - self.offset,
                )));
            }
            self.vectors.next();
            self.offset = 0;
        }
        Ok(None)
    }
}

pub(super) struct Copy {
    target: TransferTarget,
    local: Cursor,
    remote: Cursor,
    write: bool,
    done: u64,
    inflight: Option<(Arc<TransferRequest>, u64, usize)>,
    word: Option<[u8; 8]>,
}

fn local_bytes(address: u64, data: &mut [u8], memory: &mut impl CpuMemory, write: bool) -> usize {
    let mut done = 0;
    while done < data.len() {
        let Some(address) = address.checked_add(done as u64) else {
            break;
        };
        let end = data
            .len()
            .min(done + (PAGE_SIZE - address % PAGE_SIZE) as usize);
        let result = if write {
            memory.write(address, &data[done..end])
        } else {
            memory.read(address, &mut data[done..end])
        };
        if result.is_err() {
            break;
        }
        done = end;
    }
    done
}

impl Copy {
    fn step(
        &mut self,
        memory: &mut impl CpuMemory,
        signal: &Arc<IoSignal>,
        peek: bool,
    ) -> Result<Option<u64>, Errno> {
        if let Some((request, local, requested)) = &self.inflight {
            let Some(result) = request.take() else {
                return Ok(None);
            };
            if peek {
                let bytes = result.map_err(|e| match e {
                    TransferError::Fault => Errno(5),
                    other => errno(other),
                })?;
                if bytes.len() != 8 {
                    return Err(Errno(5));
                }
                if !self.write {
                    memory.write(*local, &bytes).map_err(|_| Errno(14))?;
                }
                return Ok(Some(0));
            }
            let mut bytes = result.map_err(errno)?;
            let n = if self.write {
                bytes.len()
            } else {
                local_bytes(*local, &mut bytes, memory, true)
            };
            self.done += n as u64;
            if n < *requested {
                return if self.done == 0 {
                    Err(Errno(14))
                } else {
                    Ok(Some(self.done))
                };
            }
            self.local.offset += n as u64;
            self.remote.offset += n as u64;
            self.inflight = None;
        }
        let Some((local, n)) = self.local.span()? else {
            return Ok(Some(self.done));
        };
        let Some((remote, m)) = self.remote.span()? else {
            return Ok(Some(self.done));
        };
        let size = n.min(m).min(TRANSFER_WINDOW as u64) as usize;
        let mut data = vec![0; size];
        if let Some(word) = self.word {
            data.copy_from_slice(&word);
        } else if self.write {
            let read = local_bytes(local, &mut data, memory, false);
            if read == 0 {
                return Err(Errno(14));
            }
            data.truncate(read);
        }
        let request = if peek {
            self.target.submit_ptrace(
                remote,
                self.write,
                data.as_slice().try_into().unwrap(),
                signal.clone(),
            )
        } else {
            self.target.submit(remote, self.write, data, signal.clone())
        }
        .map_err(errno)?;
        self.inflight = Some((request, local, size));
        Ok(None)
    }
}
fn errno(error: TransferError) -> Errno {
    Errno(match error {
        TransferError::Retired => 3,
        TransferError::Fault => 14,
        TransferError::Unavailable => 38,
    })
}

impl DirectSyscalls {
    pub fn start_process_vm(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        tid: u32,
        wake: &Weak<dyn IoWake>,
        admit: impl FnOnce() -> Result<Option<TransferTarget>, Errno>,
    ) -> IoAttempt {
        // Linux PEEK returns one word through the fourth syscall argument.
        // Short remote reads must leave the output word untouched.
        let vectors = if number == 117 {
            if !matches!(args[0], 1 | 2 | 4 | 5) {
                return IoAttempt::Complete(Err(Errno(22)));
            }
            Ok(Some((vec![(args[3], 8)], vec![(args[2], 8)])))
        } else {
            import(args, memory)
        };
        let (local, remote) = match vectors {
            Ok(Some(vectors)) => vectors,
            Ok(None) => return IoAttempt::Complete(Ok(0)),
            Err(error) => return IoAttempt::Complete(Err(error)),
        };
        let target = match admit() {
            Ok(Some(target)) => target,
            Ok(None) if number == 117 => {
                return IoAttempt::Complete(if matches!(args[0], 4 | 5) {
                    memory
                        .write_array(args[2], args[3].to_le_bytes())
                        .map(|_| 0)
                        .map_err(|_| Errno(5))
                } else {
                    memory
                        .read_array::<8>(args[2])
                        .map_err(|_| Errno(5))
                        .and_then(|word| {
                            memory.write_array(args[3], word).map_err(|_| Errno(14))?;
                            Ok(0)
                        })
                });
            }
            Ok(None) => return IoAttempt::Complete(copy_local(number, local, remote, memory)),
            Err(error) => return IoAttempt::Complete(Err(error)),
        };
        let copy = Copy {
            target,
            local: Cursor::new(local),
            remote: Cursor::new(remote),
            write: number == 271 || number == 117 && matches!(args[0], 4 | 5),
            word: (number == 117 && matches!(args[0], 4 | 5)).then(|| args[3].to_le_bytes()),
            done: 0,
            inflight: None,
        };
        self.resume_process_vm(
            PendingIo {
                process_vm: Some(Box::new(copy)),
                number,
                args,
                signal: IoSignal::new(tid, wake.clone()),
                target: wake.clone(),
                binder: None,
                aio: None,
                message: None,
                deadline: None,
                flock: None,
                record: None,
                retained_byte: None,
                retained_socket: None,
                native_tcp: None,
                resource_deadline: None,
                retained_poll: None,
                epoll_revision: None,
                terminal_job: false,
                _subscriptions: Vec::new(),
                host_subscription: None,
                socket_subscriptions: Vec::new(),
                uring: None,
                poll_uring: None,
                file: None,
                fifo_open: None,
            },
            memory,
        )
    }
    pub(super) fn resume_process_vm(
        &self,
        mut pending: PendingIo,
        memory: &mut impl CpuMemory,
    ) -> IoAttempt {
        pending.signal.reset();
        let copy = pending.process_vm.as_mut().unwrap();
        let result = match copy.step(memory, &pending.signal, pending.number == 117) {
            Ok(None) => return IoAttempt::Blocked(pending),
            Ok(Some(n)) => Ok(n),
            Err(_) if copy.done != 0 => Ok(copy.done),
            Err(error) => Err(error),
        };
        IoAttempt::Complete(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};

    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }

    #[test]
    fn ptrace_word_never_copies_a_prefix_of_an_inaccessible_word() {
        let mut local = Memory::default();
        let mut remote = Memory::default();
        local.map(PAGE_SIZE, PAGE_SIZE, Permissions::RW).unwrap();
        remote.map(PAGE_SIZE, PAGE_SIZE, Permissions::RW).unwrap();
        local.write_array(PAGE_SIZE, *b"sentinel").unwrap();
        remote.write_array(2 * PAGE_SIZE - 4, *b"abcd").unwrap();
        remote.memory_report().bind_read_waker(Arc::new(|_| {}));
        let direct = DirectSyscalls::new(trames_vfs::Vfs::default().direct_descriptors());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let IoAttempt::Blocked(wait) = direct.start_process_vm(
            117,
            [2, 42, 2 * PAGE_SIZE - 4, PAGE_SIZE, 0, 0],
            &mut local,
            1,
            &Arc::downgrade(&wake),
            || Ok(Some(remote.transfer_target())),
        ) else {
            panic!("expected pending word");
        };
        assert!(remote.activate_proc_reads());
        assert!(matches!(
            direct.resume(wait, &mut local),
            IoAttempt::Complete(Err(Errno(5)))
        ));
        assert_eq!(local.read_array::<8>(PAGE_SIZE).unwrap(), *b"sentinel");
    }

    #[test]
    fn inaccessible_second_page_preserves_exact_progress_at_either_end() {
        for write in [false, true] {
            for fault_at_target in [false, true] {
                let mut local = Memory::default();
                let mut remote = Memory::default();
                for mm in [&mut local, &mut remote] {
                    mm.map(0x1000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
                }
                let data = if write { &mut local } else { &mut remote };
                data.write(0x2ffc, b"abcdefgh").unwrap();
                let fault = if fault_at_target {
                    &mut remote
                } else {
                    &mut local
                };
                fault.protect(0x3000, PAGE_SIZE, Permissions::NONE).unwrap();
                local.write_array(0x1000, 0x2ffcu64.to_le_bytes()).unwrap();
                local.write_array(0x1008, 8u64.to_le_bytes()).unwrap();
                remote.memory_report().bind_read_waker(Arc::new(|_| {}));
                let vfs = trames_vfs::Vfs::default();
                let direct = DirectSyscalls::new(vfs.direct_descriptors());
                let wake: Arc<dyn IoWake> = Arc::new(Wake);
                let IoAttempt::Blocked(wait) = direct.start_process_vm(
                    if write { 271 } else { 270 },
                    [2, 0x1000, 1, 0x1000, 1, 0],
                    &mut local,
                    1,
                    &Arc::downgrade(&wake),
                    || Ok(Some(remote.transfer_target())),
                ) else {
                    panic!("expected target work")
                };
                assert!(remote.activate_proc_reads());
                let result = direct.resume(wait, &mut local);
                assert!(matches!(result, IoAttempt::Complete(Ok(4))));
                let output = if write { &mut remote } else { &mut local };
                output.protect(0x3000, PAGE_SIZE, Permissions::RW).unwrap();
                assert_eq!(output.read_array::<8>(0x2ffc).unwrap(), *b"abcd\0\0\0\0");
            }
        }
    }
}
