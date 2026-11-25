// SPDX-License-Identifier: GPL-3.0-or-later
//! An original dequeued work item owns its reply through user copy. Buffer
//! visibility/call-stack publication follows the last successful reply byte.
use super::*;

#[derive(Default)]
pub(super) struct Read {
    pub cursor: usize,
    pub initialized: bool,
    pub noop: bool,
    pub written: bool,
    pub dequeued: bool,
    pub process_work: Option<bool>,
    pub nonblocking: bool,
}
pub(super) struct Item {
    len: usize,
    stop: bool,
    notice: Option<Arc<Node>>,
    buffer: Option<Arc<Buffer>>,
    call: Option<Arc<Call>>,
    committed: bool,
    return_error: bool,
}
impl Item {
    pub fn commit(mut self, request: &mut Ioctl) -> Result<()> {
        if self.return_error {
            if let Some(thread) = request
                .process
                .state
                .lock()
                .unwrap()
                .threads
                .get_mut(&request.tid)
            {
                thread.return_error = false;
            }
        }
        if let Some(buffer) = &self.buffer {
            let mut state = request.process.state.lock().unwrap();
            if state.closed {
                return Err(Errno(111));
            }
            buffer.received.store(true, Ordering::Relaxed);
            if let Some(call) = &buffer.call {
                call.to_tid.store(request.tid as u64, Ordering::Relaxed);
                state
                    .threads
                    .entry(request.tid)
                    .or_default()
                    .stack
                    .push(call.clone());
            }
        }
        request.read.cursor = request.read.cursor.checked_add(self.len).ok_or(Errno(14))?;
        request.read.written |= self.len != 0;
        self.committed = true;
        if let Some(notice) = self.notice.take() {
            notice.notice_delivered();
        }
        if self.stop {
            request.phase = Phase::ReadDone;
        }
        Ok(())
    }
}
impl Drop for Item {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(call) = self.call.take() {
                call.fail_with(BR_FAILED_REPLY);
            }
        }
    }
}
impl Ioctl {
    pub(super) fn read_one(&mut self) -> Result<bool> {
        let capacity = usize::try_from(word(&self.header, 24)).map_err(|_| Errno(22))?;
        if capacity == 0 {
            self.phase = Phase::Publish;
            self.result = Some(Ok(0));
            return Ok(true);
        }
        if !self.read.initialized {
            self.read.cursor = usize::try_from(word(&self.header, 32)).map_err(|_| Errno(22))?;
            self.read.nonblocking = self.file.open.flags.get() & O_NONBLOCK != 0;
            self.read.initialized = true;
            self.read.noop = self.read.cursor != 0;
        }
        let base = word(&self.header, 40);
        if !self.read.noop {
            self.output.push_slice(base, &BR_NOOP.to_le_bytes());
            self.after = Some(After::Noop);
            return Ok(true);
        }
        let process_work = *self.read.process_work.get_or_insert_with(|| {
            let mut state = self.process.state.lock().unwrap();
            let thread = state.threads.entry(self.tid).or_default();
            thread.stack.is_empty() && thread.queue.is_empty()
        });
        let work = {
            let mut state = self.process.state.lock().unwrap();
            if state.closed {
                return Err(Errno(111));
            }
            let thread = state.threads.entry(self.tid).or_default();
            thread.waiting = false;
            let process_queue = thread.queue.is_empty();
            let candidate = if let Some(work) = thread.queue.front() {
                Some(work)
            } else if process_work {
                state.queue.front()
            } else {
                None
            };
            if let Some(candidate) = candidate {
                // The native reader reserves room for its largest transaction
                // record before dequeuing any work, including short notices.
                let room = capacity.wrapping_sub(self.read.cursor);
                if room < 76 || candidate.size() > room {
                    self.phase = Phase::ReadDone;
                    return Ok(true);
                }
                if process_queue {
                    state.queue.pop_front()
                } else {
                    state.threads.get_mut(&self.tid).unwrap().queue.pop_front()
                }
            } else {
                None
            }
        };
        let Some(work) = work else {
            if self.read.written {
                self.phase = Phase::ReadDone;
                return Ok(true);
            }
            if self.read.dequeued {
                self.read.dequeued = false;
                if self.read.cursor != 4 {
                    self.phase = Phase::ReadDone;
                } else {
                    self.read.process_work = None;
                }
                return Ok(true);
            }
            if self.read.nonblocking {
                return Err(Errno(11));
            }
            self.process
                .state
                .lock()
                .unwrap()
                .threads
                .entry(self.tid)
                .or_default()
                .waiting = process_work;
            return Ok(false);
        };
        self.read.dequeued = true;
        if let Work::Reply(_, call) = &work {
            self.pop_call(call);
        }
        let mut item = Item {
            len: 0,
            stop: false,
            notice: None,
            buffer: None,
            call: None,
            committed: false,
            return_error: false,
        };
        let output = match work {
            Work::Bytes(bytes) => bytes,
            Work::ReturnError(code) => {
                item.return_error = true;
                command(code, &[])
            }
            Work::Node(node) => {
                let out = node.notices();
                item.notice = Some(node);
                out
            }
            Work::Death(cookie) => {
                item.stop = true;
                command(BR_DEAD_BINDER, &cookie.to_le_bytes())
            }
            Work::ClearDeath(cookie) => command(BR_CLEAR_DEATH, &cookie.to_le_bytes()),
            Work::Dead(call, error) => {
                self.pop_call(&call);
                item.stop = true;
                command(error, &[])
            }
            Work::Transaction(buffer) | Work::Reply(buffer, _) => {
                let reply = buffer.node.is_none();
                if let Err(error) = buffer.install(&self.factory) {
                    if let Some(call) = &buffer.call {
                        call.fail_with(BR_FAILED_REPLY);
                    }
                    if reply {
                        item.stop = true;
                        command(BR_FAILED_REPLY, &[])
                    } else {
                        let _ = error;
                        return Ok(true);
                    }
                } else {
                    let address = buffer.pool.base + buffer.offset as u64;
                    let accepted = {
                        let mut state = self.process.state.lock().unwrap();
                        if state.closed {
                            false
                        } else {
                            state.buffers.insert(address, buffer.clone());
                            true
                        }
                    };
                    if !accepted {
                        if let Some(call) = &buffer.call {
                            call.fail();
                        }
                        return Err(Errno(111));
                    }
                    let mut header = buffer.header;
                    let sender = if dword(&header, 20) & ONE_WAY != 0 {
                        0
                    } else {
                        self.factory.local_pid(dword(&header, 24))
                    };
                    put32(&mut header, 24, sender);
                    item.call = buffer.call.clone();
                    item.buffer = Some(buffer);
                    item.stop = true;
                    command(if reply { BR_REPLY } else { BR_TRANSACTION }, &header)
                }
            }
        };
        item.len = output.len();
        if output.is_empty() {
            item.commit(self)?;
            return Ok(true);
        }
        let address = base.checked_add(self.read.cursor as u64).ok_or(Errno(14))?;
        self.output.push(address, output);
        self.after = Some(After::Item(item));
        Ok(true)
    }
    pub(super) fn read_done(&mut self) {
        put(&mut self.header, 32, self.read.cursor as u64);
        let spawn = {
            let mut state = self.process.state.lock().unwrap();
            let looper = state
                .threads
                .get(&self.tid)
                .is_some_and(|thread| thread.looper);
            let registered = state
                .threads
                .values()
                .filter(|thread| thread.registered)
                .count() as u32;
            let waiting = state
                .threads
                .values()
                .any(|thread| thread.waiting && thread.stack.is_empty() && thread.queue.is_empty());
            let spawn = looper
                && !waiting
                && state.requested_threads == 0
                && registered < state.max_threads;
            if spawn {
                state.requested_threads += 1;
            }
            spawn
        };
        if spawn {
            self.output
                .push_slice(word(&self.header, 40), &BR_SPAWN.to_le_bytes());
        }
        self.phase = Phase::Publish;
        self.result = Some(Ok(0));
    }
}
