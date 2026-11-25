// SPDX-License-Identifier: GPL-3.0-or-later
//! Only completed commands advance write_consumed. Import cursors retain the
//! current command and its already accepted objects through page waits.
use super::*;
pub(super) struct Command {
    code: u32,
    address: u64,
    argument: Option<Vec<u8>>,
    import: Option<Import>,
}
impl Ioctl {
    pub(super) fn write_one<M: CpuMemory>(&mut self, memory: &Reader<'_, M>) -> Result<bool> {
        if self
            .process
            .state
            .lock()
            .unwrap()
            .threads
            .get(&self.tid)
            .is_some_and(|thread| thread.return_error)
        {
            return Ok(true);
        }
        let size = word(&self.header, 0);
        let consumed = word(&self.header, 8);
        if consumed >= size {
            return Ok(true);
        }
        if self.command.is_none() {
            let address = word(&self.header, 16)
                .checked_add(consumed)
                .ok_or(Errno(14))?;
            let bytes = memory.read_array::<4>(address).map_err(|_| Errno(14))?;
            let code = dword(&bytes, 0);
            match code {
                TRANSACTION | REPLY | TRANSACTION_SG | REPLY_SG | FREE_BUFFER | INCREFS
                | ACQUIRE | RELEASE | DECREFS | INCREFS_DONE | ACQUIRE_DONE | REGISTER_LOOPER
                | ENTER_LOOPER | EXIT_LOOPER | REQUEST_DEATH | CLEAR_DEATH | DEAD_DONE => {}
                _ => return Err(Errno(22)),
            }
            self.command = Some(Command {
                code,
                address,
                argument: None,
                import: None,
            });
            memory.accepted();
        }
        let mut command = self.command.take().unwrap();
        let result = self.execute_command(&mut command, memory);
        if let Ok(stop) = result {
            let size = ((command.code >> 16) & 0x3fff) as u64;
            put(
                &mut self.header,
                8,
                consumed.checked_add(4 + size).ok_or(Errno(14))?,
            );
            memory.accepted();
            Ok(stop)
        } else {
            self.command = Some(command);
            result
        }
    }
    fn execute_command<M: CpuMemory>(
        &self,
        command: &mut Command,
        memory: &Reader<'_, M>,
    ) -> Result<bool> {
        let cmd = command.code;
        if command.argument.is_none() {
            let len = ((cmd >> 16) & 0x3fff) as usize;
            command.argument = Some(read(
                memory,
                command.address.checked_add(4).ok_or(Errno(14))?,
                len,
            )?);
            memory.accepted();
        }
        let argument = command.argument.as_ref().unwrap();
        match cmd {
            TRANSACTION | REPLY | TRANSACTION_SG | REPLY_SG => {
                let reply = matches!(cmd, REPLY | REPLY_SG);
                let identity = [self.process.owner, self.uid];
                let result = (|| {
                    if command.import.is_none() {
                        command.import = Some(Import::new(argument)?);
                    }
                    let packet = command.import.as_mut().unwrap().progress(self, memory)?;
                    self.process.submit(self.tid, packet, reply, identity)
                })();
                if let Err(error) = result {
                    if memory.pending() {
                        return Err(error);
                    }
                    if reply {
                        self.process.reject_reply(self.tid, BR_FAILED_REPLY)?;
                    } else {
                        let response = if matches!(error.0, 3 | 111) {
                            BR_DEAD_REPLY
                        } else {
                            BR_FAILED_REPLY
                        };
                        {
                            let mut state = self.process.state.lock().unwrap();
                            let thread = state.threads.entry(self.tid).or_default();
                            thread.error = (0, response, -(error.0 as i32));
                            thread.return_error = true;
                        }
                        self.process
                            .enqueue(Some(self.tid), Work::ReturnError(response))?;
                    }
                    return Ok(true);
                }
            }
            FREE_BUFFER => {
                let _ = self.process.free_buffer(word(argument, 0));
            }
            INCREFS | ACQUIRE | RELEASE | DECREFS => {
                self.process.ref_command(cmd, dword(argument, 0))?
            }
            INCREFS_DONE | ACQUIRE_DONE => {
                let node = self
                    .process
                    .state
                    .lock()
                    .unwrap()
                    .nodes
                    .get(&word(argument, 0))
                    .cloned();
                if let Some(node) = node {
                    if node.cookie == word(argument, 8) {
                        // Driver user errors do not abort the enclosing
                        // write/read and kill an otherwise healthy server.
                        let _ = node.acknowledge(cmd);
                    }
                }
            }
            REGISTER_LOOPER | ENTER_LOOPER | EXIT_LOOPER => {
                let mut state = self.process.state.lock().unwrap();
                if cmd == REGISTER_LOOPER {
                    if state.requested_threads == 0 {
                        return Err(Errno(22));
                    }
                    state.requested_threads -= 1;
                }
                let thread = state.threads.entry(self.tid).or_default();
                thread.looper = cmd != EXIT_LOOPER;
                thread.registered = cmd == REGISTER_LOOPER;
            }
            REQUEST_DEATH => self
                .process
                .request_death(dword(argument, 0), word(argument, 4))?,
            CLEAR_DEATH => self
                .process
                .clear_death(dword(argument, 0), word(argument, 4))?,
            DEAD_DONE => self.process.death_done(word(argument, 0))?,
            _ => return Err(Errno(22)),
        }
        Ok(false)
    }
}
