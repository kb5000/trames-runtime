// SPDX-License-Identifier: GPL-3.0-or-later
//! Each control imports once, performs its original query/mutation once, then
//! retains the output while its actual caller waits for user pages.
use super::*;
pub(super) struct ControlOutput {
    pub bytes: [u8; 24],
    pub len: usize,
}
impl<const N: usize> From<[u8; N]> for ControlOutput {
    fn from(bytes: [u8; N]) -> Self {
        let mut output = Self {
            bytes: [0; 24],
            len: N,
        };
        output.bytes[..N].copy_from_slice(&bytes);
        output
    }
}
impl Ioctl {
    pub(super) fn control(&mut self, memory: &impl CpuMemory) -> Result<Option<ControlOutput>> {
        let (process, tid, address) = (&self.process, self.tid, self.address);
        match self.cmd {
            VERSION => {
                return Ok(Some(8u32.to_le_bytes().into()));
            }
            SET_MAX_THREADS => {
                let value = memory.read_array::<4>(address).map_err(|_| Errno(14))?;
                process.state.lock().unwrap().max_threads = u32::from_le_bytes(value);
            }
            SET_CONTEXT_MGR | SET_CONTEXT_MGR_EXT => {
                let (pointer, cookie, flags) = if self.cmd == SET_CONTEXT_MGR_EXT {
                    let bytes = memory.read_array::<24>(address).map_err(|_| Errno(14))?;
                    (word(&bytes, 8), word(&bytes, 16), dword(&bytes, 4))
                } else {
                    let _ = memory.read_array::<4>(address).map_err(|_| Errno(14))?;
                    (0, 0, 0x100)
                };
                process.set_manager(pointer, cookie, flags, self.uid, tid)?;
            }
            THREAD_EXIT => process.thread_exit(tid),
            GET_NODE_DEBUG => {
                let input = memory.read_array::<24>(address).map_err(|_| Errno(14))?;
                let node = process
                    .state
                    .lock()
                    .unwrap()
                    .nodes
                    .range((
                        std::ops::Bound::Excluded(word(&input, 0)),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(_, node)| node.clone());
                let mut out = [0; 24];
                if let Some(node) = node {
                    put(&mut out, 0, node.pointer);
                    put(&mut out, 8, node.cookie);
                    let state = node.state.lock().unwrap();
                    put32(&mut out, 16, u32::from(state.strong != 0));
                    put32(&mut out, 20, u32::from(state.weak != 0));
                }
                return Ok(Some(out.into()));
            }
            GET_NODE_INFO => {
                let mut out = memory.read_array::<24>(address).map_err(|_| Errno(14))?;
                if out[4..].iter().any(|b| *b != 0) {
                    return Err(Errno(22));
                }
                let manager = process
                    .context
                    .manager
                    .lock()
                    .unwrap()
                    .node
                    .as_ref()
                    .and_then(Weak::upgrade);
                if !manager.is_some_and(|node| node.owner.ptr_eq(&process.myself)) {
                    return Err(Errno(1));
                }
                let node = process.strong_target(dword(&out, 0))?;
                let state = node.state.lock().unwrap();
                put32(&mut out, 4, state.strong as u32);
                put32(&mut out, 8, state.local_weak as u32);
                drop(state);
                return Ok(Some(out.into()));
            }
            GET_EXTENDED_ERROR => {
                let error = {
                    let mut state = process.state.lock().unwrap();
                    let thread = state.threads.entry(tid).or_default();
                    std::mem::replace(&mut thread.error, (0, BR_OK, 0))
                };
                let mut out = [0; 12];
                put32(&mut out, 0, error.0);
                put32(&mut out, 4, error.1);
                put32(&mut out, 8, error.2 as u32);
                return Ok(Some(out.into()));
            }
            _ => return Err(Errno(22)),
        }
        Ok(None)
    }
}
