// SPDX-License-Identifier: GPL-3.0-or-later
//! Message IPC imports arguments once, parks on the original queue, and copies
//! results on its source executor. No CPU slot or namespace directory is held.
use super::*;
use trames_vfs::sysv_message::{Reply, Request, MSGMAX};
#[cfg(test)]
#[path = "message_tests.rs"]
mod tests;

#[derive(Clone)]
pub struct RetainedMessage {
    request: Arc<Request>,
    number: u32,
    args: [u64; 6],
}
impl RetainedMessage {
    fn attempt(&self, memory: &mut impl CpuMemory) -> Result<u64, Errno> {
        match self.request.attempt()? {
            Reply::Sent => Ok(0),
            Reply::Received { kind, data } => {
                // Linux consumes an accepted receive even when copyout faults.
                memory
                    .write_array(self.args[1], kind.to_le_bytes())
                    .map_err(|_| Errno(14))?;
                memory
                    .write(self.args[1].checked_add(8).ok_or(Errno(14))?, &data)
                    .map_err(|_| Errno(14))?;
                Ok(data.len() as u64)
            }
        }
    }
    fn waits(&self, error: Errno) -> bool {
        if self.number == 189 {
            error.0 == 11 && self.args[3] & 0x800 == 0
        } else {
            error.0 == 42 && self.args[4] & 0x800 == 0
        }
    }
}
pub(crate) fn control(
    factory: &trames_vfs::DescriptorFactory,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    if number == 186 {
        return factory.message_get(a[0] as i32, a[1] as u32).map(u64::from);
    }
    let input = if a[1] as u32 & !0x100 == 1 {
        Some(memory.read_array::<120>(a[2]).map_err(|_| Errno(14))?)
    } else {
        None
    };
    let (value, bytes) = factory.message_control(a[0] as u32, a[1] as u32, input.as_ref())?;
    if !bytes.is_empty() {
        memory.write(a[2], &bytes).map_err(|_| Errno(14))?;
    }
    Ok(value)
}
fn import(
    factory: &trames_vfs::DescriptorFactory,
    number: u32,
    args: [u64; 6],
    memory: &impl CpuMemory,
    pid: u32,
) -> Result<RetainedMessage, Errno> {
    let process = factory.local_sender_credentials()[0];
    let pid = if process == 0 { pid } else { process };
    let request = if number == 189 {
        if args[2] > MSGMAX as u64 {
            return Err(Errno(22));
        }
        let kind = i64::from_le_bytes(memory.read_array(args[1]).map_err(|_| Errno(14))?);
        let mut bytes = vec![0; args[2] as usize];
        memory
            .read(args[1].checked_add(8).ok_or(Errno(14))?, &mut bytes)
            .map_err(|_| Errno(14))?;
        factory.message_send(args[0] as u32, kind, bytes, pid)?
    } else {
        factory.message_receive(
            args[0] as u32,
            args[3] as i64,
            usize::try_from(args[2]).map_err(|_| Errno(22))?,
            args[4] as u32,
            pid,
        )?
    };
    Ok(RetainedMessage {
        request: Arc::new(request),
        number,
        args,
    })
}
pub(crate) fn call(
    factory: &trames_vfs::DescriptorFactory,
    number: u32,
    args: [u64; 6],
    memory: &mut impl CpuMemory,
    pid: u32,
) -> Result<u64, Errno> {
    if number <= 187 {
        return control(factory, number, args, memory);
    }
    import(factory, number, args, memory, pid)?.attempt(memory)
}
impl DirectSyscalls {
    pub(super) fn start_message(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let factory = self.resources.as_ref()?;
        if number <= 187 {
            return Some(self.complete(number, args, control(factory, number, args, memory)));
        }
        Some(match import(factory, number, args, memory, pid) {
            Ok(message) => self.start_retained_message(message, memory, pid, target),
            Err(error) => self.complete(number, args, Err(error)),
        })
    }
    pub fn start_retained_message(
        &self,
        message: RetainedMessage,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        match message.attempt(memory) {
            Err(error) if message.waits(error) => {}
            result => return self.complete(message.number, message.args, result),
        }
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = vec![message.request.subscribe(&signal)];
        // Subscribe before the deciding retry. Queue removal, data arrival and
        // capacity release cannot be lost between EAGAIN and parking.
        match message.attempt(memory) {
            Err(error) if message.waits(error) => {}
            result => return self.complete(message.number, message.args, result),
        }
        IoAttempt::Blocked(PendingIo {
            number: message.number,
            args: message.args,
            message: Some(message),
            signal,
            _subscriptions: subscriptions,
            target: target.clone(),
            binder: None,
            aio: None,
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
            host_subscription: None,
            socket_subscriptions: Vec::new(),
            uring: None,
            poll_uring: None,
            file: None,
            fifo_open: None,
        })
    }
}
