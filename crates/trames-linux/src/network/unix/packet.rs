// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted packet ABI and one resolved addressed-send target per syscall.
use super::*;
pub(crate) struct DatagramState {
    pub source: trames_vfs::LocalOperation,
    pub target: std::sync::OnceLock<trames_vfs::LocalDatagram>,
}
impl DatagramState {
    pub fn new(source: trames_vfs::LocalOperation) -> Self {
        Self {
            source,
            target: Default::default(),
        }
    }
}
#[derive(Clone)]
pub(crate) enum PreparedTransfer<R> {
    Message(PreparedMessage<R>),
    Packet(PreparedPacket),
}
#[derive(Clone)]
pub(crate) struct PreparedPacket {
    parts: Vec<(u64, usize)>,
    count: usize,
    output: Option<AddressOutput>,
    flags: u32,
    send: Option<Vec<u8>>,
    destination: Option<Vec<u8>>,
    identity: [u32; 3],
}
pub(crate) fn prepare_transfer<I: MessageIo>(
    number: u32,
    args: [u64; 6],
    memory: &impl CpuMemory,
    io: &I,
) -> Option<Result<PreparedTransfer<I::Rights>>> {
    if matches!(number, 211 | 212) {
        return prepare_message(number, args, memory, io)
            .map(|result| result.map(PreparedTransfer::Message));
    }
    if !matches!(number, 63..=66 | 206 | 207) {
        return None;
    }
    Some(PreparedPacket::prepare(number, args, memory, io).map(PreparedTransfer::Packet))
}
impl PreparedPacket {
    fn prepare(
        number: u32,
        a: [u64; 6],
        memory: &impl CpuMemory,
        io: &impl MessageIo,
    ) -> Result<Self> {
        let sending = matches!(number, 64 | 66 | 206);
        let destination = if number == 206 && a[4] != 0 {
            Some(address(memory, a[4], a[5])?)
        } else {
            None
        };
        let mut bytes = Vec::new();
        let (parts, count) = if number == 65 {
            Linux::readv_parts(memory, a)?
        } else if number == 66 {
            Linux::writev_transport_mode(a, memory, &mut bytes, false, |bytes| {
                Ok(bytes.len() as u64)
            })?;
            (Vec::new(), bytes.len())
        } else {
            let count = a[2].min(crate::MAX_WRITE as u64) as usize;
            Linux::check(
                memory,
                a[1],
                count,
                if sending { Access::Read } else { Access::Write },
            )?;
            if sending {
                bytes.resize(count, 0);
                memory.read(a[1], &mut bytes).map_err(|_| Errno(14))?;
            }
            (vec![(a[1], count)], count)
        };
        let output = if number == 207 && io.kind() != 1 {
            AddressOutput::prepare(memory, a[4], a[5], 110)?
        } else {
            None
        };
        Ok(Self {
            parts,
            count,
            output,
            flags: if matches!(number, 206 | 207) {
                a[3] as u32
            } else {
                0
            },
            send: sending.then_some(bytes),
            destination,
            identity: io.sender_credentials(),
        })
    }
    fn recheck(&self, memory: &impl CpuMemory) -> Result<()> {
        if self.send.is_some() {
            return Ok(());
        }
        for &(pointer, size) in &self.parts {
            Linux::check(memory, pointer, size, Access::Write)?;
        }
        if let Some(output) = &self.output {
            Linux::check(memory, output.length_pointer, 4, Access::Write)?;
            Linux::check(
                memory,
                output.pointer,
                output.capacity.min(110),
                Access::Write,
            )?;
        }
        Ok(())
    }
    fn progress(
        &self,
        memory: &mut impl CpuMemory,
        io: &mut impl MessageIo,
    ) -> Option<Result<u64>> {
        if let Some(bytes) = &self.send {
            let rights = match io.send_rights(&[])? {
                Ok(rights) => rights,
                Err(error) => return Some(Err(error)),
            };
            return io
                .send(
                    bytes,
                    self.flags,
                    self.destination.as_deref(),
                    rights,
                    self.identity,
                )
                .map(|r| r.map(|n| n as u64));
        }
        let received = match io.recv(self.count, self.flags | io.nonblocking())? {
            Ok(received) => received,
            Err(error) => return Some(Err(error)),
        };
        Some((|| {
            Linux::scatter(memory, &self.parts, &received.data)?;
            if let Some(output) = self.output {
                output.write_bytes(memory, &received.source)?;
            }
            // Plain reads/recvfrom discard ancillary rights on their original
            // owner/portable path, outside the queue lock.
            io.receive_rights(received.rights, 0, false);
            Ok(if self.flags & MSG_TRUNC != 0 {
                received.length
            } else {
                received.data.len()
            } as u64)
        })())
    }
}
impl<R: Clone> PreparedTransfer<R> {
    pub fn recheck(&self, memory: &impl CpuMemory) -> Result<()> {
        match self {
            Self::Message(prepared) => prepared.recheck(memory),
            Self::Packet(prepared) => prepared.recheck(memory),
        }
    }
    pub fn progress(
        &self,
        memory: &mut impl CpuMemory,
        io: &mut impl MessageIo<Rights = R>,
    ) -> Option<Result<u64>> {
        match self {
            Self::Message(prepared) => prepared.progress(memory, io),
            Self::Packet(prepared) => prepared.progress(memory, io),
        }
    }
    pub fn owner(
        &self,
        rights: impl Fn(&R) -> trames_vfs::LocalRights,
    ) -> PreparedTransfer<trames_vfs::LocalRights> {
        match self {
            Self::Message(prepared) => PreparedTransfer::Message(prepared.owner(rights)),
            Self::Packet(prepared) => PreparedTransfer::Packet(prepared.clone()),
        }
    }
}
