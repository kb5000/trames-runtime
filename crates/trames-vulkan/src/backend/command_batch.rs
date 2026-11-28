// SPDX-License-Identifier: GPL-3.0-or-later
//! One object-owned recording packet, consumed synchronously on its worker.
//! Read guest transport bytes before effects; inner commands see only that
//! immutable packet, so a later malformed offset cannot request a guest fault
//! checkpoint and replay already-recorded native commands.
use super::*;
pub(super) const OPERATION: u64 = 276;
pub(super) const CAPABILITY: u64 = 1 << 16;
const RECORDS: usize = 64;
const PAYLOAD: usize = 16384;

impl Backend {
    pub(super) fn command_batch(&mut self, m: &impl CpuMemory, a: [u64; 16]) -> Result<()> {
        let count = bounded(a[3], RECORDS)?;
        let size = bounded(a[5], PAYLOAD)?;
        if count == 0 || size < 8 {
            return invalid();
        }
        self.object(a[1], Kind::CommandBuffer)?;
        let records = words64(m, a[2], count * 17)?;
        let mut packet = Packet(vec![0; size]);
        m.read(a[4], &mut packet.0)?;
        // Reject foreign objects and non-recording operations for the whole
        // envelope before its first native command. No create/query/submit,
        // descriptor update, nested packet or write-to-guest entry is admitted.
        for row in records.chunks_exact(17) {
            if !(core_commands::records_only(row[0]) || row[0] == 219)
                || row[1] != a[0]
                || row[2] != a[1]
            {
                return invalid();
            }
        }
        for row in records.chunks_exact(17) {
            if row[0] == 219 {
                // Secondary buffers can finish old execution while the primary
                // is being recorded. Retain its original collection boundary.
                self.collect();
            }
            let mut args = [0; 16];
            args.copy_from_slice(&row[1..]);
            match self.device_call(&mut packet, row[0], args) {
                // These are packet-format errors, not accesses to an original
                // guest address. Never surface an asynchronous guest fault or
                // retry a partially recorded sequence. Original Vulkan object,
                // feature and resource failures retain their existing result.
                Err(Failure::Memory(_)) => return invalid(),
                result => result?,
            }
        }
        Ok(())
    }
}

/// This is a view of an already-copied wire payload, not another guest mm or
/// permission policy. Offset zero encodes NULL; every nonempty read is bounded
/// to owned bytes. Recording operations have no guest-memory outputs.
struct Packet(Vec<u8>);
impl Packet {
    fn range(
        &self,
        address: u64,
        length: usize,
    ) -> std::result::Result<std::ops::Range<usize>, MemoryError> {
        let at = usize::try_from(address).map_err(|_| MemoryError::InvalidRange)?;
        let end = at.checked_add(length).ok_or(MemoryError::InvalidRange)?;
        if at < 8 || end > self.0.len() {
            return Err(MemoryError::InvalidRange);
        }
        Ok(at..end)
    }
}
impl CpuMemory for Packet {
    fn mapped_at_or_after(&self, address: u64) -> bool {
        address < self.0.len() as u64
    }
    fn read(&self, address: u64, out: &mut [u8]) -> std::result::Result<(), MemoryError> {
        if out.is_empty() {
            return Ok(());
        }
        out.copy_from_slice(&self.0[self.range(address, out.len())?]);
        Ok(())
    }
    fn write(&mut self, _: u64, _: &[u8]) -> std::result::Result<(), MemoryError> {
        Err(MemoryError::InvalidRange)
    }
    fn check(
        &self,
        address: u64,
        length: usize,
        access: Access,
    ) -> std::result::Result<(), MemoryError> {
        if access != Access::Read {
            return Err(MemoryError::InvalidRange);
        }
        if length == 0 {
            return Ok(());
        }
        self.range(address, length).map(|_| ())
    }
    fn check_translation(&self, address: u64) -> std::result::Result<(), MemoryError> {
        self.range(address, 1).map(|_| ())
    }
    fn fetch_u32(&self, _: u64) -> std::result::Result<u32, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        (0, 0, 0)
    }
    fn instruction_page_identity(
        &self,
        _: u64,
    ) -> std::result::Result<(u64, u64, u64), MemoryError> {
        Err(MemoryError::InvalidRange)
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> std::result::Result<T, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> std::result::Result<u128, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
    fn exclusive_write(
        &mut self,
        _: u64,
        _: &[u8],
        _: Option<u128>,
    ) -> std::result::Result<bool, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::Permissions;
    #[test]
    fn packet_offsets_are_owned_read_only_and_cannot_escape_to_guest_addresses() {
        let mut packet = Packet(vec![0; 64]);
        packet.0[8..12].copy_from_slice(&0x12345678u32.to_le_bytes());
        assert_eq!(
            packet.read_array::<4>(8).unwrap(),
            0x12345678u32.to_le_bytes()
        );
        for at in [0, 7, 63, 0x1000, u64::MAX] {
            assert!(packet.read_array::<8>(at).is_err());
        }
        assert!(packet.write(8, &[1]).is_err());
        assert!(packet.check(8, 4, Access::Write).is_err());
        assert!(packet.check(8, 4, Access::Execute).is_err());
        assert!(packet.fetch_u32(8).is_err());
        packet.read(u64::MAX, &mut []).unwrap();
    }

    fn words(m: &mut Memory, at: u64, values: &[u64]) {
        m.write(
            at,
            &values
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    }
    fn invoke(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> Invocation {
        let mut a = [0; 16];
        a[..args.len()].copy_from_slice(args);
        b.invoke_graph(m, op, a).unwrap()
    }
    fn ok(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> u64 {
        assert_eq!(invoke(b, m, op, args), Invocation::Complete(0), "op {op}");
        m.read_u64(0x2000).unwrap()
    }
    fn rows(m: &mut Memory, dev: u64, command: u64, buffer: u64, bad: bool) {
        let mut records = [[0u64; 17]; 3];
        records[0][..8].copy_from_slice(&[213, dev, command, buffer, 0, 4, 8, 0]);
        records[1][..7].copy_from_slice(&[46, dev, command, buffer, 4, 4, 0x11223344]);
        records[2][..11].copy_from_slice(&[
            44,
            dev,
            command,
            vk::PipelineStageFlags::TRANSFER.as_raw() as u64,
            vk::PipelineStageFlags::HOST.as_raw() as u64,
            vk::AccessFlags::TRANSFER_WRITE.as_raw() as u64,
            vk::AccessFlags::HOST_READ.as_raw() as u64,
            0,
            0,
            12,
            0,
        ]);
        if bad {
            records[1][0] = OPERATION;
        }
        words(m, 0x3000, &records.concat());
        m.write(0x5008, &0x55667788u32.to_le_bytes()).unwrap();
    }
    #[test]
    #[ignore = "requires original native Vulkan driver; checks actual GPU transfer output"]
    fn hardware_recording_packet_preserves_gpu_output_and_faults_only_before_effects() {
        let mut b = Backend::with_budget(crate::Budget::host_managed());
        let mut m = Memory::default();
        m.map(0x1000, 0x8000, Permissions::RW).unwrap();
        let instance = ok(&mut b, &mut m, 1, &[0x2000]);
        m.write(0x2400, &1u32.to_le_bytes()).unwrap();
        let physical = ok(&mut b, &mut m, 3, &[instance, 0x2400, 0x2000]);
        let caps = ok(&mut b, &mut m, 115, &[physical, 0x2000]);
        assert_ne!(caps & CAPABILITY, 0);
        let dev = ok(&mut b, &mut m, 8, &[physical, 0, 0x2000]);
        let queue = ok(&mut b, &mut m, 10, &[dev, 0, 0, 0x2000]);
        let buffer = ok(&mut b, &mut m, 11, &[dev, 64, 3, 0x2000]);
        ok(&mut b, &mut m, 13, &[dev, buffer, 0x2100]);
        let allocation = m.read_u64(0x2100).unwrap();
        let bits = m.read_u64(0x2110).unwrap() as u32;
        ok(&mut b, &mut m, 5, &[physical, 0x2500]);
        let count = m.read_u64(0x2500).unwrap() as u32;
        let memory_type = (0..count)
            .find(|i| {
                let flags = u32::from_le_bytes(m.read_array(0x2504 + u64::from(*i) * 8).unwrap());
                bits & (1 << i) != 0 && flags & 6 == 6
            })
            .unwrap();
        let memory = ok(
            &mut b,
            &mut m,
            14,
            &[dev, allocation, memory_type as u64, 0x2000],
        );
        ok(&mut b, &mut m, 16, &[dev, buffer, memory, 0]);
        let pool = ok(&mut b, &mut m, 34, &[dev, 0, 2, 0x2000]);
        let command = ok(&mut b, &mut m, 36, &[dev, pool, 0x2000]);
        ok(&mut b, &mut m, 38, &[dev, command, 0]);
        rows(&mut m, dev, command, buffer, true);
        assert_ne!(
            invoke(
                &mut b,
                &mut m,
                OPERATION,
                &[dev, command, 0x3000, 3, 0x5000, 16]
            ),
            Invocation::Complete(0)
        );
        assert_eq!(
            b.objects[&command].deps.borrow().len(),
            1,
            "bad envelope must not record its earlier command"
        );
        rows(&mut m, dev, command, buffer, false);
        // A structurally valid envelope can still contain a malformed payload
        // in a later command. Its accepted prefix is never sent to a guest-mm
        // fault checkpoint or replayed. Reset retires that old recording.
        words(
            &mut m,
            0x3000 + 17 * 8,
            &[213, dev, command, buffer, 4, 4, u64::MAX],
        );
        assert!(
            matches!(invoke(&mut b,&mut m,OPERATION,&[dev,command,0x3000,3,0x5000,16]),Invocation::Complete(value) if value!=0)
        );
        assert!(b.objects[&command].deps.borrow().len() > 1);
        ok(&mut b, &mut m, 40, &[dev, command, 0]);
        ok(&mut b, &mut m, 38, &[dev, command, 0]);
        rows(&mut m, dev, command, buffer, false);
        m.protect(0x5000, 4096, Permissions::NONE).unwrap();
        let mut args = [0; 16];
        args[..6].copy_from_slice(&[dev, command, 0x3000, 3, 0x5000, 16]);
        assert!(b.invoke_graph(&mut m, OPERATION, args).is_err());
        assert_eq!(
            b.objects[&command].deps.borrow().len(),
            1,
            "guest snapshot faults precede native recording"
        );
        m.protect(0x5000, 4096, Permissions::RW).unwrap();
        ok(
            &mut b,
            &mut m,
            OPERATION,
            &[dev, command, 0x3000, 3, 0x5000, 16],
        );
        ok(&mut b, &mut m, 39, &[dev, command]);
        let fence = ok(&mut b, &mut m, 48, &[dev, 0, 0x2000]);
        words(&mut m, 0x4000, &[command]);
        words(&mut m, 0x4100, &[0, 0, 0, 0x4000, 1, 0, 0]);
        ok(&mut b, &mut m, 56, &[dev, queue, 0x4100, 1, fence]);
        let began = std::time::Instant::now();
        while invoke(&mut b, &mut m, 51, &[dev, fence]) != Invocation::Complete(0) {
            assert!(began.elapsed() < std::time::Duration::from_secs(10));
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        ok(&mut b, &mut m, 17, &[dev, memory, 0, 8, 0x6000]);
        assert_eq!(m.read_u64(0x6000).unwrap(), 0x1122334455667788);
        ok(&mut b, &mut m, 18, &[dev, memory]);
        ok(&mut b, &mut m, 49, &[dev, fence]);
        ok(&mut b, &mut m, 35, &[dev, pool]);
        ok(&mut b, &mut m, 12, &[dev, buffer]);
        ok(&mut b, &mut m, 15, &[dev, memory]);
        ok(&mut b, &mut m, 9, &[dev]);
        ok(&mut b, &mut m, 2, &[instance]);
    }
}
