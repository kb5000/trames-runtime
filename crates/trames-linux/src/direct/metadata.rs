// SPDX-License-Identifier: GPL-3.0-or-later
//! Scalar metadata snapshots and original UTS input across real page waits.
use super::*;
#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;

pub(super) struct UtsInput {
    uts: trames_vfs::UtsAccess,
    number: u32,
    args: [u64; 6],
    bytes: file_input::Bytes,
}
impl UtsInput {
    fn progress(
        &self,
        memory: &impl CpuMemory,
    ) -> Result<Result<u64, Errno>, trames_memory::PageFault> {
        let reader = file_input::Reader::new(memory, &self.bytes);
        let mut name = vec![0; self.args[1] as u32 as usize];
        let copied = reader.read(self.args[0], &mut name);
        if let Some(fault) = reader.fault() {
            return Err(fault);
        }
        Ok(copied
            .map_err(|_| Errno(14))
            .and_then(|()| self.uts.set(self.number == 162, &name).map(|()| 0)))
    }
    pub(super) fn resume(
        self: Box<Self>,
        source: &DirectSyscalls,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        match self.progress(memory) {
            Ok(result) => IoAttempt::Complete(result),
            Err(fault) => {
                let (number, args) = (self.number, self.args);
                source.park_input(
                    file_input::Accepted::Uts(self),
                    fault,
                    number,
                    args,
                    pid,
                    target,
                )
            }
        }
    }
}
impl DirectSyscalls {
    pub fn start_metadata_copy(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        if !matches!(
            number,
            86 | 87 | 113 | 114 | 160..=162 | 168 | 169 | 179 | 278
        ) {
            return None;
        }
        self.start_prepared_file(number, args, memory, pid, target)
    }
    pub fn invoke_statistics(
        &self,
        info: crate::SystemInfo,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if self.file_prepared(179, args) {
            return None;
        }
        self.finish_metadata_output(
            179,
            args,
            args[0],
            crate::system_info::encode(info).to_vec(),
            false,
            memory,
        )
    }
    pub(super) fn finish_metadata_output(
        &self,
        number: u32,
        args: [u64; 6],
        address: u64,
        bytes: Vec<u8>,
        partial: bool,
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        let output = if partial {
            FileOutput::Scalar(address)
        } else {
            FileOutput::Buffer {
                address,
                capacity: bytes.len() as u64,
                query_size: false,
                zero: true,
            }
        };
        let copy = file::FileCopyout::new(&output, Ok(trames_vfs::FileValue::Bytes(bytes)));
        self.finish_file_copyout(number, args, copy, memory)
    }
    pub fn invoke_time(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        started: Instant,
        cpu: Option<Result<Duration, Errno>>,
        task: Option<&trames_vfs::ProcessView>,
    ) -> Option<Result<u64, Errno>> {
        if self.file_prepared(number, args) {
            return None;
        }
        if number == 169 {
            if !memory.async_faults_possible() {
                return Some(crate::gettimeofday(memory, args[0], args[1]));
            }
            let mut copy =
                file::FileCopyout::new(&FileOutput::None, Ok(trames_vfs::FileValue::Count(0)));
            if args[0] != 0 {
                let time = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                {
                    Ok(time) => time,
                    Err(_) => return Some(Err(Errno(5))),
                };
                copy.append_scalar(args[0], time.as_secs().to_le_bytes().to_vec());
                let Some(address) = args[0].checked_add(8) else {
                    return Some(Err(Errno(14)));
                };
                copy.append_scalar(
                    address,
                    (time.subsec_micros() as u64).to_le_bytes().to_vec(),
                );
            }
            if args[1] != 0 {
                copy.append(args[1], vec![0; 8]);
            }
            return self.finish_file_copyout(number, args, copy, memory);
        }
        let bytes = if let Some(cpu) = cpu {
            cpu.map(|elapsed| crate::time_read::cpu_clock_snapshot(number, elapsed))
        } else {
            crate::time_read::clock_snapshot(number, args[0], started, self.boot_clock, task)
        };
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(error) => return Some(Err(error)),
        };
        if number == 114 && args[1] == 0 {
            return Some(Ok(0));
        }
        if !memory.async_faults_possible() {
            return Some(crate::time_read::copy_timespec(memory, args[1], bytes).map(|()| 0));
        }
        self.finish_metadata_output(number, args, args[1], bytes.to_vec(), false, memory)
    }
    pub fn invoke_getcpu(
        &self,
        args: [u64; 6],
        processor: u32,
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if self.file_prepared(168, args) {
            return None;
        }
        if !memory.async_faults_possible() {
            let mut failed = false;
            for (address, value) in [(args[0], processor), (args[1], 0)] {
                if address != 0 {
                    failed |= memory.write_array(address, value.to_le_bytes()).is_err();
                }
            }
            return Some(if failed { Err(Errno(14)) } else { Ok(0) });
        }
        let mut copy =
            file::FileCopyout::new(&FileOutput::None, Ok(trames_vfs::FileValue::Count(0)));
        copy.continue_errors();
        if args[0] != 0 {
            copy.append_scalar(args[0], processor.to_le_bytes().to_vec());
        }
        if args[1] != 0 {
            copy.append_scalar(args[1], 0u32.to_le_bytes().to_vec());
        }
        self.finish_file_copyout(168, args, copy, memory)
    }
    pub fn invoke_uts(
        &self,
        uts: &trames_vfs::UtsAccess,
        personality: &crate::TaskPersonality,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if !matches!(number, 160..=162) {
            return None;
        }
        if !memory.async_faults_possible() {
            return Some(crate::uts_call_for_task(
                uts,
                personality,
                number,
                args,
                memory,
            ));
        }
        if self.file_prepared(number, args) {
            return None;
        }
        if number == 160 {
            let output = FileOutput::Buffer {
                address: args[0],
                capacity: 390,
                query_size: false,
                zero: true,
            };
            let mut copy = file::FileCopyout::new(
                &output,
                Ok(trames_vfs::FileValue::Bytes(
                    crate::uts::fields(uts, false).to_vec(),
                )),
            );
            if personality.uname26() {
                // Linux applies the compatibility override only after the
                // complete new_utsname copy, including any earlier page wait.
                let Some(address) = args[0].checked_add(130) else {
                    return Some(Err(Errno(14)));
                };
                copy.append(address, b"2.6.60-trames\0".to_vec());
            }
            return self.finish_file_copyout(number, args, copy, memory);
        }
        if let Err(error) = uts.writable() {
            return Some(Err(error));
        }
        let length = args[1] as u32 as i32;
        if !(0..=64).contains(&length) {
            return Some(Err(Errno(22)));
        }
        let call = Box::new(UtsInput {
            uts: uts.clone(),
            number,
            args,
            bytes: Default::default(),
        });
        match call.progress(memory) {
            Ok(result) => Some(result),
            Err(fault) => {
                self.prepare_input(file_input::Accepted::Uts(call), fault, number, args);
                None
            }
        }
    }
    pub fn invoke_entropy(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if !memory.async_faults_possible() {
            return Some(crate::getrandom(args, memory));
        }
        if self.file_prepared(278, args) {
            return None;
        }
        let count = match crate::entropy::parameters(args) {
            Ok(count) => count,
            Err(error) => return Some(Err(error)),
        };
        // import_ubuf performs access_ok before generating data. This checks
        // only the address extent, without touching a lazy backing or imposing
        // an all-pages-present requirement on subsequent user copies.
        let address = args[0] & 0x00ff_ffff_ffff_ffff;
        if address >= trames_memory::ADDRESS_LIMIT
            || count as u64 > trames_memory::ADDRESS_LIMIT - address
        {
            return Some(Err(Errno(14)));
        }
        let mut bytes = vec![0; count];
        if let Err(error) = crate::fill_entropy(&mut bytes) {
            return Some(Err(error));
        }
        self.finish_metadata_output(278, args, args[0], bytes, true, memory)
    }
}
