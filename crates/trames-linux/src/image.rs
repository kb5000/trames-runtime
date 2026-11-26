// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux process-entry ABI shared by interpreter and hardware execution.
use trames_elf::LoadedElf;
use trames_execution::Features;
use trames_memory::{Memory, MemoryError, Permissions, PAGE_SIZE};
#[cfg(test)]
#[path = "image_resource_tests.rs"]
mod resource_tests;
pub const STACK_TOP: u64 = 0x0000_7fff_fff0_0000;
pub const STACK_SIZE: u64 = 1024 * 1024;
// RLIMIT_STACK is fixed at STACK_SIZE on both executors. Linux allows a
// quarter of this limit for argument bytes and their guest pointer slots.
pub const EXEC_ARGUMENT_BYTES: usize = STACK_SIZE as usize / 4;
pub const EXEC_STRING_BYTES: usize = 32 * PAGE_SIZE as usize;
#[derive(Debug)]
pub enum ImageError {
    Arguments(&'static str),
    Memory(MemoryError),
}
impl From<MemoryError> for ImageError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}
fn push_string(
    writes: &mut Vec<(u64, Vec<u8>)>,
    cursor: &mut u64,
    string: &[u8],
) -> Result<u64, ImageError> {
    if string.len() >= EXEC_STRING_BYTES {
        return Err(ImageError::Arguments("argument string too long"));
    }
    if string.contains(&0) {
        return Err(ImageError::Arguments("NUL in argv or envp"));
    }
    let len = string
        .len()
        .checked_add(1)
        .ok_or(ImageError::Arguments("string size"))?;
    *cursor = cursor
        .checked_sub(len as u64)
        .filter(|&address| address >= STACK_TOP - STACK_SIZE)
        .ok_or(ImageError::Arguments("argument stack exhausted"))?;
    let mut bytes = string.to_vec();
    bytes.push(0);
    writes.push((*cursor, bytes));
    Ok(*cursor)
}
pub fn build_initial_stack(
    elf: &mut LoadedElf,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    credentials: &trames_vfs::Credentials,
    features: Features,
    extra_auxv: &[(u64, u64)],
    exec_filename: Option<&[u8]>,
) -> Result<u64, ImageError> {
    let mut stack = InitialStack::new(
        elf,
        argv,
        envp,
        credentials,
        features,
        extra_auxv,
        exec_filename,
    )?;
    let mut wait = None;
    loop {
        match stack.run(&mut elf.memory) {
            Err(ImageError::Memory(MemoryError::Pending(fault))) => {
                let wait = match &mut wait {
                    Some(wait) => wait,
                    slot @ None => slot.insert(
                        trames_shared::HostWait::new().map_err(|_| MemoryError::BackingIo(5))?,
                    ),
                };
                wait.begin();
                wait.retain(fault.wait.subscribe(wait.signal()));
                if let Some(deadline) = fault.wait.deadline() {
                    wait.until(deadline);
                }
                if !fault.wait.ready() {
                    wait.wait().map_err(|_| MemoryError::BackingIo(5))?;
                }
            }
            result => return result,
        }
    }
}

/// One unpublished initial stack. Entropy, pointers and completed physical
/// page writes remain the originals when allocation pressure suspends exec.
pub struct InitialStack {
    writes: Vec<(u64, Vec<u8>)>,
    index: usize,
    written: usize,
    mapped: bool,
    trampoline: u8,
    ranges: trames_memory::ImageRanges,
    resources: trames_memory::CgroupMemoryContext,
    sp: u64,
}
impl InitialStack {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        elf: &LoadedElf,
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
        credentials: &trames_vfs::Credentials,
        features: Features,
        extra_auxv: &[(u64, u64)],
        exec_filename: Option<&[u8]>,
    ) -> Result<Self, ImageError> {
        if argv.is_empty() {
            return Err(ImageError::Arguments("argv[0] is required"));
        }
        let mut budget = EXEC_ARGUMENT_BYTES;
        for value in argv.iter().chain(envp) {
            budget = budget
                .checked_sub(value.len() + 1 + 8)
                .ok_or(ImageError::Arguments("argument list too long"))?;
        }
        let mut writes = Vec::new();
        let mut cursor = STACK_TOP;
        let mut arguments = Vec::new();
        let mut environment = Vec::new();
        let execfn = exec_filename
            .map(|name| push_string(&mut writes, &mut cursor, name))
            .transpose()?;
        // Linux places argv[0..] then envp[0..] in increasing address order.
        // libuv uses that contiguous region for process.title. Packing forwards
        // onto a descending stack reverses it and can underflow its area length.
        for value in envp.iter().rev() {
            environment.push(push_string(&mut writes, &mut cursor, value)?);
        }
        environment.reverse();
        for value in argv.iter().rev() {
            arguments.push(push_string(&mut writes, &mut cursor, value)?);
        }
        arguments.reverse();
        // Keep the actual contiguous string spans on their original mm. Loaded
        // host vectors and later pointer-array edits are not proc byte authority.
        let arg_start = arguments[0];
        let arg_end = arguments.last().unwrap() + argv.last().unwrap().len() as u64 + 1;
        let env_start = environment.first().copied().unwrap_or(arg_end);
        let env_end = environment
            .last()
            .map_or(arg_end, |last| last + envp.last().unwrap().len() as u64 + 1);
        let platform = push_string(&mut writes, &mut cursor, b"aarch64")?;
        cursor -= 16;
        let mut entropy = [0; 16];
        crate::fill_entropy(&mut entropy)
            .map_err(|_| ImageError::Arguments("host entropy source unavailable"))?;
        writes.push((cursor, entropy.to_vec()));
        // Static Linux auxv, including real host entropy for the guest stack guard.
        let mut auxv = vec![
            (6u64, PAGE_SIZE),
            (17, 100),      // AT_CLKTCK: the same Linux USER_HZ used by /proc stat.
            (15, platform), // AT_PLATFORM points into the new image.
            (16, features.hwcap),
            (26, features.hwcap2),
            (27, 28), // AT_RSEQ_FEATURE_SIZE: through mm_cid.
            (28, 32), // AT_RSEQ_ALIGN.
            (9, elf.entry),
            (7, elf.interpreter_base),
            (11, credentials.uid as u64),
            (12, credentials.euid as u64),
            (13, credentials.gid as u64),
            (14, credentials.egid as u64),
            (23, u64::from(credentials.secure_exec())),
            (31, execfn.unwrap_or(arguments[0])),
            (25, cursor),
        ];
        if features.hwcap2 & (1 << 23) != 0 {
            auxv.push((51, trames_execution::SME_SIGNAL_STACK_MIN));
        }
        if let Some(phdr) = elf.phdr {
            auxv.extend([(3, phdr), (4, 56), (5, elf.phnum as u64)]);
        }
        auxv.extend_from_slice(extra_auxv);
        auxv.push((0, 0));
        let mut words = vec![argv.len() as u64];
        words.extend(arguments);
        words.push(0);
        words.extend(environment);
        words.push(0);
        for (key, value) in auxv {
            words.extend([key, value]);
        }
        let sp = cursor
            .checked_sub(words.len() as u64 * 8)
            .map(|v| v & !15)
            .filter(|&v| v >= STACK_TOP - STACK_SIZE)
            .ok_or(ImageError::Arguments("argument stack exhausted"))?;
        let ranges = trames_memory::ImageRanges {
            arguments: (arg_start, arg_end),
            environment: (env_start, env_end),
            start_stack: sp,
            executable: trames_memory::ExecutableRanges {
                code: elf.code,
                data: elf.data,
                start_brk: elf.brk_base,
            },
        };
        let mut bytes = Vec::with_capacity(words.len() * 8);
        for word in words {
            bytes.extend(word.to_le_bytes());
        }
        writes.push((sp, bytes));
        Ok(Self {
            writes,
            index: 0,
            written: 0,
            mapped: false,
            trampoline: 0,
            ranges,
            resources: trames_memory::CgroupMemoryContext::capture(),
            sp,
        })
    }
    pub fn run(&mut self, memory: &mut Memory) -> Result<u64, ImageError> {
        let _resources = self.resources.enter();
        if !self.mapped {
            memory.map_initial_stack(STACK_TOP - STACK_SIZE, STACK_SIZE)?;
            self.mapped = true;
        }
        while let Some((address, bytes)) = self.writes.get(self.index) {
            while self.written < bytes.len() {
                let at = address + self.written as u64;
                let count = (bytes.len() - self.written).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
                memory.write(at, &bytes[self.written..self.written + count])?;
                self.written += count;
            }
            self.index += 1;
            self.written = 0;
        }
        let trampoline = 0x0000_7fff_ffd0_0000;
        if self.trampoline == 0 {
            memory.map(trampoline, PAGE_SIZE, Permissions::RW)?;
            self.trampoline = 1;
        }
        if self.trampoline == 1 {
            memory.write(
                trampoline,
                &[0x68, 0x11, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4],
            )?;
            self.trampoline = 2;
        }
        if self.trampoline == 2 {
            memory.protect(trampoline, PAGE_SIZE, Permissions::RX)?;
            self.trampoline = 3;
        }
        memory.set_image_ranges(self.ranges);
        Ok(self.sp)
    }
}
