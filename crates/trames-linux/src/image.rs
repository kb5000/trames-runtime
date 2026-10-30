// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux process-entry ABI shared by interpreter and hardware execution.
use trames_elf::LoadedElf;
use trames_execution::Features;
use trames_memory::{Memory, MemoryError, Permissions, PAGE_SIZE};
pub const STACK_TOP: u64 = 0x0000_7fff_fff0_0000;
pub const STACK_SIZE: u64 = 1024 * 1024;
const INITIAL_ARGUMENT_BYTES: u64 = 64 * 1024;
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
fn push_string(memory: &mut Memory, cursor: &mut u64, string: &[u8]) -> Result<u64, ImageError> {
    if string.contains(&0) {
        return Err(ImageError::Arguments("NUL in argv or envp"));
    }
    let len = string
        .len()
        .checked_add(1)
        .ok_or(ImageError::Arguments("string size"))?;
    *cursor = cursor
        .checked_sub(len as u64)
        .filter(|&address| address >= STACK_TOP - INITIAL_ARGUMENT_BYTES)
        .ok_or(ImageError::Arguments("stack exceeds 64 KiB"))?;
    memory.write(*cursor, string)?;
    memory.write(*cursor + string.len() as u64, &[0])?;
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
    if argv.is_empty() {
        return Err(ImageError::Arguments("argv[0] is required"));
    }
    if argv.len() + envp.len() > 4096 {
        return Err(ImageError::Arguments(
            "too many arguments or environment entries",
        ));
    }
    elf.memory
        .map(STACK_TOP - STACK_SIZE, STACK_SIZE, Permissions::RW)?;
    let mut cursor = STACK_TOP;
    let mut arguments = Vec::new();
    let mut environment = Vec::new();
    let execfn = exec_filename
        .map(|name| push_string(&mut elf.memory, &mut cursor, name))
        .transpose()?;
    // Linux places argv[0..] then envp[0..] in increasing address order.
    // libuv uses that contiguous region for process.title. Packing forwards
    // onto a descending stack reverses it and can underflow its area length.
    for value in envp.iter().rev() {
        environment.push(push_string(&mut elf.memory, &mut cursor, value)?);
    }
    environment.reverse();
    for value in argv.iter().rev() {
        arguments.push(push_string(&mut elf.memory, &mut cursor, value)?);
    }
    arguments.reverse();
    cursor -= 16;
    let mut entropy = [0; 16];
    crate::fill_entropy(&mut entropy)
        .map_err(|_| ImageError::Arguments("host entropy source unavailable"))?;
    elf.memory.write(cursor, &entropy)?;
    // Static Linux auxv, including real host entropy for the guest stack guard.
    let mut auxv = vec![
        (6u64, PAGE_SIZE),
        (16, features.hwcap),
        (26, features.hwcap2),
        (9, elf.entry),
        (7, elf.interpreter_base),
        (11, credentials.uid as u64),
        (12, credentials.euid as u64),
        (13, credentials.gid as u64),
        (14, credentials.egid as u64),
        (
            23,
            u64::from(credentials.uid != credentials.euid || credentials.gid != credentials.egid),
        ),
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
        .filter(|&v| v >= STACK_TOP - INITIAL_ARGUMENT_BYTES)
        .ok_or(ImageError::Arguments("stack exceeds 64 KiB"))?;
    for (index, word) in words.iter().enumerate() {
        elf.memory
            .write(sp + index as u64 * 8, &word.to_le_bytes())?;
    }
    let trampoline = 0x0000_7fff_ffd0_0000;
    elf.memory.map(trampoline, PAGE_SIZE, Permissions::RW)?;
    elf.memory.write(
        trampoline,
        &[0x68, 0x11, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4],
    )?;
    elf.memory.protect(trampoline, PAGE_SIZE, Permissions::RX)?;
    Ok(sp)
}
