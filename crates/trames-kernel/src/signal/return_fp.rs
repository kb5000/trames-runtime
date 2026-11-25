// SPDX-License-Identifier: GPL-3.0-or-later
//! Native ARM64 record discovery precedes FP, TPIDR2, ZA and ZT restoration.
//! Each completed stage survives a later fault, on this same task.
//! Reference: Linux v6.12 arch/arm64/kernel/signal.c, restore_sigframe().
use super::frame::{EXTRA_MAGIC, SVE_MAGIC, TPIDR2_MAGIC, ZA_MAGIC, ZT_MAGIC};
use super::*;
use crate::user_copy::{Copies, CopyError};
use trames_execution::{Aarch64State, SmeConfig, SmeState};
use trames_memory::{MemoryError, PAGE_SIZE};

const FPSIMD_MAGIC: u32 = 0x46508001;
#[derive(Clone, Copy)]
struct Record {
    address: u64,
    size: u32,
}
#[derive(Default)]
struct Records {
    fp: Option<Record>,
    sve: Option<Record>,
    tls: Option<Record>,
    za: Option<Record>,
    zt: Option<Record>,
}
#[derive(Clone, Copy)]
enum Phase {
    Parse,
    SveHeader,
    SvePayload,
    Fpsimd,
    Tpidr2,
    ZaHeader,
    ZaPayload,
    ZtHeader,
    ZtPayload,
    Done,
}
pub(super) struct Floating {
    address: u64,
    config: Option<SmeConfig>,
    sme2: bool,
    phase: Phase,
    records: Records,
    copies: Copies,
    registers: Option<Box<SmeState>>,
    sve_payload: Vec<u8>,
    copied: usize,
    streaming: bool,
}
fn copied<T>(result: Result<T, MemoryError>) -> Result<T, CopyError> {
    result.map_err(|error| match error {
        MemoryError::Pending(fault) => CopyError::Page(fault),
        _ => CopyError::Error(Errno(14)),
    })
}
fn invalid<T>() -> Result<T, CopyError> {
    Err(CopyError::Error(Errno(22)))
}
// __get_user_error still accesses the second scalar after a permanent error
// in the first. A genuine page wait suspends before that second access.
fn pair<const A: usize, const B: usize>(
    copies: &Copies,
    memory: &impl CpuMemory,
    first: u64,
    second: u64,
) -> Result<([u8; A], [u8; B]), CopyError> {
    let a = copies.read_array::<A>(memory, first);
    if let Err(MemoryError::Pending(fault)) = &a {
        return Err(CopyError::Page(fault.clone()));
    }
    let b = copies.read_array::<B>(memory, second);
    if let Err(MemoryError::Pending(fault)) = &b {
        return Err(CopyError::Page(fault.clone()));
    }
    Ok((copied(a)?, copied(b)?))
}
fn discover(
    copies: &Copies,
    memory: &impl CpuMemory,
    frame: u64,
    sme: bool,
    sme2: bool,
) -> Result<Records, CopyError> {
    let mut records = Records::default();
    let mut base = frame + 592;
    let mut offset = 0u64;
    let mut limit = 4096u64;
    let mut extra = false;
    loop {
        if offset & 15 != 0 || limit.saturating_sub(offset) < 8 {
            return invalid();
        }
        let address = base + offset;
        let (magic, size) = pair::<4, 4>(copies, memory, address, address + 4)?;
        let magic = u32::from_le_bytes(magic);
        let size = u32::from_le_bytes(size);
        if size as u64 > limit - offset {
            return invalid();
        }
        let record = Record { address, size };
        let slot = match magic {
            0 => {
                if size != 0 {
                    return invalid();
                }
                return Ok(records);
            }
            FPSIMD_MAGIC => Some(&mut records.fp),
            SVE_MAGIC if sme => Some(&mut records.sve),
            TPIDR2_MAGIC if sme => Some(&mut records.tls),
            ZA_MAGIC if sme => Some(&mut records.za),
            ZT_MAGIC if sme2 => Some(&mut records.zt),
            0x45535201 => None, // ESR records are ignored, including repetitions.
            EXTRA_MAGIC => {
                if extra || size < 32 {
                    return invalid();
                }
                let (data, bytes) = pair::<8, 4>(copies, memory, address + 8, address + 16)?;
                if limit - offset - (size as u64) < 16 {
                    return invalid();
                }
                let end = address + size as u64;
                let (end_magic, end_size) = pair::<4, 4>(copies, memory, end, end + 4)?;
                if end_magic != [0; 4] || end_size != [0; 4] {
                    return invalid();
                }
                let data = u64::from_le_bytes(data);
                let bytes = u32::from_le_bytes(bytes) as u64;
                if data != end + 16
                    || data & 15 != 0
                    || bytes & 15 != 0
                    || bytes > frame + 256 * 1024 - data
                    || (data & 0x00ff_ffff_ffff_ffff)
                        .checked_add(bytes)
                        .is_none_or(|end| end > trames_memory::ADDRESS_LIMIT)
                {
                    return invalid();
                }
                base = data;
                offset = 0;
                limit = bytes;
                extra = true;
                continue;
            }
            _ => return invalid(),
        };
        if let Some(slot) = slot {
            if slot.is_some() {
                return invalid();
            }
            *slot = Some(record);
        }
        if size < 8 {
            return invalid();
        }
        offset += size as u64;
    }
}
fn payload(
    memory: &impl CpuMemory,
    address: u64,
    bytes: &mut [u8],
    cursor: &mut usize,
) -> Result<(), CopyError> {
    while *cursor < bytes.len() {
        let at = address + *cursor as u64;
        let count = (bytes.len() - *cursor).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
        copied(memory.read(at, &mut bytes[*cursor..*cursor + count]))?;
        *cursor += count;
    }
    Ok(())
}
impl Floating {
    pub fn new(
        address: u64,
        config: Option<SmeConfig>,
        sme2: bool,
        registers: Option<&SmeState>,
    ) -> Self {
        Self {
            address,
            config,
            sme2,
            phase: Phase::Parse,
            records: Default::default(),
            copies: Default::default(),
            registers: registers.cloned().map(Box::new),
            sve_payload: Vec::new(),
            copied: 0,
            streaming: false,
        }
    }
    pub fn result(&self) -> Option<Option<Box<SmeState>>> {
        self.config.map(|_| self.registers.clone())
    }
    pub fn take_result(&mut self) -> Option<Option<Box<SmeState>>> {
        self.config.map(|_| self.registers.take())
    }
    fn advance(&mut self, phase: Phase) {
        self.phase = phase;
        self.copies = Default::default();
        self.copied = 0;
    }
    fn ensure_registers(&mut self) -> &mut SmeState {
        self.registers.get_or_insert_with(|| {
            Box::new(SmeState {
                vl: self.config.unwrap().vl as u64,
                ..Default::default()
            })
        })
    }
    pub fn progress(
        &mut self,
        state: &mut Aarch64State,
        memory: &impl CpuMemory,
    ) -> Result<(), CopyError> {
        loop {
            match self.phase {
                Phase::Parse => {
                    self.records = discover(
                        &self.copies,
                        memory,
                        self.address,
                        self.config.is_some(),
                        self.sme2,
                    )?;
                    if self.records.fp.is_none() {
                        return invalid();
                    }
                    self.advance(Phase::SveHeader);
                }
                Phase::SveHeader => {
                    let Some(record) = self.records.sve else {
                        self.advance(Phase::Fpsimd);
                        continue;
                    };
                    if record.size < 16 {
                        return invalid();
                    }
                    let (vl, flags) = pair::<2, 2>(
                        &self.copies,
                        memory,
                        record.address + 8,
                        record.address + 10,
                    )?;
                    self.streaming = u16::from_le_bytes(flags) & 1 != 0;
                    // This engine profile advertises SME streaming SVE, not SVE.
                    let expected = if self.streaming {
                        self.config.unwrap().vl
                    } else {
                        0
                    };
                    if u16::from_le_bytes(vl) != expected {
                        return invalid();
                    }
                    if record.size == 16 {
                        if let Some(registers) = &mut self.registers {
                            registers.svcr &= !1;
                        }
                        self.advance(Phase::Fpsimd);
                    } else {
                        let bytes = expected as usize * 32 + expected as usize / 8 * 17;
                        if (record.size as usize) < 16 + bytes {
                            return invalid();
                        }
                        let registers = self.ensure_registers();
                        registers.z.fill(0);
                        registers.p.fill(0);
                        self.sve_payload = vec![0; bytes];
                        self.advance(Phase::SvePayload);
                    }
                }
                Phase::SvePayload => {
                    let record = self.records.sve.unwrap();
                    let result = payload(
                        memory,
                        record.address + 16,
                        &mut self.sve_payload,
                        &mut self.copied,
                    );
                    let registers = self.registers.as_mut().unwrap();
                    let z = if self.streaming {
                        self.config.unwrap().vl as usize * 32
                    } else {
                        0
                    };
                    let p = z / 16;
                    registers.z[..z].copy_from_slice(&self.sve_payload[..z]);
                    registers.p[..p].copy_from_slice(&self.sve_payload[z..z + p]);
                    result?;
                    if self.streaming {
                        registers.svcr |= 1;
                    }
                    self.advance(Phase::Fpsimd);
                }
                Phase::Fpsimd => {
                    let record = self.records.fp.unwrap();
                    if self.records.sve.is_none() && record.size != 528 {
                        return invalid();
                    }
                    let vectors = self.copies.read_array::<512>(memory, record.address + 16);
                    if let Err(MemoryError::Pending(fault)) = &vectors {
                        return Err(CopyError::Page(fault.clone()));
                    }
                    let (fpsr, fpcr) = pair::<4, 4>(
                        &self.copies,
                        memory,
                        record.address + 8,
                        record.address + 12,
                    )?;
                    let vectors = copied(vectors)?;
                    for index in 0..32 {
                        state.vectors[index] = u128::from_le_bytes(
                            vectors[index * 16..index * 16 + 16].try_into().unwrap(),
                        );
                    }
                    state.fpsr = u32::from_le_bytes(fpsr);
                    state.fpcr = u32::from_le_bytes(fpcr);
                    if let Some(registers) = self
                        .registers
                        .as_mut()
                        .filter(|registers| registers.svcr & 1 != 0)
                    {
                        for (index, vector) in state.vectors.iter().enumerate() {
                            let offset = index * registers.vl as usize;
                            registers.z[offset..offset + 16].copy_from_slice(&vector.to_le_bytes());
                        }
                    }
                    self.advance(Phase::Tpidr2);
                }
                Phase::Tpidr2 => {
                    if let Some(record) = self.records.tls {
                        if record.size != 16 {
                            return invalid();
                        }
                        state.tpidr2_el0 = u64::from_le_bytes(copied(
                            self.copies.read_array::<8>(memory, record.address + 8),
                        )?);
                    }
                    self.advance(Phase::ZaHeader);
                }
                Phase::ZaHeader => {
                    let Some(record) = self.records.za else {
                        self.advance(Phase::ZtHeader);
                        continue;
                    };
                    if record.size < 16 {
                        return invalid();
                    }
                    let vl = u16::from_le_bytes(copied(
                        self.copies.read_array::<2>(memory, record.address + 8),
                    )?);
                    if vl != self.config.unwrap().vl {
                        return invalid();
                    }
                    if record.size == 16 {
                        if let Some(registers) = &mut self.registers {
                            registers.svcr &= !2;
                        }
                        self.advance(Phase::ZtHeader);
                    } else {
                        if (record.size as usize) < 16 + vl as usize * vl as usize {
                            return invalid();
                        }
                        let registers = self.ensure_registers();
                        registers.za.fill(0);
                        registers.zt.fill(0);
                        self.advance(Phase::ZaPayload);
                    }
                }
                Phase::ZaPayload => {
                    let record = self.records.za.unwrap();
                    let vl = self.config.unwrap().vl as usize;
                    let registers = self.registers.as_mut().unwrap();
                    payload(
                        memory,
                        record.address + 16,
                        &mut registers.za[..vl * vl],
                        &mut self.copied,
                    )?;
                    registers.svcr |= 2;
                    self.advance(Phase::ZtHeader);
                }
                Phase::ZtHeader => {
                    let Some(record) = self.records.zt else {
                        self.advance(Phase::Done);
                        continue;
                    };
                    if self
                        .registers
                        .as_ref()
                        .is_none_or(|registers| registers.svcr & 2 == 0)
                        || record.size != 80
                    {
                        return invalid();
                    }
                    if u16::from_le_bytes(copied(
                        self.copies.read_array::<2>(memory, record.address + 8),
                    )?) != 1
                    {
                        return invalid();
                    }
                    self.advance(Phase::ZtPayload);
                }
                Phase::ZtPayload => {
                    let record = self.records.zt.unwrap();
                    payload(
                        memory,
                        record.address + 16,
                        &mut self.registers.as_mut().unwrap().zt,
                        &mut self.copied,
                    )?;
                    self.advance(Phase::Done);
                }
                Phase::Done => return Ok(()),
            }
        }
    }
}
