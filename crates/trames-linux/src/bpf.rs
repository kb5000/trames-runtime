// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest cgroup device filters only. No program is handed to the host kernel.
use super::{Access, Linux, Memory};
use trames_memory::CpuMemory;
use trames_vfs::Errno;

impl Linux {
    pub(super) fn bpf_syscall(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64, Errno> {
        call(&self.vfs.descriptor_factory(), a, memory)
    }
}
pub(super) fn call(
    factory: &trames_vfs::DescriptorFactory,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    factory.bpf_authorized()?;
    let command = a[0] as u32;
    let size = a[2] as u32 as usize;
    if size > 4096 {
        return Err(Errno(7));
    }
    Linux::check(memory, a[1], size, Access::Read)?;
    let mut attr = vec![0; size.max(152)];
    memory
        .read(a[1], &mut attr[..size])
        .map_err(|_| Errno(14))?;
    let u32_at = |i| u32::from_le_bytes(attr[i..i + 4].try_into().unwrap());
    let u64_at = |i| u64::from_le_bytes(attr[i..i + 8].try_into().unwrap());
    let tail = |i| {
        if attr[i..].iter().any(|b| *b != 0) {
            Err(Errno(7))
        } else {
            Ok(())
        }
    };
    match command {
        5 => {
            // BPF_PROG_LOAD
            tail(72)?;
            if !matches!(u32_at(0), 8 | 15)
                || !matches!((u32_at(0), u32_at(68)), (15, 0 | 6) | (8, 0 | 1))
            {
                return Err(Errno(22));
            }
            if u32_at(40) != 0 || u32_at(44) != 0 || u32_at(64) != 0 || u32_at(24) & !7 != 0 {
                return Err(Errno(22));
            }
            if attr[48..64]
                .iter()
                .take_while(|b| **b != 0)
                .any(|b| !b.is_ascii_alphanumeric() && *b != b'_')
            {
                return Err(Errno(22));
            }
            let count = u32_at(4) as usize;
            if count == 0 {
                return Err(Errno(22));
            }
            if count > 4096 {
                return Err(Errno(7));
            }
            memory
                .read_c_string(u64_at(16), 128)
                .map_err(|_| Errno(14))?;
            Linux::check(memory, u64_at(8), count * 8, Access::Read)?;
            let mut code = vec![0; count * 8];
            memory.read(u64_at(8), &mut code).map_err(|_| Errno(14))?;
            // Preflight the bounded log before allocating an FD. The verifier
            // has no host pointers, helpers, loops, maps or stack memory.
            let log =
                b"cgroup device verifier: unsupported or invalid instruction/control flow\n\0";
            let log_size = if u32_at(24) != 0 {
                (u32_at(28) as usize).min(log.len())
            } else {
                0
            };
            if log_size > 0 {
                Linux::check(memory, u64_at(32), log_size, Access::Write)?;
            }
            let result = factory.bpf_load_program(u32_at(0), &code);
            if log_size > 0 {
                let mut bytes = if result.is_ok() {
                    vec![0]
                } else {
                    log[..log_size].to_vec()
                };
                *bytes.last_mut().unwrap() = 0;
                memory.write(u64_at(32), &bytes).map_err(|_| Errno(14))?;
            }
            result.map(u64::from)
        }
        8 | 9 => {
            // BPF_PROG_ATTACH / BPF_PROG_DETACH
            tail(20)?;
            if u32_at(8) != 6 {
                return Err(Errno(95));
            }
            if command == 8 {
                // Linux ignores replace_bpf_fd without BPF_F_REPLACE.
                // Older cilium/runc passes -1 in this unused field.
                factory.bpf_attach_device(u32_at(0), u32_at(4), u32_at(12), u32_at(16))?;
            } else {
                if u32_at(12) != 0 || u32_at(16) != 0 {
                    return Err(Errno(22));
                }
                factory.bpf_detach_device(u32_at(0), u32_at(4))?;
            }
            Ok(0)
        }
        13 => {
            // BPF_PROG_GET_FD_BY_ID
            tail(4)?;
            factory.bpf_get_fd(u32_at(0)).map(u64::from)
        }
        15 => {
            // BPF_OBJ_GET_INFO_BY_FD. Advertise only the implemented type/ID
            // prefix; do not fabricate tags, JIT state or execution stats.
            tail(16)?;
            let info = factory.bpf_program_identity(u32_at(0)).map_err(|e| {
                if e.0 == 9 {
                    Errno(77)
                } else {
                    e
                }
            })?;
            let length = u32_at(4) as usize;
            if length > 4096 {
                return Err(Errno(7));
            }
            let count = length.min(info.len());
            if length > info.len() {
                Linux::check(
                    memory,
                    u64_at(8).checked_add(8).ok_or(Errno(14))?,
                    length - 8,
                    Access::Read,
                )?;
                let mut extra = vec![0; length - 8];
                memory
                    .read(u64_at(8).checked_add(8).ok_or(Errno(14))?, &mut extra)
                    .map_err(|_| Errno(14))?;
                if extra.iter().any(|b| *b != 0) {
                    return Err(Errno(7));
                }
            }
            Linux::check(memory, u64_at(8), count, Access::Write)?;
            Linux::check(memory, a[1] + 4, 4, Access::Write)?;
            memory
                .write(u64_at(8), &info[..count])
                .map_err(|_| Errno(14))?;
            memory
                .write(a[1] + 4, &(count as u32).to_le_bytes())
                .map_err(|_| Errno(14))?;
            Ok(0)
        }
        16 => {
            // BPF_PROG_QUERY
            tail(28)?;
            if u32_at(4) != 6 {
                return Err(Errno(95));
            }
            if u32_at(8) & !1 != 0 {
                return Err(Errno(22));
            }
            let (flags, ids) = factory.bpf_query_device(u32_at(0), u32_at(8) == 1)?;
            let capacity = u32_at(24) as usize;
            let copied = capacity.min(ids.len());
            Linux::check(memory, a[1] + 12, 4, Access::Write)?;
            Linux::check(memory, a[1] + 24, 4, Access::Write)?;
            Linux::check(memory, u64_at(16), copied * 4, Access::Write)?;
            let bytes: Vec<_> = ids[..copied]
                .iter()
                .flat_map(|id| id.to_le_bytes())
                .collect();
            memory.write(u64_at(16), &bytes).map_err(|_| Errno(14))?;
            memory
                .write(a[1] + 12, &flags.to_le_bytes())
                .map_err(|_| Errno(14))?;
            memory
                .write(a[1] + 24, &(ids.len() as u32).to_le_bytes())
                .map_err(|_| Errno(14))?;
            if capacity < ids.len() {
                Err(Errno(28))
            } else {
                Ok(0)
            }
        }
        // Unknown commands (including unsupported BTF operations) follow
        // Linux's EINVAL feature-probe contract; EOPNOTSUPP makes libbpf
        // and cilium treat the probe itself as an unexpected failure.
        _ => Err(Errno(22)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DirectSyscalls;
    use trames_memory::Permissions;
    use trames_vfs::{Credentials, RuntimeInfo, AT_FDCWD, O_PATH};

    #[test]
    fn source_bpf_preflights_guest_outputs_and_publishes_original_files() {
        let mut owner = Linux::new(0x9000);
        owner.vfs.set_runtime_info(1, RuntimeInfo::default());
        let group = owner
            .vfs
            .open_at(AT_FDCWD, b"/sys/fs/cgroup", O_PATH, 0)
            .unwrap();
        let source = DirectSyscalls::default().with_resources(owner.vfs.descriptor_factory());
        let mut memory = Memory::default();
        memory.map(0x1000, 4096, Permissions::RW).unwrap();
        let mut attr = [0u8; 152];
        attr[..4].copy_from_slice(&15u32.to_le_bytes());
        attr[4..8].copy_from_slice(&2u32.to_le_bytes());
        attr[8..16].copy_from_slice(&0x1200u64.to_le_bytes());
        attr[16..24].copy_from_slice(&0x1300u64.to_le_bytes());
        attr[24..28].copy_from_slice(&1u32.to_le_bytes());
        attr[28..32].copy_from_slice(&64u32.to_le_bytes());
        attr[32..40].copy_from_slice(&0x9000u64.to_le_bytes());
        memory.write(0x1100, &attr).unwrap();
        memory
            .write(
                0x1200,
                &[0xb7, 0, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0],
            )
            .unwrap();
        memory.write(0x1300, b"GPL\0").unwrap();
        assert_eq!(
            source.invoke_creation(280, [5, 0x1100, 152, 0, 0, 0], &mut memory),
            Some(Err(Errno(14)))
        );
        assert_eq!(owner.vfs.fd_snapshot().len(), 4);
        memory.write(0x1120, &0x1400u64.to_le_bytes()).unwrap();
        let program = source
            .invoke_creation(280, [5, 0x1100, 152, 0, 0, 0], &mut memory)
            .unwrap()
            .unwrap() as u32;
        assert_eq!(memory.read_array::<1>(0x1400).unwrap(), [0]);
        let info = owner.vfs.bpf_program_identity(program).unwrap();
        assert_eq!(&info[..4], &15u32.to_le_bytes());
        owner.vfs.bpf_attach_device(group, program, 2, 0).unwrap();
        // An invalid query destination must not partially publish its count.
        attr.fill(0);
        attr[..4].copy_from_slice(&group.to_le_bytes());
        attr[4..8].copy_from_slice(&6u32.to_le_bytes());
        attr[16..24].copy_from_slice(&0x9000u64.to_le_bytes());
        attr[24..28].copy_from_slice(&8u32.to_le_bytes());
        memory.write(0x1100, &attr).unwrap();
        assert_eq!(
            source.invoke_creation(280, [16, 0x1100, 152, 0, 0, 0], &mut memory),
            Some(Err(Errno(14)))
        );
        assert_eq!(memory.read_array::<4>(0x1118).unwrap(), 8u32.to_le_bytes());
        // Permission errors precede reading the guest's attribute buffer.
        owner.vfs.credentials = Credentials::user(1000, 1000);
        let future = DirectSyscalls::default().with_resources(owner.vfs.descriptor_factory());
        assert_eq!(
            future.invoke_creation(280, [999, u64::MAX, u64::MAX, 0, 0, 0], &mut memory),
            Some(Err(Errno(1)))
        );
        assert_eq!(
            source.invoke_creation(280, [999, 0x1100, 152, 0, 0, 0], &mut memory),
            Some(Err(Errno(22)))
        );
    }
}
