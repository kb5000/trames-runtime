// SPDX-License-Identifier: GPL-3.0-or-later
//! Identical comm ABI for source/solo; commit only after the input is imported.
use crate::Linux;
use trames_memory::{Access, CpuMemory};
use trames_vfs::{Errno, TaskName};

pub fn task_name_call(
    name: &TaskName,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    if a[0] == 15 {
        let mut value = [0; 15];
        let mut count = 0;
        for i in 0..15 {
            memory
                .read(a[1] + i, &mut value[count..count + 1])
                .map_err(|_| Errno(14))?;
            if value[count] == 0 {
                break;
            }
            count += 1;
        }
        name.set(&value[..count]);
    } else {
        Linux::check(memory, a[1], 16, Access::Write)?;
        memory.write(a[1], &name.bytes()).map_err(|_| Errno(14))?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    #[test]
    fn comm_abi_stops_at_nul_or_fifteen_bytes_and_faults_before_publication() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let name = TaskName::default();
        name.set(b"before");
        memory.write(0x1ff8, b"nonzero!").unwrap();
        assert_eq!(
            task_name_call(&name, [15, 0x1ff8, 0, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(name.get(), b"before");
        memory.write(0x1fff, &[0]).unwrap();
        assert_eq!(
            task_name_call(&name, [15, 0x1fff, 0, 0, 0, 0], &mut memory),
            Ok(0)
        );
        assert!(name.get().is_empty());
        memory.write(0x1ff1, b"123456789012345").unwrap();
        assert_eq!(
            task_name_call(&name, [15, 0x1ff1, 0, 0, 0, 0], &mut memory),
            Ok(0)
        );
        assert_eq!(name.bytes(), *b"123456789012345\0");
        let before = memory.read_array::<8>(0x1ff8).unwrap();
        assert_eq!(
            task_name_call(&name, [16, 0x1ff8, 0, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(memory.read_array::<8>(0x1ff8).unwrap(), before);
    }
    #[test]
    fn accepted_diagnostics_observe_the_original_name_after_a_later_rename() {
        let linux = Linux::new(0x10000);
        linux.command_name.set(b"before");
        let diagnostics = linux.syscall_diagnostics(7);
        linux.command_name.set(b"after-rename");
        assert_eq!(
            diagnostics.unsupported(0x7fff, 0x4000, [0; 6]),
            (-38i64) as u64
        );
        let log = String::from_utf8(linux.vfs.syslog(3, 16384).unwrap()).unwrap();
        assert!(log.contains("comm=\"after-rename\""), "{log}");
        assert!(!log.contains("comm=\"before\""));
    }
}
