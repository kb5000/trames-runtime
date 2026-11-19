// SPDX-License-Identifier: GPL-3.0-or-later
use trames_memory::CpuMemory;
use trames_vfs::{DescriptorFactory, Errno};
pub(super) fn actor(factory: &DescriptorFactory, pid: u32) -> u32 {
    let group = factory.local_sender_credentials()[0];
    if group == 0 {
        pid
    } else {
        group
    }
}
pub(super) fn control(
    factory: &DescriptorFactory,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
    pid: u32,
) -> Result<u64, Errno> {
    if number == 194 {
        return factory
            .shm_get(a[0] as i32, a[1], a[2] as u32, actor(factory, pid))
            .map(u64::from);
    }
    let cmd = a[1] as u32 & !0x100;
    let input = if cmd == 1 {
        Some(memory.read_array(a[2]).map_err(|_| Errno(14))?)
    } else {
        None
    };
    let (result, data) = factory.shm_control(a[0] as u32, cmd, input.as_ref())?;
    if !data.is_empty() {
        memory.write(a[2], &data).map_err(|_| Errno(14))?
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapturedOutput, Linux};
    use trames_memory::{Memory, Permissions, PAGE_SIZE as P};

    fn attach(
        linux: &mut Linux,
        mem: &mut Memory,
        id: u32,
        addr: u64,
        flags: u64,
    ) -> Result<u64, Errno> {
        linux.syscall(
            196,
            [id.into(), addr, flags, 0, 0, 0],
            mem,
            &mut CapturedOutput::default(),
        )
    }
    fn stat(f: &DescriptorFactory, id: u32) -> Result<(u32, u64), Errno> {
        let (_, b) = f.shm_control(id, 2, None)?;
        Ok((
            u32::from_le_bytes(b[84..88].try_into().unwrap()),
            u64::from_le_bytes(b[88..96].try_into().unwrap()),
        ))
    }

    #[test]
    fn removed_key_can_be_reused_while_fork_and_old_namespace_retain_original_bytes() {
        let mut linux = Linux::new(0);
        linux.vfs.set_lock_owner(12);
        let f = linux.vfs.descriptor_factory();
        let old = f.shm_get(37, P * 3, 0o1600, 12).unwrap();
        let mut mm = Memory::default();
        let a = attach(&mut linux, &mut mm, old, 0x10000, 0).unwrap();
        assert_eq!(attach(&mut linux, &mut mm, old, a, 0), Err(Errno(22)));
        assert_eq!(stat(&f, old).unwrap(), (12, 1));
        mm.write_array(a, [31u8]).unwrap();
        let mut child = mm.try_fork_for(42).unwrap();
        assert_eq!(stat(&f, old).unwrap(), (42, 2));
        child.write_array(a, [32u8]).unwrap();
        assert_eq!(mm.read_array::<1>(a).unwrap(), [32]);
        f.shm_control(old, 0, None).unwrap();
        let new = f.shm_get(37, P, 0o1600, 12).unwrap();
        assert_ne!(old, new);
        linux.vfs.unshare_ipc().unwrap();
        assert_eq!(
            linux.vfs.descriptor_factory().shm_get(37, 0, 0, 12),
            Err(Errno(2))
        );
        drop(child);
        assert_eq!(stat(&f, old).unwrap(), (42, 1));
        let mut peer = mm.share();
        assert_eq!(stat(&f, old).unwrap().1, 1);
        peer.detach_segment(a, 15).unwrap();
        assert!(mm.is_free(a, P * 3));
        assert_eq!(stat(&f, old), Err(Errno(22)));
        assert_eq!(f.shm_get(37, 0, 0, 12).unwrap(), new);
    }

    #[test]
    fn shared_segment_remap_and_detach_preserve_aliases_and_replacements() {
        let mut linux = Linux::new(0);
        let f = linux.vfs.descriptor_factory();
        let id = f.shm_get(0, P * 3, 0o600, 1).unwrap();
        let mut m = Memory::default();
        let a = attach(&mut linux, &mut m, id, 0x10000, 0).unwrap();
        let alias = attach(&mut linux, &mut m, id, 0x20000, 0).unwrap();
        m.write_array(alias + 2 * P, [42u8]).unwrap();
        m.remap(a, 3 * P, 0x40000, 2 * P, true).unwrap();
        m.remap(0x40000, 2 * P, 0x40000, 3 * P, false).unwrap();
        assert_eq!(m.read_array::<1>(0x40000 + 2 * P).unwrap(), [42]);
        m.map_fixed(0x40000 + P, P, Permissions::RW).unwrap();
        m.write_array(0x40000 + P, [89u8]).unwrap();
        m.detach_segment(0x40000, 1).unwrap();
        assert!(m.is_free(0x40000, P));
        assert!(m.is_free(0x40000 + 2 * P, P));
        assert_eq!(m.read_array::<1>(0x40000 + P).unwrap(), [89]);
        assert_eq!(m.read_array::<1>(alias + 2 * P).unwrap(), [42]);
        m.advise_fork(alias, P * 3, 10).unwrap();
        let child = m.try_fork_for(2).unwrap();
        assert!(child.is_free(alias, P * 3));
        assert_eq!(stat(&f, id).unwrap().1, 1);
    }
}
