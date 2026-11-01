// SPDX-License-Identifier: GPL-3.0-or-later
//! Anonymous-resource ABI over the real shared Files domain.
use crate::Linux;
use trames_memory::{Access, CpuMemory};
use trames_vfs::{DescriptorFactory, Errno};
pub(super) fn call(
    factory: &DescriptorFactory,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Option<Result<u64, Errno>> {
    Some(match number {
        19 => factory.eventfd(a[0] as u32, a[1] as u32).map(u64::from),
        26 => factory.inotify_init(a[0] as u32).map(u64::from),
        85 => factory.timerfd(a[0] as u32, a[1] as u32).map(u64::from),
        59 => (|| {
            Linux::check(memory, a[0], 8, Access::Write)?;
            factory.pipe_with_output(a[1] as u32, |fds| {
                let mut bytes = [0; 8];
                bytes[..4].copy_from_slice(&fds[0].to_le_bytes());
                bytes[4..].copy_from_slice(&fds[1].to_le_bytes());
                memory.write(a[0], &bytes).map_err(|_| Errno(14))
            })?;
            Ok(0)
        })(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    #[test]
    fn owner_and_worker_creation_share_abi_flags_copyout_and_error_order() {
        for (number, args) in [
            (19, [7, 0, 0, 0, 0, 0]),
            (19, [0, 2, 0, 0, 0, 0]),
            (26, [0, 0, 0, 0, 0, 0]),
            (26, [1, 0, 0, 0, 0, 0]),
            (59, [0x1000, 0, 0, 0, 0, 0]),
            (59, [0x1ffc, 0, 0, 0, 0, 0]),
            (59, [0x1ffc, 1, 0, 0, 0, 0]),
            (59, [0x9000, 1, 0, 0, 0, 0]),
            (59, [0x1000, 1, 0, 0, 0, 0]),
        ] {
            let mut owner = Linux::new(0x10000);
            let worker = Linux::new(0x10000);
            let mut a = Memory::new(8192);
            a.map(0x1000, 4096, Permissions::RW).unwrap();
            a.write(0x1000, &[0x55; 8]).unwrap();
            let mut b = a.clone();
            let actual = call(&worker.vfs.descriptor_factory(), number, args, &mut a).unwrap();
            let expected = owner.syscall(
                number as u64,
                args,
                &mut b,
                &mut crate::CapturedOutput::default(),
            );
            assert_eq!(actual, expected, "{number} {args:?}");
            assert_eq!(
                a.read_array::<8>(0x1000).unwrap(),
                b.read_array::<8>(0x1000).unwrap()
            );
            assert_eq!(
                owner.vfs.fd_snapshot().len(),
                worker.vfs.fd_snapshot().len()
            );
        }
    }
}
