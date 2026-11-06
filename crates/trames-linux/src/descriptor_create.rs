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
        280 => crate::bpf::call(factory, a, memory),
        74 => {
            let mask = match Linux::signalfd_parameters(a, memory) {
                Ok(mask) => mask,
                Err(error) => return Some(Err(error)),
            };
            factory
                .signalfd(a[0] as i32, mask, a[3] as u32)?
                .map(u64::from)
        }
        198 => factory
            .socket(a[0] as u32, a[1] as u32, a[2] as u32)
            .map(u64::from),
        199 => (|| {
            Linux::check(memory, a[3], 8, Access::Write)?;
            factory.local_pair_with_output(a[0] as u32, a[1] as u32, a[2] as u32, |fds| {
                let mut bytes = [0; 8];
                bytes[..4].copy_from_slice(&fds[0].to_le_bytes());
                bytes[4..].copy_from_slice(&fds[1].to_le_bytes());
                memory.write(a[3], &bytes).map_err(|_| Errno(14))
            })?;
            Ok(0)
        })(),
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

impl Linux {
    pub fn signalfd(&mut self, a: [u64; 6], memory: &impl CpuMemory) -> Result<u64, Errno> {
        let mask = Self::signalfd_parameters(a, memory)?;
        self.vfs
            .signalfd(a[0] as i32, mask, a[3] as u32)
            .map(u64::from)
    }
    pub fn signalfd_parameters(a: [u64; 6], memory: &impl CpuMemory) -> Result<u64, Errno> {
        if a[2] != 8 {
            return Err(Errno(22));
        }
        Ok(u64::from_le_bytes(
            memory.read_array(a[1]).map_err(|_| Errno(14))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    #[test]
    fn owner_and_worker_creation_share_abi_flags_copyout_and_error_order() {
        for (number, args) in [
            (198, [1, 1, 0, 0, 0, 0]),
            (198, [1, 2, 0, 0, 0, 0]),
            (198, [1, 5, 0, 0, 0, 0]),
            (198, [1, 4, 0, 0, 0, 0]),
            (198, [1, 1, 6, 0, 0, 0]),
            (199, [1, 1, 0, 0x1000, 0, 0]),
            (199, [1, 2, 0, 0x1000, 0, 0]),
            (199, [1, 5, 0, 0x1000, 0, 0]),
            (199, [1, 1, 0, 0x1ffc, 0, 0]),
            (199, [2, 1, 0, 0x1000, 0, 0]),
            (199, [2, 1, 0, 0x9000, 0, 0]),
            (199, [1, 4, 6, 0x1000, 0, 0]),
            (199, [1, 1, 6, 0x1000, 0, 0]),
            (198, [2, 1, 0, 0, 0, 0]),
            (198, [2, 2, 17, 0, 0, 0]),
            (198, [16, 3, 0, 0, 0, 0]),
            (198, [2, 1, 17, 0, 0, 0]),
            (198, [2, 0xffff, 0, 0, 0, 0]),
            (198, [0xffff, 1, 0, 0, 0, 0]),
            (74, [u64::MAX, 0x1000, 8, 0, 0, 0]),
            (
                74,
                [
                    u64::MAX,
                    0x1000,
                    8,
                    trames_vfs::O_NONBLOCK as u64 | trames_vfs::O_CLOEXEC as u64,
                    0,
                    0,
                ],
            ),
            (74, [u64::MAX, 0x9000, 8, 0, 0, 0]),
            (74, [u64::MAX, 0x9000, 4, 0, 0, 0]),
            (74, [u64::MAX, 0x1000, 8, 1, 0, 0]),
            (74, [999, 0x1000, 8, 0, 0, 0]),
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
