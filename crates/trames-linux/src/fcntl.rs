// SPDX-License-Identifier: GPL-3.0-or-later
//! Short controls share the same original OFD/credential ABI on every executor.
use trames_vfs::{DescriptorFactory, Errno};
pub(crate) fn short(factory: &DescriptorFactory, args: [u64; 6]) -> Option<Result<u64, Errno>> {
    // These families already retain their own creation/lock/async/FileWork state.
    if matches!(args[1],0|5..=11|15|16|36..=38|1030|1033|1034) {
        return None;
    }
    Some(
        factory
            .descriptor_control(args[0] as u32)
            .and_then(|control| {
                control.short(
                    args[0] as u32,
                    args[1],
                    args[2],
                    factory.local_credentials(),
                )
            }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_and_solo_short_control_share_errors_and_never_read_unused_arguments() {
        let mut linux = crate::Linux::new(0x100000);
        linux.vfs.import_file(b"/file", Vec::new()).unwrap();
        let file = linux.vfs.open_at(-100, b"/file", 2, 0).unwrap();
        let path = linux
            .vfs
            .open_at(-100, b"/", trames_vfs::O_PATH, 0)
            .unwrap();
        linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        let mut memory = trames_memory::Memory::default();
        for (fd, cmd, arg, expected) in [
            (file, 4, 0x80040000, Err(Errno(1))),
            (file, 4, 0x80000000, Err(Errno(22))),
            (path, 4, u64::MAX, Err(Errno(9))),
            (file, 12, u64::MAX, Err(Errno(22))),
            (path, 12, u64::MAX, Err(Errno(9))),
            (u32::MAX, 12, u64::MAX, Err(Errno(9))),
            (file, 0x100000003, 0, Err(Errno(22))),
            (file, 2, 1, Ok(0)),
            (file, 1, 0, Ok(1)),
            (file, 3, 0, Ok(2)),
        ] {
            let args = [fd as u64, cmd, arg, 0, 0, 0];
            assert_eq!(short(&linux.vfs.descriptor_factory(), args), Some(expected));
            assert_eq!(
                linux.syscall(25, args, &mut memory, &mut crate::CapturedOutput::default()),
                expected
            );
        }
        for cmd in [
            0, 5, 6, 7, 8, 9, 10, 11, 15, 16, 36, 37, 38, 1030, 1033, 1034,
        ] {
            assert_eq!(
                short(
                    &linux.vfs.descriptor_factory(),
                    [file as u64, cmd, 0, 0, 0, 0]
                ),
                None
            );
        }
    }
}
