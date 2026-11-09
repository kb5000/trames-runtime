// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest power controls validate Linux policy; they never call a host power API.
use trames_vfs::{capabilities, Credentials, Errno, PidNamespace};

pub fn prepare(
    credentials: &Credentials,
    namespace: &PidNamespace,
    args: [u64; 6],
) -> Result<(), Errno> {
    if !credentials.has_cap(capabilities::SYS_BOOT) {
        return Err(Errno(1));
    }
    if args[0] as u32 != 0xfee1_dead
        || !matches!(
            args[1] as u32,
            0x2812_1969 | 0x0512_1996 | 0x1604_1998 | 0x2011_2000
        )
    {
        return Err(Errno(22));
    }
    match args[2] as u32 {
        0xcdef_0123 | 0x4321_fedc => {}
        0x0123_4567 | 0xa1b2_c3d4 | 0x4558_4543 | 0xd000_fce2 | 0x89ab_cdef | 0 => {
            return Err(Errno(95))
        }
        _ => return Err(Errno(22)),
    }
    // Existing nested restart/status translation is unsupported. In particular,
    // its PID 1 may never shut down the containing userspace Linux instance.
    if namespace.is_nested() {
        return Err(Errno(95));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn power_policy_preserves_authority_magic_commands_and_namespace_order() {
        let root = Credentials::default();
        let namespace = PidNamespace::default();
        assert_eq!(
            prepare(&Credentials::user(1000, 1000), &namespace, [0; 6]),
            Err(Errno(1))
        );
        assert_eq!(prepare(&root, &namespace, [0; 6]), Err(Errno(22)));
        for magic in [0x2812_1969, 0x0512_1996, 0x1604_1998, 0x2011_2000] {
            for command in [0xcdef_0123, 0x4321_fedc] {
                // High bits of the int arguments and the unused pointer retain
                // the existing ABI; no guest bytes or host API are touched.
                assert_eq!(
                    prepare(
                        &root,
                        &namespace,
                        [
                            0xaaaa_0000_fee1_dead,
                            magic | 0xbbbb_0000_0000_0000,
                            command,
                            u64::MAX,
                            0,
                            0
                        ]
                    ),
                    Ok(())
                );
            }
        }
        for command in [
            0,
            0x0123_4567,
            0xa1b2_c3d4,
            0x4558_4543,
            0xd000_fce2,
            0x89ab_cdef,
        ] {
            assert_eq!(
                prepare(
                    &root,
                    &namespace,
                    [0xfee1_dead, 0x2812_1969, command, 0, 0, 0]
                ),
                Err(Errno(95))
            );
        }
        assert_eq!(
            prepare(&root, &namespace, [0xfee1_dead, 0x2812_1969, 123, 0, 0, 0]),
            Err(Errno(22))
        );
        let mut nested = trames_vfs::Vfs::default();
        nested.unshare_pid().unwrap();
        nested.activate_child_pid(42).unwrap();
        assert_eq!(
            prepare(
                &root,
                nested.pid_namespace(),
                [0xfee1_dead, 0x2812_1969, 0x4321_fedc, 0, 0, 0]
            ),
            Err(Errno(95))
        );
    }
}
