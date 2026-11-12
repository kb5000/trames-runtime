// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};

fn memory() -> Memory {
    let mut memory = Memory::default();
    memory.map(0x1000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
    memory
}
fn capture(linux: &Linux) -> DirectSyscalls {
    DirectSyscalls::new(linux.vfs.direct_descriptors()).with_paths(linux.vfs.path_queries())
}
fn setup(kind: u8) -> (Linux, Memory, u32) {
    let mut linux = Linux::new(0x10000);
    linux.vfs.set_runtime_info(
        1,
        trames_vfs::RuntimeInfo {
            processes: vec![trames_vfs::ProcessInfo {
                pid: 1,
                tgid: 1,
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    linux.vfs.enable_video_device();
    linux
        .vfs
        .configure_local_fabric(trames_vfs::NetworkMode::Loopback)
        .unwrap();
    let fd = match kind {
        0 => linux.vfs.pipe(0).unwrap()[0],
        1 => linux.vfs.socket(2, 2, 0).unwrap(),
        2 => linux
            .vfs
            .open_at(-100, b"/dev/dri/renderD128", 2, 0)
            .unwrap(),
        3 => linux.vfs.open_at(-100, b"/proc/self/ns/net", 0, 0).unwrap(),
        4 => linux.vfs.socketpair(1, 1, 0).unwrap()[0],
        5 => linux
            .vfs
            .open_at(-100, b"/", trames_vfs::O_PATH, 0)
            .unwrap(),
        _ => unreachable!(),
    };
    (linux, memory(), fd)
}

#[test]
fn musl_signed_render_ioctl_and_high_register_bits_use_the_same_u32_command() {
    let mut expected = None;
    for request in [0xc0406400, 0xffffffffc0406400, 0x12345678c0406400] {
        for source in [false, true] {
            let (mut linux, mut m, fd) = setup(2);
            m.write(0x1000, &[0; 64]).unwrap();
            m.write_array(0x1010, 16u64.to_le_bytes()).unwrap();
            m.write_array(0x1018, 0x2000u64.to_le_bytes()).unwrap();
            let args = [fd as u64, request, 0x1000, 0, 0, 0];
            let result = if source {
                capture(&linux).invoke(29, args, &mut m).unwrap()
            } else {
                linux.syscall(29, args, &mut m, &mut crate::CapturedOutput::default())
            };
            assert_eq!(result, Ok(0));
            assert_eq!(m.read_array::<6>(0x2000).unwrap(), *b"trames");
            let actual = (
                m.read_array::<64>(0x1000).unwrap(),
                m.read_array::<16>(0x2000).unwrap(),
            );
            if let Some(expected) = &expected {
                assert_eq!(&actual, expected);
            } else {
                expected = Some(actual);
            }
        }
    }
}

#[test]
fn descriptor_discovery_and_unsupported_ioctl_share_the_complete_source_solo_abi() {
    for (kind, request) in [
        (0, 0x1234),
        (0, 0xdeadbeef),
        (1, 0x1234),
        (4, 0x1234),
        (1, 0x8910),
        (1, 0x8912),
        (1, 0x8913),
        (1, 0x8914),
        (1, 0x8915),
        (1, 0x891b),
        (1, 0x8921),
        (1, 0x8933),
        (1, 0x8942),
        (1, 0x8927),
        (4, 0x8933),
        (2, 0xc0406400),
        (2, 0x1234),
        (3, 0xb703),
        (3, 0x1234),
        (5, 0x1234),
    ] {
        let mut results = Vec::new();
        for source in [false, true] {
            let (mut linux, mut m, fd) = setup(kind);
            m.write(0x1000, b"lo\0").unwrap();
            if request == 0x8910 {
                m.write_array(0x1010, 1u32.to_le_bytes()).unwrap();
            }
            if request == 0x8914 {
                m.write_array(0x1010, 1u16.to_le_bytes()).unwrap();
            }
            if request == 0x8912 {
                m.write_array(0x1000, 80u32.to_le_bytes()).unwrap();
                m.write_array(0x1008, 0x2000u64.to_le_bytes()).unwrap();
            }
            if request == 0xc0406400 {
                m.write(0x1000, &[0; 64]).unwrap();
                for offset in [16, 32, 48] {
                    m.write_array(0x1000 + offset, 64u64.to_le_bytes()).unwrap();
                    m.write_array(0x1008 + offset, (0x2000 + offset * 4).to_le_bytes())
                        .unwrap();
                }
            }
            let args = [fd as u64, request, 0x1000, 0, 0, 0];
            let result = if source {
                capture(&linux)
                    .invoke(29, args, &mut m)
                    .expect("original descriptor control")
            } else {
                linux.syscall(29, args, &mut m, &mut crate::CapturedOutput::default())
            };
            results.push((
                result,
                m.read_array::<4096>(0x1000).unwrap(),
                m.read_array::<4096>(0x2000).unwrap(),
            ));
        }
        assert_eq!(results[0], results[1], "kind={kind} request={request:#x}");
    }
}

#[test]
fn ioctl_rejections_and_partial_render_outputs_preserve_error_precedence() {
    for (kind, request, pointer) in [
        (0, 0x1234, u64::MAX),
        (1, 0x1234, u64::MAX),
        (1, 0x8933, u64::MAX),
        (2, 0x1234, u64::MAX),
        (2, 0xc0406400, u64::MAX),
        (3, 0xb703, u64::MAX),
        (5, 0xc0406400, u64::MAX),
        (2, 0xc0406400, 0x1000),
    ] {
        let mut results = Vec::new();
        for source in [false, true] {
            let (mut linux, mut m, fd) = setup(kind);
            m.write(0x1000, &[0; 64]).unwrap();
            if pointer == 0x1000 {
                m.write_array(0x1010, 6u64.to_le_bytes()).unwrap();
                m.write_array(0x1018, 0x2000u64.to_le_bytes()).unwrap();
                m.write_array(0x1020, 8u64.to_le_bytes()).unwrap();
                m.write_array(0x1028, u64::MAX.to_le_bytes()).unwrap();
            }
            let args = [fd as u64, request, pointer, 0, 0, 0];
            let result = if source {
                capture(&linux).invoke(29, args, &mut m).unwrap()
            } else {
                linux.syscall(29, args, &mut m, &mut crate::CapturedOutput::default())
            };
            results.push((
                result,
                m.read_array::<64>(0x1000).unwrap(),
                m.read_array::<8>(0x2000).unwrap(),
            ));
        }
        assert_eq!(results[0], results[1], "kind={kind} request={request:#x}");
    }
    let (linux, mut m, _) = setup(0);
    assert_eq!(
        capture(&linux).invoke(29, [u32::MAX as u64, 0x1234, u64::MAX, 0, 0, 0], &mut m),
        Some(Err(Errno(9)))
    );
}

#[test]
fn interface_controls_observe_live_original_network_and_credentials() {
    let (mut linux, mut m, fd) = setup(1);
    linux.vfs.unshare_net().unwrap();
    let direct = capture(&linux);
    m.write(0x1000, b"lo\0").unwrap();
    for up in [false, true] {
        linux.vfs.set_loopback_up(up).unwrap();
        assert_eq!(
            direct.invoke(29, [fd as u64, 0x8913, 0x1000, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            u16::from_le_bytes(m.read_array(0x1010).unwrap()) & 1,
            u16::from(up)
        );
    }
    linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
    let limited = capture(&linux);
    m.write_array(0x1010, 0u16.to_le_bytes()).unwrap();
    assert_eq!(
        limited.invoke(29, [fd as u64, 0x8914, 0x1000, 0, 0, 0], &mut m),
        Some(Err(Errno(1)))
    );
    assert!(
        linux
            .vfs
            .network_devices()
            .iter()
            .find(|d| d.index == 1)
            .unwrap()
            .up
    );
}
