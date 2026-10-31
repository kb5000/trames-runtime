// SPDX-License-Identifier: GPL-3.0-or-later
//! Runtime-owned pseudo files. These nodes never enter a disk manifest.
use super::*;
use std::time::Duration;

// /proc/net/route exposes the guest's little-endian in_addr words, even though
// Rust's u32::from(Ipv4Addr) is a network-order numeric value. to_le() alone is
// therefore wrong on a little-endian host. Netlink keeps its separate wire ABI.
fn proc_ipv4_route_row(
    name: &[u8],
    ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: Option<std::net::Ipv4Addr>,
    metric: u32,
) -> String {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    let destination = u32::from_le_bytes((u32::from(ip) & mask).to_be_bytes());
    let mask = u32::from_le_bytes(mask.to_be_bytes());
    let gw = gateway.map_or(0, |ip| u32::from_le_bytes(ip.octets()));
    format!(
        "{}\t{destination:08X}\t{gw:08X}\t{:04X}\t0\t0\t{metric}\t{mask:08X}\t0\t0\t0\n",
        String::from_utf8_lossy(name),
        if gateway.is_some() { 3 } else { 1 }
    )
}

// Linux kernel/random/uuid is a fresh read-only UUID on each retrieval.
// Use the same host CSPRNG as /dev/urandom; no guest/process metadata is needed.
fn proc_uuid() -> Result<Vec<u8>> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| Errno(5))?;
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = Vec::with_capacity(37);
    for (i, byte) in random.into_iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            value.push(b'-');
        }
        value.push(HEX[(byte >> 4) as usize]);
        value.push(HEX[(byte & 15) as usize]);
    }
    value.push(b'\n');
    Ok(value)
}

#[derive(Clone)]
pub struct FdInfo {
    pub fd: u32,
    pub target: Vec<u8>,
    pub position: u64,
    pub flags: u32,
    pub inode: u64,
    pub mount_id: u64,
    pub socket: Option<trames_net::SocketInfo>,
    pub signal_mask: Option<u64>,
    open: OpenWeak,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(v: &mut Vfs) {
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    state: 'R',
                    command: b"ash".to_vec(),
                    arguments: vec![b"ash".to_vec()],
                    cwd: b"/".to_vec(),
                    terminal: v
                        .fd_kind(0)
                        .is_ok_and(|kind| matches!(kind, FdKind::Terminal)),
                    fds: v.fd_snapshot(),
                    ..ProcessInfo::default()
                }],
                memory_limit: 256 * 1024 * 1024,
                ..RuntimeInfo::default()
            },
        );
    }
    fn read(v: &mut Vfs, path: &[u8]) -> Vec<u8> {
        let fd = v.open_at(AT_FDCWD, path, 0, 0).unwrap();
        let out = v.read(fd, 65536).unwrap();
        v.close(fd).unwrap();
        out
    }
    #[test]
    fn boot_id_is_stable_across_tasks_but_fresh_in_a_new_session() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        let first = read(&mut v, b"/proc/sys/kernel/random/boot_id");
        assert_eq!(first.len(), 37);
        assert_eq!(read(&mut v, b"/proc/sys/kernel/random/boot_id"), first);
        let mut child = v.clone();
        assert_eq!(read(&mut child, b"/proc/sys/kernel/random/boot_id"), first);
        let mut next = Vfs::default();
        snapshot(&mut next);
        assert_ne!(read(&mut next, b"/proc/sys/kernel/random/boot_id"), first);
    }
    #[test]
    fn random_uuid_is_fresh_v4_readonly_and_discoverable() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        let capacity = v.capacity();
        let path = b"/proc/sys/kernel/random/uuid";
        let mut values = std::collections::BTreeSet::new();
        for _ in 0..16 {
            let fd = v.open_at(AT_FDCWD, path, 0, 0).unwrap();
            let value = v.read(fd, 128).unwrap();
            assert_eq!(value.len(), 37);
            assert_eq!(value[36], b'\n');
            for (i, &byte) in value[..36].iter().enumerate() {
                if matches!(i, 8 | 13 | 18 | 23) {
                    assert_eq!(byte, b'-');
                } else {
                    assert!(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
                }
            }
            assert_eq!(value[14], b'4');
            assert!(b"89ab".contains(&value[19]));
            assert!(values.insert(value));
            assert!(v.read(fd, 128).unwrap().is_empty());
            v.close(fd).unwrap();
        }
        assert_eq!(v.open_at(AT_FDCWD, path, 1, 0), Err(Errno(30)));
        let directory = v
            .open_at(AT_FDCWD, b"/proc/sys/kernel/random", O_DIRECTORY, 0)
            .unwrap();
        assert!(v
            .getdents(directory, 4096)
            .unwrap()
            .windows(5)
            .any(|w| w == b"uuid\0"));
        assert_eq!(
            v.capacity(),
            capacity,
            "runtime pseudo files do not enter storage quotas"
        );
    }

    #[test]
    fn proc_limits_reports_the_runtime_address_cap_or_unlimited() {
        for (value, expected) in [(4u64 << 30, "4294967296"), (u64::MAX, "unlimited")] {
            let mut vfs = Vfs::default();
            vfs.set_runtime_info(
                1,
                RuntimeInfo {
                    processes: vec![ProcessInfo {
                        pid: 1,
                        tgid: 1,
                        address_space_limit: Some(value),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
            let text = String::from_utf8(read(&mut vfs, b"/proc/1/limits")).unwrap();
            let row = text
                .lines()
                .find(|line| line.starts_with("Max address space"))
                .unwrap();
            assert_eq!(
                row.split_whitespace().skip(3).collect::<Vec<_>>(),
                [expected, expected, "bytes"]
            );
        }
    }
    #[test]
    fn meminfo_can_report_reclaimable_availability_separately_from_free_bytes() {
        let mut vfs = Vfs::default();
        vfs.set_runtime_info(
            1,
            RuntimeInfo {
                memory_limit: 24usize << 30,
                used_memory: 21usize << 30,
                available_memory: Some(8usize << 30),
                ..Default::default()
            },
        );
        let text = String::from_utf8(read(&mut vfs, b"/proc/meminfo")).unwrap();
        let values: BTreeMap<_, _> = text
            .lines()
            .filter_map(|line| {
                let (key, rest) = line.split_once(':')?;
                Some((
                    key,
                    rest.split_whitespace()
                        .next()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap(),
                ))
            })
            .collect();
        assert_eq!(values["MemTotal"], 24 << 20);
        assert_eq!(values["MemFree"], 3 << 20);
        assert_eq!(values["MemAvailable"], 8 << 20);
    }
    #[test]
    fn proc_route_uses_guest_little_endian_addresses_for_native_and_bridge_rows() {
        use std::net::Ipv4Addr;
        // Decode the text exactly as little-endian route/BusyBox consumers do.
        let decode =
            |field: &str| Ipv4Addr::from(u32::from_str_radix(field, 16).unwrap().to_le_bytes());
        for (name, ip, prefix, gateway, destination, mask) in [
            (
                b"eth0".as_slice(),
                [192, 168, 2, 99],
                24,
                None,
                [192, 168, 2, 0],
                [255, 255, 255, 0],
            ),
            (
                b"eth0",
                [0, 0, 0, 0],
                0,
                Some([192, 168, 2, 1]),
                [0, 0, 0, 0],
                [0, 0, 0, 0],
            ),
            (
                b"docker0",
                [172, 17, 0, 1],
                16,
                None,
                [172, 17, 0, 0],
                [255, 255, 0, 0],
            ),
            (
                b"veth0",
                [10, 23, 8, 7],
                32,
                Some([10, 23, 8, 1]),
                [10, 23, 8, 7],
                [255, 255, 255, 255],
            ),
        ] {
            let row = proc_ipv4_route_row(name, ip.into(), prefix, gateway.map(Ipv4Addr::from), 7);
            let fields: Vec<_> = row.split_whitespace().collect();
            assert_eq!(decode(fields[1]), Ipv4Addr::from(destination));
            assert_eq!(decode(fields[2]), Ipv4Addr::from(gateway.unwrap_or([0; 4])));
            assert_eq!(decode(fields[7]), Ipv4Addr::from(mask));
            assert_eq!(fields[6], "7");
            assert_eq!(fields[3], if gateway.is_some() { "0003" } else { "0001" });
        }
    }
    #[test]
    fn proc_setgroups_reports_initial_user_namespace_policy() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        assert_eq!(read(&mut v, b"/proc/self/setgroups"), b"allow\n");
        assert_eq!(read(&mut v, b"/proc/1/task/1/setgroups"), b"allow\n");
        // User namespaces and changing their setgroups policy are unsupported.
        assert!(v.open_at(AT_FDCWD, b"/proc/self/setgroups", 1, 0).is_err());
    }
    #[test]
    fn proc_root_inode_matches_linux_across_paths_fds_and_bind_mounts() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        let fd = v
            .open_at(AT_FDCWD, b"/proc", O_PATH | O_DIRECTORY, 0)
            .unwrap();
        let root = v.stat_at(AT_FDCWD, b"/proc").unwrap();
        assert_eq!(&root[8..16], &1u64.to_le_bytes());
        assert_eq!(v.stat_fd(fd).unwrap(), root);
        assert_eq!(v.stat_at(fd as i32, b".").unwrap(), root);
        assert_eq!(&v.statfs_fd(fd).unwrap()[..8], &0x9fa0u64.to_le_bytes());
        v.mkdir_at(AT_FDCWD, b"/proc-alias", 0o755).unwrap();
        v.mount(Some(b"/proc"), b"/proc-alias", None, 4096, None)
            .unwrap();
        assert_eq!(v.stat_at(AT_FDCWD, b"/proc-alias").unwrap(), root);
        // Ordinary synthesized entries retain their separate inode range.
        assert_ne!(
            &v.stat_at(AT_FDCWD, b"/proc/stat").unwrap()[8..16],
            &root[8..16]
        );
    }
    #[test]
    fn proc_readlink_empty_path_retains_symlink_inode_and_refreshes_fd_target() {
        let mut v = Vfs::default();
        v.symlink_at(b"missing", AT_FDCWD, b"/link").unwrap();
        let link = v
            .open_at(AT_FDCWD, b"/link", O_PATH | O_NOFOLLOW, 0)
            .unwrap();
        v.unlink_at(AT_FDCWD, b"/link", false).unwrap();
        assert_eq!(v.readlink_at(link as i32, b"").unwrap(), b"missing");
        v.import_file(b"/target", b"data".to_vec()).unwrap();
        let target = v.open_at(AT_FDCWD, b"/target", 0, 0).unwrap();
        snapshot(&mut v);
        let proc_link = v
            .open_at(
                AT_FDCWD,
                format!("/proc/self/fd/{target}").as_bytes(),
                O_PATH | O_NOFOLLOW,
                0,
            )
            .unwrap();
        snapshot(&mut v);
        assert_eq!(v.readlink_at(proc_link as i32, b"").unwrap(), b"/target");
        v.rename_at(AT_FDCWD, b"/target", AT_FDCWD, b"/renamed", 0)
            .unwrap();
        snapshot(&mut v);
        assert_eq!(v.readlink_at(proc_link as i32, b"").unwrap(), b"/renamed");
        assert_eq!(v.readlink_at(target as i32, b""), Err(Errno(2)));
        assert_eq!(v.readlink_at(AT_FDCWD, b""), Err(Errno(2)));
        let credentials = v.credentials.clone();
        v.credentials = Credentials::user(1000, 1000);
        // A fork can retain this link FD, but changing its credentials does
        // not grant inspection of the original process's descriptor table.
        v.set_process_context(2);
        assert_eq!(v.readlink_at(proc_link as i32, b""), Err(Errno(13)));
        v.set_process_context(1);
        v.credentials = credentials;
        v.close(target).unwrap();
        snapshot(&mut v);
        assert_eq!(v.readlink_at(proc_link as i32, b""), Err(Errno(2)));
        assert_eq!(v.readlink_at(250, b""), Err(Errno(9)));
    }
    #[test]
    fn proc_sysctl_path_fd_reopens_with_truncation_and_keeps_network_namespace() {
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        snapshot(&mut v);
        let path = b"/proc/sys/net/ipv4/ip_unprivileged_port_start";
        let original = v.open_at(AT_FDCWD, path, O_PATH, 0).unwrap();
        v.unshare_net().unwrap();
        snapshot(&mut v);
        let fd = v
            .open_at(
                AT_FDCWD,
                format!("/proc/self/fd/{original}").as_bytes(),
                2 | 0x200,
                0,
            )
            .unwrap();
        assert_eq!(v.write(fd, b"0\n").unwrap(), 2);
        v.seek(fd, 0, 0).unwrap();
        assert_eq!(v.read(fd, 100).unwrap(), b"0\n");
        assert_eq!(read(&mut v, path), b"1024\n");
        v.credentials = Credentials::user(1000, 1000);
        assert_eq!(v.write(fd, b"1\n"), Err(Errno(13)));
    }
    #[test]
    fn render_device_discovery_requires_opt_in_and_has_linux_char_identity() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        assert_eq!(v.stat_at(AT_FDCWD, b"/dev/dri/renderD128"), Err(Errno(2)));
        v.enable_video_device();
        let fd = v.open_at(AT_FDCWD, b"/dev/dri/renderD128", 2, 0).unwrap();
        let stat = v.stat_fd(fd).unwrap();
        assert_eq!(
            u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o170000,
            0o20000
        );
        assert_eq!(u64::from_le_bytes(stat[32..40].try_into().unwrap()), 0xe280);
        assert!(v.is_render_device(fd).unwrap());
        v.stat_at(AT_FDCWD, b"/sys/dev/char/226:128/device/drm")
            .unwrap();
    }
    #[test]
    fn device_directory_enumerates_only_available_embedding_devices() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        for attached in [false, true] {
            if attached {
                v.attach_bridge(trames_bridge::Broker::default());
            }
            let fd = v.open_at(AT_FDCWD, b"/dev", O_DIRECTORY, 0).unwrap();
            let entries = v.getdents(fd, 4096).unwrap();
            let mut at = 0;
            let mut found = false;
            while at < entries.len() {
                let length =
                    u16::from_le_bytes(entries[at + 16..at + 18].try_into().unwrap()) as usize;
                let name = entries[at + 19..at + length]
                    .split(|b| *b == 0)
                    .next()
                    .unwrap();
                v.stat_at_flags(fd as i32, name, true).unwrap();
                found |= name == b"trames-bridge";
                at += length;
            }
            assert_eq!(found, attached);
            v.close(fd).unwrap();
        }
    }
    #[test]
    fn logical_block_identity_agrees_across_mounts_stat_and_sysfs() {
        let mut v = Vfs::default();
        let capacity = v.capacity();
        snapshot(&mut v);
        let root = v.stat_at(AT_FDCWD, b"/").unwrap();
        let block = v.stat_at(AT_FDCWD, b"/dev/vda1").unwrap();
        assert_eq!(&root[..8], &0xfd01u64.to_le_bytes());
        assert_eq!(&block[32..40], &root[..8]);
        assert_eq!(
            u32::from_le_bytes(block[16..20].try_into().unwrap()) & 0o170000,
            0o60000
        );
        for alias in [
            b"/sys/class/block/vda1/dev".as_slice(),
            b"/sys/dev/block/253:1/dev",
        ] {
            assert_eq!(read(&mut v, alias), b"253:1\n");
        }
        assert_eq!(
            read(&mut v, b"/sys/block/vda/size"),
            format!("{}\n", capacity.budget_bytes / 512).as_bytes()
        );
        assert_eq!(
            read(&mut v, b"/sys/class/block/vda1/size"),
            format!("{}\n", capacity.budget_bytes / 512).as_bytes()
        );
        assert_eq!(read(&mut v, b"/sys/class/block/vda1/partition"), b"1\n");
        assert!(read(&mut v, b"/proc/self/mountinfo")
            .starts_with(b"1 1 253:1 / / rw,relatime - rootfs /dev/vda1 rw\n"));
        let fd = v.open_at(AT_FDCWD, b"/dev/vda1", 2, 0).unwrap();
        assert_eq!(v.read(fd, 512), Err(Errno(95)));
        assert_eq!(v.write(fd, &[0; 512]), Err(Errno(95)));
        assert_eq!(
            v.fd_snapshot()
                .into_iter()
                .find(|f| f.fd == fd)
                .unwrap()
                .mount_id,
            1
        );
        assert_eq!(v.capacity().used_bytes, capacity.used_bytes);
    }
    #[test]
    fn directory_links_and_mount_identity_match_live_namespace() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        v.mkdir_at(AT_FDCWD, b"/parent", 0o755).unwrap();
        let links = |v: &Vfs| {
            u32::from_le_bytes(
                v.stat_at(AT_FDCWD, b"/parent").unwrap()[20..24]
                    .try_into()
                    .unwrap(),
            )
        };
        assert_eq!(links(&v), 2);
        v.mkdir_at(AT_FDCWD, b"/parent/child", 0o755).unwrap();
        assert_eq!(links(&v), 3);
        v.unlink_at(AT_FDCWD, b"/parent/child", true).unwrap();
        assert_eq!(links(&v), 2);
        let fd = v.open_at(AT_FDCWD, b"/proc/self/status", 0, 0).unwrap();
        snapshot(&mut v);
        let path = format!("/proc/self/fdinfo/{fd}");
        assert!(read(&mut v, path.as_bytes())
            .windows(10)
            .any(|w| w == b"mnt_id:\t2\n"));
        v.enable_terminal().unwrap();
        snapshot(&mut v);
        snapshot(&mut v);
        let terminal = v.fd_snapshot().into_iter().find(|f| f.fd == 0).unwrap();
        assert_eq!(terminal.mount_id, 4);
        assert_eq!(terminal.inode.to_le_bytes(), v.stat_fd(0).unwrap()[8..16]);
        assert_eq!(&v.stat_fd(0).unwrap()[32..40], &0x8800u64.to_le_bytes());
    }
    #[test]
    fn process_views_are_live_readonly_and_outside_storage_quota() {
        let mut v = Vfs::default();
        let before = v.capacity();
        snapshot(&mut v);
        assert_eq!(v.readlink_at(AT_FDCWD, b"/proc/self").unwrap(), b"1");
        assert_eq!(
            v.readlink_at(AT_FDCWD, b"/proc/thread-self").unwrap(),
            b"1/task/1"
        );
        assert_eq!(read(&mut v, b"/proc/self/cmdline"), b"ash\0");
        assert!(read(&mut v, b"/proc/self/status")
            .windows(8)
            .any(|w| w == b"Tgid:\t1\n"));
        assert_eq!(
            v.open_at(AT_FDCWD, b"/proc/self/status", 2, 0),
            Err(Errno(30))
        );
        assert_eq!(
            v.mkdir_at(AT_FDCWD, b"/proc/injected", 0o777),
            Err(Errno(30))
        );
        let stat = v.stat_at(AT_FDCWD, b"/proc/self/status").unwrap();
        assert_eq!(&stat[..8], &2u64.to_le_bytes());
        assert_eq!(&stat[48..56], &0u64.to_le_bytes());
        assert_eq!(
            &v.statfs_at(b"/proc").unwrap()[..8],
            &0x9fa0u64.to_le_bytes()
        );
        assert_eq!(v.capacity().used_bytes, before.used_bytes);
        v.set_runtime_info(1, RuntimeInfo::default());
        assert_eq!(v.stat_at(AT_FDCWD, b"/proc/1/status"), Err(Errno(2)));
    }
    #[test]
    fn fd_magic_links_keep_deleted_inodes_and_pipe_identity() {
        let mut v = Vfs::default();
        v.import_file(b"/data", b"content".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
        let copy = v.dup(fd, 0, false).unwrap();
        let [reader, writer] = v.pipe(0).unwrap();
        assert_eq!(
            &v.stat_fd(reader).unwrap()[8..16],
            &v.stat_fd(writer).unwrap()[8..16]
        );
        v.unlink_at(AT_FDCWD, b"/data", false).unwrap();
        snapshot(&mut v);
        let path = format!("/proc/self/fd/{copy}");
        assert_eq!(
            v.readlink_at(AT_FDCWD, path.as_bytes()).unwrap(),
            b"/data (deleted)"
        );
        assert_eq!(
            v.stat_at(AT_FDCWD, path.as_bytes()).unwrap(),
            v.stat_fd(fd).unwrap()
        );
        assert_eq!(read(&mut v, path.as_bytes()), b"content");
        assert_eq!(
            v.open_at(AT_FDCWD, path.as_bytes(), 0xc0, 0o600),
            Err(Errno(17))
        );
        assert!(v.stat_at(AT_FDCWD, b"/dev/stdout").is_ok());
        let stat = v.stat_at(AT_FDCWD, b"/dev/stdout").unwrap();
        assert_eq!(
            u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o170000,
            0o10000
        );
    }
    #[test]
    fn common_devices_and_cross_process_privacy_have_real_behavior() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        let fd = v.open_at(AT_FDCWD, b"/dev/zero", 0, 0).unwrap();
        assert_eq!(v.read(fd, 23).unwrap(), vec![0; 23]);
        let fd = v.open_at(AT_FDCWD, b"/dev/urandom", 0, 0).unwrap();
        assert_eq!(v.read(fd, 32).unwrap().len(), 32);
        let fd = v.open_at(AT_FDCWD, b"/dev/full", 1, 0).unwrap();
        assert_eq!(v.write(fd, b"x"), Err(Errno(28)));
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 2,
                    tgid: 2,
                    credentials: Credentials::user(1000, 1000),
                    environment: vec![b"SECRET=guest-private".to_vec()],
                    ..ProcessInfo::default()
                }],
                ..RuntimeInfo::default()
            },
        );
        v.credentials = Credentials::user(2000, 2000);
        assert_eq!(
            v.open_at(AT_FDCWD, b"/proc/2/environ", 0, 0),
            Err(Errno(13))
        );
    }
}
#[derive(Clone, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub processor: u32,
    pub nice: i32,
    pub scheduler: u32,
    pub affinity: u64,
    pub tgid: u32,
    pub parent: u32,
    pub group: u32,
    pub session: u32,
    pub state: char,
    pub credentials: Credentials,
    pub namespaces: NamespaceSnapshot,
    pub namespace_ids: [Vec<u32>; 4],
    pub command: Vec<u8>,
    pub cgroup: Vec<u8>,
    pub nondumpable: bool,
    pub seccomp: u32,
    pub seccomp_filters: usize,
    pub arguments: Vec<Vec<u8>>,
    pub environment: Vec<Vec<u8>>,
    pub executable: Vec<u8>,
    pub executable_file: Option<Weak<ExecutableFile>>,
    pub cwd: Vec<u8>,
    pub mapped_bytes: usize,
    pub virtual_bytes: u64,
    pub maps: Vec<u8>,
    pub user_ticks: u64,
    pub start_ticks: u64,
    pub terminal: bool,
    pub terminal_number: u32,
    pub fds: Vec<FdInfo>,
    pub auxiliary: Vec<u8>,
    pub file_size_limits: Option<(u64, u64)>,
    pub core_limits: Option<(u64, u64)>,
    pub address_space_limit: Option<u64>,
    pub oom: std::sync::Weak<OomTask>,
    pub pending: u64,
    pub shared_pending: u64,
    pub blocked: u64,
    pub ignored: u64,
    pub caught: u64,
}
#[derive(Clone, Default)]
pub struct RuntimeInfo {
    pub cpu_count: usize,
    /// Zero retains the default capacity when no session snapshot is present.
    pub task_limit: usize,
    pub per_cpu_ticks: Vec<u64>,
    pub cpu_features: &'static str,
    pub processes: Vec<ProcessInfo>,
    pub uptime: Duration,
    pub boot_time: u64,
    pub context_switches: u64,
    pub cpu_user_ticks: u64,
    pub idle: Duration,
    pub memory_limit: usize,
    /// Host-managed MemAvailable hint; None retains total minus guest usage.
    pub available_memory: Option<usize>,
    pub load: [f64; 3],
    pub processes_created: u32,
    pub used_memory: usize,
}
#[derive(Default)]
pub(super) struct PseudoFs {
    boot_id: std::cell::OnceCell<Result<Vec<u8>>>,
    pub(super) video_device: bool,
    pub(super) enabled: bool,
    pub(super) runtime: RuntimeInfo,
    pub(super) nodes: BTreeMap<(u64, Vec<u8>), NodeRef>,
    next_inode: u64,
}
impl PseudoFs {
    pub(super) fn path_of(&self, node: &NodeRef) -> Option<Vec<u8>> {
        self.nodes
            .iter()
            .find(|(_, n)| Arc::ptr_eq(n, node))
            .map(|((_, p), _)| p.clone())
    }
    pub(super) fn cache(
        &mut self,
        ns: u64,
        path: &[u8],
        content: Content,
        mode: u32,
    ) -> Result<NodeRef> {
        if let Some(node) = self.nodes.get(&(ns, path.to_vec())) {
            node.borrow_mut().content = content;
            return Ok(node.clone());
        }
        if self.nodes.len() >= 32768 {
            return Err(Errno(28));
        }
        self.next_inode = self.next_inode.checked_add(1).ok_or(Errno(28))?;
        let node = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: std::sync::OnceLock::new(),
            whole_locks: std::sync::OnceLock::new(),
            notifications: inotify::Marks::default(),
            path_hint: SharedCell::default(),
            content,
            mode,
            uid: 0,
            gid: 0,
            volatile: true,
            device: if path == b"/proc" || path.starts_with(b"/proc/") {
                2
            } else if path == b"/sys" || path.starts_with(b"/sys/") {
                3
            } else if path == b"/dev/pts" || path.starts_with(b"/dev/pts/") {
                4
            } else {
                0xfd01
            },
            // Linux PROC_ROOT_INO is 1. Original runc/pathrs validates this
            // along with procfs's superblock type before trusting proc paths.
            inode: if path == b"/proc" {
                1
            } else {
                (1u64 << 63) + self.next_inode
            },
            links: 1,
            times: [storage::Timestamp::default(); 3],
            xattrs: BTreeMap::new(),
            seals: None,
        }));
        self.nodes.insert((ns, path.to_vec()), node.clone());
        Ok(node)
    }
}
#[derive(Clone, Copy)]
pub(super) enum Device {
    Render,
    Unregistered(u32),
    Kmsg,
    Zero,
    Full,
    Random,
    Urandom,
    Pts(u32, u32), // scheduler identity, devpts-local slave number
    Ptmx,
    Bridge,
    Vda,
    Vda1,
}
impl Device {
    /// Resolve guest device numbers only. Never open a host device node.
    pub(super) fn node(rdev: u32, block: bool) -> Content {
        if block {
            return Content::Device(Self::Unregistered(rdev));
        }
        match rdev {
            0x103 => Content::Null,
            0x500 => Content::Terminal,
            value => Content::Device(match value {
                0x105 => Self::Zero,
                0x107 => Self::Full,
                0x108 => Self::Random,
                0x109 => Self::Urandom,
                0x10b => Self::Kmsg,
                0x502 => Self::Ptmx,
                0xe280 => Self::Render,
                _ => Self::Unregistered(value),
            }),
        }
    }
    pub(super) fn rdev(self) -> u64 {
        match self {
            Self::Unregistered(rdev) => rdev as u64,
            Self::Render => 0xe280,
            Self::Kmsg => 0x10b,
            Self::Zero => 0x105,
            Self::Full => 0x107,
            Self::Random => 0x108,
            Self::Urandom => 0x109,
            Self::Pts(_, number) => ((136 + number / 256) as u64) << 8 | (number % 256) as u64,
            Self::Ptmx => 0x502,
            Self::Bridge => 0xf000,
            Self::Vda => 0xfd00,
            Self::Vda1 => 0xfd01,
        }
    }
    pub(super) fn read(self, count: usize) -> Result<Vec<u8>> {
        let mut data = vec![0; count.min(storage::MAX_TRANSFER)];
        match self {
            Self::Unregistered(_) => return Err(Errno(6)),
            Self::Render => return Err(Errno(22)),
            Self::Zero | Self::Full => {}
            Self::Random | Self::Urandom => getrandom::fill(&mut data).map_err(|_| Errno(5))?,
            Self::Kmsg => return Err(Errno(29)),
            Self::Pts(_, _) => return Err(Errno(11)),
            Self::Ptmx => return Err(Errno(95)),
            Self::Bridge => return Err(Errno(19)),
            Self::Vda | Self::Vda1 => return Err(Errno(95)),
        }
        Ok(data)
    }
    pub(super) fn write(self, data: &[u8]) -> Result<usize> {
        match self {
            Self::Unregistered(_) => Err(Errno(6)),
            Self::Render => Err(Errno(22)),
            Self::Full => Err(Errno(28)),
            Self::Kmsg => Err(Errno(29)),
            Self::Pts(_, _) => Err(Errno(11)),
            Self::Ptmx => Err(Errno(95)),
            Self::Bridge => Err(Errno(19)),
            Self::Vda | Self::Vda1 => Err(Errno(95)),
            _ => Ok(data.len()),
        }
    }
}
fn file(data: impl Into<Vec<u8>>) -> Content {
    Content::File(storage::FileData::memory(data.into()))
}
fn nul_list(values: &[Vec<u8>]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.iter().copied().chain([0]))
        .take(1024 * 1024)
        .collect()
}
fn comm(p: &ProcessInfo) -> Vec<u8> {
    let mut name: Vec<_> = p.command.iter().copied().take(15).collect();
    if name.is_empty() {
        name.extend_from_slice(b"trames");
    }
    name.push(b'\n');
    name
}
impl Vfs {
    pub fn is_render_device(&self, fd: u32) -> Result<bool> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        Ok(open
            .node
            .as_ref()
            .is_some_and(|n| matches!(n.borrow().content, Content::Device(Device::Render))))
    }
    pub fn enable_video_device(&self) {
        self.pseudo.borrow_mut().video_device = true;
    }
    pub fn set_runtime_info(&mut self, pid: u32, mut runtime: RuntimeInfo) {
        self.pid = pid;
        if let Some(p) = runtime.processes.iter_mut().find(|p| p.pid == pid) {
            p.namespaces = self.namespace_snapshot();
        }
        let mut pseudo = self.pseudo.borrow_mut();
        pseudo.nodes.retain(|(ns, path), _| {
            if !self.pid_ns.namespace_alive(*ns) {
                return false;
            }
            let local = |p: &ProcessInfo, id| {
                if *ns == 0 {
                    id
                } else {
                    p.namespaces
                        .pid
                        .upgrade()
                        .map_or(0, |n| PidNamespace(n).local_in(*ns, id))
                }
            };
            let parts: Vec<_> = path.split(|b| *b == b'/').collect();
            if !(parts.len() > 2
                && parts[1] == b"proc"
                && parts[2].first().is_some_and(u8::is_ascii_digit))
            {
                return true;
            }
            let pid = std::str::from_utf8(parts[2])
                .ok()
                .and_then(|p| p.parse::<u32>().ok());
            if !runtime
                .processes
                .iter()
                .any(|p| Some(local(p, p.pid)) == pid)
            {
                return false;
            }
            if parts.len() > 4 && parts[3] == b"task" {
                let tid = std::str::from_utf8(parts[4])
                    .ok()
                    .and_then(|p| p.parse::<u32>().ok());
                return runtime
                    .processes
                    .iter()
                    .any(|p| Some(local(p, p.pid)) == tid && Some(local(p, p.tgid)) == pid);
            }
            true
        });
        pseudo.enabled = true;
        pseudo.runtime = runtime;
    }
    pub fn set_process_context(&mut self, pid: u32) {
        self.pid = pid;
    }
    pub fn process_context(&self) -> u32 {
        self.pid
    }
    pub fn fd_snapshot(&self) -> Vec<FdInfo> {
        self.fds
            .entries()
            .iter()
            .filter(|(_, descriptor)| descriptor.ready().is_ok())
            .map(|(&fd, d)| {
                let o = d.open.borrow();
                let node = o.node.clone().or_else(|| {
                    if matches!(o.kind, FdKind::Terminal) {
                        self.node(b"/dev/pts/0").ok()
                    } else {
                        None
                    }
                });
                let inode = node.as_ref().map_or_else(
                    || {
                        o.namespace.as_ref().map_or_else(
                            || o.pipe.as_ref().map_or(o.id, |p| p.pipe.inode),
                            linux_namespace::NamespaceHandle::id,
                        )
                    },
                    |n| n.borrow().inode,
                );
                let target = if let Some(ns) = &o.namespace {
                    ns.label()
                } else {
                    match &o.kind {
                        FdKind::Node(path) => o
                            .node
                            .as_ref()
                            .and_then(|n| {
                                self.location(n, &self.mount_for_path(o.mount.as_ref()))
                                    .map(|p| self.path_visible(&p).unwrap_or(p.key))
                                    .ok()
                            })
                            .unwrap_or_else(|| {
                                let mut p = path.clone();
                                p.extend_from_slice(b" (deleted)");
                                p
                            }),
                        FdKind::Terminal if o.pty.is_some() => {
                            let end = o.pty.as_ref().expect("PTY");
                            if end.master {
                                b"/dev/ptmx".to_vec()
                            } else {
                                format!("/dev/pts/{}", end.pair.number).into_bytes()
                            }
                        }
                        FdKind::Terminal => node
                            .as_ref()
                            .and_then(|n| self.path_of(n).ok())
                            .unwrap_or_else(|| b"/dev/pts/0".to_vec()),
                        FdKind::Anonymous if o.native_image.is_some() => {
                            b"anon_inode:[trames-image]".to_vec()
                        }
                        FdKind::Anonymous => o
                            .anonymous
                            .as_ref()
                            .expect("anonymous description")
                            .name()
                            .to_vec(),
                        FdKind::Socket => format!("socket:[{inode}]").into_bytes(),
                        FdKind::PipeRead | FdKind::PipeWrite => {
                            format!("pipe:[{inode}]").into_bytes()
                        }
                        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => {
                            format!("pipe:[{inode}]").into_bytes()
                        }
                    }
                };
                FdInfo {
                    signal_mask: match o.anonymous {
                        Some(events::Anonymous::Signal { mask }) => Some(mask),
                        _ => None,
                    },
                    fd,
                    target,
                    position: o.current_position(),
                    flags: o.flags.get() | if d.cloexec.get() { O_CLOEXEC } else { 0 },
                    inode,
                    mount_id: o.mount.as_ref().map_or(
                        if o.namespace.is_some() {
                            17
                        } else if matches!(o.kind, FdKind::Terminal) {
                            4
                        } else {
                            1
                        },
                        |m| m.id,
                    ),
                    socket: o.socket.as_ref().and_then(|s| s.info()),
                    open: d.open.downgrade(),
                }
            })
            .collect()
    }
    pub(super) fn pseudo_readonly(&self, path: &[u8]) -> bool {
        self.pseudo.borrow().enabled
            && (path == b"/proc"
                || path.starts_with(b"/proc/")
                || path == b"/sys"
                || path.starts_with(b"/sys/"))
    }
    pub(super) fn pseudo_immutable(&self, node: &NodeRef) -> Result<()> {
        Self::pseudo_immutable_node(&node.borrow())
    }
    pub(super) fn pseudo_immutable_node(n: &Node) -> Result<()> {
        if n.volatile && !matches!(n.content, Content::Device(_)) {
            Err(Errno(30))
        } else {
            Ok(())
        }
    }
    pub(super) fn proc_fd_description(
        &self,
        dirfd: i32,
        path: &[u8],
    ) -> Result<Option<OpenHandle>> {
        if !self.pseudo.borrow().enabled {
            return Ok(None);
        }
        let link_path = self.resolve_final(dirfd, path, false)?;
        if let Some(ns) = link_path.mount.as_ref().and_then(|m| m.namespace.clone()) {
            let description = self.namespace_description(ns);
            description.borrow_mut().mount = link_path.mount.map(OpenMount::Owner);
            return Ok(Some(description));
        }
        if !self.uses_pseudo(&link_path) {
            return Ok(None);
        }
        let mut actual = link_path;
        if matches!(
            actual.as_slice(),
            b"/dev/stdin" | b"/dev/stdout" | b"/dev/stderr"
        ) {
            let fd = if actual == b"/dev/stdin" {
                0
            } else if actual == b"/dev/stdout" {
                1
            } else {
                2
            };
            actual =
                self.resolve_final(AT_FDCWD, format!("/proc/self/fd/{fd}").as_bytes(), false)?;
        }
        if let Some(ns) = self.namespace_for_path(&actual)? {
            return Ok(Some(self.namespace_description(ns)));
        }
        if let Some(open) = self.proc_fd_description_normalized(&actual)? {
            return Ok(Some(open));
        }
        if self
            .node(&actual)
            .is_ok_and(|n| matches!(n.borrow().content, Content::Symlink(_)))
        {
            let resolved = self.resolve_final(dirfd, path, true)?;
            if let Some(ns) = self.namespace_for_path(&resolved)? {
                return Ok(Some(self.namespace_description(ns)));
            }
        }
        let Some((node, label, mount)) = self.proc_exe_node_normalized(&actual)? else {
            return Ok(None);
        };
        let owner = {
            let metadata = node.borrow();
            (metadata.uid, metadata.gid)
        };
        Ok(Some(OpenHandle::new(OpenDescription {
            shared: Arc::new(SharedOpenDescription {
                _disk_file: None,
                #[cfg(all(feature = "hostfs", unix))]
                host_file: None,
                native_image: None,
                mount_resource: std::sync::OnceLock::new(),
                control: None,
                read_node: None,
                id: self.open_id(),
                owner,
                kind: FdKind::Node(label),
                flags: (0).into(),
                file_position: Arc::default(),
                flock: std::sync::OnceLock::new(),
                ofd_records: Default::default(),
                node: Some(node),
                pipe: None,
                bridge: None,
                kernel_log: None,
                notification: None,
            }),
            position: 0,
            socket: None,
            anonymous: None,
            local: None,
            pty: None,
            namespace: None,
            network_control: None,
            mount_file: None,
            oom: None,
            mount: mount.map(OpenMount::Owner),
        })))
    }
    fn proc_fd_description_normalized(&self, actual: &ResolvedPath) -> Result<Option<OpenHandle>> {
        let Some(rest) = actual.strip_prefix(b"/proc/") else {
            return Ok(None);
        };
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let (pid_part, fd_part) = if parts.len() == 3 && parts[1] == b"fd" {
            (parts[0], parts[2])
        } else if parts.len() == 5 && parts[1] == b"task" && parts[3] == b"fd" {
            let group = std::str::from_utf8(parts[0])
                .ok()
                .and_then(|s| s.parse::<u32>().ok());
            let tid = std::str::from_utf8(parts[2])
                .ok()
                .and_then(|s| s.parse::<u32>().ok());
            if !self
                .proc_runtime(actual, &self.pseudo.borrow().runtime)
                .processes
                .iter()
                .any(|p| Some(p.pid) == tid && Some(p.tgid) == group)
            {
                return Err(Errno(2));
            }
            (parts[2], parts[4])
        } else {
            return Ok(None);
        };
        let pid = std::str::from_utf8(pid_part)
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        let fd = std::str::from_utf8(fd_part)
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        let open = {
            let pseudo = self.pseudo.borrow();
            let runtime = self.proc_runtime(actual, &pseudo.runtime);
            let process = runtime
                .processes
                .iter()
                .find(|p| Some(p.pid) == pid)
                .ok_or(Errno(2))?;
            if !self.may_inspect(actual, &runtime, process) {
                return Err(Errno(13));
            }
            process
                .fds
                .iter()
                .find(|f| Some(f.fd) == fd)
                .and_then(|f| f.open.upgrade())
                .ok_or(Errno(2))?
        };
        Ok(Some(open))
    }
    pub(super) fn proc_magic_node_normalized(
        &self,
        path: &ResolvedPath,
    ) -> Result<Option<ResolvedInode>> {
        if let Some(open) = self.proc_fd_description_normalized(path)? {
            let o = open.borrow();
            let node = o.node.clone().ok_or(Errno(13))?;
            let label = match &o.kind {
                FdKind::Node(label) => label.clone(),
                _ => path.to_vec(),
            };
            return Ok(Some((node, label, self.mount_for_path(o.mount.as_ref()))));
        }
        self.proc_exe_node_normalized(path)
    }
    fn proc_exe_node_normalized(&self, path: &ResolvedPath) -> Result<Option<ResolvedInode>> {
        let Some(rest) = path.strip_prefix(b"/proc/") else {
            return Ok(None);
        };
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let (group, pid) = match parts.as_slice() {
            [pid, b"exe"] => (None, *pid),
            [group, b"task", pid, b"exe"] => (Some(*group), *pid),
            _ => return Ok(None),
        };
        let parse = |s: &[u8]| {
            std::str::from_utf8(s)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
        };
        let pseudo = self.pseudo.borrow();
        let runtime = self.proc_runtime(path, &pseudo.runtime);
        let process = runtime
            .processes
            .iter()
            .find(|p| Some(p.pid) == parse(pid) && group.is_none_or(|g| Some(p.tgid) == parse(g)))
            .ok_or(Errno(2))?;
        if !self.may_inspect(path, &runtime, process) {
            return Err(Errno(13));
        }
        let Some(file) = process.executable_file.as_ref().and_then(Weak::upgrade) else {
            return Ok(None);
        };
        Ok(Some((
            file.node.clone(),
            file.label.clone(),
            file.mount.clone(),
        )))
    }
    pub(super) fn open_proc_fd(
        &mut self,
        dirfd: i32,
        path: &[u8],
        flags: u32,
    ) -> Result<Option<u32>> {
        if flags & O_NOFOLLOW != 0 {
            return Ok(None);
        }
        let Some(open) = self.proc_fd_description(dirfd, path)? else {
            return Ok(None);
        };
        let original = open.borrow();
        if flags & 0xc0 == 0xc0 {
            return Err(Errno(17));
        }
        if original.socket.is_some()
            || original.local.is_some()
            || original.anonymous.is_some()
            || original.native_image.is_some()
        {
            return Err(Errno(6));
        }
        if flags & O_DIRECTORY != 0
            && !original
                .node
                .as_ref()
                .is_some_and(|n| matches!(n.borrow().content, Content::Directory))
        {
            return Err(Errno(20));
        }
        if flags & O_PATH != 0 {
            // O_PATH references the inode without admitting data reads/writes.
        } else if let Some(node) = &original.node {
            let n = node.borrow();
            self.check_device_open(&n, flags)?;
            if (flags & 3 != 1 && !self.allowed(&n, 4)) || (flags & 3 != 0 && !self.allowed(&n, 2))
            {
                return Err(Errno(13));
            }
        } else if (flags & 3 != 1 && original.flags.get() & 3 == 1)
            || (flags & 3 != 0 && original.flags.get() & 3 == 0)
        {
            return Err(Errno(13));
        }
        if flags & O_PATH == 0 && (flags & 3 != 0 || flags & 0x200 != 0) {
            if let Some(m) = &original.mount {
                m.writable()?;
            }
            if let Some(node) = &original.node {
                self.overlay_prepare(
                    &ResolvedPath {
                        key: Vec::new(),
                        mount: self.mount_for_path(original.mount.as_ref()),
                    },
                    node,
                    flags & 0x200 != 0,
                )?;
            }
        }
        let fd = self.available(0)?;
        let pipe = if let Some(node) = &original.node {
            if let Content::Fifo(pipe) = &node.borrow().content {
                PipeEnd::open(pipe, flags)?
            } else {
                original.pipe.clone()
            }
        } else {
            original.pipe.clone()
        };
        let notification = original.node.as_ref().and_then(|node| {
            inotify::FileClose::reopen(node, flags, original.notification.as_ref())
        });
        // Reopening a proc magic link is a fresh device open, not dup(). In
        // particular, runc reopens an O_PATH ptmx handle to allocate a new PTY.
        let pty = if flags & O_PATH != 0 {
            None
        } else if let Some(node) = &original.node {
            match node.borrow().content {
                Content::Device(Device::Ptmx) => {
                    let key = match &original.kind {
                        FdKind::Node(path) => path.clone(),
                        _ if original.mount.as_ref().is_some_and(|m| m.devpts.is_some()) => {
                            b"/ptmx".to_vec()
                        }
                        _ => b"/dev/ptmx".to_vec(),
                    };
                    Some(self.allocate_pty(&ResolvedPath {
                        key,
                        mount: self.mount_for_path(original.mount.as_ref()),
                    })?)
                }
                Content::Device(Device::Pts(id, _)) if id != 0 => {
                    let pair = self.pty_by_id(id).ok_or(Errno(5))?;
                    if pair.locked.get()
                        || !pair.master_alive.load(std::sync::atomic::Ordering::Relaxed)
                    {
                        return Err(Errno(5));
                    }
                    Some(pty::PtyEnd::new(pair, false))
                }
                _ => original.pty.clone(),
            }
        } else {
            original.pty.clone()
        };
        let descriptor = OpenDescription {
            mount_file: None,
            shared: Arc::new(SharedOpenDescription {
                _disk_file: None,
                #[cfg(all(feature = "hostfs", unix))]
                host_file: None,
                native_image: None,
                mount_resource: std::sync::OnceLock::new(),
                control: None,
                read_node: if flags & O_PATH == 0 && flags & 3 == 0 {
                    original
                        .node
                        .as_ref()
                        .and_then(|node| match &node.borrow().content {
                            Content::File(storage::FileData::Lower(source)) => Some(source.clone()),
                            _ => None,
                        })
                } else {
                    None
                },
                id: self.open_id(),
                owner: original.owner,
                kind: if pty.is_some() {
                    FdKind::Terminal
                } else {
                    original.kind.clone()
                },
                flags: (flags & !O_CLOEXEC).into(),
                file_position: Arc::default(),
                flock: std::sync::OnceLock::new(),
                ofd_records: Default::default(),
                node: original.node.clone(),
                pipe,
                bridge: original.bridge.clone(),
                kernel_log: None,
                notification,
            }),
            position: 0,
            socket: None,
            anonymous: None,
            local: None,
            pty,
            namespace: original.namespace.clone(),
            network_control: original.network_control.clone(),
            oom: original.oom.clone(),
            mount: original.mount.clone(),
        };
        drop(original);
        self.fds.insert(
            fd,
            Descriptor {
                open: OpenHandle::new(descriptor),
                cloexec: (flags & O_CLOEXEC != 0).into(),
            },
        );
        if flags & 0x200 != 0
            && self.descriptor(fd)?.open.borrow().oom.is_none()
            && self.descriptor(fd)?.open.borrow().network_control.is_none()
            && self
                .descriptor(fd)?
                .open
                .borrow()
                .node
                .as_ref()
                .is_some_and(|n| matches!(n.borrow().content, Content::File(_)))
        {
            if let Err(error) = self.truncate_fd(fd, 0) {
                self.fds.remove(&fd);
                return Err(error);
            }
        }
        Ok(Some(fd))
    }
    pub fn statfs_at(&self, path: &[u8]) -> Result<[u8; 120]> {
        let path = self.resolve(AT_FDCWD, path)?;
        self.node(&path)?;
        self.mount_statfs(path.mount.as_ref().map(|m| &*m.shared))
    }
    pub fn statfs_fd(&self, fd: u32) -> Result<[u8; 120]> {
        let o_descriptor = self.descriptor(fd)?;
        let o = o_descriptor.open.borrow();
        let mut out = self.mount_statfs(o.mount.as_deref())?;
        if o.namespace.is_some()
            || o.socket.is_some()
            || o.local.is_some()
            || (o.pipe.is_some() && o.node.is_none())
            || o.anonymous.is_some()
            || o.native_image.is_some()
        {
            out.fill(0);
            let magic = if o.native_image.is_some() {
                0x444d4142u64
            } else if o.namespace.is_some() {
                0x6e736673u64
            } else if o.anonymous.is_some() {
                0x09041934u64
            } else if o.socket.is_some() || o.local.is_some() {
                0x534f434bu64
            } else {
                0x50495045
            };
            out[..8].copy_from_slice(&magic.to_le_bytes());
            out[8..16].copy_from_slice(&4096u64.to_le_bytes());
        }
        Ok(out)
    }
    pub(super) fn refresh_pseudo_fd(&self, fd: u32) -> Result<()> {
        let o_descriptor = self.descriptor(fd)?;
        let o = o_descriptor.open.borrow();
        if o.oom.is_some() || o.network_control.is_some() {
            return Ok(());
        }
        if let FdKind::Node(key) = &o.kind {
            let path = ResolvedPath {
                key: key.clone(),
                mount: self.mount_for_path(o.mount.as_ref()),
            };
            if self.uses_pseudo(&path) && self.pseudo_readonly(&path) {
                self.pseudo_node(&path)?;
            }
        }
        Ok(())
    }
    pub(super) fn pseudo_node<P: PathArg + ?Sized>(&self, at: &P) -> Result<Option<NodeRef>> {
        let path = at.key();
        if ![b"/proc".as_slice(), b"/sys", b"/dev"].iter().any(|base| {
            path == *base
                || path
                    .strip_prefix(*base)
                    .is_some_and(|tail| tail.starts_with(b"/"))
        }) {
            return Ok(None);
        }
        if !self.pseudo.borrow().enabled {
            return Ok(None);
        }
        let content = self.pseudo_content(at)?;
        if let Some((content, mode)) = content {
            let node = self.pseudo.borrow_mut().cache(
                if path.starts_with(b"/proc") && self.proc_namespace(at).is_nested() {
                    self.proc_namespace(at).id()
                } else {
                    0
                },
                path,
                content,
                mode,
            )?;
            if let Some(rest) = path.strip_prefix(b"/proc/") {
                let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
                // Raw clone threads can have distinct credentials. Task paths
                // belong to the selected TID, not always the group leader.
                let pid = if parts.get(1) == Some(&b"task".as_slice()) {
                    parts.get(2)
                } else {
                    parts.first()
                }
                .and_then(|s| std::str::from_utf8(s).ok())
                .and_then(|s| s.parse::<u32>().ok());
                if let Some(p) = self
                    .proc_runtime(at, &self.pseudo.borrow().runtime)
                    .processes
                    .iter()
                    .find(|p| Some(p.pid) == pid)
                {
                    let mut n = node.borrow_mut();
                    n.uid = if p.nondumpable { 0 } else { p.credentials.euid };
                    n.gid = if p.nondumpable { 0 } else { p.credentials.egid };
                    if rest.ends_with(b"/environ") || rest.ends_with(b"/auxv") {
                        n.mode = 0o100400;
                    }
                    if rest.ends_with(b"/fd") || rest.ends_with(b"/fdinfo") {
                        n.mode = 0o40500;
                    }
                }
            }
            return Ok(Some(node));
        }
        if self.pseudo_readonly(path) || path == b"/dev/pts" || path.starts_with(b"/dev/pts/") {
            return Err(Errno(2));
        }
        Ok(None)
    }
    fn pseudo_content<P: PathArg + ?Sized>(&self, at: &P) -> Result<Option<(Content, u32)>> {
        let path = at.key();
        let pseudo = self.pseudo.borrow();
        let r = self.proc_runtime(at, &pseudo.runtime);
        let task_limit = if r.task_limit == 0 {
            MAX_TASKS
        } else {
            r.task_limit
        };
        let current = self.proc_namespace(at).local(self.pid);
        let own = r.processes.iter().find(|p| p.pid == current);
        let directory = || Some((Content::Directory, 0o40555));
        let regular = |value: Vec<u8>| Some((file(value), 0o100444));
        let link = |value: Vec<u8>| Some((Content::Symlink(value), 0o120777));
        if let Some(tail) = path.strip_prefix(b"/dev/pts/") {
            if let Some(id) = std::str::from_utf8(tail)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
            {
                if id == 0 && self.embedding_terminal.get()
                    || self.pty_by_id(id).is_some_and(|p| {
                        !p.private() && p.master_alive.load(std::sync::atomic::Ordering::Relaxed)
                    })
                {
                    return Ok(Some((Content::Device(Device::Pts(id, id)), 0o20620)));
                }
                return Ok(None);
            }
        }
        if let Some(tail) = path.strip_prefix(b"/sys/devices/system/cpu/cpu") {
            let parts: Vec<_> = tail.split(|c| *c == b'/').collect();
            if let Some(cpu) = std::str::from_utf8(parts[0])
                .ok()
                .and_then(|n| n.parse::<usize>().ok())
                .filter(|n| *n < r.cpu_count.max(1))
            {
                if parts.len() == 1
                    || parts.get(1) == Some(&b"topology".as_slice()) && parts.len() == 2
                {
                    return Ok(directory());
                }
                let value = match parts[1..] {
                    [b"online"] => "1\n".to_string(),
                    [b"topology", b"core_id"] => format!("{cpu}\n"),
                    [b"topology", b"physical_package_id"] => "0\n".to_string(),
                    [b"topology", b"thread_siblings_list"] => format!("{cpu}\n"),
                    [b"topology", b"thread_siblings"] => format!("{:08x}\n", 1u32 << cpu),
                    _ => return Ok(None),
                };
                return Ok(regular(value.into_bytes()));
            }
        }
        match path {
            b"/dev/dri" | b"/sys/dev/char" | b"/sys/class/drm" |
            b"/sys/devices/platform" | b"/sys/devices/platform/trames" |
            b"/sys/devices/platform/trames/drm" | b"/sys/devices/platform/trames/drm/renderD128" |
            b"/sys/bus" | b"/sys/bus/platform" if self.pseudo.borrow().video_device => return Ok(directory()),
            b"/dev/dri/renderD128" if self.pseudo.borrow().video_device => return Ok(Some((Content::Device(Device::Render), 0o20666))),
            b"/sys/dev/char/226:128" | b"/sys/class/drm/renderD128" if self.pseudo.borrow().video_device => return Ok(link(b"../../devices/platform/trames/drm/renderD128".to_vec())),
            b"/sys/devices/platform/trames/drm/renderD128/device" if self.pseudo.borrow().video_device => return Ok(link(b"../..".to_vec())),
            b"/sys/devices/platform/trames/drm/renderD128/subsystem" if self.pseudo.borrow().video_device => return Ok(link(b"../../../../../class/drm".to_vec())),
            b"/sys/devices/platform/trames/subsystem" if self.pseudo.borrow().video_device => return Ok(link(b"../../../bus/platform".to_vec())),
            b"/sys/devices/platform/trames/drm/renderD128/dev" if self.pseudo.borrow().video_device => return Ok(regular(b"226:128\n".to_vec())),
            b"/sys/devices/platform/trames/drm/renderD128/uevent" if self.pseudo.borrow().video_device => return Ok(regular(b"MAJOR=226\nMINOR=128\nDEVNAME=dri/renderD128\nDEVTYPE=drm_minor\n".to_vec())),
            b"/sys/devices/platform/trames/uevent" if self.pseudo.borrow().video_device => return Ok(regular(b"DRIVER=trames\nMODALIAS=platform:trames\n".to_vec())),
            b"/proc" | b"/sys" | b"/sys/fs" | b"/sys/fs/cgroup" | b"/sys/class" | b"/sys/class/net" | b"/sys/devices" |
            b"/sys/devices/system" | b"/sys/devices/system/cpu" | b"/sys/devices/virtual" | b"/sys/devices/virtual/net" | b"/sys/block" |
            b"/sys/class/block" | b"/sys/devices/virtual/block" | b"/sys/devices/virtual/block/vda" |
            b"/sys/devices/virtual/block/vda/vda1" | b"/sys/devices/virtual/block/vda/queue" |
            b"/sys/dev" | b"/sys/dev/block" | b"/dev/block" | b"/proc/sys" |
            b"/proc/sys/kernel" | b"/proc/sys/kernel/random" | b"/proc/sys/fs" | b"/proc/sys/vm" | b"/proc/sys/net" |
            b"/proc/sys/net/ipv4" | b"/dev/pts" => return Ok(directory()),
            b"/dev/tty" => return Ok(Some((Content::Terminal, 0o20666))),
            b"/sys/devices/system/cpu/online"|b"/sys/devices/system/cpu/possible"|b"/sys/devices/system/cpu/present"=>return Ok(regular(if r.cpu_count.max(1)==1{b"0\n".to_vec()}else{format!("0-{}\n",r.cpu_count-1).into_bytes()})),
            b"/sys/devices/system/cpu/offline"=>return Ok(regular(b"\n".to_vec())),
            b"/proc/self" => return Ok(link(own.map_or(current, |p| p.tgid).to_string().into_bytes())),
            b"/proc/thread-self" => return Ok(link(format!("{}/task/{}", own.map_or(current, |p| p.tgid), current).into_bytes())),
            b"/proc/mounts" => return Ok(link(b"self/mounts".to_vec())),
            b"/proc/net" => return Ok(link(b"self/net".to_vec())),
            b"/dev/fd" => return Ok(link(b"/proc/self/fd".to_vec())),
            b"/dev/stdin" | b"/dev/stdout" | b"/dev/stderr" => {
                let fd = if path == b"/dev/stdin" { 0 } else if path == b"/dev/stdout" { 1 } else { 2 };
                return Ok(link(format!("/proc/self/fd/{fd}").into_bytes()));
            }
            b"/dev/trames-bridge" if self.bridge.is_some() => return Ok(Some((Content::Device(Device::Bridge), 0o20600))),
            b"/dev/kmsg" => return Ok(Some((Content::Device(Device::Kmsg),0o20600))),
            b"/dev/vda" => return Ok(Some((Content::Device(Device::Vda),0o60600))),
            b"/dev/vda1" => return Ok(Some((Content::Device(Device::Vda1),0o60600))),
            b"/dev/block/253:0" => return Ok(link(b"../vda".to_vec())),
            b"/dev/block/253:1" => return Ok(link(b"../vda1".to_vec())),
            b"/sys/block/vda" => return Ok(link(b"../devices/virtual/block/vda".to_vec())),
            b"/sys/class/block/vda" => return Ok(link(b"../../devices/virtual/block/vda".to_vec())),
            b"/sys/class/block/vda1" => return Ok(link(b"../../devices/virtual/block/vda/vda1".to_vec())),
            b"/sys/dev/block/253:0" => return Ok(link(b"../../devices/virtual/block/vda".to_vec())),
            b"/sys/dev/block/253:1" => return Ok(link(b"../../devices/virtual/block/vda/vda1".to_vec())),
            b"/dev/zero" | b"/dev/full" | b"/dev/random" | b"/dev/urandom" | b"/dev/ptmx" => {
                let d = match path { b"/dev/zero" => Device::Zero, b"/dev/full" => Device::Full,
                    b"/dev/random" => Device::Random, b"/dev/urandom" => Device::Urandom, _ => Device::Ptmx };
                return Ok(Some((Content::Device(d), 0o20666)));
            }
            b"/proc/uptime" => return Ok(regular(format!("{:.2} {:.2}\n", r.uptime.as_secs_f64(), r.idle.as_secs_f64()).into_bytes())),
            b"/proc/meminfo" => {
                let total = r.memory_limit as u64 / 1024;
                let used: u64 = r.used_memory as u64 / 1024;
                let free = total.saturating_sub(used);
                let available = r.available_memory.map_or(free, |bytes| (bytes as u64 / 1024).min(total));
                return Ok(regular(format!("MemTotal: {total:8} kB\nMemFree: {free:8} kB\nMemAvailable: {available:8} kB\nBuffers: 0 kB\nCached: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n").into_bytes()));
            }
            b"/proc/cpuinfo" => return Ok(regular((0..r.cpu_count.max(1)).map(|cpu|format!("processor\t: {cpu}\nmodel name\t: Trames AArch64 interpreter\nCPU architecture: 8\nFeatures\t: {}\n\n",r.cpu_features)).collect::<String>().into_bytes())),
            b"/proc/swaps" => return Ok(regular(b"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n".to_vec())),
            b"/proc/partitions" => return Ok(regular(format!("major minor  #blocks  name\n\n 253 0 {} vda\n 253 1 {} vda1\n",self.capacity().budget_bytes/1024,self.capacity().budget_bytes/1024).into_bytes())),
            b"/proc/devices" => return Ok(regular(b"Character devices:\n  1 mem\n  5 /dev/tty\n136 pts\n\nBlock devices:\n253 virtblk\n".to_vec())),
            b"/proc/diskstats" => return Ok(regular(b"253 0 vda 0 0 0 0 0 0 0 0 0 0 0\n253 1 vda1 0 0 0 0 0 0 0 0 0 0 0\n".to_vec())),
            b"/proc/version" => return Ok(regular(b"Linux version 6.0.0-trames (Trames userspace compatibility runtime)\n".to_vec())),
            b"/proc/cgroups" => return Ok(regular(self.cgroup_subsystems())),
            b"/proc/filesystems" => return Ok(regular(b"nodev\tproc\nnodev\tsysfs\nnodev\tdevpts\nnodev\trootfs\nnodev\ttmpfs\nnodev\tcgroup2\nnodev\tmqueue\nnodev\toverlay\n".to_vec())),
            b"/proc/stat" => {
                let user = r.cpu_user_ticks;
                let idle = r.idle.as_millis() / 10;
                let running = r.processes.iter().filter(|p| p.state == 'R').count();
                let mut text=format!("cpu {user} 0 0 {idle} 0 0 0 0 0 0\n");
                for cpu in 0..r.cpu_count.max(1){let ticks=r.per_cpu_ticks.get(cpu).copied().unwrap_or(if cpu==0{user}else{0});text.push_str(&format!("cpu{cpu} {ticks} 0 0 {} 0 0 0 0 0 0\n",idle/r.cpu_count.max(1) as u128));}
                text.push_str(&format!("intr 0\nctxt {}\nbtime {}\nprocesses {}\nprocs_running {running}\nprocs_blocked 0\nsoftirq 0 0 0 0 0 0 0 0 0 0 0\n",r.context_switches,r.boot_time,r.processes_created));
                return Ok(regular(text.into_bytes()));
            }
            b"/proc/loadavg" => {
                let running = r.processes.iter().filter(|p| p.state == 'R').count();
                return Ok(regular(format!("{:.2} {:.2} {:.2} {running}/{} {}\n", r.load[0],r.load[1],r.load[2],r.processes.len(),r.processes_created).into_bytes()));
            }
            b"/proc/sys/kernel/random/uuid" => return Ok(regular(proc_uuid()?)),
            b"/proc/sys/kernel/random/boot_id" => return Ok(regular(pseudo.boot_id.get_or_init(proc_uuid).clone()?)),
            b"/proc/sys/kernel/ostype" => return Ok(regular(b"Linux\n".to_vec())),
            b"/proc/sys/kernel/osrelease" => return Ok(regular(b"6.0.0-trames\n".to_vec())),
            b"/proc/sys/kernel/version" => return Ok(regular(b"Trames userspace runtime\n".to_vec())),
            b"/proc/sys/kernel/hostname" => { let mut n = self.uts_name(false); n.push(b'\n'); return Ok(regular(n)); },
            b"/proc/sys/kernel/domainname" => { let mut n = self.uts_name(true); n.push(b'\n'); return Ok(regular(n)); },
            b"/proc/sys/kernel/cap_last_cap" => return Ok(regular(format!("{}\n", capabilities::LAST).into_bytes())),
            b"/proc/sys/kernel/pid_max" => return Ok(regular(b"2147483647\n".to_vec())),
            b"/proc/sys/kernel/threads-max" => return Ok(regular(format!("{task_limit}\n").into_bytes())),
            b"/proc/sys/fs/file-max" => return Ok(regular(format!("{}\n", task_limit * MAX_FDS as usize).into_bytes())),
            b"/proc/sys/fs/file-nr" => return Ok(regular(format!("{}\t0\t{}\n", r.processes.iter().map(|p| p.fds.len()).sum::<usize>(), task_limit * MAX_FDS as usize).into_bytes())),
            b"/proc/sys/vm/overcommit_memory" => return Ok(regular(b"2\n".to_vec())),
            b"/proc/sys/net/bridge/bridge-nf-call-iptables"|b"/proc/sys/net/bridge/bridge-nf-call-ip6tables"|b"/proc/sys/net/ipv4/ip_forward"|b"/proc/sys/net/ipv4/conf/all/forwarding"|b"/proc/sys/net/ipv6/conf/all/forwarding"=>return Ok(Some((file(Vec::new()),0o100644))),
            b"/proc/sys/net/bridge"|b"/proc/sys/net/ipv4/conf"|b"/proc/sys/net/ipv4/conf/all"|b"/proc/sys/net/ipv6"|b"/proc/sys/net/ipv6/conf"|b"/proc/sys/net/ipv6/conf/all"=>return Ok(directory()),
            b"/proc/sys/net/ipv4/ip_local_port_range" => return Ok(regular(b"49152\t65535\n".to_vec())),
            b"/proc/sys/net/ipv4/ip_default_ttl" => return Ok(regular(b"64\n".to_vec())),
            b"/proc/sys/net/ipv4/ping_group_range" | b"/proc/sys/net/ipv4/ip_unprivileged_port_start" => return Ok(Some((file(Vec::new()),0o100644))),
            _ => {},
        }
        if let Some(rest) = path.strip_prefix(b"/proc/") {
            let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
            let pid = std::str::from_utf8(parts[0])
                .ok()
                .and_then(|s| s.parse::<u32>().ok());
            if let Some(pid) = pid {
                let Some(mut p) = r.processes.iter().find(|p| p.pid == pid) else {
                    return Ok(None);
                };
                let mut i = 1;
                if parts.get(1) == Some(&b"task".as_slice()) {
                    if parts.len() == 2 {
                        return Ok(directory());
                    }
                    let tid = std::str::from_utf8(parts[2])
                        .ok()
                        .and_then(|s| s.parse::<u32>().ok());
                    let Some(thread) = r
                        .processes
                        .iter()
                        .find(|t| t.tgid == p.tgid && Some(t.pid) == tid)
                    else {
                        return Ok(None);
                    };
                    p = thread;
                    i = 3;
                }
                if parts.len() == i {
                    return Ok(directory());
                }
                let key = parts[i];
                if parts.len() == i + 2
                    && key == b"ns"
                    && matches!(
                        parts[i + 1],
                        b"uts"
                            | b"mnt"
                            | b"pid"
                            | b"pid_for_children"
                            | b"net"
                            | b"ipc"
                            | b"cgroup"
                    )
                {
                    return Ok(
                        linux_namespace::snapshot_label(&p.namespaces, parts[i + 1]).and_then(link)
                    );
                }
                if parts.len() == i + 1 {
                    let value = match key {
                        b"fd" | b"fdinfo" | b"net" | b"ns" => return Ok(directory()),
                        b"cwd" => return Ok(link(p.cwd.clone())),
                        b"root" => return Ok(link(b"/".to_vec())),
                        b"exe" if p.state != 'Z' => return Ok(link(p.executable.clone())),
                        b"exe" => return Ok(None),
                        b"oom_score_adj" => return Ok(Some((file(Vec::new()), 0o100644))),
                        // All tasks currently belong to the initial user
                        // namespace; supplementary groups are not disabled.
                        b"setgroups" => b"allow\n".to_vec(),
                        b"comm" => comm(p),
                        b"cgroup" => {
                            [b"0::".as_slice(), &self.cgroup_view_path(&p.cgroup), b"\n"].concat()
                        }
                        b"cmdline" => nul_list(&p.arguments),
                        b"environ" => nul_list(&p.environment),
                        b"auxv" => p.auxiliary.clone(),
                        b"maps" => p.maps.clone(),
                        b"mounts" => mounts::table_text(&p.namespaces, false),
                        b"mountinfo" => mounts::table_text(&p.namespaces, true),
                        b"statm" => format!(
                            "{} {} 0 0 0 0 0\n",
                            p.virtual_bytes / 4096,
                            p.mapped_bytes / 4096
                        )
                        .into_bytes(),
                        b"stat" => {
                            let name = String::from_utf8_lossy(&comm(p))
                                .trim_end()
                                .replace(['\n', ')'], "_");
                            let mut fields = vec!["0".to_string(); 50];
                            fields[0] = p.state.to_string();
                            fields[1] = p.parent.to_string();
                            fields[2] = p.group.to_string();
                            fields[3] = p.session.to_string();
                            fields[4] = if p.terminal {
                                (34816 + p.terminal_number).to_string()
                            } else {
                                "0".into()
                            };
                            fields[5] = p.group.to_string();
                            fields[11] = p.user_ticks.to_string();
                            fields[15] = (20 + p.nice).to_string();
                            fields[16] = p.nice.to_string();
                            fields[38] = p.scheduler.to_string();
                            fields[17] = r
                                .processes
                                .iter()
                                .filter(|t| t.tgid == p.tgid)
                                .count()
                                .to_string();
                            fields[19] = p.start_ticks.to_string();
                            fields[20] = p.virtual_bytes.to_string();
                            fields[21] = (p.mapped_bytes / 4096).to_string();
                            fields[22] = u64::MAX.to_string();
                            fields[36] = p.processor.to_string();
                            format!("{} ({name}) {}\n", p.pid, fields.join(" ")).into_bytes()
                        }
                        b"status" => {
                            let c = &p.credentials;
                            let name = String::from_utf8_lossy(&comm(p))
                                .trim_end()
                                .replace('\n', "_");
                            let name = format!(
                                "{name}\nCpus_allowed:\t{:08x}\nCpus_allowed_list:\t{}",
                                p.affinity,
                                (0..32)
                                    .filter(|i| p.affinity & (1u64 << i) != 0)
                                    .map(|i| i.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            );
                            let threads = r.processes.iter().filter(|t| t.tgid == p.tgid).count();
                            let mut name = name;
                            for (key, mask) in [
                                ("CapInh", c.caps.inheritable),
                                ("CapPrm", c.caps.permitted),
                                ("CapEff", c.caps.effective),
                                ("CapBnd", c.caps.bounding),
                                ("CapAmb", c.caps.ambient),
                            ] {
                                name.push_str(&format!("\n{key}:\t{mask:016x}"));
                            }
                            name.push_str(&format!(
                                "\nNoNewPrivs:\t{}",
                                u32::from(c.caps.no_new_privs)
                            ));
                            name.push_str(&format!(
                                "\nSeccomp:\t{}\nSeccomp_filters:\t{}",
                                p.seccomp, p.seccomp_filters
                            ));
                            for (key, ids) in ["NStgid", "NSpid", "NSpgid", "NSsid"]
                                .iter()
                                .zip(&p.namespace_ids)
                            {
                                if !ids.is_empty() {
                                    name.push_str(&format!(
                                        "\n{key}:\t{}",
                                        ids.iter()
                                            .map(u32::to_string)
                                            .collect::<Vec<_>>()
                                            .join("\t")
                                    ));
                                }
                            }
                            format!("Name:\t{name}\nState:\t{}\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nTracerPid:\t0\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nFDSize:\t256\nGroups:\t{}\nVmSize:\t{} kB\nVmRSS:\t{} kB\nThreads:\t{threads}\nSigPnd:\t{:016x}\nShdPnd:\t{:016x}\nSigBlk:\t{:016x}\nSigIgn:\t{:016x}\nSigCgt:\t{:016x}\n", p.state, p.tgid, p.pid, p.parent,
                                c.uid,c.euid,c.suid,c.fsuid,c.gid,c.egid,c.sgid,c.fsgid,c.groups.iter().map(u32::to_string).collect::<Vec<_>>().join(" "),p.virtual_bytes/1024,p.mapped_bytes/1024,p.pending,p.shared_pending,p.blocked,p.ignored,p.caught).into_bytes()
                        }
                        b"limits" => {
                            let (soft, hard) = p.file_size_limits.unwrap_or((u64::MAX, u64::MAX));
                            let limit = |v: u64| {
                                if v == u64::MAX {
                                    "unlimited".to_owned()
                                } else {
                                    v.to_string()
                                }
                            };
                            let address_limit = limit(p.address_space_limit.unwrap_or(512 << 20));
                            let (core_soft, core_hard) = p.core_limits.unwrap_or((0, u64::MAX));
                            format!("Limit                     Soft Limit           Hard Limit           Units\nMax open files            256                  256                  files\nMax processes             {task_limit:<20} {task_limit:<20} processes\nMax address space         {address_limit:<20} {address_limit:<20} bytes\nMax file size             {:<20} {:<20} bytes\nMax core file size        {:<20} {:<20} bytes\n", limit(soft), limit(hard),limit(core_soft),limit(core_hard)).into_bytes()
                        }
                        _ => return Ok(None),
                    };
                    return Ok(regular(value));
                }
                if parts.len() == i + 2 && matches!(key, b"fd" | b"fdinfo") {
                    let fd = std::str::from_utf8(parts[i + 1])
                        .ok()
                        .and_then(|s| s.parse::<u32>().ok());
                    let Some(fd) = p.fds.iter().find(|f| Some(f.fd) == fd) else {
                        return Ok(None);
                    };
                    if key == b"fd" {
                        return Ok(link(fd.target.clone()));
                    }
                    return Ok(regular(
                        format!(
                            "pos:\t{}\nflags:\t0{:o}\nmnt_id:\t{}\nino:\t{}\n{}",
                            fd.position,
                            fd.flags,
                            fd.mount_id,
                            fd.inode,
                            fd.signal_mask
                                .map(|mask| format!("sigmask:\t{mask:016x}\n"))
                                .unwrap_or_default()
                        )
                        .into_bytes(),
                    ));
                }
                if parts.len() == i + 2 && key == b"net" {
                    let network = p
                        .namespaces
                        .net
                        .upgrade()
                        .map(|ns| ns.network.borrow().clone());
                    let info = network.as_ref().and_then(|n| n.info());
                    return Ok(match parts[i + 1] {
                        b"tcp" | b"tcp6" | b"udp" | b"udp6" | b"raw" | b"raw6" | b"icmp"
                        | b"icmp6" => {
                            let key = parts[i + 1];
                            let family = if key.ends_with(b"6") { 10 } else { 2 };
                            let (kind, protocol) = if key.starts_with(b"tcp") {
                                (1, 6)
                            } else if key.starts_with(b"udp") {
                                (2, 17)
                            } else if key.starts_with(b"raw") {
                                (3, if family == 2 { 1 } else { 58 })
                            } else {
                                (2, if family == 2 { 1 } else { 58 })
                            };
                            let hex = |a: Option<std::net::SocketAddr>, port: Option<u16>| {
                                let (address, p) = a.map_or(
                                    (if family == 2 { vec![0; 4] } else { vec![0; 16] }, 0),
                                    |a| {
                                        (
                                            match a.ip() {
                                                std::net::IpAddr::V4(v) => v.octets().to_vec(),
                                                std::net::IpAddr::V6(v) => v.octets().to_vec(),
                                            },
                                            a.port(),
                                        )
                                    },
                                );
                                format!(
                                    "{}:{:04X}",
                                    address
                                        .chunks_exact(4)
                                        .map(|p| format!(
                                            "{:08X}",
                                            u32::from_le_bytes(p.try_into().unwrap())
                                        ))
                                        .collect::<String>(),
                                    port.unwrap_or(p)
                                )
                            };
                            let mut data=String::from("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
                            let mut seen = BTreeMap::new();
                            for process in &r.processes {
                                for fd in &process.fds {
                                    if let Some(s) = fd.socket.as_ref().filter(|s| {
                                        network
                                            .as_ref()
                                            .is_some_and(|n| n.namespace_id() == s.namespace_id)
                                            && s.family == family
                                            && s.kind == kind
                                            && s.protocol == protocol
                                    }) {
                                        if seen.insert(fd.inode, ()).is_some() {
                                            continue;
                                        }
                                        data.push_str(&format!("{:4}: {} {} {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} 0 {} 1 0000000000000000\n",seen.len()-1,hex(s.local,(kind==3).then_some(protocol as u16)),hex(s.peer,None),s.state,s.tx_queue.unwrap_or(0),s.rx_queue.unwrap_or(0),process.credentials.euid,fd.inode));
                                    }
                                }
                            }
                            regular(data.into_bytes())
                        }
                        b"unix" => regular(
                            b"Num       RefCount Protocol Flags    Type St Inode Path\n".to_vec(),
                        ),
                        b"dev" => {
                            let mut data=String::from("Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
                            if let Some(network) = &network {
                                let links = network.links();
                                for mut d in network.devices() {
                                    if let Some(links) = links {
                                        if d.kind == trames_net::DeviceKind::Loopback {
                                            d.stats = links[0];
                                        } else if d.kind == trames_net::DeviceKind::Direct {
                                            d.stats = links[1];
                                        }
                                    }
                                    let name = String::from_utf8_lossy(&d.name);
                                    let s = d.stats;
                                    data.push_str(&format!(
                                        "{name:>6}: {} {} 0 {} 0 0 0 0 {} {} 0 {} 0 0 0 0\n",
                                        s.rx_bytes,
                                        s.rx_packets,
                                        s.rx_dropped,
                                        s.tx_bytes,
                                        s.tx_packets,
                                        s.tx_dropped
                                    ));
                                }
                            }
                            regular(data.into_bytes())
                        }
                        b"route"
                            if network.as_ref().is_some_and(|n| {
                                n.devices().iter().any(|d| {
                                    matches!(
                                        d.kind,
                                        trames_net::DeviceKind::Veth { .. }
                                            | trames_net::DeviceKind::Bridge
                                    )
                                })
                            }) =>
                        {
                            let n = network.as_ref().unwrap();
                            let devices = n.devices();
                            let mut data=String::from("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n");
                            for route in n.routes() {
                                if let std::net::IpAddr::V4(ip) = route.destination.ip {
                                    let Some(d) = devices.iter().find(|d| d.index == route.device)
                                    else {
                                        continue;
                                    };
                                    let gateway = match route.gateway {
                                        Some(std::net::IpAddr::V4(gateway)) => Some(gateway),
                                        _ => None,
                                    };
                                    data.push_str(&proc_ipv4_route_row(
                                        &d.name,
                                        ip,
                                        route.destination.prefix,
                                        gateway,
                                        route.metric,
                                    ));
                                }
                            }
                            regular(data.into_bytes())
                        }
                        b"route" => regular(if let Some(n) = info {
                            if n.id == 0 {
                                let mut data = String::from("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n");
                                data.push_str(&proc_ipv4_route_row(
                                    b"eth0",
                                    std::net::Ipv4Addr::UNSPECIFIED,
                                    0,
                                    None,
                                    0,
                                ));
                                data.push_str(&proc_ipv4_route_row(
                                    b"eth0", n.ipv4, n.prefix4, None, 0,
                                ));
                                data.into_bytes()
                            } else {
                                format!("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t{:08X}\t0003\t0\t0\t0\t00000000\t0\t0\t0\neth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n", u32::from_le_bytes(n.gateway4.octets())).into_bytes()
                            }
                        } else {
                            b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n".to_vec()
                        }),
                        b"if_inet6" => {
                            let mut data = String::new();
                            if let Some(n) = &network {
                                for d in n.devices() {
                                    if d.kind == trames_net::DeviceKind::Loopback && !d.up {
                                        continue;
                                    }
                                    for a in d.addresses {
                                        if let std::net::IpAddr::V6(ip) = a.ip {
                                            data.push_str(&format!(
                                                "{:032x} {:02x} {:02x} {:02x} 80 {}\n",
                                                u128::from(ip),
                                                d.index,
                                                a.prefix,
                                                if ip.is_loopback() { 16 } else { 0 },
                                                String::from_utf8_lossy(&d.name)
                                            ));
                                        }
                                    }
                                }
                            }
                            regular(data.into_bytes())
                        }
                        _ => None,
                    });
                }
            }
        }
        if let Some(rest) = path.strip_prefix(b"/sys/devices/virtual/block/vda/") {
            let partition = rest.starts_with(b"vda1/");
            let attribute = if partition { &rest[5..] } else { rest };
            let value = match attribute {
                b"size" => format!("{}\n", self.capacity().budget_bytes / 512),
                b"dev" => format!("253:{}\n", u8::from(partition)),
                b"ro" | b"removable" | b"alignment_offset" | b"discard_alignment" | b"start" => {
                    "0\n".into()
                }
                b"partition" if partition => "1\n".into(),
                b"stat" => "0 0 0 0 0 0 0 0 0 0 0\n".into(),
                b"uevent" => if partition {
                    "MAJOR=253\nMINOR=1\nDEVNAME=vda1\nDEVTYPE=partition\nPARTN=1\n"
                } else {
                    "MAJOR=253\nMINOR=0\nDEVNAME=vda\nDEVTYPE=disk\n"
                }
                .into(),
                b"queue/logical_block_size" => "512\n".into(),
                b"queue/physical_block_size" | b"queue/minimum_io_size" => "4096\n".into(),
                b"queue/optimal_io_size" | b"queue/rotational" => "0\n".into(),
                _ => return Ok(None),
            };
            return Ok(regular(value.into_bytes()));
        }
        if let Some(name) = path.strip_prefix(b"/sys/class/net/") {
            if self.network_devices().iter().any(|d| d.name == name) {
                let mut target = b"../../devices/virtual/net/".to_vec();
                target.extend_from_slice(name);
                return Ok(link(target));
            }
        }
        if let Some(rest) = path.strip_prefix(b"/sys/devices/virtual/net/") {
            let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
            let Some(d) = self
                .network_devices()
                .into_iter()
                .find(|d| d.name == parts[0])
            else {
                return Ok(None);
            };
            if parts.len() == 1 {
                return Ok(directory());
            }
            if parts.get(1) == Some(&b"bridge".as_slice())
                && d.kind == trames_net::DeviceKind::Bridge
            {
                if parts.len() == 2 {
                    return Ok(directory());
                }
                // This IP fabric has no STP engine; report its actual disabled
                // state read-only rather than fabricate configurable STP.
                if parts.len() == 3 && parts[2] == b"stp_state" {
                    return Ok(regular(b"0\n".to_vec()));
                }
                return Ok(None);
            }
            if parts.get(1) == Some(&b"brif".as_slice()) && d.kind == trames_net::DeviceKind::Bridge
            {
                if parts.len() == 2 {
                    return Ok(directory());
                }
                if parts.len() == 3
                    && self
                        .network_devices()
                        .iter()
                        .any(|p| p.master == Some(d.index) && p.name == parts[2])
                {
                    let mut target = b"../../".to_vec();
                    target.extend_from_slice(parts[2]);
                    target.extend_from_slice(b"/brport");
                    return Ok(link(target));
                }
                return Ok(None);
            }
            if parts.get(1) == Some(&b"brport".as_slice()) {
                let Some(master) = d.master else {
                    return Ok(None);
                };
                if parts.len() == 2 {
                    return Ok(directory());
                }
                if parts.len() == 3 && parts[2] == b"state" {
                    // No STP/qdisc layer: an up, connected port forwards;
                    // detached/down links never claim a forwarding state.
                    let forwarding = self.network_carrier(&d)
                        && self
                            .network_devices()
                            .iter()
                            .any(|p| p.index == master && p.up);
                    return Ok(regular(if forwarding { b"3\n" } else { b"0\n" }.to_vec()));
                }
                return Ok(None);
            }
            if parts.get(1) == Some(&b"statistics".as_slice()) {
                if parts.len() == 2 {
                    return Ok(directory());
                }
                if parts.len() == 3 {
                    let v = match parts[2] {
                        b"rx_bytes" => d.stats.rx_bytes,
                        b"rx_packets" => d.stats.rx_packets,
                        b"rx_dropped" => d.stats.rx_dropped,
                        b"tx_bytes" => d.stats.tx_bytes,
                        b"tx_packets" => d.stats.tx_packets,
                        b"tx_dropped" => d.stats.tx_dropped,
                        _ => return Ok(None),
                    };
                    return Ok(regular(format!("{v}\n").into_bytes()));
                }
            }
            if parts.len() == 2 {
                let lo = d.kind == trames_net::DeviceKind::Loopback;
                let carrier = self.network_carrier(&d);
                let value = match parts[1] {
                    b"ifindex" => format!("{}\n", d.index),
                    b"iflink" => format!(
                        "{}\n",
                        if let trames_net::DeviceKind::Veth { peer } = d.kind {
                            peer
                        } else {
                            d.index
                        }
                    ),
                    b"type" => format!(
                        "{}\n",
                        if lo {
                            772
                        } else if d.kind == trames_net::DeviceKind::Direct {
                            65534
                        } else {
                            1
                        }
                    ),
                    b"mtu" => format!("{}\n", d.mtu),
                    b"address" | b"broadcast" => {
                        let mac = if parts[1] == b"broadcast"
                            && !lo
                            && d.kind != trames_net::DeviceKind::Direct
                        {
                            [255; 6]
                        } else {
                            d.mac
                        };
                        format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                        )
                    }
                    b"flags" => format!(
                        "0x{:x}\n",
                        if lo {
                            8 | u32::from(d.up)
                        } else if d.kind == trames_net::DeviceKind::Direct {
                            0x11
                        } else {
                            0x1002 | u32::from(d.up)
                        }
                    ),
                    b"operstate" => if !d.up || !carrier {
                        "down\n"
                    } else if lo {
                        "unknown\n"
                    } else {
                        "up\n"
                    }
                    .into(),
                    b"carrier" => format!("{}\n", u8::from(carrier)),
                    b"tx_queue_len" => format!("{}\n", d.tx_queue_len),
                    _ => return Ok(None),
                };
                return Ok(regular(value.into_bytes()));
            }
        }
        Ok(None)
    }
    pub(super) fn pseudo_children<P: PathArg + ?Sized>(&self, at: &P) -> Result<Vec<Vec<u8>>> {
        let path = at.key();
        if let Some(tail) = path.strip_prefix(b"/sys/devices/system/cpu/cpu") {
            let parts: Vec<_> = tail.split(|c| *c == b'/').collect();
            if std::str::from_utf8(parts[0])
                .ok()
                .and_then(|n| n.parse::<usize>().ok())
                .is_some_and(|n| n < self.pseudo.borrow().runtime.cpu_count.max(1))
            {
                return Ok(if parts.len() == 1 {
                    vec![b"online".to_vec(), b"topology".to_vec()]
                } else if parts.len() == 2 && parts[1] == b"topology" {
                    [
                        "core_id",
                        "physical_package_id",
                        "thread_siblings_list",
                        "thread_siblings",
                    ]
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect()
                } else {
                    Vec::new()
                });
            }
        }
        if !self.pseudo.borrow().enabled {
            return Ok(Vec::new());
        }
        let mut names: Vec<Vec<u8>> = match path {
            b"/" => vec![b"proc".to_vec(), b"sys".to_vec()],
            b"/proc" => [
                "self",
                "thread-self",
                "net",
                "mounts",
                "uptime",
                "meminfo",
                "cpuinfo",
                "version",
                "filesystems",
                "cgroups",
                "stat",
                "loadavg",
                "sys",
                "swaps",
                "partitions",
                "devices",
                "diskstats",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/dev" => [
                "zero", "full", "random", "urandom", "kmsg", "ptmx", "pts", "fd", "stdin",
                "stdout", "stderr", "vda", "vda1", "block",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/dev/dri" | b"/sys/class/drm" => vec![b"renderD128".to_vec()],
            b"/sys/dev/char" => vec![b"226:128".to_vec()],
            b"/sys/devices/platform" => vec![b"trames".to_vec()],
            b"/sys/devices/platform/trames" => {
                vec![b"drm".to_vec(), b"subsystem".to_vec(), b"uevent".to_vec()]
            }
            b"/sys/devices/platform/trames/drm" => vec![b"renderD128".to_vec()],
            b"/sys/devices/platform/trames/drm/renderD128" => vec![
                b"dev".to_vec(),
                b"device".to_vec(),
                b"subsystem".to_vec(),
                b"uevent".to_vec(),
            ],
            b"/sys/bus" => vec![b"platform".to_vec()],
            b"/sys/fs" => vec![b"cgroup".to_vec()],
            b"/sys" => vec![
                b"fs".to_vec(),
                b"class".to_vec(),
                b"devices".to_vec(),
                b"block".to_vec(),
                b"dev".to_vec(),
            ],
            b"/sys/class" => vec![b"net".to_vec(), b"block".to_vec()],
            b"/sys/devices" => vec![b"virtual".to_vec(), b"system".to_vec()],
            b"/sys/devices/system" => vec![b"cpu".to_vec()],
            b"/sys/devices/system/cpu" => {
                let mut names: Vec<_> = ["online", "offline", "possible", "present"]
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect();
                names.extend(
                    (0..self.pseudo.borrow().runtime.cpu_count.max(1))
                        .map(|i| format!("cpu{i}").into_bytes()),
                );
                names
            }
            b"/sys/devices/virtual" => vec![b"net".to_vec(), b"block".to_vec()],
            b"/sys/dev" => vec![b"block".to_vec()],
            b"/dev/block" | b"/sys/dev/block" => vec![b"253:0".to_vec(), b"253:1".to_vec()],
            b"/sys/block" | b"/sys/devices/virtual/block" => vec![b"vda".to_vec()],
            b"/sys/class/block" => vec![b"vda".to_vec(), b"vda1".to_vec()],
            b"/sys/devices/virtual/block/vda" => [
                "vda1",
                "queue",
                "dev",
                "size",
                "ro",
                "removable",
                "stat",
                "uevent",
                "alignment_offset",
                "discard_alignment",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/sys/devices/virtual/block/vda/vda1" => [
                "dev",
                "size",
                "ro",
                "stat",
                "uevent",
                "start",
                "partition",
                "alignment_offset",
                "discard_alignment",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/sys/devices/virtual/block/vda/queue" => [
                "logical_block_size",
                "physical_block_size",
                "minimum_io_size",
                "optimal_io_size",
                "rotational",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/sys/class/net" | b"/sys/devices/virtual/net" => {
                self.network_devices().into_iter().map(|d| d.name).collect()
            }
            b"/proc/sys" => ["kernel", "fs", "vm", "net"]
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            b"/proc/sys/kernel" => [
                "ostype",
                "osrelease",
                "version",
                "hostname",
                "domainname",
                "pid_max",
                "cap_last_cap",
                "threads-max",
                "random",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            b"/proc/sys/kernel/random" => vec![b"uuid".to_vec(), b"boot_id".to_vec()],
            b"/proc/sys/fs" => vec![b"file-max".to_vec(), b"file-nr".to_vec()],
            b"/proc/sys/vm" => vec![b"overcommit_memory".to_vec()],
            b"/proc/sys/net" => vec![b"ipv4".to_vec(), b"ipv6".to_vec(), b"bridge".to_vec()],
            b"/proc/sys/net/bridge" => vec![
                b"bridge-nf-call-iptables".to_vec(),
                b"bridge-nf-call-ip6tables".to_vec(),
            ],
            b"/proc/sys/net/ipv4/conf" | b"/proc/sys/net/ipv6/conf" => vec![b"all".to_vec()],
            b"/proc/sys/net/ipv4/conf/all" | b"/proc/sys/net/ipv6/conf/all" => {
                vec![b"forwarding".to_vec()]
            }
            b"/proc/sys/net/ipv6" => vec![b"conf".to_vec()],
            b"/proc/sys/net/ipv4" => [
                "conf",
                "ip_forward",
                "ip_unprivileged_port_start",
                "ip_local_port_range",
                "ip_default_ttl",
                "ping_group_range",
            ]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
            _ => Vec::new(),
        };
        if self.pseudo.borrow().video_device {
            match path {
                b"/dev" => names.push(b"dri".to_vec()),
                b"/sys" => names.push(b"bus".to_vec()),
                b"/sys/class" => names.push(b"drm".to_vec()),
                b"/sys/dev" => names.push(b"char".to_vec()),
                b"/sys/devices" => names.push(b"platform".to_vec()),
                _ => {}
            }
        }
        if path == b"/dev" && self.bridge.is_some() {
            names.push(b"trames-bridge".to_vec());
        }
        let pseudo = self.pseudo.borrow();
        let r = self.proc_runtime(at, &pseudo.runtime);
        if path == b"/proc" {
            names.extend(
                r.processes
                    .iter()
                    .filter(|p| p.pid == p.tgid)
                    .map(|p| p.pid.to_string().into_bytes()),
            );
        }
        if path == b"/dev/pts" {
            if self.embedding_terminal.get() {
                names.push(b"0".to_vec());
            }
            names.extend(
                self.live_ptys()
                    .iter()
                    .filter(|p| {
                        !p.private() && p.master_alive.load(std::sync::atomic::Ordering::Relaxed)
                    })
                    .map(|p| p.id.to_string().into_bytes()),
            );
        }
        if let Some(rest) = path.strip_prefix(b"/proc/") {
            let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
            let pid = std::str::from_utf8(parts[0])
                .ok()
                .and_then(|s| s.parse::<u32>().ok());
            if let Some(mut p) = r.processes.iter().find(|p| Some(p.pid) == pid) {
                let mut depth = 1;
                if parts.get(1) == Some(&b"task".as_slice()) {
                    if parts.len() == 2 {
                        names.extend(
                            r.processes
                                .iter()
                                .filter(|t| t.tgid == p.tgid)
                                .map(|p| p.pid.to_string().into_bytes()),
                        );
                    }
                    if parts.len() >= 3 {
                        let tid = std::str::from_utf8(parts[2])
                            .ok()
                            .and_then(|s| s.parse::<u32>().ok());
                        if let Some(thread) = r
                            .processes
                            .iter()
                            .find(|t| t.tgid == p.tgid && Some(t.pid) == tid)
                        {
                            p = thread;
                            depth = 3;
                        }
                    }
                }
                if parts.len() == depth {
                    names.extend(
                        [
                            "stat",
                            "status",
                            "statm",
                            "oom_score_adj",
                            "setgroups",
                            "cgroup",
                            "cmdline",
                            "environ",
                            "comm",
                            "maps",
                            "auxv",
                            "cwd",
                            "root",
                            "exe",
                            "mounts",
                            "mountinfo",
                            "ns",
                            "limits",
                            "fd",
                            "fdinfo",
                            "net",
                        ]
                        .iter()
                        .map(|s| s.as_bytes().to_vec()),
                    );
                    if depth == 1 {
                        names.push(b"task".to_vec());
                    }
                }
                if parts.len() == depth + 1 {
                    if parts[depth] == b"ns"
                        && linux_namespace::snapshot_label(&p.namespaces, b"uts").is_some()
                    {
                        names.push(b"uts".to_vec());
                        names.push(b"pid".to_vec());
                        names.push(b"pid_for_children".to_vec());
                        names.push(b"net".to_vec());
                        names.push(b"ipc".to_vec());
                        names.push(b"cgroup".to_vec());
                        if p.namespaces.mount.strong_count() != 0 {
                            names.push(b"mnt".to_vec());
                        }
                    }
                    if matches!(parts[depth], b"fd" | b"fdinfo") {
                        names.extend(p.fds.iter().map(|f| f.fd.to_string().into_bytes()));
                    }
                    if parts[depth] == b"net" {
                        names.extend(
                            [
                                "route", "if_inet6", "dev", "tcp", "tcp6", "udp", "udp6", "raw",
                                "raw6", "icmp", "icmp6", "unix",
                            ]
                            .iter()
                            .map(|s| s.as_bytes().to_vec()),
                        );
                    }
                }
            }
        }
        if let Some(rest) = path.strip_prefix(b"/sys/devices/virtual/net/") {
            let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
            if let Some(d) = self
                .network_devices()
                .into_iter()
                .find(|d| d.name == parts[0])
            {
                if parts.len() == 1 {
                    names.extend(
                        [
                            "ifindex",
                            "iflink",
                            "type",
                            "mtu",
                            "address",
                            "broadcast",
                            "flags",
                            "operstate",
                            "carrier",
                            "tx_queue_len",
                            "statistics",
                        ]
                        .iter()
                        .map(|s| s.as_bytes().to_vec()),
                    );
                    if d.kind == trames_net::DeviceKind::Bridge {
                        names.push(b"brif".to_vec());
                        names.push(b"bridge".to_vec());
                    }
                    if d.master.is_some() {
                        names.push(b"brport".to_vec());
                    }
                }
                if parts.len() == 2
                    && parts[1] == b"brif"
                    && d.kind == trames_net::DeviceKind::Bridge
                {
                    names.extend(
                        self.network_devices()
                            .into_iter()
                            .filter(|p| p.master == Some(d.index))
                            .map(|p| p.name),
                    );
                }
                if parts.len() == 2
                    && parts[1] == b"bridge"
                    && d.kind == trames_net::DeviceKind::Bridge
                {
                    return Ok(vec![b"stp_state".to_vec()]);
                }
                if parts.len() == 2 && parts[1] == b"brport" && d.master.is_some() {
                    names.push(b"state".to_vec());
                }
                if parts.len() == 2 && parts[1] == b"statistics" {
                    names.extend(
                        [
                            "rx_bytes",
                            "rx_packets",
                            "rx_dropped",
                            "tx_bytes",
                            "tx_packets",
                            "tx_dropped",
                        ]
                        .iter()
                        .map(|s| s.as_bytes().to_vec()),
                    );
                }
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }
}

#[cfg(test)]
mod proc_probe_tests {
    use super::*;
    #[test]
    fn live_argument_demand_survives_alias_cwd_and_directory_fd_resolution() {
        let mut v = Vfs::default();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        v.symlink_at(b"/proc/self/cmdline", AT_FDCWD, b"/arguments")
            .unwrap();
        for path in [b"/proc/self/cmdline".as_slice(), b"/arguments"] {
            assert_eq!(
                v.proc_observation(AT_FDCWD, path),
                Some(ProcRefresh::Arguments)
            );
        }
        v.symlink_at(b"/proc/self/fdinfo", AT_FDCWD, b"/descriptors")
            .unwrap();
        assert_eq!(
            v.proc_observation(AT_FDCWD, b"/descriptors"),
            Some(ProcRefresh::Descriptors)
        );
        for path in [
            b"/proc/self/status".as_slice(),
            b"/proc/self/stat",
            b"/proc/self/statm",
        ] {
            assert_eq!(
                v.proc_observation(AT_FDCWD, path),
                Some(ProcRefresh::Residency)
            );
        }
        for path in [
            b"/proc/self/fd/1".as_slice(),
            b"/proc/self/fdinfo/1",
            b"/proc/self/net/tcp",
            b"/proc/sys/fs/file-nr",
        ] {
            assert_eq!(ProcRefresh::for_path(path), ProcRefresh::Descriptors);
        }
        let fd = v.open_at(AT_FDCWD, b"/proc/self", O_DIRECTORY, 0).unwrap();
        assert_eq!(
            v.proc_observation(fd as i32, b"cmdline"),
            Some(ProcRefresh::Arguments)
        );
        let argv = v.open_at(AT_FDCWD, b"/proc/self/cmdline", 0, 0).unwrap();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    fds: v.fd_snapshot(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        assert_eq!(
            v.proc_observation(AT_FDCWD, format!("/proc/self/fd/{argv}").as_bytes()),
            Some(ProcRefresh::Arguments.merge(ProcRefresh::Descriptors))
        );
        v.chdir(b"/proc/self").unwrap();
        assert_eq!(
            v.proc_observation(AT_FDCWD, b"cmdline"),
            Some(ProcRefresh::Arguments)
        );
    }
    #[test]
    fn proc_observation_tracks_dependencies_through_aliases_and_failed_lookups() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v.symlink_at(b"/proc/sys/kernel", AT_FDCWD, b"/keys")
            .unwrap();
        assert_eq!(
            v.proc_observation(AT_FDCWD, b"/keys/random/uuid"),
            Some(ProcRefresh::Independent)
        );
        assert_eq!(
            v.proc_observation(AT_FDCWD, b"/proc/cpuinfo"),
            Some(ProcRefresh::Independent)
        );
        let fd = v.open_at(AT_FDCWD, b"/proc/sys", O_DIRECTORY, 0).unwrap();
        assert_eq!(
            v.proc_observation(fd as i32, b"kernel/random/uuid"),
            Some(ProcRefresh::Independent)
        );
        v.chdir(b"/proc/sys").unwrap();
        assert_eq!(
            v.proc_observation(AT_FDCWD, b"kernel/random/uuid"),
            Some(ProcRefresh::Independent)
        );
        assert_eq!(
            v.proc_observation(AT_FDCWD, b"/proc/12345/status"),
            Some(ProcRefresh::Metadata)
        );
        assert_eq!(
            v.proc_observation(AT_FDCWD, b"/proc/12345/maps"),
            Some(ProcRefresh::Metadata),
            "unknown tasks need conservative refresh before their final file can resolve"
        );
        assert_eq!(v.proc_observation(AT_FDCWD, b"/ordinary"), None);
        assert_eq!(
            ProcRefresh::for_path(b"/proc/1/maps"),
            ProcRefresh::Mappings
        );
        assert_eq!(
            ProcRefresh::for_path(b"/proc/1/statm"),
            ProcRefresh::Residency
        );
        assert_eq!(
            ProcRefresh::for_path(b"/proc/sys/fs/file-nr"),
            ProcRefresh::Descriptors
        );
        for (path, demand) in [
            (b"/proc/1/maps".as_slice(), ProcRefresh::Mappings),
            (b"/proc/1/environ", ProcRefresh::Environment),
            (b"/proc/1/auxv", ProcRefresh::Auxiliary),
        ] {
            assert_eq!(ProcRefresh::for_path(path), demand);
            let combined = demand.merge(ProcRefresh::Descriptors);
            assert!(combined.descriptors());
            assert_eq!(combined.mappings(), demand.mappings());
            assert_eq!(combined.environment(), demand.environment());
            assert_eq!(combined.auxiliary(), demand.auxiliary());
            assert!(!combined.arguments());
            assert!(!combined.residency());
            assert_eq!(ProcRefresh::Metadata.merge(demand), demand);
        }
    }

    #[test]
    fn proc_probe_follows_aliases_cwd_and_dirfd_even_for_missing_processes() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v.mkdir_at(AT_FDCWD, b"/work", 0o755).unwrap();
        v.symlink_at(b"/proc", AT_FDCWD, b"/work/p").unwrap();
        v.symlink_at(b"../proc", AT_FDCWD, b"/alias").unwrap();
        assert!(!v.accesses_proc(AT_FDCWD, b"/work/file"));
        assert!(!v.accesses_proc(AT_FDCWD, b"/missing/proc/file"));
        assert!(v.accesses_proc(AT_FDCWD, b"/proc/12345/status"));
        assert!(v.accesses_proc(AT_FDCWD, b"/work/p/12345/status"));
        assert!(v.accesses_proc(AT_FDCWD, b"/alias/stat"));
        let fd = v.open_at(AT_FDCWD, b"/proc", O_DIRECTORY, 0).unwrap();
        assert!(v.accesses_proc(fd as i32, b"12345/status"));
        v.chdir(b"/proc").unwrap();
        assert!(v.accesses_proc(AT_FDCWD, b"12345/status"));
        assert!(!v.accesses_proc(AT_FDCWD, b"/work/file"));
    }
}
