// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded, interpreted CGROUP_DEVICE programs. Guest pointers are never host
//! pointers: the only readable memory is the twelve-byte device context.
use crate::*;

const MAX_INSNS: usize = 4096;
const MAX_PROGRAMS: usize = 128;
#[derive(Clone, Copy)]
struct Insn {
    code: u8,
    dst: usize,
    src: usize,
    off: i16,
    imm: i32,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reg {
    Uninit,
    Scalar,
    Context,
}
// Verified immutable instructions are shared by FDs, cgroup attachments and
// executing workers. The weak registry never prolongs a program's lifetime.
pub(super) struct Program {
    pub id: u32,
    pub kind: u32,
    code: Vec<Insn>,
}
#[derive(Default)]
pub(super) struct Registry {
    next: u32,
    programs: BTreeMap<u32, std::sync::Weak<Program>>,
}
impl Registry {
    fn publish(&mut self, kind: u32, code: Vec<Insn>) -> Result<Arc<Program>> {
        self.programs.retain(|_, p| p.strong_count() != 0);
        if self.programs.len() >= MAX_PROGRAMS {
            return Err(Errno(28));
        }
        let id = self.next.checked_add(1).ok_or(Errno(28))?;
        let p = Arc::new(Program { id, kind, code });
        self.next = id;
        self.programs.insert(id, Arc::downgrade(&p));
        Ok(p)
    }
}
fn verify(bytes: &[u8]) -> Result<Vec<Insn>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) {
        return Err(Errno(22));
    }
    if bytes.len() / 8 > MAX_INSNS {
        return Err(Errno(7));
    }
    let code: Vec<_> = bytes
        .chunks_exact(8)
        .map(|b| Insn {
            code: b[0],
            dst: (b[1] & 15) as usize,
            src: (b[1] >> 4) as usize,
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes(b[4..8].try_into().unwrap()),
        })
        .collect();
    let mut states = vec![None; code.len()];
    let mut start = [Reg::Uninit; 10];
    start[1] = Reg::Context;
    states[0] = Some(start);
    for (pc, i) in code.iter().enumerate() {
        let mut regs = states[pc].ok_or(Errno(22))?;
        if i.dst >= 10 || i.src >= 10 {
            return Err(Errno(22));
        }
        let mut targets = Vec::with_capacity(2);
        match i.code {
            0x61 if regs[i.src] == Reg::Context && matches!(i.off, 0 | 4 | 8) && i.imm == 0 => {
                regs[i.dst] = Reg::Scalar;
                targets.push(pc + 1);
            }
            0xb4 | 0xb7 if i.off == 0 && i.src == 0 => {
                regs[i.dst] = Reg::Scalar;
                targets.push(pc + 1);
            }
            0xbc | 0xbf
                if i.off == 0
                    && i.imm == 0
                    && regs[i.src] != Reg::Uninit
                    && (i.code == 0xbf || regs[i.src] == Reg::Scalar) =>
            {
                regs[i.dst] = regs[i.src];
                targets.push(pc + 1);
            }
            0x54 | 0x57 | 0x74 | 0x77 if i.off == 0 && i.src == 0 && regs[i.dst] == Reg::Scalar => {
                if i.code & 0xf0 == 0x70
                    && !(0..if i.code & 7 == 4 { 32 } else { 64 }).contains(&i.imm)
                {
                    return Err(Errno(22));
                }
                targets.push(pc + 1);
            }
            0x15 | 0x1d | 0x55 | 0x5d if i.off >= 0 && regs[i.dst] == Reg::Scalar => {
                if i.code & 8 != 0 {
                    if regs[i.src] != Reg::Scalar || i.imm != 0 {
                        return Err(Errno(22));
                    }
                } else if i.src != 0 {
                    return Err(Errno(22));
                }
                targets.extend([pc + 1, pc + 1 + i.off as usize]);
            }
            0x05 if i.off >= 0 && i.dst == 0 && i.src == 0 && i.imm == 0 => {
                targets.push(pc + 1 + i.off as usize)
            }
            0x95 if i.dst == 0
                && i.src == 0
                && i.off == 0
                && i.imm == 0
                && regs[0] == Reg::Scalar => {}
            _ => return Err(Errno(22)),
        }
        for next in targets {
            let state = states.get_mut(next).ok_or(Errno(22))?;
            if let Some(previous) = state {
                for n in 0..10 {
                    if previous[n] != regs[n] {
                        previous[n] = Reg::Uninit;
                    }
                }
            } else {
                *state = Some(regs);
            }
        }
    }
    Ok(code)
}
impl Program {
    pub fn allows(&self, context: [u32; 3]) -> bool {
        let mut r = [0u64; 10];
        let mut pc = 0;
        // All verified branches are forward. No loops, helpers, maps, stack,
        // loads from guest memory, native execution or unbounded evaluation.
        while let Some(i) = self.code.get(pc) {
            pc += 1;
            match i.code {
                0x61 => r[i.dst] = context[i.off as usize / 4] as u64,
                0xb4 => r[i.dst] = i.imm as u32 as u64,
                0xb7 => r[i.dst] = i.imm as i64 as u64,
                0xbc => r[i.dst] = r[i.src] as u32 as u64,
                0xbf => r[i.dst] = r[i.src],
                0x54 => r[i.dst] = (r[i.dst] as u32 & i.imm as u32) as u64,
                0x57 => r[i.dst] &= i.imm as i64 as u64,
                0x74 => r[i.dst] = (r[i.dst] as u32 >> i.imm) as u64,
                0x77 => r[i.dst] >>= i.imm,
                0x15 | 0x1d | 0x55 | 0x5d => {
                    let other = if i.code & 8 != 0 {
                        r[i.src]
                    } else {
                        i.imm as i64 as u64
                    };
                    if (r[i.dst] == other) == (i.code & 0xf0 == 0x10) {
                        pc += i.off as usize;
                    }
                }
                0x05 => pc += i.off as usize,
                0x95 => return r[0] != 0,
                _ => return false,
            }
        }
        false
    }
}
impl Vfs {
    pub fn bpf_authorized(&self) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        Ok(())
    }
    pub fn bpf_load_device(&mut self, code: &[u8]) -> Result<u32> {
        self.bpf_load_program(15, code)
    }
    pub fn bpf_load_program(&mut self, kind: u32, code: &[u8]) -> Result<u32> {
        self.descriptor_factory().bpf_load_program(kind, code)
    }
    pub fn bpf_get_fd(&mut self, id: u32) -> Result<u32> {
        self.descriptor_factory().bpf_get_fd(id)
    }
    pub fn bpf_program_identity(&self, fd: u32) -> Result<[u8; 8]> {
        self.descriptor_factory().bpf_program_identity(fd)
    }
    #[cfg(test)]
    pub(super) fn bpf_program(&self, fd: u32) -> Result<Arc<Program>> {
        self.descriptor_factory().bpf_program(fd)
    }
}
impl DescriptorFactory {
    pub fn bpf_authorized(&self) -> Result<()> {
        if !self.local_credentials().has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        Ok(())
    }
    pub fn bpf_load_program(&self, kind: u32, code: &[u8]) -> Result<u32> {
        self.bpf_authorized()?;
        let reserved = self.files.reserve()?;
        if !matches!(kind, 8 | 15) {
            return Err(Errno(22));
        }
        // Verification is pure and bounded. Do it before the original registry
        // transaction, so independent callers do not serialize their verifier.
        let code = verify(code)?;
        if kind == 8 && code.iter().any(|i| i.code == 0x61) {
            return Err(Errno(22));
        }
        let program = self.cgroups.borrow_mut().bpf.publish(kind, code)?;
        reserved.publish(
            events::anonymous_descriptor(
                self.open_id(),
                O_CLOEXEC,
                events::Anonymous::Bpf(program),
            ),
            None,
        )
    }
    pub fn bpf_get_fd(&self, id: u32) -> Result<u32> {
        self.bpf_authorized()?;
        let program = self
            .cgroups
            .borrow()
            .bpf
            .programs
            .get(&id)
            .and_then(std::sync::Weak::upgrade)
            .ok_or(Errno(2))?;
        let reserved = self.files.reserve()?;
        reserved.publish(
            events::anonymous_descriptor(
                self.open_id(),
                O_CLOEXEC,
                events::Anonymous::Bpf(program),
            ),
            None,
        )
    }
    /// Stable info prefix supported by the guest device-program registry.
    pub fn bpf_program_identity(&self, fd: u32) -> Result<[u8; 8]> {
        let program = self.bpf_program(fd)?;
        let mut info = [0; 8];
        info[..4].copy_from_slice(&program.kind.to_le_bytes());
        info[4..].copy_from_slice(&program.id.to_le_bytes());
        Ok(info)
    }
    pub(super) fn bpf_program(&self, fd: u32) -> Result<Arc<Program>> {
        let file = self.files.lookup(fd).ok_or(Errno(22))??;
        match &file.open.control {
            Some(events::SharedControl::Bpf(p)) if file.open.flags.get() & O_PATH == 0 => {
                Ok(p.clone())
            }
            _ => Err(Errno(22)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_cgroup_path_consumers_share_original_targets_and_control_files() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        struct Source;
        impl ProcSource for Source {
            fn observe(&self, _: ProcQuery<'_>) -> RuntimeInfo {
                RuntimeInfo::default()
            }
        }
        v.set_proc_source(Arc::new(Source));
        let paths = v.path_queries();
        let files = DirectFiles::default();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/source", 0o755)
            .unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/source/leaf", 0o755)
            .unwrap();
        let parent = paths
            .open_at_resolve(
                AT_FDCWD,
                b"/sys/fs/cgroup/source",
                O_DIRECTORY,
                0,
                0,
                &files,
            )
            .unwrap()
            .unwrap();
        let leaf = paths
            .open_at_resolve(parent as i32, b"leaf", O_PATH, 0, 0, &files)
            .unwrap()
            .unwrap();
        let control = paths
            .open_at_resolve(leaf as i32, b"cgroup.freeze", 2, 0, 0, &files)
            .unwrap()
            .unwrap();
        assert_eq!(v.read(control, 32).unwrap(), b"0\n");
        assert!(paths
            .getdents(parent, 4096, || Ok(()))
            .unwrap()
            .unwrap()
            .windows(4)
            .any(|s| s == b"leaf"));
        let factory = v.descriptor_factory();
        let program = factory.bpf_load_program(15, &constant(1)).unwrap();
        factory.bpf_attach_device(leaf, program, 2, 0).unwrap();
        assert_eq!(factory.bpf_query_device(leaf, false).unwrap().1.len(), 1);
        // A deleted target cannot be redirected through the reused pathname.
        v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/source/leaf", true)
            .unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/source/leaf", 0o755)
            .unwrap();
        assert_eq!(factory.bpf_query_device(leaf, false), Err(Errno(19)));
        let replacement = paths
            .open_at_resolve(parent as i32, b"leaf", O_PATH, 0, 0, &files)
            .unwrap()
            .unwrap();
        assert!(factory
            .bpf_query_device(replacement, true)
            .unwrap()
            .1
            .is_empty());
    }
    #[test]
    fn parallel_factories_publish_original_programs_and_attachments_without_owner_collection() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/policy", 0o755)
            .unwrap();
        let target = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/policy", O_PATH, 0)
            .unwrap();
        let factory = v.descriptor_factory();
        let barrier = Arc::new(std::sync::Barrier::new(12));
        let workers: Vec<_> = (0..12)
            .map(|_| {
                let factory = factory.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let fd = factory.bpf_load_program(15, &constant(1)).unwrap();
                    let info = factory.bpf_program_identity(fd).unwrap();
                    let id = u32::from_le_bytes(info[4..].try_into().unwrap());
                    factory.bpf_attach_device(target, fd, 2, 0).unwrap();
                    factory.files.close(fd, 1).unwrap().unwrap();
                    barrier.wait();
                    let (flags, ids) = factory.bpf_query_device(target, false).unwrap();
                    assert_eq!((flags, ids.len()), (2, 12));
                    assert!(ids.contains(&id));
                    let reopened = factory.bpf_get_fd(id).unwrap();
                    assert_eq!(factory.bpf_program_identity(reopened).unwrap(), info);
                    barrier.wait();
                    factory.bpf_detach_device(target, reopened).unwrap();
                    factory.files.close(reopened, 1).unwrap().unwrap();
                    barrier.wait();
                    assert_eq!(factory.bpf_get_fd(id), Err(Errno(2)));
                    id
                })
            })
            .collect();
        let ids: std::collections::BTreeSet<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(ids.len(), 12);
        assert_eq!(v.bpf_query_device(target, false).unwrap(), (0, vec![]));
        // Owner observation sees the original Files publication immediately.
        assert_eq!(v.fd_snapshot().len(), 4);
    }
    #[test]
    fn factory_policy_keeps_original_files_and_refreshes_new_call_credentials() {
        let mut v = Vfs::default();
        let original = v.descriptor_factory();
        let (detached, _owner) = original.files.fork();
        let mut fresh = original.clone();
        fresh.files = detached;
        let fd = fresh.bpf_load_program(15, &constant(1)).unwrap();
        assert_eq!(original.bpf_program_identity(fd), Err(Errno(9)));
        let id = u32::from_le_bytes(
            fresh.bpf_program_identity(fd).unwrap()[4..]
                .try_into()
                .unwrap(),
        );
        let reopened = original.bpf_get_fd(id).unwrap();
        assert_eq!(
            v.bpf_program_identity(reopened),
            fresh.bpf_program_identity(fd)
        );
        v.credentials = Credentials::user(1000, 1000);
        let unprivileged = v.descriptor_factory();
        assert_eq!(
            unprivileged.bpf_load_program(15, &constant(1)),
            Err(Errno(1))
        );
        assert_eq!(unprivileged.bpf_get_fd(id), Err(Errno(1)));
        // An already captured call retains submission authority; future calls
        // use the refreshed factory, as other descriptor controls do.
        assert!(original.bpf_get_fd(id).is_ok());
    }
    #[test]
    fn removing_a_cgroup_during_source_policy_queries_never_uses_a_stale_group_index() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        let program = v.bpf_load_device(&constant(1)).unwrap();
        for _ in 0..32 {
            v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/removed", 0o755)
                .unwrap();
            let target = v
                .open_at(AT_FDCWD, b"/sys/fs/cgroup/removed", O_PATH, 0)
                .unwrap();
            let source = v.descriptor_factory();
            let start = Arc::new(std::sync::Barrier::new(2));
            let peer_start = start.clone();
            let peer = std::thread::spawn(move || {
                peer_start.wait();
                for _ in 0..128 {
                    assert!(matches!(
                        source.bpf_query_device(target, true),
                        Ok(_) | Err(Errno(19))
                    ));
                    assert!(matches!(
                        source.bpf_attach_device(target, program, 2, 0),
                        Ok(()) | Err(Errno(17 | 19))
                    ));
                    assert!(matches!(
                        source.bpf_detach_device(target, program),
                        Ok(()) | Err(Errno(2 | 19))
                    ));
                }
            });
            start.wait();
            v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/removed", true)
                .unwrap();
            peer.join().unwrap();
            assert_eq!(v.bpf_query_device(target, false), Err(Errno(19)));
            v.close(target).unwrap();
        }
    }
    fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let mut bytes = [code, dst | src << 4, 0, 0, 0, 0, 0, 0];
        bytes[2..4].copy_from_slice(&off.to_le_bytes());
        bytes[4..].copy_from_slice(&imm.to_le_bytes());
        bytes
    }
    fn constant(value: i32) -> Vec<u8> {
        [insn(0xb7, 0, 0, 0, value), insn(0x95, 0, 0, 0, 0)].concat()
    }
    #[test]
    fn typed_forward_verifier_rejects_unsafe_and_uninitialized_programs() {
        for code in [
            vec![],
            vec![0; 7],
            vec![0; (MAX_INSNS + 1) * 8],
            insn(0x95, 0, 0, 0, 0).to_vec(), // uninitialized return
            [insn(0x61, 0, 1, 12, 0), insn(0x95, 0, 0, 0, 0)].concat(), // context OOB
            [
                insn(0xb7, 1, 0, 0, 0),
                insn(0x61, 0, 1, 0, 0),
                insn(0x95, 0, 0, 0, 0),
            ]
            .concat(), // scalar pointer
            [insn(0x05, 0, 0, -1, 0), insn(0x95, 0, 0, 0, 0)].concat(), // loop
            [
                insn(0xb7, 0, 0, 0, 1),
                insn(0x77, 0, 0, 0, 64),
                insn(0x95, 0, 0, 0, 0),
            ]
            .concat(),
            [insn(0x85, 0, 0, 0, 1), insn(0x95, 0, 0, 0, 0)].concat(), // helper
            [
                insn(0x61, 2, 1, 0, 0),
                insn(0x15, 2, 0, 1, 2),
                insn(0xb7, 0, 0, 0, 1),
                insn(0x95, 0, 0, 0, 0),
            ]
            .concat(), // uninitialized join
            [insn(0xb7, 0, 0, 0, 1), insn(0x05, 0, 0, 9, 0)].concat(), // OOB jump
        ] {
            assert!(verify(&code).is_err());
        }
    }
    #[test]
    fn crun_style_context_mask_and_branches_enforce_device_access() {
        // Permit only read or mknod of character device 1:3; reject writes,
        // other device types/numbers and combined read/write access.
        let bytes = [
            insn(0x61, 2, 1, 0, 0),
            insn(0x54, 2, 0, 0, 0xffff),
            insn(0x61, 3, 1, 0, 0),
            insn(0x74, 3, 0, 0, 16),
            insn(0x61, 4, 1, 4, 0),
            insn(0x61, 5, 1, 8, 0),
            insn(0x55, 2, 0, 7, 2),
            insn(0xbc, 1, 3, 0, 0),
            insn(0x54, 1, 0, 0, 3),
            insn(0x5d, 1, 3, 4, 0),
            insn(0x55, 4, 0, 3, 1),
            insn(0x55, 5, 0, 2, 3),
            insn(0xb7, 0, 0, 0, 1),
            insn(0x95, 0, 0, 0, 0),
            insn(0xb7, 0, 0, 0, 0),
            insn(0x95, 0, 0, 0, 0),
        ]
        .concat();
        let p = Program {
            id: 1,
            kind: 15,
            code: verify(&bytes).unwrap(),
        };
        for access in 1..=7 {
            for kind in [1, 2] {
                for major in [0, 1, 259] {
                    for minor in [0, 3, 258] {
                        assert_eq!(
                            p.allows([kind | access << 16, major, minor]),
                            kind == 2 && major == 1 && minor == 3 && access & !3 == 0
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn scalar_skb_load_has_real_identity_but_cannot_bypass_device_type() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        let fd = v.bpf_load_program(8, &constant(1)).unwrap();
        assert_eq!(
            &v.bpf_program_identity(fd).unwrap()[..4],
            &8u32.to_le_bytes()
        );
        assert!(v.bpf_program(fd).unwrap().allows([0; 3]));
        let context = [insn(0x61, 0, 1, 0, 0), insn(0x95, 0, 0, 0, 0)].concat();
        assert_eq!(v.bpf_load_program(8, &context), Err(Errno(22)));
        let group = v.open_at(AT_FDCWD, b"/sys/fs/cgroup", O_PATH, 0).unwrap();
        assert_eq!(v.bpf_attach_device(group, fd, 2, 0), Err(Errno(22)));
    }
    #[test]
    fn attachments_survive_close_replace_atomically_and_follow_membership() {
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
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/a", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/a/b", 0o755).unwrap();
        let parent = v.open_at(AT_FDCWD, b"/sys/fs/cgroup/a", O_PATH, 0).unwrap();
        let child = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/b", O_PATH, 0)
            .unwrap();
        let deny = v.bpf_load_device(&constant(0)).unwrap();
        let allow = v.bpf_load_device(&constant(1)).unwrap();
        v.bpf_attach_device(parent, deny, 2, 0).unwrap();
        let (_, ids) = v.bpf_query_device(parent, false).unwrap();
        v.close(deny).unwrap();
        let deny = v.bpf_get_fd(ids[0]).unwrap();
        assert_eq!(v.bpf_query_device(child, true).unwrap(), (0, ids.clone()));
        v.open_at(AT_FDCWD, b"/dev/null", 2, 0).unwrap(); // root unaffected
        let procs = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/b/cgroup.procs", 1, 0)
            .unwrap();
        let authority = v.device_access();
        assert!(authority.check(0o20666, 0x103, 2).is_ok());
        v.write(procs, b"0").unwrap();
        assert_eq!(authority.check(0o20666, 0x103, 2), Err(Errno(1)));
        assert_eq!(v.open_at(AT_FDCWD, b"/dev/null", 0, 0), Err(Errno(1)));
        let path = v.open_at(AT_FDCWD, b"/dev/null", O_PATH, 0).unwrap();
        let fds = v.fd_snapshot();
        v.pseudo.borrow_mut().runtime.processes[0].fds = fds;
        assert_eq!(
            v.open_at(AT_FDCWD, format!("/proc/self/fd/{path}").as_bytes(), 0, 0),
            Err(Errno(1))
        );
        assert_eq!(
            v.mknod_at(AT_FDCWD, b"/bpf-null", 0o20666, 0x103),
            Err(Errno(1))
        );
        v.bpf_attach_device(child, allow, 2, 0).unwrap(); // cannot override parent
        assert_eq!(v.open_at(AT_FDCWD, b"/dev/null", 0, 0), Err(Errno(1)));
        v.bpf_attach_device(parent, allow, 6, deny).unwrap();
        assert!(authority.check(0o20666, 0x103, 2).is_ok());
        assert!(v.open_at(AT_FDCWD, b"/dev/null", 2, 0).is_ok());
        v.close(deny).unwrap();
        assert_eq!(v.bpf_get_fd(ids[0]), Err(Errno(2)));
        v.bpf_detach_device(child, allow).unwrap();
        v.bpf_detach_device(parent, allow).unwrap();
        assert!(v.bpf_query_device(child, true).unwrap().1.is_empty());
        v.bpf_attach_device(parent, allow, 0, 0).unwrap();
        assert_eq!(v.bpf_attach_device(child, allow, 2, 0), Err(Errno(1)));
    }
    #[test]
    fn registry_quota_reclaims_dead_programs() {
        let mut registry = Registry::default();
        let mut programs = Vec::new();
        for _ in 0..MAX_PROGRAMS {
            programs.push(registry.publish(15, verify(&constant(1)).unwrap()).unwrap());
        }
        assert!(matches!(
            registry.publish(15, verify(&constant(1)).unwrap()),
            Err(Errno(28))
        ));
        programs.pop();
        assert!(registry.publish(15, verify(&constant(1)).unwrap()).is_ok());
    }
    #[test]
    fn worker_program_lease_keeps_identity_and_releases_registry_quota() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Program>();
        let mut v = Vfs::default();
        let fd = v.bpf_load_device(&constant(1)).unwrap();
        let program = v.bpf_program(fd).unwrap();
        let id = program.id;
        let weak = Arc::downgrade(&program);
        let (released, release) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            for context in [[1, 1, 3], [2, 8, 0], [u32::MAX; 3]] {
                assert!(program.allows(context));
            }
            release
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            drop(program);
        });
        v.close(fd).unwrap();
        let reopened = v.bpf_get_fd(id).unwrap();
        assert_eq!(v.bpf_program(reopened).unwrap().id, id);
        v.close(reopened).unwrap();
        let mut others = Vec::new();
        for _ in 1..MAX_PROGRAMS {
            others.push(v.bpf_load_device(&constant(0)).unwrap());
        }
        assert_eq!(v.bpf_load_device(&constant(0)), Err(Errno(28)));
        released.send(()).unwrap();
        worker.join().unwrap();
        assert!(weak.upgrade().is_none());
        assert_eq!(v.bpf_get_fd(id), Err(Errno(2)));
        assert!(v.bpf_load_device(&constant(0)).is_ok());
    }
}
