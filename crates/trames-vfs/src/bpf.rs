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
pub(super) struct Program {
    pub id: u32,
    code: Vec<Insn>,
}
#[derive(Default)]
pub(super) struct Registry {
    next: u32,
    programs: BTreeMap<u32, Weak<Program>>,
}
impl Registry {
    fn load(&mut self, bytes: &[u8]) -> Result<Rc<Program>> {
        let code = verify(bytes)?;
        self.programs.retain(|_, p| p.strong_count() != 0);
        if self.programs.len() >= MAX_PROGRAMS {
            return Err(Errno(28));
        }
        let id = self.next.checked_add(1).ok_or(Errno(28))?;
        let p = Rc::new(Program { id, code });
        self.next = id;
        self.programs.insert(id, Rc::downgrade(&p));
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
        self.bpf_authorized()?;
        self.available(0)?;
        let program = self.cgroups.borrow_mut().bpf.load(code)?;
        self.anonymous(O_CLOEXEC, events::Anonymous::Bpf(program))
    }
    pub fn bpf_get_fd(&mut self, id: u32) -> Result<u32> {
        self.bpf_authorized()?;
        let program = self
            .cgroups
            .borrow()
            .bpf
            .programs
            .get(&id)
            .and_then(Weak::upgrade)
            .ok_or(Errno(2))?;
        self.anonymous(O_CLOEXEC, events::Anonymous::Bpf(program))
    }
    pub(super) fn bpf_program(&self, fd: u32) -> Result<Rc<Program>> {
        let o = self.descriptor(fd)?.open.borrow();
        match &o.anonymous {
            Some(events::Anonymous::Bpf(p)) if o.flags & O_PATH == 0 => Ok(p.clone()),
            _ => Err(Errno(22)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        v.cgroup_fork(1, 1, 1);
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
        v.write(procs, b"0").unwrap();
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
            programs.push(registry.load(&constant(1)).unwrap());
        }
        assert!(matches!(registry.load(&constant(1)), Err(Errno(28))));
        programs.pop();
        assert!(registry.load(&constant(1)).is_ok());
    }
}
