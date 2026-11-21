// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest tracing request admission against the original task directory.
use super::*;

const PTRACE_TRACEME: u64 = 0;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;
const PTRACE_O_SUSPEND_SECCOMP: u64 = 1 << 21;
const PTRACE_O_MASK: u64 = 0xff | (1 << 20) | PTRACE_O_SUSPEND_SECCOMP;

impl IoRoutes {
    pub fn ptrace(&self, caller: &IoTask, args: [u64; 6]) -> Result<u64, Errno> {
        let [request, pid, addr, options, ..] = args;
        if request == PTRACE_TRACEME {
            // Success commits a tracer relationship and changes wait/exec
            // semantics. No relationship has been established at this point.
            return Err(Errno(38));
        }

        let id = self.namespace.global(pid as u32).ok_or(Errno(3))?;
        let target = self
            .directory
            .tasks(0, id)
            .into_iter()
            .next()
            .ok_or(Errno(3))?;
        if !matches!(request, PTRACE_ATTACH | PTRACE_SEIZE) {
            // Linux checks for an existing tracer relationship before decoding
            // the operation or accessing any of the caller's guest pointers.
            return Err(Errno(3));
        }
        if request == PTRACE_SEIZE {
            if addr != 0 || options & !PTRACE_O_MASK != 0 {
                return Err(Errno(5));
            }
            if options & PTRACE_O_SUSPEND_SECCOMP != 0 {
                // This runtime does not implement checkpoint/restore of seccomp.
                return Err(Errno(22));
            }
        }
        if target.tgid() == caller.tgid() || !target.live() {
            return Err(Errno(1));
        }
        let credentials = caller.credentials().read().clone();
        target.credentials().check_trace_attach(&credentials)?;
        // Keep authorized requests visibly unsupported until a live task can
        // publish and acknowledge its own tracing stop.
        Err(Errno(38))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracing_requests_resolve_the_target_before_reading_arguments() {
        let directory = Arc::new(IoDirectory::default());
        let caller = Arc::new(IoTask::default());
        let sibling = Arc::new(IoTask::default());
        directory.publish(&caller, 42, 42, 42, 1000, 1000);
        directory.publish(&sibling, 43, 42, 42, 1000, 1000);
        let routes = IoRoutes {
            directory,
            namespace: Default::default(),
            uid: 1000,
            euid: 1000,
        };
        let request = |op, pid, addr, flags| routes.ptrace(&caller, [op, pid, addr, flags, 0, 0]);
        assert_eq!(request(PTRACE_ATTACH, 99, 0, 0), Err(Errno(3)));
        assert_eq!(request(PTRACE_SEIZE, 99, 1, u64::MAX), Err(Errno(3)));
        for tid in [42, 43] {
            assert_eq!(request(PTRACE_ATTACH, tid, 0, 0), Err(Errno(1)));
            assert_eq!(request(PTRACE_SEIZE, tid, 0, 0), Err(Errno(1)));
            assert_eq!(request(PTRACE_SEIZE, tid, 1, 0), Err(Errno(5)));
            assert_eq!(request(PTRACE_SEIZE, tid, 0, 1 << 12), Err(Errno(5)));
            assert_eq!(request(0x4204, tid, u64::MAX, u64::MAX), Err(Errno(3)));
        }
    }
}
