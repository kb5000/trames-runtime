// SPDX-License-Identifier: GPL-3.0-or-later
//! Keep an accepted original-mm operation across its resource wait.
use super::*;
pub(super) struct Control {
    number: u32,
    args: [u64; 6],
    request: Arc<trames_memory::MmControl>,
}
impl Control {
    pub(super) fn resume(
        self: Box<Self>,
        source: &DirectSyscalls,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if let Some(value) = self.request.result() {
            return source.complete(self.number, self.args, value.map(|_| 0).map_err(Errno));
        }
        let trames_memory::MemoryError::Pending(fault) = self.request.fault(0) else {
            unreachable!()
        };
        let (number, args) = (self.number, self.args);
        source.park_input(
            file_input::Accepted::MmControl(self),
            fault,
            number,
            args,
            pid,
            target,
        )
    }
}
impl DirectSyscalls {
    pub fn start_mm_control(
        &self,
        number: u32,
        args: [u64; 6],
        pid: u32,
        target: &Weak<dyn IoWake>,
        admit: impl FnOnce() -> Result<Arc<trames_memory::MmControl>, Errno>,
    ) -> IoAttempt {
        match admit() {
            Err(error) => self.complete(number, args, Err(error)),
            Ok(request) => Box::new(Control {
                number,
                args,
                request,
            })
            .resume(self, pid, target),
        }
    }
}
