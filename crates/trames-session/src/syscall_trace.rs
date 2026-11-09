// SPDX-License-Identifier: GPL-3.0-or-later
//! Optional diagnostics travel with the original accepted syscall. Recording a
//! completion never writes host output; queue/resource locks can only record.
use trames_engine::Cpu;

#[derive(Default)]
pub(crate) struct Trace(Option<Box<State>>);
struct State {
    enabled: bool,
    call: Option<Call>,
    line: String,
}
struct Call {
    pid: u32,
    number: u32,
    args: [u64; 6],
    result: Option<Outcome>,
    suspended: bool,
}
#[derive(Clone, Copy)]
enum Outcome {
    Return(u64),
    Replaced,
    Restarted,
}
impl Trace {
    pub fn enable(&mut self, enabled: bool) {
        if let Some(state) = &mut self.0 {
            state.enabled = enabled;
        } else if enabled {
            self.0 = Some(Box::new(State {
                enabled,
                call: None,
                line: String::with_capacity(256),
            }));
        }
    }
    /// Only called on the actual executor, outside the scheduling queue lock.
    pub fn begin(&mut self, pid: u32, number: u32, args: [u64; 6]) {
        let Some(state) = &mut self.0 else {
            return;
        };
        state.flush();
        if state.enabled && state.call.is_none() {
            state.call = Some(Call {
                pid,
                number,
                args,
                result: None,
                suspended: false,
            });
        }
    }
    pub fn begin_cpu<C: Cpu>(&mut self, pid: u32, cpu: &C) {
        if self.0.is_some() {
            self.begin(pid, cpu.x(8) as u32, std::array::from_fn(|i| cpu.x(i)));
        }
    }
    fn outcome(&mut self, outcome: Outcome) {
        if let Some(call) = self.0.as_mut().and_then(|state| state.call.as_mut()) {
            call.result = Some(outcome);
        }
    }
    pub fn record(&mut self, value: u64) {
        self.outcome(Outcome::Return(value));
    }
    pub fn replaced(&mut self) {
        self.outcome(Outcome::Replaced);
    }
    pub fn restart(&mut self) {
        self.outcome(Outcome::Restarted);
    }
    pub fn finish<C: Cpu>(&mut self, cpu: &mut C, value: u64) {
        cpu.set_x(0, value);
        self.record(value);
    }
    /// Host logging is deliberately deferred until the execution thread owns
    /// the job again; notification producers never print under resource locks.
    pub fn flush(&mut self) {
        if let Some(state) = &mut self.0 {
            state.flush();
        }
    }
    pub fn suspend(&mut self) {
        let Some(state) = &mut self.0 else {
            return;
        };
        state.flush();
        if let Some(call) = &mut state.call {
            if !call.suspended {
                call.write(&mut state.line, Outcome::Replaced);
                call.suspended = true;
            }
        }
    }
}
impl State {
    fn flush(&mut self) {
        if self.call.as_ref().is_some_and(|call| call.result.is_some()) {
            let call = self.call.take().unwrap();
            call.write(&mut self.line, call.result.unwrap());
        }
    }
}
impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Return(value) => write!(f, "{}", *value as i64),
            Self::Replaced => f.write_str("suspended/replaced"),
            Self::Restarted => f.write_str("restarted"),
        }
    }
}
impl Call {
    fn write(&self, line: &mut String, result: Outcome) {
        use std::{fmt::Write as _, io::Write as _};
        line.clear();
        // Stderr is unbuffered. Format once in the original task's reusable
        // scratch, then issue one line write instead of a host write per field.
        writeln!(
            line,
            "trames pid {} syscall {}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}) = {}",
            self.pid,
            self.number,
            self.args[0],
            self.args[1],
            self.args[2],
            self.args[3],
            self.args[4],
            self.args[5],
            result
        )
        .expect("String formatting");
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_keeps_the_accepted_call_and_requires_an_explicit_unlocked_flush() {
        let mut trace = Trace::default();
        trace.begin(1, 63, [7; 6]);
        assert!(trace.0.as_ref().is_none_or(|state| state.call.is_none()));
        trace.enable(true);
        trace.begin(2, 63, [9; 6]);
        trace.begin(2, 999, [0; 6]); // original operation is still parked
        trace.record((-4i64) as u64);
        let call = trace.0.as_ref().unwrap().call.as_ref().unwrap();
        assert_eq!((call.pid, call.number, call.args), (2, 63, [9; 6]));
        assert!(matches!(call.result, Some(Outcome::Return(v)) if v == (-4i64) as u64));
        trace.flush();
        assert!(trace.0.as_ref().is_none_or(|state| state.call.is_none()));
        trace.begin(2, 221, [3; 6]);
        trace.replaced();
        trace.flush();
        assert!(trace.0.as_ref().is_none_or(|state| state.call.is_none()));
    }
}
