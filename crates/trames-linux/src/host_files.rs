// SPDX-License-Identifier: GPL-3.0-or-later
//! Authorized embedding I/O on the existing disk pool. Jobs retain original
//! resources and owned host operands; no guest CPU or pointer crosses this API.
use std::sync::Arc;
pub use trames_memory::layout::{Layout as HostFileLayout, LayoutExclusive as HostFileAdmission};

pub trait HostFileTask: Send {
    /// Only an operation consuming mapped bytes requests backing admission.
    fn layout(&self) -> Option<Arc<HostFileLayout>> {
        None
    }
    fn run(self: Box<Self>, exclusive: Option<HostFileAdmission>);
    /// Closed/spawn-failed pools complete the original response, without doing
    /// blocking host I/O on the execution/control poller.
    fn fail(self: Box<Self>);
}
