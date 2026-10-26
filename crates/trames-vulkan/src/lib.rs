// SPDX-License-Identifier: GPL-3.0-or-later
//! Experimental Vulkan compute, graphics and native display over an independent NativeCall.
pub const PROFILE: u64 = 0x0001_0006;
pub const AUXV_KEY: u64 = 0x5452_0008;
mod backend;
pub use backend::{Backend, Invocation, TransferMetrics};
mod context;
pub use context::Context;
mod budget;
mod display;
mod task;
pub use budget::Budget;
pub use display::Display;
