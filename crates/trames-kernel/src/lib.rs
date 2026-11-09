// SPDX-License-Identifier: GPL-3.0-or-later
//! Execution-independent Linux task state and scheduling policy.
//! Backend transports, decoders and product integration belong to their callers.
#![recursion_limit = "512"]
pub mod children;
pub mod completion;
pub mod family;
pub mod limits;
pub mod power;
pub mod scheduling;
pub mod signal;
pub mod task;
pub mod task_control;
pub mod task_parent;
pub mod timers;
pub mod vfork;
