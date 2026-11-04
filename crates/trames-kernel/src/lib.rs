// SPDX-License-Identifier: GPL-3.0-or-later
//! Execution-independent Linux task state and scheduling policy.
//! Backend transports, decoders and product integration belong to their callers.
pub mod limits;
pub mod scheduling;
pub mod signal;
pub mod timers;
