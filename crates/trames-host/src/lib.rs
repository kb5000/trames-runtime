// SPDX-License-Identifier: GPL-3.0-or-later
//! Portable host protocol adapters. CPU engines and product lifetime stay with callers.
//! Existing host waits and guest byte resources carry all traffic; no service thread.
pub mod console;
pub mod exec;
