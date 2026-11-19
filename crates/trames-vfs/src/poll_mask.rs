// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux readiness bits shared by poll, epoll and io_uring.
pub const READ_NORMAL: u16 = 0x001 | 0x040;
pub const WRITE_NORMAL: u16 = 0x004 | 0x100;
pub const SUPPORTED: u32 = 0x201f | 0x040 | 0x100;

/// A source may drain and refill between observations. Its per-direction
/// generation then supplies a new edge even when the visible bits match.
pub fn new_edges(ready: u16, previous: u16, epoch: [u64; 2], last: [u64; 2]) -> u16 {
    let mut edges = ready & !previous;
    if epoch[0] != last[0] {
        edges |= ready & (READ_NORMAL | 2);
    }
    if epoch[1] != last[1] {
        edges |= ready & WRITE_NORMAL;
    }
    edges
}
