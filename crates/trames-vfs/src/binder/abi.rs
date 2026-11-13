// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux v6.12 include/uapi/linux/android/binder.h, 64-bit little-endian ABI.
//! Guest words are decoded explicitly; no host C layout or guest references.
pub const fn io(direction: u32, group: u8, number: u32, size: u32) -> u32 {
    direction << 30 | size << 16 | (group as u32) << 8 | number
}
pub const WRITE_READ: u32 = io(3, b'b', 1, 48);
pub const SET_MAX_THREADS: u32 = io(1, b'b', 5, 4);
pub const SET_CONTEXT_MGR: u32 = io(1, b'b', 7, 4);
pub const THREAD_EXIT: u32 = io(1, b'b', 8, 4);
pub const VERSION: u32 = io(3, b'b', 9, 4);
pub const SET_CONTEXT_MGR_EXT: u32 = io(1, b'b', 13, 24);
pub const GET_NODE_DEBUG: u32 = io(3, b'b', 11, 24);
pub const GET_NODE_INFO: u32 = io(3, b'b', 12, 24);
pub const GET_EXTENDED_ERROR: u32 = io(3, b'b', 17, 12);
pub const TRANSACTION: u32 = io(1, b'c', 0, 64);
pub const REPLY: u32 = io(1, b'c', 1, 64);
pub const FREE_BUFFER: u32 = io(1, b'c', 3, 8);
pub const INCREFS: u32 = io(1, b'c', 4, 4);
pub const ACQUIRE: u32 = io(1, b'c', 5, 4);
pub const RELEASE: u32 = io(1, b'c', 6, 4);
pub const DECREFS: u32 = io(1, b'c', 7, 4);
pub const INCREFS_DONE: u32 = io(1, b'c', 8, 16);
pub const ACQUIRE_DONE: u32 = io(1, b'c', 9, 16);
pub const REGISTER_LOOPER: u32 = io(0, b'c', 11, 0);
pub const ENTER_LOOPER: u32 = io(0, b'c', 12, 0);
pub const EXIT_LOOPER: u32 = io(0, b'c', 13, 0);
pub const REQUEST_DEATH: u32 = io(1, b'c', 14, 12);
pub const CLEAR_DEATH: u32 = io(1, b'c', 15, 12);
pub const DEAD_DONE: u32 = io(1, b'c', 16, 8);
pub const TRANSACTION_SG: u32 = io(1, b'c', 17, 72);
pub const REPLY_SG: u32 = io(1, b'c', 18, 72);
pub const BR_TRANSACTION: u32 = io(2, b'r', 2, 64);
pub const BR_REPLY: u32 = io(2, b'r', 3, 64);
pub const BR_DEAD_REPLY: u32 = io(0, b'r', 5, 0);
pub const BR_COMPLETE: u32 = io(0, b'r', 6, 0);
pub const BR_INCREFS: u32 = io(2, b'r', 7, 16);
pub const BR_ACQUIRE: u32 = io(2, b'r', 8, 16);
pub const BR_RELEASE: u32 = io(2, b'r', 9, 16);
pub const BR_DECREFS: u32 = io(2, b'r', 10, 16);
pub const BR_NOOP: u32 = io(0, b'r', 12, 0);
pub const BR_SPAWN: u32 = io(0, b'r', 13, 0);
pub const BR_DEAD_BINDER: u32 = io(2, b'r', 15, 8);
pub const BR_CLEAR_DEATH: u32 = io(2, b'r', 16, 8);
pub const BR_FAILED_REPLY: u32 = io(0, b'r', 17, 0);
pub const TYPE_BINDER: u32 = 0x73622a85;
pub const TYPE_WEAK_BINDER: u32 = 0x77622a85;
pub const TYPE_HANDLE: u32 = 0x73682a85;
pub const TYPE_WEAK_HANDLE: u32 = 0x77682a85;
pub const TYPE_FD: u32 = 0x66642a85;
pub const TYPE_PTR: u32 = 0x70742a85;
pub const TYPE_FDA: u32 = 0x66646185;
pub const ONE_WAY: u32 = 1;
pub const ACCEPT_FDS: u32 = 0x10;
pub const CLEAR_BUF: u32 = 0x20;
pub fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
pub fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
pub fn put(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
pub fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub fn command(command: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = command.to_le_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}
