// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux task capabilities in the guest's initial user namespace.
//! These masks never confer authority over host objects or credentials.
use crate::{Errno, Result};

pub const CHOWN: u32 = 0;
pub const DAC_OVERRIDE: u32 = 1;
pub const DAC_READ_SEARCH: u32 = 2;
pub const FOWNER: u32 = 3;
pub const FSETID: u32 = 4;
pub const KILL: u32 = 5;
pub const SETGID: u32 = 6;
pub const SETUID: u32 = 7;
pub const SETPCAP: u32 = 8;
pub const NET_ADMIN: u32 = 12;
pub const NET_RAW: u32 = 13;
pub const SYS_CHROOT: u32 = 18;
pub const SYS_PTRACE: u32 = 19;
pub const SYS_ADMIN: u32 = 21;
pub const SYS_NICE: u32 = 23;
pub const NET_BIND_SERVICE: u32 = 10;
pub const SYS_RESOURCE: u32 = 24;
pub const MKNOD: u32 = 27;
pub const SYSLOG: u32 = 34;
pub const LAST: u32 = 40;
pub const ALL: u64 = (1 << (LAST + 1)) - 1;
const FS: u64 = (1 << CHOWN)
    | (1 << DAC_OVERRIDE)
    | (1 << DAC_READ_SEARCH)
    | (1 << FOWNER)
    | (1 << FSETID)
    | (1 << 9)
    | (1 << 27)
    | (1 << 32);
pub const NOROOT: u32 = 1;
pub const NO_SETUID_FIXUP: u32 = 4;
const KEEP_CAPS: u32 = 16;
const NO_AMBIENT_RAISE: u32 = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub bounding: u64,
    pub ambient: u64,
    pub securebits: u32,
    pub no_new_privs: bool,
}
impl Default for Capabilities {
    fn default() -> Self {
        Self::for_uid(0)
    }
}
impl Capabilities {
    pub fn for_uid(uid: u32) -> Self {
        Self {
            effective: if uid == 0 { ALL } else { 0 },
            permitted: if uid == 0 { ALL } else { 0 },
            inheritable: 0,
            bounding: ALL,
            ambient: 0,
            securebits: 0,
            no_new_privs: false,
        }
    }
    pub fn has(&self, cap: u32) -> bool {
        cap <= LAST && self.effective & (1 << cap) != 0
    }
    pub fn set(&mut self, effective: u64, permitted: u64, inheritable: u64) -> Result<()> {
        let (effective, permitted, inheritable) =
            (effective & ALL, permitted & ALL, inheritable & ALL);
        if effective & !permitted != 0
            || permitted & !self.permitted != 0
            || inheritable & !(self.inheritable | self.bounding) != 0
            || (!self.has(SETPCAP) && inheritable & !(self.inheritable | self.permitted) != 0)
        {
            return Err(Errno(1));
        }
        self.effective = effective;
        self.permitted = permitted;
        self.inheritable = inheritable;
        self.ambient &= permitted & inheritable;
        Ok(())
    }
    pub fn fsuid_changed(&mut self, old: u32, new: u32) {
        if self.securebits & NO_SETUID_FIXUP != 0 {
            return;
        }
        if old == 0 && new != 0 {
            self.effective &= !FS;
        }
        if old != 0 && new == 0 {
            self.effective |= self.permitted & FS;
        }
    }
    pub fn uids_changed(&mut self, old: [u32; 3], new: [u32; 3]) {
        if self.securebits & NO_SETUID_FIXUP != 0 {
            return;
        }
        if old.contains(&0) && !new.contains(&0) {
            if self.securebits & KEEP_CAPS == 0 {
                self.permitted = 0;
            }
            self.effective = 0;
            self.ambient = 0;
        }
        if old[1] == 0 && new[1] != 0 {
            self.effective = 0;
        }
        if old[1] != 0 && new[1] == 0 {
            self.effective = self.permitted;
        }
    }
    /// File capabilities are not yet supported. Apply ordinary/set-ID ELF rules.
    pub fn exec(&mut self, uid: u32, euid: u32, privileged: bool) {
        if privileged {
            self.ambient = 0;
        }
        let root = self.securebits & NOROOT == 0 && (uid == 0 || euid == 0);
        let mut permitted = self.ambient;
        if root {
            permitted |= self.inheritable | self.bounding;
        }
        if self.no_new_privs {
            permitted &= self.permitted;
        }
        self.permitted = permitted;
        self.effective = if root && euid == 0 {
            permitted
        } else {
            self.ambient
        };
        self.securebits &= !KEEP_CAPS;
    }
    pub fn prctl(&mut self, a: [u64; 6]) -> Result<u64> {
        let cap_bit = |cap: u64| {
            if cap <= LAST as u64 {
                Ok(1u64 << cap)
            } else {
                Err(Errno(22))
            }
        };
        match a[0] {
            7 => Ok(u64::from(self.securebits & KEEP_CAPS != 0)),
            8 => {
                if a[1] > 1 {
                    return Err(Errno(22));
                }
                if self.securebits & (KEEP_CAPS << 1) != 0 {
                    return Err(Errno(1));
                }
                self.securebits = (self.securebits & !KEEP_CAPS) | (a[1] as u32 * KEEP_CAPS);
                Ok(0)
            }
            23 => Ok(u64::from(self.bounding & cap_bit(a[1])? != 0)),
            24 => {
                if !self.has(SETPCAP) {
                    return Err(Errno(1));
                }
                self.bounding &= !cap_bit(a[1])?;
                Ok(0)
            }
            27 => Ok(self.securebits as u64),
            28 => {
                let value = a[1] as u32;
                let locks = self.securebits & 0xaa;
                if !self.has(SETPCAP)
                    || a[1] > 255
                    || value & locks != locks
                    || (value ^ self.securebits) & (locks >> 1) != 0
                {
                    return Err(Errno(1));
                }
                self.securebits = value;
                Ok(0)
            }
            38 | 39 => {
                if a[2..5] != [0; 3] || a[1] != u64::from(a[0] == 38) {
                    return Err(Errno(22));
                }
                if a[0] == 38 {
                    self.no_new_privs = true;
                    Ok(0)
                } else {
                    Ok(u64::from(self.no_new_privs))
                }
            }
            47 => {
                if a[3] != 0 || a[4] != 0 {
                    return Err(Errno(22));
                }
                if a[1] == 4 {
                    if a[2] != 0 {
                        return Err(Errno(22));
                    }
                    self.ambient = 0;
                    return Ok(0);
                }
                let bit = cap_bit(a[2])?;
                match a[1] {
                    1 => return Ok(u64::from(self.ambient & bit != 0)),
                    2 => {
                        if self.permitted & self.inheritable & bit == 0
                            || self.securebits & NO_AMBIENT_RAISE != 0
                        {
                            return Err(Errno(1));
                        }
                        self.ambient |= bit;
                    }
                    3 => self.ambient &= !bit,
                    _ => return Err(Errno(22)),
                }
                Ok(0)
            }
            _ => Err(Errno(22)),
        }
    }
}
