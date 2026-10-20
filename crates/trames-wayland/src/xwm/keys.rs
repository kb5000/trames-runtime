// SPDX-License-Identifier: GPL-3.0-or-later
//! XIM commits and XTEST keyboard events use one X11 connection, preserving
//! text/navigation ordering without synchronizing two independent transports.
use super::*;
use std::collections::BTreeSet;
use x11rb::protocol::xtest;
#[derive(Default)]
pub(super) struct Keys {
    held: BTreeSet<u8>,
    modifiers: u32,
}
impl Keys {
    fn emit(&mut self, c: &RustConnection, key: u8, pressed: bool) -> Result<()> {
        let changed = if pressed {
            self.held.insert(key)
        } else {
            self.held.remove(&key)
        };
        if changed {
            xtest::fake_input(
                c,
                if pressed {
                    KEY_PRESS_EVENT
                } else {
                    KEY_RELEASE_EVENT
                },
                key,
                CURRENT_TIME,
                NONE,
                0,
                0,
                0,
            )?;
        }
        Ok(())
    }
    pub fn key(
        &mut self,
        c: &RustConnection,
        key: u32,
        pressed: bool,
        modifiers: u32,
    ) -> Result<()> {
        if key > 247 {
            return Ok(());
        }
        for (mask, code) in [(1, 50), (4, 37), (8, 64), (64, 133)] {
            self.emit(c, code, modifiers & mask != 0)?;
        }
        if (self.modifiers ^ modifiers) & 2 != 0 {
            self.emit(c, 66, true)?;
            self.emit(c, 66, false)?;
        }
        self.modifiers = modifiers;
        if ![29, 97, 42, 54, 56, 100, 125, 126, 58].contains(&key) {
            self.emit(c, (key + 8) as u8, pressed)?;
        }
        Ok(())
    }
    pub fn release(&mut self, c: &RustConnection) -> Result<()> {
        for key in self.held.clone() {
            self.emit(c, key, false)?;
        }
        self.modifiers &= 2;
        Ok(())
    }
}
