// SPDX-License-Identifier: GPL-3.0-or-later
//! XIM commits and XTEST keyboard events use one X11 connection, preserving
//! text/navigation ordering without synchronizing two independent transports.
use super::*;
use std::collections::BTreeSet;
use std::io::IoSlice;
use x11rb::{
    connection::RequestConnection,
    protocol::{xinput, xkb, xtest},
};
#[derive(Clone, Copy)]
struct NativeKeyboard {
    device: u8,
    master: u8,
    event: u8,
    xkb: u8,
}
#[derive(Default)]
pub(super) struct Keys {
    held: BTreeSet<u8>,
    physical: BTreeSet<u8>,
    modifiers: u32,
    native: Option<NativeKeyboard>,
    native_state: Option<crate::KeyboardModifiers>,
    modifier_map: Vec<Vec<u8>>,
}
impl Keys {
    fn emit(&mut self, c: &RustConnection, key: u8, pressed: bool) -> Result<()> {
        let changed = if pressed {
            self.held.insert(key)
        } else {
            self.held.remove(&key)
        };
        if changed {
            let (device, event) = self.native.map_or(
                (
                    0,
                    if pressed {
                        KEY_PRESS_EVENT
                    } else {
                        KEY_RELEASE_EVENT
                    },
                ),
                |native| {
                    (
                        native.device,
                        native.event
                            + if pressed {
                                xinput::DEVICE_KEY_PRESS_EVENT
                            } else {
                                xinput::DEVICE_KEY_RELEASE_EVENT
                            },
                    )
                },
            );
            xtest::fake_input(c, event, key, CURRENT_TIME, NONE, 0, 0, device)?;
        }
        Ok(())
    }
    fn initialize_native(&mut self, c: &RustConnection) -> Result<()> {
        if self.native.is_none() {
            let extension = c
                .extension_information(xinput::X11_EXTENSION_NAME)?
                .ok_or("XInput extension unavailable")?;
            let devices = xinput::list_input_devices(c)?.reply()?;
            let device = devices
                .devices
                .iter()
                .zip(&devices.names)
                .find(|(d, n)| {
                    d.device_use == xinput::DeviceUse::IS_X_EXTENSION_KEYBOARD
                        && !n.name.windows(5).any(|s| s == b"XTEST")
                })
                .ok_or("Xwayland native keyboard unavailable")?
                .0
                .device_id;
            let master = devices
                .devices
                .iter()
                .find(|d| d.device_use == xinput::DeviceUse::IS_X_KEYBOARD)
                .ok_or("Xwayland core keyboard unavailable")?
                .device_id;
            if !xkb::use_extension(c, 1, 0)?.reply()?.supported {
                return Err("XKB unavailable".into());
            }
            let xkb = c
                .extension_information(xkb::X11_EXTENSION_NAME)?
                .ok_or("XKB unavailable")?
                .major_opcode;
            self.native = Some(NativeKeyboard {
                device,
                master,
                event: extension.first_event,
                xkb,
            });
        }
        Ok(())
    }
    fn locks(&self, c: &RustConnection, m: crate::KeyboardModifiers) -> Result<()> {
        // xcb-proto 1.x omits modLatches and treats its byte as padding. Fill
        // that public XKB-v1 field explicitly; the C oracle checks this layout.
        let native = self.native.unwrap();
        for device in [native.device, native.master] {
            let request = xkb::LatchLockStateRequest {
                device_spec: u16::from(device),
                affect_mod_locks: 255u8.into(),
                mod_locks: (m.locked as u8).into(),
                lock_group: true,
                group_lock: (m.group as u8 & 3).into(),
                affect_mod_latches: 255u8.into(),
                latch_group: true,
                group_latch: 0,
            };
            let (buffers, fds) = request.serialize(native.xkb);
            let mut bytes = buffers[0].to_vec();
            bytes[11] = m.latched as u8;
            c.send_request_without_reply(&[IoSlice::new(&bytes)], fds)?;
        }
        Ok(())
    }
    pub fn mapping(&mut self, c: &RustConnection) -> Result<()> {
        self.modifier_map.clear();
        if let Some(m) = self.native_state {
            self.native_modifiers(c, m)?;
        }
        Ok(())
    }
    pub fn native_modifiers(
        &mut self,
        c: &RustConnection,
        m: crate::KeyboardModifiers,
    ) -> Result<()> {
        self.initialize_native(c)?;
        if self.modifier_map.is_empty() {
            let map = c.get_modifier_mapping()?.reply()?;
            let count = map.keycodes.len() / 8;
            self.modifier_map = (0..8)
                .map(|i| {
                    map.keycodes[i * count..(i + 1) * count]
                        .iter()
                        .copied()
                        .filter(|k| *k != 0)
                        .collect()
                })
                .collect();
        }
        for index in 0..8 {
            let codes = self.modifier_map[index].clone();
            if m.depressed & (1 << index) == 0 {
                for code in codes {
                    if self.held.contains(&code) && !self.physical.contains(&code) {
                        self.emit(c, code, false)?;
                    }
                }
            } else if !codes.iter().any(|code| self.held.contains(code)) {
                if let Some(code) = codes.first() {
                    self.emit(c, *code, true)?;
                }
            }
        }
        self.locks(c, m)?;
        self.native_state = Some(m);
        Ok(())
    }
    pub fn raw(&mut self, c: &RustConnection, key: u32, pressed: bool) -> Result<()> {
        self.initialize_native(c)?;
        if key <= 247 {
            let code = (key + 8) as u8;
            if pressed {
                self.physical.insert(code);
            } else {
                self.physical.remove(&code);
            }
            self.emit(c, code, pressed)?;
            if self.modifier_map.iter().any(|codes| codes.contains(&code)) {
                if let Some(m) = self.native_state {
                    self.locks(c, m)?;
                }
            }
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
        self.physical.clear();
        for key in self.held.clone() {
            self.emit(c, key, false)?;
        }
        self.modifiers &= 2;
        Ok(())
    }
}
