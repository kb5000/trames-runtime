// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared guest terminal line discipline; queues are bounded to 64 KiB.
use crate::Errno;
use std::collections::VecDeque;

const CANON_PAYLOAD: usize = 4095;
const IUTF8: u16 = 0x4000;
const IEXTEN: u32 = 0x8000;
const ECHO: u32 = 8;
const ECHOE: u32 = 16;

#[derive(Clone)]
pub struct Terminal {
    pub attributes: [u8; 36],
    pub window: [u8; 8],
    pub foreground: u32,
    pub session: u32,
    speeds: [u32; 2],
    column: usize,
    edit: Vec<u8>,
    packets: VecDeque<VecDeque<u8>>,
    queued_charge: usize,
    pub echo: Vec<u8>,
    pub eof: bool,
    pub output_queue: VecDeque<u8>,
    pub flow_stopped: bool,
    pub input_epoch: u64,
    pub input_space_epoch: u64,
    pub output_epoch: u64,
    pub output_space_epoch: u64,
}
impl Default for Terminal {
    fn default() -> Self {
        let mut attributes = [0; 36];
        attributes[0..4].copy_from_slice(&0x500u32.to_le_bytes());
        attributes[4..8].copy_from_slice(&5u32.to_le_bytes());
        attributes[8..12].copy_from_slice(&0xbfu32.to_le_bytes());
        attributes[12..16].copy_from_slice(&0x8a3bu32.to_le_bytes());
        attributes[17..36].copy_from_slice(&[
            3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0,
        ]);
        let mut window = [0; 8];
        window[0..2].copy_from_slice(&24u16.to_le_bytes());
        window[2..4].copy_from_slice(&80u16.to_le_bytes());
        Self {
            attributes,
            window,
            foreground: 1,
            session: 1,
            speeds: [38400; 2],
            column: 0,
            edit: Vec::new(),
            packets: VecDeque::new(),
            queued_charge: 0,
            echo: Vec::new(),
            eof: false,
            output_queue: VecDeque::new(),
            flow_stopped: false,
            input_epoch: 0,
            input_space_epoch: 0,
            output_epoch: 0,
            output_space_epoch: 0,
        }
    }
}
impl Terminal {
    fn echo_bytes(&mut self, bytes: &[u8]) {
        let take = bytes.len().min(65536 - self.echo.len());
        self.echo.extend_from_slice(&bytes[..take]);
    }
    pub fn drain_output(&mut self, maximum: usize) -> Vec<u8> {
        let take = maximum.min(self.output_queue.len());
        if take != 0 {
            self.output_space_epoch = self.output_space_epoch.wrapping_add(1);
        }
        self.output_queue.drain(..take).collect()
    }
    pub fn input_capacity(&self) -> usize {
        65536 - self.edit.len() - self.queued_charge
    }
    pub fn readable(&self) -> bool {
        !self.packets.is_empty() || self.eof
    }
    pub fn flush_input(&mut self) {
        self.input_space_epoch = self.input_space_epoch.wrapping_add(1);
        self.edit.clear();
        self.packets.clear();
        self.queued_charge = 0;
    }
    pub fn queue_output(&mut self, bytes: &[u8]) -> Result<usize, Errno> {
        let flags = self.attributes[4];
        let mut count = 0;
        if flags & 1 == 0 {
            count = bytes.len().min(65536 - self.output_queue.len());
            self.output_queue.extend(&bytes[..count]);
        } else {
            let utf8 = self.iflag() & IUTF8 != 0;
            for &byte in bytes {
                let mut column = self.column;
                let mut scratch = [byte];
                let out = Self::output_char(&mut scratch, flags, utf8, &mut column);
                if out.len() > 65536 - self.output_queue.len() {
                    break;
                }
                self.output_queue.extend(out);
                self.column = column;
                count += 1;
            }
        }
        if !bytes.is_empty() && count == 0 {
            Err(Errno(11))
        } else {
            if count != 0 {
                self.output_epoch = self.output_epoch.wrapping_add(1);
            }
            Ok(count)
        }
    }
    pub fn lflag(&self) -> u32 {
        u32::from_le_bytes(self.attributes[12..16].try_into().expect("termios"))
    }
    pub fn available(&self) -> usize {
        self.packets.front().map_or(0, VecDeque::len)
    }
    pub fn resize(&mut self, rows: u16, columns: u16) {
        self.window[0..2].copy_from_slice(&rows.to_le_bytes());
        self.window[2..4].copy_from_slice(&columns.to_le_bytes());
    }
    fn iflag(&self) -> u16 {
        u16::from_le_bytes([self.attributes[0], self.attributes[1]])
    }
    fn input_char(&self, raw: u8) -> Option<u8> {
        let flags = self.iflag();
        match raw {
            b'\r' if flags & 0x80 != 0 => None,
            b'\r' if flags & 0x100 != 0 => Some(b'\n'),
            b'\n' if flags & 0x40 != 0 => Some(b'\r'),
            _ => Some(raw),
        }
    }
    fn delimiter(&self, c: u8) -> bool {
        c == b'\n'
            || c != 0
                && (c == self.attributes[28]
                    || self.lflag() & IEXTEN != 0 && c == self.attributes[33])
    }
    fn commit_line(&mut self) {
        self.queued_charge += self.edit.len().max(1);
        self.packets
            .push_back(std::mem::take(&mut self.edit).into());
    }
    fn erase(&mut self, word: bool) {
        let visible = self.lflag() & (ECHO | ECHOE) == ECHO | ECHOE;
        let utf8 = self.iflag() & IUTF8 != 0;
        let mut in_word = false;
        while let Some(mut start) = self.edit.len().checked_sub(1) {
            if utf8 {
                while self.edit[start] & 0xc0 == 0x80 {
                    if start == 0 {
                        return;
                    }
                    start -= 1;
                }
            }
            let byte = self.edit[start];
            let part = byte.is_ascii_alphanumeric() || byte == b'_' || !byte.is_ascii();
            if word && in_word && !part {
                break;
            }
            in_word |= part;
            self.edit.truncate(start);
            if visible {
                self.echo_bytes(b"\x08 \x08");
            }
            if !word {
                break;
            }
        }
    }
    pub fn termios2(&self) -> [u8; 44] {
        let mut out = [0; 44];
        out[..36].copy_from_slice(&self.attributes);
        out[36..40].copy_from_slice(&self.speeds[0].to_le_bytes());
        out[40..].copy_from_slice(&self.speeds[1].to_le_bytes());
        out
    }
    pub fn set_attributes(
        &mut self,
        attr: [u8; 36],
        speeds: Option<[u32; 2]>,
        flush: bool,
    ) -> Result<(), Errno> {
        if attr[22] != 0 {
            return Err(Errno(95));
        }
        let was_canonical = self.lflag() & 2 != 0;
        self.attributes = attr;
        let cflag = u32::from_le_bytes(attr[8..12].try_into().unwrap());
        let requested = speeds.unwrap_or(self.speeds);
        let output = baud_rate(cflag, requested[1]);
        let input = if (cflag >> 16) & 0x100f == 0 {
            output
        } else {
            baud_rate(cflag >> 16, requested[0])
        };
        self.speeds = [input, output];
        if flush {
            self.flush_input();
        } else if was_canonical != (self.lflag() & 2 != 0) {
            let mut pending: VecDeque<u8> = self.packets.drain(..).flatten().collect();
            pending.extend(self.edit.drain(..));
            self.queued_charge = 0;
            if !pending.is_empty() {
                if was_canonical || pending.len() <= CANON_PAYLOAD {
                    self.queued_charge = pending.len();
                    self.packets.push_back(pending);
                } else {
                    // The first input-buffer load becomes readable immediately.
                    // Remaining bytes enter the new canonical editing line.
                    let tail = pending.split_off(CANON_PAYLOAD);
                    self.queued_charge = pending.len();
                    self.packets.push_back(pending);
                    for c in tail {
                        if self.delimiter(c) {
                            self.edit.push(c);
                            self.commit_line();
                        } else if c != 0 && c == self.attributes[21] {
                            self.commit_line();
                        } else if self.edit.len() < CANON_PAYLOAD {
                            self.edit.push(c);
                        }
                    }
                }
            }
        }
        self.input_epoch = self.input_epoch.wrapping_add(1);
        self.input_space_epoch = self.input_space_epoch.wrapping_add(1);
        Ok(())
    }
    /// Same CR/flow-control precedence used by input; no state is modified.
    pub fn input_signal(&self, raw: u8) -> Option<u32> {
        if self.lflag() & 1 == 0 {
            return None;
        }
        let c = self.input_char(raw)?;
        let cc = &self.attributes[17..];
        if self.attributes[1] & 4 != 0 && (c == cc[8] || c == cc[9]) {
            return None;
        }
        if c != 0 && c == cc[0] {
            Some(2)
        } else if c != 0 && c == cc[1] {
            Some(3)
        } else if c != 0 && c == cc[10] {
            Some(20)
        } else {
            None
        }
    }
    /// Input is bounded to 64 KiB; returns terminal-generated signals for the foreground group.
    pub fn input(&mut self, bytes: &[u8]) -> Vec<u32> {
        let before = (self.packets.len(), self.queued_charge);
        let mut signals = Vec::new();
        for &raw in bytes {
            if self.input_capacity() == 0 {
                break;
            }
            let Some(c) = self.input_char(raw) else {
                continue;
            };
            let local = self.lflag();
            let cc = &self.attributes[17..];
            if self.attributes[1] & 4 != 0 && c != 0 {
                if c == cc[9] {
                    self.flow_stopped = true;
                    continue;
                }
                if c == cc[8] {
                    self.flow_stopped = false;
                    continue;
                }
            }
            if local & 1 != 0 {
                let sig = self.input_signal(raw);
                if let Some(sig) = sig {
                    self.edit.clear();
                    self.packets.clear();
                    self.queued_charge = 0;
                    if local & 8 != 0 {
                        if local & 512 != 0 {
                            self.echo_bytes(&[b'^', c.wrapping_add(64)]);
                        } else {
                            self.echo_bytes(&[c]);
                        }
                        self.echo_bytes(b"\n");
                    }
                    signals.push(sig);
                    continue;
                }
            }
            if local & 2 != 0 {
                if c != 0 && (c == cc[2] || local & IEXTEN != 0 && c == cc[14]) {
                    self.erase(c != cc[2]);
                    continue;
                }
                if c == cc[3] && c != 0 {
                    self.edit.clear();
                    if local & 32 != 0 {
                        self.echo_bytes(b"\n");
                    }
                    continue;
                }
                if c == cc[4] && c != 0 {
                    self.commit_line();
                    continue;
                }
                let delimiter = self.delimiter(c);
                if delimiter || self.edit.len() < CANON_PAYLOAD {
                    self.edit.push(c);
                }
                if local & 8 != 0 || (c == b'\n' && local & 64 != 0) {
                    self.echo_bytes(&[c]);
                }
                if delimiter {
                    self.commit_line();
                }
            } else {
                if local & 8 != 0 {
                    self.echo_bytes(&[c]);
                }
                if self.packets.back().is_none_or(VecDeque::is_empty) {
                    self.packets.push_back(VecDeque::new());
                }
                self.packets.back_mut().expect("packet").push_back(c);
                self.queued_charge += 1;
            }
        }
        if before != (self.packets.len(), self.queued_charge) {
            self.input_epoch = self.input_epoch.wrapping_add(1);
        }
        signals
    }
    pub fn read(&mut self, count: usize) -> Result<Vec<u8>, Errno> {
        if count == 0 {
            return Ok(Vec::new());
        }
        if self.lflag() & 2 == 0 && !self.eof {
            let minimum = self.attributes[23] as usize;
            if minimum == 0 && self.packets.is_empty() {
                return Ok(Vec::new());
            }
            if self.available() < minimum.min(count) {
                return Err(Errno(11));
            }
        }
        let Some(p) = self.packets.front_mut() else {
            return if self.eof {
                Ok(Vec::new())
            } else {
                Err(Errno(11))
            };
        };
        let take = count.min(p.len());
        self.input_space_epoch = self.input_space_epoch.wrapping_add(1);
        let bytes = p.drain(..take).collect();
        self.queued_charge -= take.max(1);
        if p.is_empty() {
            self.packets.pop_front();
        }
        Ok(bytes)
    }
    fn output_char<'a>(
        byte: &'a mut [u8; 1],
        flags: u8,
        utf8: bool,
        column: &mut usize,
    ) -> &'a [u8] {
        match byte[0] {
            b'\n' if flags & 4 != 0 => {
                *column = 0;
                return b"\r\n";
            }
            b'\n' if flags & 32 != 0 => *column = 0,
            b'\r' if flags & 16 != 0 && *column == 0 => return b"",
            b'\r' if flags & 8 != 0 => {
                if flags & 32 != 0 {
                    *column = 0;
                }
                return b"\n";
            }
            b'\r' => *column = 0,
            b'\t' => *column = column.saturating_add(8 - (*column & 7)),
            8 => *column = column.saturating_sub(1),
            c if !c.is_ascii_control() => {
                if !utf8 || c & 0xc0 != 0x80 {
                    *column = column.saturating_add(1);
                }
                if flags & 2 != 0 {
                    byte[0] = c.to_ascii_uppercase();
                }
            }
            _ => {}
        }
        byte
    }
    pub fn output(&self, bytes: &[u8]) -> Vec<u8> {
        if self.attributes[4] & 1 == 0 {
            return bytes.to_vec();
        }
        let mut out = Vec::with_capacity(bytes.len());
        let mut column = self.column;
        for &c in bytes {
            out.extend_from_slice(Self::output_char(
                &mut [c],
                self.attributes[4],
                self.iflag() & IUTF8 != 0,
                &mut column,
            ));
        }
        out
    }
}

fn baud_rate(flags: u32, custom: u32) -> u32 {
    const RATES: [u32; 31] = [
        0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600,
        115200, 230400, 460800, 500000, 576000, 921600, 1000000, 1152000, 1500000, 2000000,
        2500000, 3000000, 3500000, 4000000,
    ];
    match flags & 0x100f {
        0x1000 => custom,
        code if code < 16 => RATES[code as usize],
        code => RATES[(15 + (code & 15)) as usize],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_lines_erase_eof_and_control_signals() {
        let mut t = Terminal::default();
        assert!(t.input(b"ab\x7fc\r").is_empty());
        assert_eq!(t.read(10).unwrap(), b"ac\n");
        assert_eq!(t.read(1), Err(Errno(11)));
        t.input(b"tail\x04");
        assert_eq!(t.read(10).unwrap(), b"tail");
        t.input(b"\x04");
        assert!(t.read(10).unwrap().is_empty());
        assert_eq!(t.input(b"ab\x03"), vec![2]);
        assert_eq!(t.read(10), Err(Errno(11)));
        assert_eq!(t.input(b"\x1a"), vec![20]);
    }
    #[test]
    fn raw_input_and_output_translation() {
        let mut t = Terminal::default();
        t.attributes[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert!(t.input(b"a\x03\0").is_empty());
        assert_eq!(t.read(8).unwrap(), b"a\x03\0");
        assert_eq!(t.output(b"a\nb"), b"a\r\nb");
        t.attributes[4..8].fill(0);
        assert_eq!(t.output(b"a\n"), b"a\n");
    }
    #[test]
    fn output_backpressure_preserves_a_complete_translated_character() {
        let mut t = Terminal::default();
        t.queue_output(&vec![b'x'; 65535]).unwrap();
        assert_eq!(t.queue_output(b"\n"), Err(Errno(11)));
        assert_eq!(t.output_queue.len(), 65535);
        t.output_queue.pop_front();
        assert_eq!(t.queue_output(b"\n").unwrap(), 1);
        assert_eq!(t.output_queue.len(), 65536);
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    #[test]
    fn custom_speeds_and_rejected_attributes_are_atomic() {
        let mut tty = Terminal::default();
        let mut attr = tty.attributes;
        attr[8..12].copy_from_slice(&0x100010b0u32.to_le_bytes());
        tty.set_attributes(attr, Some([57601, 31415]), false)
            .unwrap();
        assert_eq!(&tty.termios2()[36..40], &57601u32.to_le_bytes());
        assert_eq!(&tty.termios2()[40..], &31415u32.to_le_bytes());
        let before = tty.termios2();
        tty.input(b"pending");
        attr[22] = 1;
        assert_eq!(tty.set_attributes(attr, Some([1, 1]), true), Err(Errno(95)));
        assert_eq!(tty.termios2(), before);
        tty.input(b"\n");
        assert_eq!(tty.read(8).unwrap(), b"pending\n");
        attr[22] = 0;
        attr[8..12].copy_from_slice(&0xbdu32.to_le_bytes());
        tty.set_attributes(attr, None, false).unwrap();
        assert_eq!(tty.speeds, [9600; 2]);
    }
    #[test]
    fn canonical_to_raw_discards_eof_markers_and_preserves_editing_bytes() {
        let mut tty = Terminal::default();
        tty.input(b"\x04abc");
        let mut attr = tty.attributes;
        attr[12] &= !2;
        tty.set_attributes(attr, None, false).unwrap();
        assert_eq!(tty.read(12).unwrap(), b"abc");
        assert!(!tty.readable());
    }
    #[test]
    fn empty_eof_records_consume_capacity_and_read_frees_it() {
        let mut t = Terminal::default();
        t.input(&vec![4; 65536]);
        assert_eq!(t.input_capacity(), 0);
        assert_eq!(t.packets.len(), 65536);
        assert!(t.read(1).unwrap().is_empty());
        assert_eq!(t.input_capacity(), 1);
        t.flush_input();
        assert_eq!(t.input_capacity(), 65536);
    }
    #[test]
    fn raw_minimum_and_software_flow_control() {
        let mut t = Terminal::default();
        t.attributes[12..16].fill(0);
        t.attributes[23] = 2;
        t.input(b"a");
        assert_eq!(t.read(10), Err(Errno(11)));
        t.input(b"b");
        assert_eq!(t.read(10).unwrap(), b"ab");
        assert_eq!(t.input_capacity(), 65536);
        t.input(&[19]);
        assert!(t.flow_stopped);
        t.input(&[17]);
        assert!(!t.flow_stopped);
    }
}

#[cfg(test)]
mod echo_tests {
    use super::*;
    #[test]
    fn repeated_erases_cannot_grow_echo_past_the_budget() {
        let mut t = Terminal::default();
        let mut input = Vec::new();
        for _ in 0..20000 {
            input.extend([b'a', 127]);
        }
        t.input(&input);
        assert_eq!(t.echo.len(), 65536);
        assert_eq!(t.input_capacity(), 65536);
    }
}
