// SPDX-License-Identifier: GPL-3.0-or-later
#[derive(Clone, Copy, Debug, Default)]
pub struct Info {
    pub sender: u32,
    pub uid: u32,
    pub status: i32,
    pub code: i32,
    pub timer: Option<(i32, i32, u64)>,
    pub fault: Option<u64>,
}

pub fn write_siginfo(out: &mut [u8], sig: u32, info: Info) {
    out[..128].fill(0);
    out[..4].copy_from_slice(&sig.to_le_bytes());
    out[8..12].copy_from_slice(&info.code.to_le_bytes());
    if let Some(address) = info.fault {
        out[16..24].copy_from_slice(&address.to_le_bytes());
        if sig == 31 && info.code == 1 {
            out[4..8].copy_from_slice(&info.sender.to_le_bytes());
            out[24..28].copy_from_slice(&info.status.to_le_bytes());
            out[28..32].copy_from_slice(&info.uid.to_le_bytes());
        }
    } else if let Some((id, overrun, value)) = info.timer {
        out[16..20].copy_from_slice(&id.to_le_bytes());
        out[20..24].copy_from_slice(&overrun.to_le_bytes());
        out[24..32].copy_from_slice(&value.to_le_bytes());
    } else {
        out[16..20].copy_from_slice(&info.sender.to_le_bytes());
        out[20..24].copy_from_slice(&info.uid.to_le_bytes());
        out[24..28].copy_from_slice(&info.status.to_le_bytes());
    }
}
pub fn write_signalfd(sig: u32, info: Info) -> [u8; 128] {
    let mut out = [0; 128];
    out[..4].copy_from_slice(&sig.to_le_bytes());
    out[8..12].copy_from_slice(&info.code.to_le_bytes());
    if let Some((id, overrun, value)) = info.timer {
        out[24..28].copy_from_slice(&id.to_le_bytes());
        out[32..36].copy_from_slice(&overrun.to_le_bytes());
        out[44..48].copy_from_slice(&(value as u32).to_le_bytes());
        out[48..56].copy_from_slice(&value.to_le_bytes());
    } else if let Some(address) = info.fault {
        out[72..80].copy_from_slice(&address.to_le_bytes());
        if sig == 31 && info.code == 1 {
            out[4..8].copy_from_slice(&info.sender.to_le_bytes());
            out[84..88].copy_from_slice(&info.status.to_le_bytes());
            out[88..96].copy_from_slice(&address.to_le_bytes());
            out[96..100].copy_from_slice(&info.uid.to_le_bytes());
        }
    } else {
        out[12..16].copy_from_slice(&info.sender.to_le_bytes());
        out[16..20].copy_from_slice(&info.uid.to_le_bytes());
        out[40..44].copy_from_slice(&info.status.to_le_bytes());
    }
    out
}
