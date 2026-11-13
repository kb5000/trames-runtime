// SPDX-License-Identifier: GPL-3.0-or-later
#[derive(Clone, Copy, Debug, Default)]
pub struct Info {
    /// User-supplied sigqueue payload; unlike kernel-generated identities it is
    /// already expressed in the sender's ABI and must not be PID-translated.
    pub user: Option<[u8; 48]>,
    pub sender: u32,
    pub uid: u32,
    pub status: i32,
    pub code: i32,
    pub timer: Option<(i32, i32, u64)>,
    pub fault: Option<u64>,
    pub poll: Option<(u64, u32)>,
}

pub fn write_siginfo(out: &mut [u8], sig: u32, info: Info) {
    if let Some(user) = info.user {
        // AArch64 kernel_siginfo is 48 bytes; the user expansion is zeroed.
        out[..128].fill(0);
        out[..48].copy_from_slice(&user);
        out[..4].copy_from_slice(&sig.to_le_bytes());
        return;
    }
    out[..128].fill(0);
    out[..4].copy_from_slice(&sig.to_le_bytes());
    out[8..12].copy_from_slice(&info.code.to_le_bytes());
    if let Some((band, fd)) = info.poll {
        out[16..24].copy_from_slice(&band.to_le_bytes());
        out[24..28].copy_from_slice(&fd.to_le_bytes());
    } else if let Some(address) = info.fault {
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
    if let Some(user) = info.user {
        let code = i32::from_le_bytes(user[8..12].try_into().unwrap());
        let limit = match sig {
            4 => 11,
            5 => 6,
            7 => 5,
            8 => 15,
            11 => 10,
            17 | 29 => 6,
            31 => 2,
            _ => 0,
        };
        let specific = code > 0 && code <= limit;
        let mut out = [0; 128];
        out[..4].copy_from_slice(&sig.to_le_bytes());
        out[4..12].copy_from_slice(&user[4..12]);
        if code == -2 {
            out[24..28].copy_from_slice(&user[16..20]);
            out[32..36].copy_from_slice(&user[20..24]);
            out[44..48].copy_from_slice(&user[24..28]);
            out[48..56].copy_from_slice(&user[24..32]);
        } else if code == -5
            || code > 0 && code < 128 && (specific && sig == 29 || !specific && code <= 6)
        {
            out[20..24].copy_from_slice(&user[24..28]);
            out[28..32].copy_from_slice(&user[16..20]);
        } else if specific && sig == 17 {
            out[12..20].copy_from_slice(&user[16..24]);
            out[40..44].copy_from_slice(&user[24..28]);
            out[56..72].copy_from_slice(&user[32..48]);
        } else if specific && matches!(sig, 4 | 5 | 7 | 8 | 11) {
            out[72..80].copy_from_slice(&user[16..24]);
            out[80..82].copy_from_slice(&user[24..26]);
        } else if specific && sig == 31 {
            out[84..88].copy_from_slice(&user[24..28]);
            out[88..96].copy_from_slice(&user[16..24]);
            out[96..100].copy_from_slice(&user[28..32]);
        } else {
            out[12..20].copy_from_slice(&user[16..24]);
            if code < 0 {
                out[44..48].copy_from_slice(&user[24..28]);
                out[48..56].copy_from_slice(&user[24..32]);
            }
        }
        return out;
    }
    let mut out = [0; 128];
    out[..4].copy_from_slice(&sig.to_le_bytes());
    out[8..12].copy_from_slice(&info.code.to_le_bytes());
    if let Some((band, fd)) = info.poll {
        out[20..24].copy_from_slice(&fd.to_le_bytes());
        out[28..32].copy_from_slice(&(band as u32).to_le_bytes());
    } else if let Some((id, overrun, value)) = info.timer {
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
