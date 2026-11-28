// SPDX-License-Identifier: GPL-3.0-or-later
//! Reversible cold AArch64 ELF adapters. Original algorithms and entry words
//! remain available; unsupported ELF layouts are retained byte for byte.
use sha2::{Digest, Sha256};
const MARKER: &[u8; 8] = b"TRMCMP01";
const NAMES: &[(&[u8], u32)] = &[
    (b"crc32", 1),
    (b"adler32", 2),
    (b"compress2", 3),
    (b"uncompress", 4),
    (b"lzma_crc32", 5),
    (b"lzma_crc64", 6),
    (b"lzma_easy_buffer_encode", 7),
    (b"lzma_stream_buffer_decode", 8),
    (b"ZSTD_compress", 9),
    (b"ZSTD_decompress", 10),
    (b"AES_set_encrypt_key", 14),
    (b"AES_set_decrypt_key", 15),
    (b"AES_encrypt", 16),
    (b"AES_decrypt", 17),
    (b"AES_cbc_encrypt", 18),
    (b"SHA1_Init", 19),
    (b"SHA1_Update", 20),
    (b"SHA1_Final", 21),
    (b"SHA1_Transform", 22),
    (b"SHA256_Init", 23),
    (b"SHA256_Update", 24),
    (b"SHA256_Final", 25),
    (b"SHA256_Transform", 26),
    (b"SHA512_Init", 27),
    (b"SHA512_Update", 28),
    (b"SHA512_Final", 29),
    (b"SHA512_Transform", 30),
];
fn u16at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn u64at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}
fn align(n: usize, a: usize) -> Option<usize> {
    n.checked_add(a - 1).map(|n| n & !(a - 1))
}
fn branch(from: u64, to: u64, link: bool) -> Option<u32> {
    let d = to as i128 - from as i128;
    if d % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&d) {
        return None;
    }
    Some(if link { 0x94000000 } else { 0x14000000 } | ((d / 4) as u32 & 0x3ffffff))
}
fn adrp(from: u64, to: u64) -> Option<u32> {
    let d = ((to & !4095) as i128 - (from & !4095) as i128) / 4096;
    if !(-(1 << 20)..(1 << 20)).contains(&d) {
        return None;
    }
    Some(0x90000010 | ((d as u32 & 3) << 29) | (((d as u32 >> 2) & 0x7ffff) << 5))
}
fn relocatable(w: u32) -> bool {
    // Public entry guards and ADR/ADRP/B have exact relocations. Calls and
    // literal loads retain original code when an entry recipe is unavailable.
    w & 0x3b000000 != 0x18000000
        && (w & 0x7c000000 != 0x14000000 || w & 0xfc000000 == 0x14000000)
        && (w & 0xff000000 != 0x54000000 || w & 15 < 14)
}
fn words(
    at: u64,
    target: u64,
    original: u32,
    function: u32,
    got: u64,
    auth: u32,
) -> Option<Vec<u8>> {
    let mut w = vec![
        0xd10183ff,
        0xa90007e0,
        0xa9010fe2,
        0xa90217e4,
        0xa9031fe6,
        if function == 8 {
            0xf94033e9
        } else {
            0xaa1f03e9
        },
        0xf90023e9,
        0xf90027fe,
        0xd53b4209, // preserve incoming NZCV for displaced entry guards
        0xf9002be9,
    ];
    let cache = got + 16;
    let pc = at + w.len() as u64 * 4;
    w.push(adrp(pc, cache)?);
    w.push(0xb940020a | ((((cache & 4095) / 4) as u32) << 10));
    // Before library initialization (e.g. an IFUNC resolver), retain original
    // code without querying libc TLS. The initializer publishes 1/2 once.
    w.push(0x7100095f);
    let mismatch = w.len();
    w.push(0);
    w.push(0x910003e0);
    let call = w.len();
    w.push(0);
    let failed = w.len();
    w.push(0);
    w.extend([0xf94027fe, 0x910183ff, auth, 0xd65f03c0]);
    let fallback = w.len();
    w.extend([
        0xf9402be9, 0xd51b4209, 0xa94007e0, 0xa9410fe2, 0xa94217e4, 0xa9431fe6, 0xf94027fe,
        0x910183ff,
    ]);
    let relocated_at = at + w.len() as u64 * 4;
    let mut guard_branch = None;
    let relocated = if original & 0x1f000000 == 0x10000000 {
        let bits = ((original >> 5) & 0x7ffff) << 2 | ((original >> 29) & 3);
        let offset = (((bits as i32) << 11) >> 11) as i64;
        let delta = if original & 0x80000000 != 0 {
            let address = (target & !4095).wrapping_add_signed(offset * 4096);
            (address as i128 - (relocated_at & !4095) as i128) / 4096
        } else {
            target.wrapping_add_signed(offset) as i128 - relocated_at as i128
        };
        if !(-(1 << 20)..(1 << 20)).contains(&delta) {
            return None;
        }
        original & !0x60ffffe0 | ((delta as u32 & 3) << 29) | (((delta as u32 >> 2) & 0x7ffff) << 5)
    } else if original & 0x7e000000 == 0x34000000
        || original & 0xff000000 == 0x54000000
        || original & 0x7e000000 == 0x36000000
    {
        let test_bit = original & 0x7e000000 == 0x36000000;
        let (mask, bits) = if test_bit {
            (0x0007ffe0, 14)
        } else {
            (0x00ffffe0, 19)
        };
        let imm = (original >> 5) & ((1u32 << bits) - 1);
        let offset = (((imm as i32) << (32 - bits)) >> (32 - bits)) as i64 * 4;
        guard_branch = Some(branch(
            relocated_at + 4,
            target.wrapping_add_signed(offset),
            false,
        )?);
        let invert = if original & 0xff000000 == 0x54000000 {
            1
        } else {
            1 << 24
        };
        ((original ^ invert) & !mask) | (2 << 5)
    } else if original & 0xfc000000 == 0x14000000 {
        let offset = ((original << 6) as i32 >> 4) as i64;
        branch(relocated_at, target.wrapping_add_signed(offset), false)?
    } else {
        original
    };
    w.push(relocated);
    w.push(guard_branch.unwrap_or(0xd503201f));
    let from = at + w.len() as u64 * 4;
    w.push(branch(from, target + 4, false)?);
    let stub = w.len();
    w.extend([
        0xd2800170,
        0xf2a00030,
        0xd2800011 | (function << 5),
        crate::native::INSTRUCTION,
        0xd65f03c0,
    ]);
    w[mismatch] = 0x54000001 | (((fallback - mismatch) as u32) << 5);
    w[call] = branch(at + call as u64 * 4, at + stub as u64 * 4, true)?;
    w[failed] = 0xb5000001 | (((fallback - failed) as u32) << 5);
    Some(w.into_iter().flat_map(u32::to_le_bytes).collect())
}
fn initializer(at: u64, got: u64, original: Option<(u64, usize)>) -> Option<Vec<u8>> {
    let mut w = vec![
        0xd503245f, 0xd10183ff, 0xa90007e0, 0xa9010fe2, 0xa90217e4, 0xa9031fe6, 0xf90027fe,
    ];
    // Both glibc and musl run INIT_ARRAY after TLS initialization. Musl on
    // AArch64 intentionally ignores legacy DT_INIT. Preserve errno and each
    // original constructor's arguments, reading its already-relocated pointer
    // from the original array rather than copying RELR/RELA-managed storage.
    for (slot, after) in [(got + 8, 0u8), (got, 1u8)] {
        let pc = at + w.len() as u64 * 4;
        w.push(adrp(pc, slot)?);
        w.push(0xf9400210 | ((((slot & 4095) / 8) as u32) << 10));
        w.push(0xd63f0200);
        if after == 0 {
            w.extend([0xf9002be0, 0xb9400009, 0xb9005be9]);
            let key = crate::compute::AUXV_KEY as u32;
            w.push(0xd2800000 | ((key & 0xffff) << 5));
            w.push(0xf2a00000 | (((key >> 16) & 0xffff) << 5));
        }
    }
    w.extend([
        0xf9402be9, 0xb9405bea, 0xb900012a, 0xd2800169, 0xf2a00029, 0xeb09001f, 0x1a9f17ea,
        0x1100054a,
    ]);
    let cache = got + 16;
    let pc = at + w.len() as u64 * 4;
    w.push(adrp(pc, cache)?);
    w.push(0xb900020a | ((((cache & 4095) / 4) as u32) << 10));
    if let Some((base, count)) = original {
        for index in 0..count {
            w.extend([0xa94007e0, 0xa9410fe2, 0xa94217e4, 0xa9431fe6]);
            let slot = base + index as u64 * 8;
            let pc = at + w.len() as u64 * 4;
            w.push(adrp(pc, slot)?);
            w.push(0xf9400210 | ((((slot & 4095) / 8) as u32) << 10));
            w.push(0xd63f0200);
        }
    }
    w.extend([
        0xa94007e0, 0xa9410fe2, 0xa94217e4, 0xa9431fe6, 0xf94027fe, 0x910183ff, 0xd65f03c0,
    ]);
    Some(w.into_iter().flat_map(u32::to_le_bytes).collect())
}
fn restored(bytes: &[u8]) -> Option<Vec<u8>> {
    if !bytes.ends_with(MARKER) {
        return None;
    }
    let size = u64at(bytes, bytes.len().checked_sub(16)?)? as usize;
    let start = bytes.len().checked_sub(size.checked_add(16)?)?;
    let record = bytes.get(start..start + size)?;
    let original_len = u64at(record, 0)? as usize;
    let header = record.get(8..72)?;
    let digest = record.get(72..104)?;
    if original_len > start
        || original_len < 64
        || record.len() < 104
        || (record.len() - 104) % 12 != 0
    {
        return None;
    }
    let mut out = bytes.get(..original_len)?.to_vec();
    out[..64].copy_from_slice(header);
    for entry in record.get(104..)?.chunks_exact(12) {
        let at = u64at(entry, 0)? as usize;
        out.get_mut(at..at.checked_add(4)?)?
            .copy_from_slice(&entry[8..12]);
    }
    if Sha256::digest(&out).as_slice() != digest {
        return None;
    }
    Some(out)
}
/// None means already selected or not safely adaptable. Disabling restores a
/// derivative only after validating its embedded exact-original SHA256 recipe.
pub fn adapt(bytes: &[u8], enabled: bool) -> Option<Vec<u8>> {
    if bytes.ends_with(MARKER) {
        return if enabled { None } else { restored(bytes) };
    }
    if !enabled
        || bytes.len() > 64 * 1024 * 1024
        || bytes.get(..6)? != b"\x7fELF\x02\x01"
        || u16at(bytes, 18)? != 183
        || u16at(bytes, 16)? != 3
    {
        return None;
    }
    let digest = format!("{:x}", Sha256::digest(bytes));
    if !include_str!("compute-catalog.tsv")
        .lines()
        .any(|line| line.split_whitespace().next() == Some(digest.as_str()))
    {
        return None;
    }
    let phoff = usize::try_from(u64at(bytes, 32)?).ok()?;
    let count = u16at(bytes, 56)? as usize;
    if u16at(bytes, 54)? != 56 || count > 128 {
        return None;
    }
    let mut ph: Vec<Vec<u8>> = bytes
        .get(phoff..phoff.checked_add(count * 56)?)?
        .chunks_exact(56)
        .map(|p| p.to_vec())
        .collect();
    let dynamic = ph.iter().position(|p| u32at(p, 0) == Some(2))?;
    let map = |addr: u64, len: usize| -> Option<usize> {
        for p in &ph {
            if u32at(p, 0)? == 1 {
                let va = u64at(p, 16)?;
                let size = u64at(p, 32)?;
                if addr >= va && addr - va <= size && len as u64 <= size - (addr - va) {
                    let at = u64at(p, 8)?.checked_add(addr - va)? as usize;
                    bytes.get(at..at.checked_add(len)?)?;
                    return Some(at);
                }
            }
        }
        None
    };
    let off = u64at(&ph[dynamic], 8)? as usize;
    let len = u64at(&ph[dynamic], 32)? as usize;
    let mut tags: Vec<(u64, u64)> = Vec::new();
    for d in bytes.get(off..off.checked_add(len)?)?.chunks_exact(16) {
        let tag = u64at(d, 0)?;
        if tag == 0 {
            break;
        }
        tags.push((tag, u64at(d, 8)?));
    }
    let value = |tag: u64| tags.iter().find(|p| p.0 == tag).map(|p| p.1);
    if value(11)? != 24 {
        return None;
    }
    let str_len = usize::try_from(value(10)?).ok()?;
    let str_at = map(value(5)?, str_len)?;
    let strings = bytes.get(str_at..str_at + str_len)?;
    let sym_addr = value(6)?;
    // Section metadata supplies the exact dynamic-symbol count, including
    // local/undefined entries. No scan beyond a validated section is allowed.
    let shoff = u64at(bytes, 40)? as usize;
    let shnum = u16at(bytes, 60)? as usize;
    if u16at(bytes, 58)? != 64 || shnum > 8192 {
        return None;
    }
    let syms = bytes
        .get(shoff..shoff.checked_add(shnum * 64)?)?
        .chunks_exact(64)
        .find(|s| u32at(s, 4) == Some(11) && u64at(s, 16) == Some(sym_addr))?;
    let sym_len = u64at(syms, 32)? as usize;
    if sym_len % 24 != 0 || sym_len / 24 > 1000000 {
        return None;
    }
    let sym_at = map(sym_addr, sym_len)?;
    let symdata = bytes.get(sym_at..sym_at + sym_len)?;
    let mut functions = Vec::new();
    for sym in symdata.chunks_exact(24) {
        if sym[4] & 15 != 2
            || !matches!(sym[4] >> 4, 1 | 2)
            || u16at(sym, 6)? == 0
            || u64at(sym, 16)? < 4
        {
            continue;
        }
        let name = strings
            .get(u32at(sym, 0)? as usize..)?
            .split(|b| *b == 0)
            .next()?;
        let Some((_, id)) = NAMES.iter().find(|p| p.0 == name) else {
            continue;
        };
        let mut va = u64at(sym, 8)?;
        let mut at = map(va, 4)?;
        let mut word = u32at(bytes, at)?;
        let auth = match word {
            0xd503233f => 0xd50323bf,
            0xd503237f => 0xd50323ff,
            _ => 0xd503201f,
        };
        if word & 0xffffff3f == 0xd503241f || auth != 0xd503201f {
            if u64at(sym, 16)? < 8 {
                continue;
            }
            va = va.checked_add(4)?;
            at = map(va, 4)?;
            word = u32at(bytes, at)?;
        }
        if relocatable(word)
            && !functions
                .iter()
                .any(|p: &(u64, usize, u32, u32, u32)| p.0 == va)
        {
            functions.push((va, at, word, *id, auth));
        }
    }
    if functions.is_empty() {
        return None;
    }
    let rela = if let Some(addr) = value(7) {
        if value(9)? != 24 {
            return None;
        }
        let len = value(8)? as usize;
        let at = map(addr, len)?;
        bytes.get(at..at + len)?.to_vec()
    } else {
        Vec::new()
    };
    let versions = if let Some(addr) = value(0x6ffffff0) {
        let at = map(addr, sym_len / 12)?;
        Some(bytes.get(at..at + sym_len / 12)?.to_vec())
    } else {
        None
    };
    let page = ph
        .iter()
        .filter(|p| u32at(p, 0) == Some(1))
        .filter_map(|p| u64at(p, 48))
        .max()?
        .max(4096) as usize;
    if !page.is_power_of_two() || page > 2 * 1024 * 1024 {
        return None;
    }
    let rxoff = align(bytes.len(), page)?;
    let rxva = align(
        ph.iter()
            .filter(|p| u32at(p, 0) == Some(1))
            .map(|p| u64at(p, 16)?.checked_add(u64at(p, 40)?))
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .max()? as usize,
        page,
    )? as u64;
    if rxva > trames_memory::ADDRESS_LIMIT.saturating_sub(192 * 1024 * 1024) {
        return None;
    }
    let init_size = value(27).unwrap_or(0) as usize;
    if init_size % 8 != 0 || init_size / 8 > 1024 {
        return None;
    }
    let original_init = if init_size == 0 {
        None
    } else {
        let address = value(25)?;
        map(address, init_size)?;
        Some((address, init_size / 8))
    };
    let phsize = (count + 2) * 56;
    let code_at = align(phsize, 16)?;
    // Every wrapper has the same fixed width (the ninth argument load replaces
    // a register zero). Obtain it with valid dummy targets before laying out RW.
    let width = words(rxva + code_at as u64, rxva, 0xd503201f, 1, rxva, 0xd503201f)?.len();
    let init_at = code_at + width * functions.len();
    let init_size = initializer(rxva + init_at as u64, rxva, original_init)?.len();
    let rxsize = init_at + init_size;
    let rwoff = align(rxoff + rxsize, page)?;
    let rwva = rxva + align(rxsize, page)? as u64;
    let mut rw = vec![0; 32]; // two GOT slots, capability cache, INIT_ARRAY entry
    let newstr = rw.len();
    rw.extend(strings);
    let get_name = rw.len() - newstr;
    rw.extend(b"getauxval\0");
    let errno_name = rw.len() - newstr;
    rw.extend(b"__errno_location\0");
    let newstr_len = rw.len() - newstr;
    rw.resize(align(rw.len(), 8)?, 0);
    let newsym = rw.len();
    rw.extend(symdata);
    for name in [get_name, errno_name] {
        rw.extend((name as u32).to_le_bytes());
        rw.extend([0x12, 0, 0, 0]);
        rw.extend([0; 16]);
    }
    let newversions = if let Some(mut v) = versions {
        rw.resize(align(rw.len(), 2)?, 0);
        let at = rw.len();
        v.extend([1, 0, 1, 0]);
        rw.extend(v);
        Some(at)
    } else {
        None
    };
    rw.resize(align(rw.len(), 8)?, 0);
    let newrela = rw.len();
    rw.extend(rela);
    for i in 0..2 {
        rw.extend((rwva + i * 8).to_le_bytes());
        rw.extend((((sym_len / 24 + i as usize) as u64) << 32 | 1025).to_le_bytes());
        rw.extend(0u64.to_le_bytes());
    }
    rw.extend((rwva + 24).to_le_bytes());
    rw.extend(1027u64.to_le_bytes()); // R_AARCH64_RELATIVE, no external symbol
    rw.extend((rxva + init_at as u64).to_le_bytes());
    let newrela_len = rw.len() - newrela;
    let changes = [
        (5, rwva + newstr as u64),
        (10, newstr_len as u64),
        (6, rwva + newsym as u64),
        (7, rwva + newrela as u64),
        (8, newrela_len as u64),
        (9, 24),
        (25, rwva + 24),
        (27, 8),
    ];
    for (tag, val) in changes {
        if let Some(pair) = tags.iter_mut().find(|p| p.0 == tag) {
            pair.1 = val;
        } else {
            tags.push((tag, val));
        }
    }
    if let Some(at) = newversions {
        tags.iter_mut().find(|p| p.0 == 0x6ffffff0)?.1 = rwva + at as u64;
    }
    rw.resize(align(rw.len(), 8)?, 0);
    let dyn_at = rw.len();
    for (tag, val) in &tags {
        rw.extend(tag.to_le_bytes());
        rw.extend(val.to_le_bytes());
    }
    rw.extend([0; 16]);
    let dyn_len = rw.len() - dyn_at;
    let mut out = bytes.to_vec();
    out.resize(rwoff, 0);
    out.extend(&rw);
    let init = initializer(rxva + init_at as u64, rwva, original_init)?;
    if init.len() != init_size {
        return None;
    }
    out[rxoff + init_at..rxoff + init_at + init_size].copy_from_slice(&init);
    let mut recipe = (bytes.len() as u64).to_le_bytes().to_vec();
    recipe.extend(&bytes[..64]);
    recipe.extend(Sha256::digest(bytes));
    for (i, (target, off, original, function, auth)) in functions.into_iter().enumerate() {
        let va = rxva + (code_at + i * width) as u64;
        let code = words(va, target, original, function, rwva, auth)?;
        if code.len() != width {
            return None;
        }
        out[rxoff + code_at + i * width..rxoff + code_at + (i + 1) * width].copy_from_slice(&code);
        out[off..off + 4].copy_from_slice(&branch(target, va, false)?.to_le_bytes());
        recipe.extend((off as u64).to_le_bytes());
        recipe.extend(original.to_le_bytes());
    }
    let set64 = |p: &mut Vec<u8>, at: usize, val: u64| {
        p[at..at + 8].copy_from_slice(&val.to_le_bytes());
    };
    for p in &mut ph {
        if u32at(p, 0) == Some(6) {
            for at in [8, 16, 24] {
                set64(p, at, if at == 8 { rxoff as u64 } else { rxva });
            }
            set64(p, 32, phsize as u64);
            set64(p, 40, phsize as u64);
        }
    }
    for (at, val) in [
        (8, (rwoff + dyn_at) as u64),
        (16, rwva + dyn_at as u64),
        (24, rwva + dyn_at as u64),
        (32, dyn_len as u64),
        (40, dyn_len as u64),
    ] {
        set64(&mut ph[dynamic], at, val);
    }
    for (offset, va, size, flags) in [(rxoff, rxva, rxsize, 5u32), (rwoff, rwva, rw.len(), 6u32)] {
        let mut p = Vec::new();
        p.extend(1u32.to_le_bytes());
        p.extend(flags.to_le_bytes());
        for n in [offset as u64, va, va, size as u64, size as u64, page as u64] {
            p.extend(n.to_le_bytes());
        }
        ph.push(p);
    }
    for (i, p) in ph.iter().enumerate() {
        out[rxoff + i * 56..rxoff + (i + 1) * 56].copy_from_slice(p);
    }
    out[32..40].copy_from_slice(&(rxoff as u64).to_le_bytes());
    out[56..58].copy_from_slice(&((count + 2) as u16).to_le_bytes());
    let size = recipe.len();
    out.extend(recipe);
    out.extend((size as u64).to_le_bytes());
    out.extend(MARKER);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_inputs_and_recovery_lengths_are_rejected_without_panics() {
        for len in 0..512 {
            let mut bytes = vec![0; len];
            assert!(adapt(&bytes, true).is_none());
            bytes.extend(u64::MAX.to_le_bytes());
            bytes.extend(MARKER);
            assert!(adapt(&bytes, false).is_none());
        }
        for length in [0u64, 1, 8, 64, 103, 104, u64::MAX] {
            let mut bytes = vec![0; 256];
            bytes.extend(length.to_le_bytes());
            bytes.extend(MARKER);
            assert!(adapt(&bytes, false).is_none());
        }
    }
    #[test]
    fn adapters_preserve_bti_pac_and_signed_branch_destinations() {
        let pc = 0x10000;
        let code = words(pc, 0x2000, 0xd10083ff, 12, 0x40000, 0xd50323bf).unwrap();
        let instructions: Vec<_> = code
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
            .collect();
        assert!(instructions
            .windows(4)
            .any(|w| w == [0xf94027fe, 0x910183ff, 0xd50323bf, 0xd65f03c0]));
        let original = branch(0x2000, 0x1800, false).unwrap();
        assert!(words(pc, 0x2000, original, 1, 0x40000, 0xd503201f).is_some());
    }
}
