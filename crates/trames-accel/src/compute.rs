// SPDX-License-Identifier: GPL-3.0-or-later
//! Stateless compression, checksum and crypto calls. All opaque stream state,
//! allocator callbacks, TLS and provider selection remain in the guest library.
use crate::native::{Error, Metrics, Return};
use trames_memory::NativeMemory;
pub const PROFILE: u64 = 0x0001_000b;
pub const AUXV_KEY: u64 = 0x5452_000c;
pub const FUNCTION_COUNT: u64 = 30;
fn fallback() -> Return {
    Return {
        value: 0,
        fallback: true,
    }
}
fn done(value: u64) -> Return {
    Return {
        value,
        fallback: false,
    }
}
struct Scratch(Vec<std::mem::MaybeUninit<u8>>);
impl Scratch {
    fn new(length: u64) -> Option<Self> {
        let length = usize::try_from(length).ok()?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).ok()?;
        // MaybeUninit has no initialization invariant. Reserve address space,
        // without zero-filling the caller's unused output capacity.
        unsafe {
            bytes.set_len(length);
        }
        Some(Self(bytes))
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr().cast()
    }
    /// The caller supplies exactly a range reported initialized by the native
    /// library's successful/partial-output contract, always within its capacity.
    unsafe fn written(&self, range: std::ops::Range<usize>) -> &[u8] {
        assert!(range.start <= range.end && range.end <= self.len());
        unsafe { std::slice::from_raw_parts(self.0.as_ptr().add(range.start).cast(), range.len()) }
    }
}

fn read(
    memory: &impl NativeMemory,
    at: u64,
    length: u64,
    metrics: &mut Metrics,
) -> Result<Option<Vec<u8>>, Error> {
    let mut bytes = Vec::new();
    let mut offset = 0u64;
    while offset < length {
        let at = at.wrapping_add(offset);
        let count = (length - offset).min(4096 - (at & 4095)) as usize;
        // Reach memory before growing staging, so bogus huge lengths fault at
        // their first invalid page instead of allocating their claimed size.
        let mut chunk = [0u8; 4096];
        memory.native_read(at, &mut chunk[..count])?;
        if bytes.try_reserve(count).is_err() {
            return Ok(None);
        }
        bytes.extend_from_slice(&chunk[..count]);
        offset += count as u64;
    }
    metrics.bytes_read += length;
    metrics.buffered_bytes_read += length;
    Ok(Some(bytes))
}
fn write(
    memory: &mut impl NativeMemory,
    at: u64,
    bytes: &[u8],
    metrics: &mut Metrics,
) -> Result<(), Error> {
    let mut offset = 0;
    memory.fill_with(at, bytes.len(), |out| {
        out.copy_from_slice(&bytes[offset..offset + out.len()]);
        offset += out.len();
    })?;
    metrics.bytes_written += bytes.len() as u64;
    metrics.buffered_bytes_written += bytes.len() as u64;
    Ok(())
}
fn word(memory: &impl NativeMemory, at: u64) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(memory.native_read_array(at)?))
}
// Only call-owned, fully checked host buffers cross FFI. No guest address,
// callback or opaque context is ever cast to a native pointer or retained.
pub(crate) fn execute(
    memory: &mut impl NativeMemory,
    function: u64,
    args: [u64; 3],
    metrics: &mut Metrics,
) -> Result<Return, Error> {
    #[cfg(not(target_arch = "aarch64"))]
    if (14..=18).contains(&function) {
        return Ok(fallback());
    }
    let frame = memory.native_read_array::<72>(args[0])?;
    let a: [u64; 9] =
        std::array::from_fn(|i| u64::from_le_bytes(frame[i * 8..i * 8 + 8].try_into().unwrap()));
    macro_rules! input {
        ($p:expr,$n:expr) => {
            match read(memory, $p, $n, metrics)? {
                Some(v) => v,
                None => return Ok(fallback()),
            }
        };
    }
    macro_rules! output {
        ($p:expr,$n:expr) => {
            match memory.native_output_range($p, $n as usize) {
                Ok(true) => {}
                Ok(false) | Err(trames_memory::NativeAccessError::Memory(_)) => {
                    return Ok(fallback())
                }
                Err(error) => return Err(error.into()),
            }
        };
    }
    macro_rules! allocated {
        ($n:expr) => {
            match Scratch::new($n) {
                Some(v) => v,
                None => return Ok(fallback()),
            }
        };
    }
    match function {
        1 | 2 | 5 | 6 => {
            let (at, length, seed) = if function <= 2 {
                (a[1], u64::from(a[2] as u32), a[0])
            } else {
                (a[0], a[1], a[2])
            };
            // zlib's NULL-buffer query does not dereference or consume len.
            if function <= 2 && at == 0 {
                return Ok(done(if function == 1 { 0 } else { 1 }));
            }
            let bytes = input!(at, length);
            let value = unsafe {
                match function {
                    1 => libz_sys::crc32(seed as _, bytes.as_ptr(), length as _) as u64,
                    2 => libz_sys::adler32(seed as _, bytes.as_ptr(), length as _) as u64,
                    5 => liblzma_sys::lzma_crc32(bytes.as_ptr(), bytes.len(), seed as _) as u64,
                    _ => liblzma_sys::lzma_crc64(bytes.as_ptr(), bytes.len(), seed),
                }
            };
            Ok(done(value))
        }
        3 | 4 => {
            let capacity = word(memory, a[1])?;
            output!(a[0], capacity);
            output!(a[1], 8);
            let input = input!(a[2], a[3]);
            let mut out = allocated!(capacity);
            let mut length = capacity as _;
            let result = unsafe {
                if function == 3 {
                    libz_sys::compress2(
                        out.as_mut_ptr(),
                        &mut length,
                        input.as_ptr(),
                        input.len() as _,
                        a[4] as i32,
                    )
                } else {
                    libz_sys::uncompress(
                        out.as_mut_ptr(),
                        &mut length,
                        input.as_ptr(),
                        input.len() as _,
                    )
                }
            };
            if result == libz_sys::Z_MEM_ERROR {
                return Ok(fallback());
            }
            if length as usize > out.len() {
                return Err(Error::InvalidEntry);
            }
            write(
                memory,
                a[0],
                unsafe { out.written(0..length as usize) },
                metrics,
            )?;
            write(memory, a[1], &(length as u64).to_le_bytes(), metrics)?;
            Ok(done(result as u64))
        }
        7 => {
            if a[2] != 0 {
                return Ok(fallback());
            } // guest allocator callbacks
            let start = word(memory, a[6])?;
            if start > a[7] {
                return Ok(fallback());
            }
            output!(a[5], a[7]);
            output!(a[6], 8);
            let input = input!(a[3], a[4]);
            let mut out = allocated!(a[7]);
            let mut position = start as usize;
            let result = unsafe {
                liblzma_sys::lzma_easy_buffer_encode(
                    a[0] as _,
                    a[1] as _,
                    std::ptr::null(),
                    input.as_ptr(),
                    input.len(),
                    out.as_mut_ptr(),
                    &mut position,
                    out.len(),
                )
            };
            if result == liblzma_sys::LZMA_MEM_ERROR {
                return Ok(fallback());
            }
            if result == liblzma_sys::LZMA_OK {
                write(
                    memory,
                    a[5].wrapping_add(start),
                    unsafe { out.written(start as usize..position) },
                    metrics,
                )?;
                write(memory, a[6], &(position as u64).to_le_bytes(), metrics)?;
            }
            Ok(done(result as u64))
        }
        8 => {
            if a[2] != 0 {
                return Ok(fallback());
            }
            let mut limit = word(memory, a[0])?;
            let start_in = word(memory, a[4])?;
            let start_out = word(memory, a[7])?;
            if start_in > a[5] || start_out > a[8] {
                return Ok(fallback());
            }
            for (p, n) in [(a[0], 8), (a[4], 8), (a[6], a[8]), (a[7], 8)] {
                output!(p, n);
            }
            let input = input!(a[3], a[5]);
            let mut out = allocated!(a[8]);
            let (mut ip, mut op) = (start_in as usize, start_out as usize);
            let result = unsafe {
                liblzma_sys::lzma_stream_buffer_decode(
                    &mut limit,
                    a[1] as _,
                    std::ptr::null(),
                    input.as_ptr(),
                    &mut ip,
                    input.len(),
                    out.as_mut_ptr(),
                    &mut op,
                    out.len(),
                )
            };
            if result == liblzma_sys::LZMA_MEM_ERROR {
                return Ok(fallback());
            }
            if result == liblzma_sys::LZMA_OK {
                write(
                    memory,
                    a[6].wrapping_add(start_out),
                    unsafe { out.written(start_out as usize..op) },
                    metrics,
                )?;
                write(memory, a[4], &(ip as u64).to_le_bytes(), metrics)?;
                write(memory, a[7], &(op as u64).to_le_bytes(), metrics)?;
            }
            if result == liblzma_sys::LZMA_MEMLIMIT_ERROR {
                write(memory, a[0], &limit.to_le_bytes(), metrics)?;
            }
            Ok(done(result as u64))
        }
        9 | 10 => {
            output!(a[0], a[1]);
            let input = input!(a[2], a[3]);
            let mut out = allocated!(a[1]);
            let result = unsafe {
                if function == 9 {
                    zstd_sys::ZSTD_compress(
                        out.as_mut_ptr().cast(),
                        out.len(),
                        input.as_ptr().cast(),
                        input.len(),
                        a[4] as i32,
                    )
                } else {
                    zstd_sys::ZSTD_decompress(
                        out.as_mut_ptr().cast(),
                        out.len(),
                        input.as_ptr().cast(),
                        input.len(),
                    )
                }
            };
            if unsafe { zstd_sys::ZSTD_getErrorCode(result) }
                == zstd_sys::ZSTD_ErrorCode::ZSTD_error_memory_allocation
            {
                return Ok(fallback());
            }
            // Native errors can leave scratch output unspecified. Guest-visible
            // output remains unspecified too; return only the library status.
            if unsafe { zstd_sys::ZSTD_isError(result) } == 0 {
                write(memory, a[0], unsafe { out.written(0..result) }, metrics)?;
            }
            Ok(done(result as u64))
        }
        11..=13 => {
            if a[2] == 0 {
                return Ok(fallback());
            } // guest static-result lifetime
            let length = match function {
                11 => 20,
                12 => 32,
                _ => 64,
            };
            output!(a[2], length);
            let input = input!(a[0], a[1]);
            let mut digest = [0u8; 64];
            unsafe {
                match function {
                    11 => {
                        let mut context = std::mem::MaybeUninit::<openssl_sys::SHA_CTX>::uninit();
                        openssl_sys::SHA1_Init(context.as_mut_ptr());
                        openssl_sys::SHA1_Update(
                            context.as_mut_ptr(),
                            input.as_ptr().cast(),
                            input.len(),
                        );
                        openssl_sys::SHA1_Final(digest.as_mut_ptr(), context.as_mut_ptr());
                    }
                    12 => {
                        let mut context =
                            std::mem::MaybeUninit::<openssl_sys::SHA256_CTX>::uninit();
                        openssl_sys::SHA256_Init(context.as_mut_ptr());
                        openssl_sys::SHA256_Update(
                            context.as_mut_ptr(),
                            input.as_ptr().cast(),
                            input.len(),
                        );
                        openssl_sys::SHA256_Final(digest.as_mut_ptr(), context.as_mut_ptr());
                    }
                    _ => {
                        let mut context =
                            std::mem::MaybeUninit::<openssl_sys::SHA512_CTX>::uninit();
                        openssl_sys::SHA512_Init(context.as_mut_ptr());
                        openssl_sys::SHA512_Update(
                            context.as_mut_ptr(),
                            input.as_ptr().cast(),
                            input.len(),
                        );
                        openssl_sys::SHA512_Final(digest.as_mut_ptr(), context.as_mut_ptr());
                    }
                }
            };
            write(memory, a[2], &digest[..length], metrics)?;
            Ok(done(a[2]))
        }
        14 | 15 => {
            let bits = a[1] as i32;
            if !matches!(bits, 128 | 192 | 256) || a[0] == 0 || a[2] == 0 {
                return Ok(fallback());
            }
            output!(a[2], 244);
            let input = input!(a[0], (bits / 8) as u64);
            // OpenSSL's AArch64 AES_KEY is 60 native u32 words plus rounds.
            // Copy only initialized schedule words, preserving the unused tail.
            let mut key = std::mem::MaybeUninit::<openssl_sys::AES_KEY>::zeroed();
            let result = unsafe {
                if function == 14 {
                    openssl_sys::AES_set_encrypt_key(input.as_ptr(), bits, key.as_mut_ptr())
                } else {
                    openssl_sys::AES_set_decrypt_key(input.as_ptr(), bits, key.as_mut_ptr())
                }
            };
            let words = 4 * (bits as usize / 32 + 7);
            let bytes = unsafe { std::slice::from_raw_parts(key.as_ptr().cast::<u8>(), 244) };
            write(memory, a[2], &bytes[..words * 4], metrics)?;
            write(memory, a[2].wrapping_add(240), &bytes[240..244], metrics)?;
            Ok(done(result as u64))
        }
        16..=18 => {
            let (length, key_at, iv) = if function == 18 {
                (a[2], a[3], Some(a[4]))
            } else {
                (16, a[2], None)
            };
            if function == 18 && (length == 0 || length % 16 != 0 || a[5] > 1) {
                return Ok(fallback());
            }
            output!(a[1], length);
            if let Some(iv) = iv {
                output!(iv, 16);
            }
            let input = input!(a[0], length);
            let mut out = allocated!(length);
            let key_bytes = input!(key_at, 244);
            let rounds = i32::from_le_bytes(key_bytes[240..244].try_into().unwrap());
            if !matches!(rounds, 10 | 12 | 14) {
                return Ok(fallback());
            }
            let mut key = std::mem::MaybeUninit::<openssl_sys::AES_KEY>::zeroed();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    key_bytes.as_ptr(),
                    key.as_mut_ptr().cast::<u8>(),
                    244,
                );
            }
            let mut iv_bytes = if let Some(iv) = iv {
                input!(iv, 16)
            } else {
                vec![]
            };
            unsafe {
                match function {
                    16 => AES_encrypt(input.as_ptr(), out.as_mut_ptr(), key.as_ptr()),
                    17 => AES_decrypt(input.as_ptr(), out.as_mut_ptr(), key.as_ptr()),
                    _ => AES_cbc_encrypt(
                        input.as_ptr(),
                        out.as_mut_ptr(),
                        out.len(),
                        key.as_ptr(),
                        iv_bytes.as_mut_ptr(),
                        a[5] as i32,
                    ),
                }
            };
            write(memory, a[1], unsafe { out.written(0..out.len()) }, metrics)?;
            if let Some(iv) = iv {
                write(memory, iv, &iv_bytes, metrics)?;
            }
            Ok(done(0))
        }
        19..=30 => hash_context(memory, function, &a, metrics),
        _ => Err(Error::InvalidEntry),
    }
}
fn hash_context(
    memory: &mut impl NativeMemory,
    function: u64,
    a: &[u64; 9],
    metrics: &mut Metrics,
) -> Result<Return, Error> {
    let family = (function - 19) / 4;
    let operation = (function - 19) % 4;
    if operation == 1 && a[2] == 0 {
        return Ok(fallback());
    }
    let size = match family {
        0 => 96,
        1 => 112,
        _ => 216,
    };
    let context = if operation == 2 { a[1] } else { a[0] };
    if !memory.native_output_range(context, size)? {
        return Ok(fallback());
    }
    let mut bytes = vec![0u8; size];
    if operation != 0 {
        memory.native_read(context, &mut bytes)?;
    }
    let (num_at, max_num, md_at) = match family {
        0 => (92, 64, None),
        1 => (104, 64, Some(108)),
        _ => (208, 128, Some(212)),
    };
    let num = u32::from_le_bytes(bytes[num_at..num_at + 4].try_into().unwrap());
    let digest_size = if operation == 0 {
        0
    } else if let Some(at) = md_at {
        let length = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        if !(if family == 1 { [28, 32] } else { [48, 64] }).contains(&length) {
            return Ok(fallback());
        }
        length as usize
    } else {
        20
    };
    if operation != 0 && num >= max_num {
        return Ok(fallback());
    }
    if operation == 2 && !memory.native_output_range(a[0], digest_size)? {
        return Ok(fallback());
    }
    let input_len = match operation {
        1 => a[2],
        3 => {
            if family == 2 {
                128
            } else {
                64
            }
        }
        _ => 0,
    };
    let start = a[1] & 0x00ff_ffff_ffff_ffff;
    let ctx = context & 0x00ff_ffff_ffff_ffff;
    if input_len > 0 && start < ctx + size as u64 && start.saturating_add(input_len) > ctx {
        return Ok(fallback());
    }
    let input = if matches!(operation, 1 | 3) {
        match read(memory, a[1], input_len, metrics)? {
            Some(v) => v,
            None => return Ok(fallback()),
        }
    } else {
        Vec::new()
    };
    let mut digest = [0u8; 64];
    macro_rules! run {
        ($type:ty,$init:path,$update:path,$final:path,$transform:path) => {{
            assert_eq!(std::mem::size_of::<$type>(), size);
            let mut c = std::mem::MaybeUninit::<$type>::uninit();
            // Public SHA contexts contain integers and inline byte storage only.
            // num/md_len are validated before any native indexing or output.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), c.as_mut_ptr().cast::<u8>(), size);
                let status = match operation {
                    0 => $init(c.as_mut_ptr()),
                    1 => $update(c.as_mut_ptr(), input.as_ptr().cast(), input.len()),
                    2 => $final(digest.as_mut_ptr(), c.as_mut_ptr()),
                    _ => {
                        $transform(c.as_mut_ptr(), input.as_ptr());
                        1
                    }
                };
                std::ptr::copy_nonoverlapping(c.as_ptr().cast::<u8>(), bytes.as_mut_ptr(), size);
                status
            }
        }};
    }
    let status = match family {
        0 => run!(
            openssl_sys::SHA_CTX,
            openssl_sys::SHA1_Init,
            openssl_sys::SHA1_Update,
            openssl_sys::SHA1_Final,
            SHA1_Transform
        ),
        1 => run!(
            openssl_sys::SHA256_CTX,
            openssl_sys::SHA256_Init,
            openssl_sys::SHA256_Update,
            openssl_sys::SHA256_Final,
            SHA256_Transform
        ),
        _ => run!(
            openssl_sys::SHA512_CTX,
            openssl_sys::SHA512_Init,
            openssl_sys::SHA512_Update,
            openssl_sys::SHA512_Final,
            SHA512_Transform
        ),
    };
    if operation == 0 && family == 2 {
        // SHA512_Init deliberately leaves its 128-byte pending block alone.
        write(memory, context, &bytes[..80], metrics)?;
        write(memory, context.wrapping_add(208), &bytes[208..], metrics)?;
    } else {
        write(memory, context, &bytes, metrics)?;
    }
    if operation == 2 {
        write(memory, a[0], &digest[..digest_size], metrics)?;
    }
    Ok(done(status as u64))
}
extern "C" {
    fn SHA1_Transform(context: *mut openssl_sys::SHA_CTX, input: *const u8);
    fn SHA256_Transform(context: *mut openssl_sys::SHA256_CTX, input: *const u8);
    fn SHA512_Transform(context: *mut openssl_sys::SHA512_CTX, input: *const u8);
    fn AES_encrypt(input: *const u8, output: *mut u8, key: *const openssl_sys::AES_KEY);
    fn AES_decrypt(input: *const u8, output: *mut u8, key: *const openssl_sys::AES_KEY);
    fn AES_cbc_encrypt(
        input: *const u8,
        output: *mut u8,
        length: usize,
        key: *const openssl_sys::AES_KEY,
        iv: *mut u8,
        encrypt: i32,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    fn memory() -> Memory {
        let mut m = Memory::default();
        for p in 0x2000..0x8000 {
            if p % 4096 == 0 {
                m.map(p, PAGE_SIZE, Permissions::RW).unwrap();
            }
        }
        m
    }
    fn call(m: &mut Memory, f: u64, a: &[u64]) -> Return {
        let mut frame = [0u8; 72];
        for (i, a) in a.iter().enumerate() {
            frame[i * 8..i * 8 + 8].copy_from_slice(&a.to_le_bytes());
        }
        m.write(0x2000, &frame).unwrap();
        execute(m, f, [0x2000, 0, 0], &mut Metrics::default()).unwrap()
    }
    #[test]
    fn checksum_hash_known_vectors_and_null_output_fallback() {
        let mut m = memory();
        m.write(0x3000, b"123456789").unwrap();
        assert_eq!(call(&mut m, 1, &[0, 0x3000, 9]).value, 0xcbf43926);
        assert_eq!(call(&mut m, 5, &[0x3000, 9, 0]).value, 0xcbf43926);
        assert_eq!(call(&mut m, 6, &[0x3000, 9, 0]).value, 0x995dc9bbdf1939fa);
        assert_eq!(call(&mut m, 1, &[111, 0, u32::MAX as u64]).value, 0);
        m.write(0x3000, b"abc").unwrap();
        assert_eq!(call(&mut m, 12, &[0x3000, 3, 0x4000]).value, 0x4000);
        assert_eq!(
            m.read_array::<32>(0x4000).unwrap(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        assert!(call(&mut m, 12, &[0x3000, 3, 0]).fallback);
    }
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aes_known_vector_and_in_place_roundtrip_uses_the_admitted_host_abi() {
        let mut m = memory();
        let key: [u8; 16] = std::array::from_fn(|i| i as u8);
        let plain: [u8; 16] = std::array::from_fn(|i| (i * 17) as u8);
        m.write(0x3000, &key).unwrap();
        m.write(0x4000, &plain).unwrap();
        let result = call(&mut m, 14, &[0x3000, 128, 0x2200]);
        assert!(!result.fallback);
        assert_eq!(result.value, 0);
        assert_eq!(m.read_array::<4>(0x22f0).unwrap(), 10i32.to_le_bytes());
        assert!(!call(&mut m, 16, &[0x4000, 0x4000, 0x2200]).fallback);
        assert_eq!(
            m.read_array::<16>(0x4000).unwrap(),
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
        assert!(!call(&mut m, 15, &[0x3000, 128, 0x2200]).fallback);
        assert!(!call(&mut m, 17, &[0x4000, 0x4000, 0x2200]).fallback);
        assert_eq!(m.read_array::<16>(0x4000).unwrap(), plain);
    }
    #[cfg(not(target_arch = "aarch64"))]
    #[test]
    fn aes_unowned_host_abi_declines_before_frame_or_output_access() {
        let mut memory = Memory::default();
        let mut metrics = Metrics::default();
        for function in 14..=18 {
            assert!(
                execute(&mut memory, function, [0; 3], &mut metrics)
                    .unwrap()
                    .fallback
            );
        }
        assert_eq!((metrics.bytes_read, metrics.bytes_written), (0, 0));
    }
    #[test]
    fn public_hash_contexts_stream_in_guest_memory_and_reject_bad_indices() {
        let mut m = memory();
        m.write(0x3000, b"abc").unwrap();
        for (init, update, finalize, length) in
            [(19, 20, 21, 20), (23, 24, 25, 32), (27, 28, 29, 64)]
        {
            m.write(0x2200, &[0xa5; 216]).unwrap();
            assert_eq!(call(&mut m, init, &[0x2200]).value, 1);
            if init == 27 {
                assert_eq!(m.read_array::<128>(0x2250).unwrap(), [0xa5; 128]);
            }
            assert_eq!(call(&mut m, update, &[0x2200, 0x3000, 1]).value, 1);
            assert_eq!(call(&mut m, update, &[0x2200, 0x3001, 2]).value, 1);
            assert_eq!(call(&mut m, finalize, &[0x4000, 0x2200]).value, 1);
            call(
                &mut m,
                if init == 19 {
                    11
                } else if init == 23 {
                    12
                } else {
                    13
                },
                &[0x3000, 3, 0x5000],
            );
            assert_eq!(
                m.read_array::<64>(0x4000).unwrap()[..length],
                m.read_array::<64>(0x5000).unwrap()[..length]
            );
        }
        call(&mut m, 23, &[0x2200]);
        m.write_array(0x2268, u32::MAX.to_le_bytes()).unwrap();
        let before = m.read_array::<112>(0x2200).unwrap();
        assert!(call(&mut m, 24, &[0x2200, 0x3000, 3]).fallback);
        assert_eq!(m.read_array::<112>(0x2200).unwrap(), before);
    }
    #[test]
    fn compression_roundtrips_and_allocator_callback_falls_back_before_effects() {
        let mut m = memory();
        let original = vec![b'x'; 512];
        m.write(0x3000, &original).unwrap();
        m.write_array(0x2100, 4096u64.to_le_bytes()).unwrap();
        assert_eq!(call(&mut m, 3, &[0x4000, 0x2100, 0x3000, 512, 6]).value, 0);
        let size = m.read_u64(0x2100).unwrap();
        m.write_array(0x2100, 4096u64.to_le_bytes()).unwrap();
        assert_eq!(call(&mut m, 4, &[0x5000, 0x2100, 0x4000, size]).value, 0);
        assert_eq!(m.read_array::<512>(0x5000).unwrap().as_slice(), original);
        let size = call(&mut m, 9, &[0x4000, 4096, 0x3000, 512, 3]).value;
        assert_eq!(call(&mut m, 10, &[0x5000, 4096, 0x4000, size]).value, 512);
        assert_eq!(m.read_array::<512>(0x5000).unwrap().as_slice(), original);
        m.write_array(0x2100, 0u64.to_le_bytes()).unwrap();
        assert_eq!(
            call(&mut m, 7, &[6, 4, 0, 0x3000, 512, 0x4000, 0x2100, 4096]).value,
            0
        );
        let size = m.read_u64(0x2100).unwrap();
        m.write_array(0x2100, 0u64.to_le_bytes()).unwrap();
        m.write_array(0x2110, 0u64.to_le_bytes()).unwrap();
        m.write_array(0x2120, u64::MAX.to_le_bytes()).unwrap();
        assert_eq!(
            call(
                &mut m,
                8,
                &[0x2120, 0, 0, 0x4000, 0x2100, size, 0x5000, 0x2110, 4096]
            )
            .value,
            0
        );
        assert_eq!(m.read_array::<512>(0x5000).unwrap().as_slice(), original);
        let before = m.read_array::<72>(0x4000).unwrap();
        assert!(
            call(
                &mut m,
                7,
                &[6, 4, 0xdead, 0x3000, 512, 0x4000, 0x2100, 4096]
            )
            .fallback
        );
        assert_eq!(m.read_array::<72>(0x4000).unwrap(), before);
    }
}
