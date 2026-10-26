// SPDX-License-Identifier: GPL-3.0-or-later
//! Original mallocng hot algorithms, ahead-of-time lowered to checked accesses.
use core::ffi::c_void;
use core::mem::MaybeUninit;

pub const MAX_WRITES: usize = 16;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Write {
    pub address: u64,
    pub value: u64,
    pub width: u32,
    padding: u32,
}
/// Private C transport descriptor; construction requires a stable scoped page borrow.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadPage {
    base: u64,
    bytes: *const u8,
}
impl ReadPage {
    /// # Safety
    /// `bytes` points to 4096 readable bytes matching guest page `base`, whose
    /// CPU permissions/backing were checked. Its owner retains the allocation unchanged
    /// until the next CAS callback or until execute returns. No host peer may
    /// write these bytes; concurrent workers must use the checked load callback.
    pub unsafe fn new(base: u64, bytes: *const u8) -> Self {
        Self { base, bytes }
    }
}
/// Every callback completes before C propagates failure. Page owners stay in the
/// callback context; the native code invalidates cached descriptors before CAS.
pub trait Access {
    fn load(&mut self, address: u64, width: usize) -> Result<u64, AccessFailure>;
    fn cas(
        &mut self,
        address: u64,
        old: u32,
        new: u32,
        writes: &[Write],
    ) -> Result<u32, AccessFailure>;
    fn read_pages_enabled(&self) -> bool {
        false
    }
    fn read_page(
        &mut self,
        _address: u64,
        _width: usize,
    ) -> Result<Option<ReadPage>, AccessFailure> {
        Ok(None)
    }
}
#[derive(Debug)]
pub struct AccessFailure;
#[repr(C)]
struct Callbacks {
    opaque: *mut c_void,
    load: unsafe extern "C" fn(*mut c_void, u64, u32, *mut u64) -> i32,
    cas: unsafe extern "C" fn(*mut c_void, u64, u32, u32, *const Write, u32, *mut u32) -> i32,
    read_page: Option<unsafe extern "C" fn(*mut c_void, u64, u32, *mut ReadPage) -> i32>,
}
#[repr(C)]
#[derive(Debug)]
pub struct ResultState {
    pub value: u64,
    pub meta: u64,
    pub index: u64,
    pub counter: u64,
    pub status: i32,
    write_count: u32,
    writes: [MaybeUninit<Write>; MAX_WRITES],
    pub load_callbacks: u32,
    pub page_callbacks: u32,
    pub direct_loads: u32,
    pub journal_writes: u32,
}
impl Default for ResultState {
    fn default() -> Self {
        Self {
            value: 0,
            meta: 0,
            index: 0,
            counter: 0,
            status: 0,
            write_count: 0,
            writes: [const { MaybeUninit::uninit() }; MAX_WRITES],
            load_callbacks: 0,
            page_callbacks: 0,
            direct_loads: 0,
            journal_writes: 0,
        }
    }
}
impl ResultState {
    pub fn pending_writes(&self) -> &[Write] {
        let count = self.write_count as usize;
        assert!(count <= MAX_WRITES, "matched native journal bound");
        // SAFETY: The count and buffer are private. Default creates an empty
        // journal; the paired C producer initializes each complete Write before
        // increasing count. CAS resets count only after consuming its initialized
        // prefix. No unused slot is read or exposed, and the slice borrows self.
        unsafe { core::slice::from_raw_parts(self.writes.as_ptr().cast(), count) }
    }
}
unsafe extern "C" {
    fn trames_native_allocator(
        callbacks: *const Callbacks,
        op: u32,
        pointer_or_size: u64,
        context: u64,
        mt: i32,
        index: u64,
        counter: u64,
        result: *mut ResultState,
    );
}
unsafe extern "C" fn load<A: Access>(p: *mut c_void, a: u64, n: u32, out: *mut u64) -> i32 {
    // SAFETY: execute lends exactly one exclusive A for the synchronous call;
    // C supplies a live stack output and retains neither pointer.
    match unsafe { (&mut *p.cast::<A>()).load(a, n as usize) } {
        Ok(value) => {
            unsafe { *out = value };
            0
        }
        Err(AccessFailure) => 1,
    }
}
unsafe extern "C" fn cas<A: Access>(
    p: *mut c_void,
    a: u64,
    old: u32,
    new: u32,
    writes: *const Write,
    count: u32,
    out: *mut u32,
) -> i32 {
    if count as usize > MAX_WRITES {
        return 1;
    }
    // SAFETY: The matched C producer lends its initialized journal, bounded by
    // MAX_WRITES, and a live uint32_t output. Neither borrow escapes this callback.
    let pending = unsafe { core::slice::from_raw_parts(writes, count as usize) };
    match unsafe { (&mut *p.cast::<A>()).cas(a, old, new, pending) } {
        Ok(value) => {
            unsafe { *out = value };
            0
        }
        Err(AccessFailure) => 1,
    }
}
unsafe extern "C" fn read_page<A: Access>(
    p: *mut c_void,
    a: u64,
    n: u32,
    out: *mut ReadPage,
) -> i32 {
    // SAFETY: Same scoped callback context; ReadPage constructors establish the
    // stronger ownership/lifetime contract. None caches only transport unavailability.
    match unsafe { (&mut *p.cast::<A>()).read_page(a, n as usize) } {
        Ok(page) => {
            unsafe {
                *out = page.unwrap_or(ReadPage {
                    base: (a & 0x00ffffffffffffff) & !4095,
                    bytes: core::ptr::null(),
                })
            };
            0
        }
        Err(AccessFailure) => 1,
    }
}
pub fn execute<A: Access>(
    access: &mut A,
    op: u32,
    value: u64,
    context: u64,
    mt: bool,
    index: u64,
    counter: u64,
) -> ResultState {
    let cb = Callbacks {
        opaque: (access as *mut A).cast(),
        load: load::<A>,
        cas: cas::<A>,
        read_page: access.read_pages_enabled().then_some(read_page::<A>),
    };
    let mut result = ResultState::default();
    // SAFETY: Private matched C ABI. Page descriptors use checked scoped borrows;
    // pending writes are published only by checked Rust transport. No cached
    // descriptor is used across a CAS, a guest callback or an execution return.
    unsafe {
        trames_native_allocator(
            &cb,
            op,
            value,
            context,
            i32::from(mt),
            index,
            counter,
            &mut result,
        )
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_transport_layout_matches_the_c_producer() {
        use core::mem::{offset_of, size_of};
        assert_eq!(size_of::<Write>(), 24);
        assert_eq!(size_of::<ReadPage>(), 16);
        assert_eq!(offset_of!(ResultState, writes), 40);
        assert_eq!(offset_of!(ResultState, load_callbacks), 424);
        assert_eq!(size_of::<ResultState>(), 440);
    }
}
