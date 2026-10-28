// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn partial_unmap_reclaims_empty_host_granules_and_reuse_is_zeroed() {
    let mut memory = Memory::default();
    let base = 0x100000;
    let granule = host::page_size().unwrap();
    memory.map(base, WINDOW as u64, Permissions::RW).unwrap();
    for offset in (0..WINDOW).step_by(P) {
        memory.write_array(base + offset as u64, [0xa5; 8]).unwrap();
    }
    let owner = memory
        .mmu
        .window(base, false)
        .unwrap()
        .mapping
        .as_ref()
        .unwrap()
        .clone();
    memory.unmap(base, granule as u64).unwrap();
    assert_eq!(owner.retired_bytes(), granule);
    assert_eq!(
        memory.read_array::<8>(base + granule as u64).unwrap(),
        [0xa5; 8]
    );
    memory.map(base, granule as u64, Permissions::RW).unwrap();
    for offset in (0..granule).step_by(P) {
        assert_eq!(
            memory.read_array::<8>(base + offset as u64).unwrap(),
            [0; 8]
        );
    }
    memory.write_array(base, [0x5a; 8]).unwrap();
    assert_eq!(memory.read_array::<8>(base).unwrap(), [0x5a; 8]);
    assert_eq!(
        memory.read_array::<8>(base + granule as u64).unwrap(),
        [0xa5; 8]
    );
}

#[test]
fn reclaim_waits_for_fork_byte_owners_and_not_the_whole_window() {
    let mut memory = Memory::default();
    let base = 0x100000;
    let granule = host::page_size().unwrap();
    memory.map(base, WINDOW as u64, Permissions::RW).unwrap();
    for offset in (0..2 * granule).step_by(P) {
        memory.write_array(base + offset as u64, [42; 8]).unwrap();
    }
    let owner = memory
        .mmu
        .window(base, false)
        .unwrap()
        .mapping
        .as_ref()
        .unwrap()
        .clone();
    let mut child = memory.clone();
    memory.unmap(base, granule as u64).unwrap();
    assert_eq!(owner.retired_bytes(), 0);
    assert_eq!(child.read_array::<8>(base).unwrap(), [42; 8]);
    child.unmap(base, granule as u64).unwrap();
    assert_eq!(owner.retired_bytes(), granule);
    assert_eq!(
        child.read_array::<8>(base + granule as u64).unwrap(),
        [42; 8]
    );
}

#[test]
fn reclaim_retires_cached_frames_after_the_last_execution_view() {
    let mut memory = Memory::default();
    let base = 0x100000;
    let granule = host::page_size().unwrap();
    memory
        .map(base, (2 * granule) as u64, Permissions::RW)
        .unwrap();
    for offset in (0..2 * granule).step_by(P) {
        memory.write_array(base + offset as u64, [17; 8]).unwrap();
    }
    let mut registry = parallel::Registry::default();
    let view = memory.parallel_view(&mut registry).unwrap();
    let frame = memory.frame(base).unwrap();
    let owner = memory.frames[frame]
        .as_ref()
        .unwrap()
        .bytes
        .physical()
        .unwrap()
        .0
        .clone();
    memory.unmap(base, granule as u64).unwrap();
    assert_eq!(owner.retired_bytes(), 0);
    assert_eq!(view.read_array::<8>(base).unwrap(), [17; 8]);
    drop(view);
    assert_eq!(memory.reclaim_unused(), granule / P);
    assert_eq!(owner.retired_bytes(), granule);
    let resumed = memory.parallel_view(&mut registry).unwrap();
    assert!(resumed.read_array::<8>(base).is_err());
    assert_eq!(
        resumed.read_array::<8>(base + granule as u64).unwrap(),
        [17; 8]
    );
    assert_eq!(
        registry.metrics.full_rebuilds, 1,
        "reclamation preserves incremental preparation"
    );
}
use std::{os::unix::process::ExitStatusExt, process::Command};

#[test]
fn software_zero_publication_keeps_coordinator_reads_coherent() {
    let mut memory = Memory::default();
    let base = 0x40000;
    memory.map(base, 65536, Permissions::RW).unwrap();
    // Warm the coordinator before a worker materializes independent software
    // storage; its old zero-filled CPU arena must never hide the real bytes.
    assert_eq!(memory.read_array::<8>(base).unwrap(), [0; 8]);
    let mut registry = crate::parallel::Registry::default();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    view.write_array(base, [42u8; 8]).unwrap();
    assert_eq!(view.read_array::<8>(base).unwrap(), [42; 8]);
    drop(view);
    memory.commit_parallel().unwrap();
    assert_eq!(memory.read_array::<8>(base).unwrap(), [42; 8]);
    memory.write_array(base + 8, [17u8; 8]).unwrap();
    let view = memory.parallel_view(&mut registry).unwrap();
    assert_eq!(view.read_array::<8>(base).unwrap(), [42; 8]);
    assert_eq!(view.read_array::<8>(base + 8).unwrap(), [17; 8]);
    assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
}

#[test]
fn untouched_worker_pages_release_physical_va_on_fork() {
    let base = 0x400000;
    let mut parent = Memory::default();
    parent.mmu.granule = 16384;
    parent
        .map(base, 4 * WINDOW as u64, Permissions::RW)
        .unwrap();
    let physical: Vec<_> = parent
        .mmu
        .windows
        .borrow()
        .values()
        .map(|window| Arc::downgrade(window.mapping.as_ref().unwrap()))
        .collect();
    assert!(!physical.is_empty());
    let mut registry = crate::parallel::Registry::default();
    let view = parent.parallel_view(&mut registry).unwrap();
    assert_eq!(view.read_array::<8>(base).unwrap(), [0; 8]);
    drop(view);
    parent.commit_parallel().unwrap();
    let mut child = parent.clone();
    assert!(
        physical.iter().all(|owner| owner.upgrade().is_none()),
        "unwritten worker pages must not pin retired physical windows across fork"
    );
    assert_eq!(parent.resident_bytes(), 0);
    assert_eq!(child.resident_bytes(), 0);
    let mut view = child.parallel_view(&mut registry).unwrap();
    view.write_array(base + PAGE_SIZE, [42u8; 8]).unwrap();
    drop(view);
    child.commit_parallel().unwrap();
    assert_eq!(child.resident_bytes(), PAGE_SIZE as usize);
    assert_eq!(child.read_array::<8>(base + PAGE_SIZE).unwrap(), [42; 8]);
    assert_eq!(parent.read_array::<8>(base + PAGE_SIZE).unwrap(), [0; 8]);
    parent.write_array(base + PAGE_SIZE, [17u8; 8]).unwrap();
    assert_eq!(child.read_array::<8>(base + PAGE_SIZE).unwrap(), [42; 8]);
}

#[test]
fn forked_untouched_parallel_pages_stay_sparse_when_host_groups_relocate() {
    let base = 0x40000;
    let len = 16 * PAGE_SIZE;
    let mut parent = Memory::default();
    parent.mmu.granule = 16384;
    parent.map(base, len, Permissions::RW).unwrap();
    let mut registry = crate::parallel::Registry::default();
    drop(parent.parallel_view(&mut registry).unwrap());
    parent.commit_parallel().unwrap();
    assert_eq!(parent.resident_bytes(), 0);
    let mut child = parent.clone();
    child.mmu.granule = 16384;
    child.refresh_mapping_mmu(base, len);
    assert!(
        child.pages.values().all(|&i| {
            let page = child.frames[i].as_ref().unwrap();
            page.bytes.is_zero() && !page.charge.resident()
        }),
        "relocating untouched aliases must not copy/materialize zero RAM"
    );
    #[cfg(target_os = "linux")]
    {
        let window = child.mmu.window(base, false).unwrap();
        let owner = window.mapping.as_ref().unwrap();
        let mut resident = vec![0u8; WINDOW / host::page_size().unwrap()];
        // SAFETY: mincore only reports residency for this complete live mapping.
        assert_eq!(
            unsafe { libc::mincore(owner.kernel.as_ptr().cast(), WINDOW, resident.as_mut_ptr()) },
            0
        );
        assert!(
            resident.iter().all(|p| p & 1 == 0),
            "no physical zero-page copy"
        );
    }
    child.write_array(base + PAGE_SIZE, [42; 8]).unwrap();
    assert_eq!(child.resident_bytes(), PAGE_SIZE as usize);
    assert_eq!(parent.read_array::<8>(base + PAGE_SIZE).unwrap(), [0; 8]);
    assert_eq!(child.read_array::<8>(base).unwrap(), [0; 8]);
    assert_eq!(child.read_array::<8>(base + PAGE_SIZE).unwrap(), [42; 8]);
    parent.write_array(base + 2 * PAGE_SIZE, [17; 8]).unwrap();
    assert_eq!(child.read_array::<8>(base + 2 * PAGE_SIZE).unwrap(), [0; 8]);
}

#[test]
fn retired_and_empty_cpu_windows_release_va_without_dropping_fork_bytes() {
    let mut memory = Memory::default();
    let base = 0x40000;
    memory.map(base, 65536, Permissions::RW).unwrap();
    memory.write_array(base, [42; 8]).unwrap();
    let window = memory.mmu.window(base, false).unwrap();
    let cpu_view = Rc::downgrade(&window);
    let physical = Arc::downgrade(window.mapping.as_ref().unwrap());
    drop(window);
    let child = memory.clone();
    assert!(
        cpu_view.upgrade().is_none(),
        "fork retains bytes, not retired CPU VA"
    );
    assert!(physical.upgrade().is_some());
    assert_eq!(child.read_array::<8>(base), Ok([42; 8]));
    memory.write_array(base, [17; 8]).unwrap();
    let window = memory.mmu.window(base, false).unwrap();
    let replacement = Rc::downgrade(&window);
    drop(window);
    memory.unmap(base, 65536).unwrap();
    assert!(
        replacement.upgrade().is_none(),
        "last unmap releases the empty window"
    );
    assert_eq!(child.read_array::<8>(base), Ok([42; 8]));
    drop(child);
    assert!(physical.upgrade().is_none());
}

#[test]
fn unavailable_host_window_stays_on_checked_software_until_a_mapping_boundary() {
    let mut memory = Memory::default();
    let base = 0x40000;
    memory.map(base, 65536, Permissions::RW).unwrap();
    memory.mmu.retire();
    // Same state as Window::new declining the optional host VA reservation.
    memory
        .mmu
        .unavailable
        .borrow_mut()
        .insert(base & !(WINDOW as u64 - 1));
    let preparations = memory.mmu.preparations.get();
    for value in 0..1000u32 {
        memory.write_array(base, value.to_le_bytes()).unwrap();
    }
    assert_eq!(memory.read_array::<4>(base), Ok(999u32.to_le_bytes()));
    assert_eq!(memory.mmu.preparations.get(), preparations);
    assert!(memory.mmu.windows.borrow().is_empty());
    memory.protect(base, 65536, Permissions::R).unwrap();
    assert!(memory.mmu.unavailable.borrow().is_empty());
    assert_eq!(memory.mmu.read::<4>(base), Some(999u32.to_le_bytes()));
    assert!(memory.write_array(base, [7]).is_err());
    let mut empty = Memory::default();
    empty
        .mmu
        .unavailable
        .borrow_mut()
        .insert(base & !(WINDOW as u64 - 1));
    empty.unmap(base, 65536).unwrap();
    assert!(empty.mmu.unavailable.borrow().is_empty());
}

#[test]
fn actual_cpu_alias_obeys_hardware_protections_and_keeps_kernel_bytes_coherent() {
    let mut memory = Memory::default();
    let base = 0x40000;
    memory.map(base, 65536, Permissions::RW).unwrap();
    // This test exercises raw backend stores, below the production TLB's
    // first-write accounting gate. Commit the target page through Memory first.
    memory.write_array(base, [0u8]).unwrap();
    assert!(
        memory.mmu.read::<8>(base).is_some(),
        "test requires a real host mapping"
    );
    for offset in 0..32 {
        macro_rules! check {
            ($n:literal) => {{
                let address = base + offset;
                let value = [0xa5; $n];
                assert!(memory.mmu.write(address, value).is_some());
                let mut plain = [0; $n];
                memory.read(address, &mut plain).unwrap();
                assert_eq!(plain, value);
                assert_eq!(memory.mmu.read::<$n>(address), Some(value));
            }};
        }
        check!(1);
        check!(2);
        check!(4);
        check!(8);
        check!(16);
    }
    memory.protect(base, 65536, Permissions::R).unwrap();
    let before = memory.read_array::<8>(base).unwrap();
    assert_eq!(memory.mmu.write(base, [0; 8]), None);
    assert_eq!(memory.read_array::<8>(base).unwrap(), before);
    memory.protect(base, 65536, Permissions::NONE).unwrap();
    assert_eq!(memory.mmu.read::<8>(base), None);
    assert_eq!(
        memory.read_array::<8>(base),
        Err(MemoryError::Permission {
            address: base,
            access: Access::Read
        })
    );
    memory
        .protect(
            base,
            65536,
            Permissions {
                read: false,
                write: true,
                execute: false,
            },
        )
        .unwrap();
    memory.write_array(base, [9; 8]).unwrap();
    assert_eq!(memory.mmu.read::<8>(base), None);
    assert!(memory.read_array::<8>(base).is_err());
}

#[test]
fn sixteen_kib_host_groups_demote_and_recover_without_permission_leaks() {
    let mut memory = Memory::default();
    memory.mmu.granule = 16384.max(host::page_size().unwrap());
    let base = 0x40000;
    memory.map(base, 65536, Permissions::RW).unwrap();
    memory.write_array(base, [42; 8]).unwrap();
    assert_eq!(memory.mmu.read::<8>(base), Some([42; 8]));
    memory
        .protect(base + PAGE_SIZE, PAGE_SIZE, Permissions::R)
        .unwrap();
    assert_eq!(memory.mmu.read::<8>(base), None);
    assert_eq!(memory.read_array::<8>(base), Ok([42; 8]));
    assert!(memory.write_array(base + PAGE_SIZE, [7; 8]).is_err());
    memory
        .protect(base + PAGE_SIZE, PAGE_SIZE, Permissions::RW)
        .unwrap();
    assert_eq!(memory.mmu.read::<8>(base), Some([42; 8]));
    memory.unmap(base + PAGE_SIZE, PAGE_SIZE).unwrap();
    assert_eq!(memory.mmu.read::<8>(base), None);
    memory
        .map(base + PAGE_SIZE, PAGE_SIZE, Permissions::RW)
        .unwrap();
    assert_eq!(memory.mmu.read::<8>(base), Some([42; 8]));
    assert_eq!(memory.read_array::<8>(base + PAGE_SIZE), Ok([0; 8]));
}

#[test]
fn software_only_host_groups_do_not_rebuild_on_each_store() {
    let mut memory = Memory::default();
    memory.mmu.granule = 16384.max(host::page_size().unwrap());
    let base = 0x40000;
    // One guest page leaves holes in a 16KiB host group. This is ordinary
    // small-heap RAM, not a file/device backing that can be skipped separately.
    memory.map(base, PAGE_SIZE, Permissions::RW).unwrap();
    let prepared = memory.mmu.preparations.get();
    for value in 0..1000u32 {
        memory.write_array(base, value.to_le_bytes()).unwrap();
    }
    assert_eq!(memory.read_array::<4>(base), Ok(999u32.to_le_bytes()));
    assert_eq!(memory.mmu.preparations.get(), prepared);
    // Mapping the rest must invalidate the negative result and enable aliases.
    memory
        .map(
            base + PAGE_SIZE,
            memory.mmu.granule as u64 - PAGE_SIZE,
            Permissions::RW,
        )
        .unwrap();
    assert_eq!(memory.mmu.read::<4>(base), Some(999u32.to_le_bytes()));
    memory
        .protect(base + PAGE_SIZE, PAGE_SIZE, Permissions::R)
        .unwrap();
    let prepared = memory.mmu.preparations.get();
    for value in 0..1000u32 {
        memory.write_array(base, value.to_le_bytes()).unwrap();
    }
    assert_eq!(memory.mmu.preparations.get(), prepared);
    assert!(memory.write_array(base + PAGE_SIZE, [1u8]).is_err());
    memory
        .protect(base + PAGE_SIZE, PAGE_SIZE, Permissions::RW)
        .unwrap();
    assert_eq!(memory.mmu.read::<4>(base), Some(999u32.to_le_bytes()));
}

#[test]
fn fork_remap_discard_and_native_calls_never_leave_stale_hardware_aliases() {
    let mut memory = Memory::default();
    memory.map(0x40000, 65536, Permissions::RW).unwrap();
    memory.write_array(0x40000, [11; 8]).unwrap();
    let mut child = memory.clone();
    assert!(memory.mmu.windows.borrow().is_empty());
    assert!(child.mmu.windows.borrow().is_empty());
    child
        .with_write_chunk(0x40000, 8, |bytes| bytes.fill(22))
        .unwrap();
    assert_eq!(child.mmu.read::<8>(0x40000), Some([22; 8]));
    assert_eq!(memory.read_array::<8>(0x40000), Ok([11; 8]));
    memory.write_array(0x40008, [33; 8]).unwrap();
    assert_eq!(child.read_array::<8>(0x40008), Ok([0; 8]));
    memory
        .remap(0x40000, 65536, 0x40000, 131072, false)
        .unwrap();
    assert_eq!(memory.read_array::<8>(0x40000), Ok([11; 8]));
    assert_eq!(memory.read_array::<8>(0x40008), Ok([33; 8]));
    memory.discard(0x40000, PAGE_SIZE).unwrap();
    assert_eq!(memory.mmu.read::<8>(0x40000), Some([0; 8]));
    memory
        .remap(0x40000, 131072, 0x7fffff000000, 131072, false)
        .unwrap();
    assert!(memory.read_array::<8>(0x40000).is_err());
    assert_eq!(memory.mmu.read::<8>(0x7fffff000000), Some([0; 8]));
}

#[test]
fn worker_cpu_aliases_native_bytes_and_dirty_publication_share_one_region_protocol() {
    let mut memory = Memory::default();
    memory.map(0x40000, 65536, Permissions::RW).unwrap();
    // This case specifically exercises physical CPU aliases. Unwritten sparse
    // zeros now keep software storage until real writes; materialize the host
    // groups before freezing their physical addresses for this view.
    for address in (0x40000..0x50000).step_by(PAGE_SIZE as usize) {
        memory.write_array(address, [0u8]).unwrap();
    }
    let mut registry = parallel::Registry::default();
    let mut worker = memory.parallel_view(&mut registry).unwrap();
    let peer = worker.clone();
    assert_eq!(worker.mmu_read::<8>(0x40000), Some([0; 8]));
    assert_eq!(worker.read_array::<8>(0x40000), Ok([0; 8]));
    assert_eq!(memory.resident_bytes(), 65536);
    worker.write_array(0x40000, [7; 8]).unwrap();
    assert_eq!(worker.mmu_read::<8>(0x40000), Some([7; 8]));
    assert_eq!(peer.mmu_read::<8>(0x40000), Some([7; 8]));
    worker.fill_with(0x40000, 8, |bytes| bytes.fill(9)).unwrap();
    assert_eq!(peer.mmu_read::<8>(0x40000), Some([9; 8]));
    drop(worker);
    drop(peer);
    memory.commit_parallel().unwrap();
    assert_eq!(memory.read_array::<8>(0x40000), Ok([9; 8]));
    memory.protect(0x40000, 65536, Permissions::R).unwrap();
    let mut worker = memory.parallel_view(&mut registry).unwrap();
    assert!(worker.write_array(0x40000, [4; 8]).is_err());
    assert_eq!(worker.mmu_read::<8>(0x40000), Some([9; 8]));
}

#[test]
fn unrelated_host_faults_preserve_queryable_host_signal_behavior() {
    fn probe(mode: &str) -> std::process::ExitStatus {
        let exe = std::env::current_exe().unwrap();
        let args = ["--exact", "mmu::tests::signal_probe_child"];
        let result = Command::new(&exe)
            .args(args)
            .env("TRAMES_MMU_SIGNAL_CHILD", mode)
            .status();
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        if result
            .as_ref()
            .is_err_and(|error| error.raw_os_error() == Some(libc::ENOEXEC))
        {
            // Linux-user QEMU does not register binfmt_misc in every CI/container.
            // Re-exec the child through the same independent CPU explicitly.
            return Command::new(
                std::env::var("QEMU_AARCH64").unwrap_or_else(|_| "qemu-aarch64".into()),
            )
            .args(["-cpu", "max"])
            .arg(exe)
            .args(args)
            .env("TRAMES_MMU_SIGNAL_CHILD", mode)
            .status()
            .unwrap();
        }
        result.unwrap()
    }
    assert_eq!(probe("default").signal(), Some(libc::SIGSEGV));
    assert!(probe("chain").success());
    let mask = probe("mask");
    assert!(mask.success(), "{mask:?}");
    let native = probe("native-reset");
    assert!(
        native.success() || native.signal() == Some(libc::SIGSEGV),
        "native reset: {native:?}"
    );
    let queried = probe("roundtrip-reset");
    assert!(queried.success() || queried.signal() == Some(libc::SIGSEGV));
    let wrapped = probe("reset");
    assert_eq!(
        (wrapped.code(), wrapped.signal()),
        (queried.code(), queried.signal()),
        "forwarding must preserve the configuration this OS query can recover"
    );
}
#[test]
fn signal_probe_child() {
    let Ok(mode) = std::env::var("TRAMES_MMU_SIGNAL_CHILD") else {
        return;
    };
    static SEEN: AtomicUsize = AtomicUsize::new(0);
    static CHECK_MASK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    extern "C" fn previous(_: i32) {
        // SAFETY: sigprocmask/sigismember are async-signal-safe. Record masks
        // without assertions, formatting, allocation or panic in the callback.
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask);
            if CHECK_MASK.load(Ordering::Relaxed) {
                let correct = libc::sigismember(&mask, libc::SIGUSR1) == 1
                    && libc::sigismember(&mask, libc::SIGSEGV) == 0;
                libc::_exit(if correct { 0 } else { 1 });
            }
            SEEN.fetch_add(1, Ordering::Relaxed);
        }
    }
    // SAFETY: isolated subprocess; the expected crash cannot affect the runner.
    unsafe {
        libc::setrlimit(
            libc::RLIMIT_CORE,
            &libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            },
        );
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut action.sa_mask);
        CHECK_MASK.store(mode == "mask", Ordering::Relaxed);
        if mode == "chain" || mode.ends_with("reset") || mode == "mask" {
            action.sa_sigaction = previous as *const () as usize;
            libc::sigaddset(&mut action.sa_mask, libc::SIGUSR1);
            action.sa_flags = libc::SA_NODEFER
                | if mode.ends_with("reset") {
                    libc::SA_RESETHAND
                } else {
                    0
                };
        } else {
            // Explicit default, independent of a sanitizer's own crash handler.
            action.sa_sigaction = libc::SIG_DFL;
        }
        assert_eq!(
            libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()),
            0
        );
        if mode == "native-reset" || mode == "roundtrip-reset" {
            if mode == "roundtrip-reset" {
                // XNU's getter omits ps_sigreset/SA_RESETHAND. Independently
                // measure that native query/restore boundary without our MMU.
                let mut queried: libc::sigaction = std::mem::zeroed();
                assert_eq!(
                    libc::sigaction(libc::SIGSEGV, std::ptr::null(), &mut queried),
                    0
                );
                assert_eq!(
                    libc::sigaction(libc::SIGSEGV, &queried, std::ptr::null_mut()),
                    0
                );
            }
            libc::raise(libc::SIGSEGV);
            assert_eq!(SEEN.load(Ordering::Relaxed), 1);
            libc::raise(libc::SIGSEGV);
            assert_eq!(SEEN.load(Ordering::Relaxed), 2);
            return;
        }
        let mapping = host::CpuMapping::new().expect("hardware mapping");
        let mut bytes = [0; 8];
        assert!(!access::access::<8>(
            false,
            mapping.cpu.as_ptr(),
            bytes.as_mut_ptr()
        ));
        assert_eq!(SEEN.load(Ordering::Relaxed), 0);
        if mode == "default" || mode == "mask" {
            // A synchronous hardware fault preserves the OS handler mask even
            // under TSan, whose deferred user-signal dispatcher changes masks.
            access::access::<8>(false, std::ptr::null_mut(), bytes.as_mut_ptr());
            panic!("non-arena fault was incorrectly swallowed");
        } else {
            libc::raise(libc::SIGSEGV);
            assert_eq!(SEEN.load(Ordering::Relaxed), 1);
            assert!(!access::access::<8>(
                false,
                mapping.cpu.as_ptr(),
                bytes.as_mut_ptr()
            ));
            if mode == "reset" {
                libc::raise(libc::SIGSEGV);
                assert_eq!(SEEN.load(Ordering::Relaxed), 2);
            }
        }
    }
}

#[test]
fn cached_cpu_aliases_are_revoked_before_fork_remap_and_page_reuse() {
    let base = 0x40000;
    let mut first = Memory::default();
    first.map(base, 65536, Permissions::RW).unwrap();
    first.write_array(base, [11; 8]).unwrap();
    assert_eq!(first.read_array::<8>(base), Ok([11; 8]));
    assert_ne!(first.translation(base).unwrap().cpu, 0);
    let mut second = Memory::default();
    second.map(base, 65536, Permissions::RW).unwrap();
    second.write_array(base, [22; 8]).unwrap();
    assert_eq!(second.read_array::<8>(base), Ok([22; 8]));
    let child = first.clone();
    assert_eq!(first.translations[Translation::slot(base)].get().cpu, 0);
    first.write_array(base, [33; 8]).unwrap();
    assert_eq!(child.read_array::<8>(base), Ok([11; 8]));
    first.unmap(base, 65536).unwrap();
    first.map(base, 65536, Permissions::RW).unwrap();
    assert_eq!(first.read_array::<8>(base), Ok([0; 8]));
    first.protect(base, 65536, Permissions::R).unwrap();
    assert!(first.write_array(base, [44; 8]).is_err());
    assert_eq!(first.read_array::<8>(base), Ok([0; 8]));
    first
        .remap(base, 65536, 0x7fffff000000, 65536, false)
        .unwrap();
    assert!(first.read_array::<8>(base).is_err());
    assert_eq!(first.read_array::<8>(0xab007fffff000000), Ok([0; 8]));
    assert_eq!(first.share().read_array::<8>(0x7fffff000000), Ok([0; 8]));
}

#[test]
fn direct_mapped_pages_keep_conflicts_and_retained_worker_snapshots_separate() {
    let mut memory = Memory::default();
    let bases: Vec<_> = (0..40).map(|i| 0x10000 + i * WINDOW as u64).collect();
    for (i, &base) in bases.iter().enumerate() {
        memory.map(base, 65536, Permissions::RW).unwrap();
        memory
            .write_array(base, (i as u64 + 1).to_le_bytes())
            .unwrap();
    }
    for _ in 0..4 {
        for (i, &base) in bases.iter().enumerate().rev() {
            assert_eq!(
                memory.read_array::<8>(base),
                Ok((i as u64 + 1).to_le_bytes())
            );
        }
    }
    let mut registry = parallel::Registry::default();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    for (i, &base) in bases.iter().enumerate().rev() {
        assert_eq!(view.read_array::<8>(base), Ok((i as u64 + 1).to_le_bytes()));
        view.write_array(base, (i as u64 + 42).to_le_bytes())
            .unwrap();
    }
    let retained = view.clone();
    drop(view);
    memory.commit_parallel().unwrap();
    memory.protect(bases[39], 65536, Permissions::R).unwrap();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    assert!(view.write_array(bases[39], [0; 8]).is_err());
    assert_eq!(retained.read_array::<8>(bases[39]), Ok(81u64.to_le_bytes()));
    assert_eq!(memory.read_array::<8>(bases[39]), Ok(81u64.to_le_bytes()));
}

#[test]
fn cached_missing_windows_are_invalidated_before_later_mapping_or_fork_write() {
    let mut memory = Memory::default();
    let base = 0x40000;
    for _ in 0..4 {
        assert_eq!(memory.mmu.read::<8>(base), None);
    }
    memory.map(base, 65536, Permissions::RW).unwrap();
    assert_eq!(memory.mmu.read::<8>(base), Some([0; 8]));
    let child = memory.clone();
    for _ in 0..4 {
        assert_eq!(memory.mmu.read::<8>(base), None);
    }
    memory.write_array(base, [42; 8]).unwrap();
    assert_eq!(memory.mmu.read::<8>(base), Some([42; 8]));
    assert_eq!(child.read_array::<8>(base), Ok([0; 8]));
}

#[test]
fn native_cow_promotion_invalidates_cached_neighbor_pages() {
    let base = 0x40000;
    let mut memory = Memory::default();
    memory.map(base, 65536, Permissions::RW).unwrap();
    memory.write_array(base, [11; 8]).unwrap();
    memory.write_array(base + PAGE_SIZE, [22; 8]).unwrap();
    let child = memory.clone();
    // Warm software-only entries after retirement, before native promotion.
    assert_eq!(memory.read_array::<8>(base), Ok([11; 8]));
    assert_eq!(memory.read_array::<8>(base + PAGE_SIZE), Ok([22; 8]));
    assert_eq!(memory.translation(base).unwrap().cpu, 0);
    memory
        .with_write_chunk(base, 8, |bytes| bytes.fill(33))
        .unwrap();
    memory
        .with_write_chunk(base + PAGE_SIZE, 8, |bytes| bytes.fill(44))
        .unwrap();
    assert_eq!(memory.read_array::<8>(base), Ok([33; 8]));
    assert_eq!(memory.read_array::<8>(base + PAGE_SIZE), Ok([44; 8]));
    assert_ne!(memory.translation(base).unwrap().cpu, 0);
    assert_ne!(memory.translation(base + PAGE_SIZE).unwrap().cpu, 0);
    assert_eq!(child.read_array::<8>(base), Ok([11; 8]));
    assert_eq!(child.read_array::<8>(base + PAGE_SIZE), Ok([22; 8]));
    memory.discard(base, 65536).unwrap();
    assert_eq!(memory.read_array::<8>(base), Ok([0; 8]));
    assert_eq!(memory.read_array::<8>(base + PAGE_SIZE), Ok([0; 8]));
}

#[test]
fn host_group_relocation_refreshes_unchanged_parallel_neighbors() {
    let mut memory = Memory::default();
    let granule = 16384.max(host::page_size().unwrap());
    memory.mmu.granule = granule;
    let base = 0x40000;
    memory.map(base, granule as u64, Permissions::RW).unwrap();
    let mut registry = parallel::Registry::default();
    let mut retained = memory.parallel_view(&mut registry).unwrap();
    retained.write_array(base, [11; 8]).unwrap();
    memory.commit_parallel().unwrap();
    // A retained view retires the coordinator's old CPU window. Rehoming one
    // guest page can move its whole 16 KiB host group, including untouched peers.
    memory.protect(base, PAGE_SIZE, Permissions::RW).unwrap();
    assert_eq!(retained.read_array::<8>(base), Ok([11; 8]));
    drop(retained);
    let mut next = memory.parallel_view(&mut registry).unwrap();
    for index in 0..granule / PAGE_SIZE as usize {
        next.write_array(base + index as u64 * PAGE_SIZE, [42 + index as u8; 8])
            .unwrap();
    }
    drop(next);
    memory.commit_parallel().unwrap();
    for index in 0..granule / PAGE_SIZE as usize {
        assert_eq!(
            memory.read_array::<8>(base + index as u64 * PAGE_SIZE),
            Ok([42 + index as u8; 8])
        );
    }
    assert!(registry.metrics.incremental_updates > 0);
}

#[test]
fn hardware_admission_keeps_software_cpu_windows_disabled_across_mapping_writes_and_fork() {
    let mut parent = Memory::default();
    parent.map(0x40000, 4 * PAGE_SIZE, Permissions::RW).unwrap();
    parent.write_array(0x40000, [0x31; 8]).unwrap();
    parent.prepare_hardware().unwrap();
    assert!(!parent.mmu.cpu_aliases_enabled());
    for i in 0..8 {
        let address = 0x100000 + i * 4 * PAGE_SIZE;
        parent.map(address, 4 * PAGE_SIZE, Permissions::RW).unwrap();
        parent.write_array(address, [i as u8; 8]).unwrap();
        parent.protect(address, PAGE_SIZE, Permissions::R).unwrap();
        assert!(parent.mmu.windows.borrow().is_empty());
    }
    let mut child = parent.clone();
    assert!(!child.mmu.cpu_aliases_enabled());
    let mut registry = crate::parallel::Registry::default();
    registry.use_hardware();
    let mut view = child.parallel_view(&mut registry).unwrap();
    view.enable_hardware();
    view.write_array(0x40000, [0x72; 8]).unwrap();
    drop(view);
    child.commit_parallel().unwrap();
    assert_eq!(child.read_array::<8>(0x40000).unwrap(), [0x72; 8]);
    assert_eq!(parent.read_array::<8>(0x40000).unwrap(), [0x31; 8]);
    assert!(child.mmu.windows.borrow().is_empty());
    assert!(parent.mmu.windows.borrow().is_empty());
    // A fresh interpreter address space keeps its protected alias fast path.
    let mut software = Memory::default();
    software
        .map(0x40000, 4 * PAGE_SIZE, Permissions::RW)
        .unwrap();
    assert!(software.mmu.cpu_aliases_enabled());
    assert!(!software.mmu.windows.borrow().is_empty());
}
