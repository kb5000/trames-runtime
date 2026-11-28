// SPDX-License-Identifier: GPL-3.0-or-later
//! Public-library acceptance runner; fixture directory contains original ELFs.
use super::{Runtime, RuntimeOptions};
use std::path::PathBuf;
type TestRuntime = Runtime<trames_cpu::Cpu>;
use trames_vfs::{DiskOptions, Vfs};
fn run_case(input: PathBuf, enabled: bool, store: PathBuf, cpus: usize) {
    let mut v = Vfs::open_disk(&store, DiskOptions::default()).unwrap();
    if input.join("ld-musl-aarch64.so.1").exists() {
        v.import_executable(
            b"/lib/ld-musl-aarch64.so.1",
            std::fs::read(input.join("ld-musl-aarch64.so.1")).unwrap(),
        )
        .unwrap();
        for name in [b"/lib/libc.musl-aarch64.so.1".as_slice(), b"/lib/libc.so"] {
            v.symlink_at(b"/lib/ld-musl-aarch64.so.1", trames_vfs::AT_FDCWD, name)
                .unwrap();
        }
    } else {
        v.import_executable(
            b"/lib/ld-linux-aarch64.so.1",
            std::fs::read(input.join("ld-linux-aarch64.so.1")).unwrap(),
        )
        .unwrap();
        v.import_file(
            b"/lib/aarch64-linux-gnu/libc.so.6",
            std::fs::read(input.join("libc.so.6")).unwrap(),
        )
        .unwrap();
    }
    for name in [
        "libz.so.1",
        "libzstd.so.1",
        "liblzma.so.5",
        "libcrypto.so.3",
    ] {
        let bytes = std::fs::read(input.join(format!("original-{name}"))).unwrap();
        if enabled && cpus == 1 {
            let mut modified = bytes.clone();
            let at = modified.len() - 1;
            modified[at] ^= 1;
            assert!(trames_accel::compute_elf::adapt(&modified, true).is_none());
        }
        v.import_file(format!("/usr/lib/{name}").as_bytes(), bytes)
            .unwrap();
    }
    let fixture = std::fs::read(input.join("compute-all-probe")).unwrap();
    v.import_executable(b"/bin/native-compute", fixture.clone())
        .unwrap();
    let mut runtime = TestRuntime::load_with_options(
        &fixture,
        &["/bin/native-compute".into()],
        &[],
        v,
        RuntimeOptions {
            pure_accelerator: enabled,
            ..Default::default()
        },
    )
    .unwrap();
    runtime.cpu_count = cpus;
    let mut output = trames_linux::CapturedOutput::default();
    let exit = runtime.run(&mut output, 500_000_000).unwrap();
    eprintln!(
        "{}",
        serde_json::json!({"family":input.file_name().unwrap().to_string_lossy(),"enabled":enabled,"cpus":cpus,"calls":runtime.metrics.native.compute_calls,"worker_calls":runtime.metrics.native.worker_calls,"operations":runtime.metrics.native.compute_operations,"fallbacks":runtime.metrics.native.compute_fallbacks})
    );
    assert_eq!(exit.code, 0, "{:?}", output.stderr.read(65536));
    if enabled {
        assert!(runtime.metrics.native.compute_calls > 0);
        assert_eq!(
            runtime.metrics.native.worker_calls,
            runtime.metrics.native.compute_calls
        );
    } else {
        assert_eq!(runtime.metrics.native.compute_calls, 0);
    }
}

#[test]
#[ignore = "requires original AArch64 compute libraries and the ABI fixture executable"]
fn native_compute_private_libraries_retain_original_fallback_and_run_on_workers() {
    let dirs = std::env::var_os("TRAMES_COMPUTE_FIXTURES").expect("fixture directories");
    for input in std::env::split_paths(&dirs) {
        for cpus in [1, 2] {
            for enabled in [false, true] {
                let store = std::env::temp_dir().join(format!(
                    "trames-compute-{}-{}-{}-{}",
                    std::process::id(),
                    input.file_name().unwrap().to_string_lossy(),
                    cpus,
                    enabled
                ));
                run_case(input.clone(), enabled, store.clone(), cpus);
                std::fs::remove_dir_all(store).unwrap();
            }
        }
    }
}

#[test]
fn native_compute_auxv_is_distinct_from_audio_capabilities() {
    for pure in [false, true] {
        for output in [false, true] {
            for input in [false, true] {
                let pairs = super::stack_auxv(RuntimeOptions {
                    pure_accelerator: pure,
                    audio_output: output,
                    audio_input: input,
                    ..Default::default()
                });
                let keys: std::collections::BTreeSet<_> = pairs.iter().map(|pair| pair.0).collect();
                assert_eq!(keys.len(), pairs.len());
                assert_eq!(
                    pairs
                        .iter()
                        .find(|p| p.0 == trames_audio::CAPS_KEY)
                        .unwrap()
                        .1,
                    u64::from(output) | (u64::from(input) << 1)
                );
            }
        }
    }
}
