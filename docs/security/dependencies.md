# Third-party dependencies — Trames Runtime

Reviewed on 2026-11-26. Third-party components keep their own copyright and
license terms. The project's GPL-3.0-or-later license does not replace them.

The complete Rust license texts and copyright notices are collected in
[THIRD_PARTY_NOTICES.txt](../../THIRD_PARTY_NOTICES.txt). The reviewed source
origins, package checksums and selected license branches are recorded in
[third-party/licenses.json](../../third-party/licenses.json). `OR` selects an
available branch; `AND` retains every applicable additional term, including the
BSD notice in `encoding_rs` and the Unicode notice in `unicode-ident`.

<!-- BEGIN GENERATED RUST DEPENDENCIES -->

## Rust dependencies

Generated from the committed lockfiles. This is the complete locked closure,
including optional, build, test and other-target packages; it is not a claim
that every entry is linked into each product. Project-owned packages are excluded.

| Package | Version | Declared license | Selected license | Scope |
| --- | --- | --- | --- | --- |
| adler2 | 2.0.1 | 0BSD OR MIT OR Apache-2.0 | MIT | Main |
| ahash | 0.8.12 | MIT OR Apache-2.0 | MIT | Main |
| aho-corasick | 1.1.5 | Unlicense OR MIT | MIT | Auxiliary only |
| anstream | 1.0.0 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| anstyle | 1.0.14 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| ash | 0.38.0+1.3.281 | MIT OR Apache-2.0 | MIT | Main |
| autocfg | 1.5.1 | Apache-2.0 OR MIT | MIT | Auxiliary only |
| bitflags | 1.3.2 | MIT/Apache-2.0 | MIT | Main |
| bitflags | 2.13.1 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| bitflags | 2.13.2 | MIT OR Apache-2.0 | MIT | Main |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 | MIT | Main |
| bumpalo | 3.20.3 | MIT OR Apache-2.0 | MIT | Main |
| byteorder | 1.5.0 | Unlicense OR MIT | MIT | Main |
| cc | 1.4.3 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| cc | 1.8.0 | MIT OR Apache-2.0 | MIT | Main |
| cfg-if | 1.0.4 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | MIT | Main |
| cfg_aliases | 0.2.2 | MIT | MIT | Main |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| concat-idents | 1.1.5 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| const-random | 0.1.18 | MIT OR Apache-2.0 | MIT | Main |
| const-random-macro | 0.1.16 | MIT OR Apache-2.0 | MIT | Main |
| constant_time_eq | 0.6.1 | CC0-1.0 OR MIT-0 OR Apache-2.0 | MIT | Main |
| core_detect | 1.0.0 | MIT/Apache-2.0 | MIT | Main |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 | MIT | Main |
| crc | 3.4.0 | MIT OR Apache-2.0 | MIT | Main |
| crc-catalog | 2.5.0 | MIT OR Apache-2.0 | MIT | Main |
| crc32fast | 1.5.2 | MIT OR Apache-2.0 | MIT | Main |
| crunchy | 0.2.4 | MIT | MIT | Main |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 | MIT | Main |
| defmt | 0.3.100 | MIT OR Apache-2.0 | MIT | Main |
| defmt | 1.1.1 | MIT OR Apache-2.0 | MIT | Main |
| defmt-macros | 1.1.1 | MIT OR Apache-2.0 | MIT | Main |
| defmt-parser | 1.0.0 | MIT OR Apache-2.0 | MIT | Main |
| digest | 0.10.7 | MIT OR Apache-2.0 | MIT | Main |
| dlib | 0.5.3 | MIT | MIT | Auxiliary only |
| downcast-rs | 1.2.1 | MIT/Apache-2.0 | MIT | Main |
| encoding_rs | 0.8.42 | (Apache-2.0 OR MIT) AND BSD-3-Clause | MIT AND BSD-3-Clause | Main |
| env_filter | 2.0.0 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| env_logger | 0.11.11 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| equivalent | 1.0.3 | Apache-2.0 OR MIT | MIT | Main |
| errno | 0.3.14 | MIT OR Apache-2.0 | MIT | Main |
| ext4-view | 1.0.0 | MIT OR Apache-2.0 | MIT | Main |
| filetime | 0.2.29 | MIT/Apache-2.0 | MIT | Main |
| find-msvc-tools | 0.1.11 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| find-msvc-tools | 0.1.14 | MIT OR Apache-2.0 | MIT | Main |
| flate2 | 1.1.10 | MIT OR Apache-2.0 | MIT | Main |
| generic-array | 0.14.7 | MIT | MIT | Main |
| gethostname | 1.1.0 | Apache-2.0 | Apache-2.0 | Main |
| getrandom | 0.2.17 | MIT OR Apache-2.0 | MIT | Main |
| getrandom | 0.3.4 | MIT OR Apache-2.0 | MIT | Main |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | MIT | Main |
| hash32 | 0.3.1 | MIT OR Apache-2.0 | MIT | Main |
| hashbrown | 0.16.1 | MIT OR Apache-2.0 | MIT | Main |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 | MIT | Main |
| heapless | 0.8.0 | MIT OR Apache-2.0 | MIT | Main |
| indexmap | 2.14.2 | Apache-2.0 OR MIT | MIT | Main |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| itoa | 1.0.18 | MIT OR Apache-2.0 | MIT | Main |
| jiff | 0.2.35 | Unlicense OR MIT | MIT | Auxiliary only |
| jiff-core | 0.1.0 | Unlicense OR MIT | MIT | Auxiliary only |
| jiff-static | 0.2.35 | Unlicense OR MIT | MIT | Auxiliary only |
| js-sys | 0.3.107 | MIT OR Apache-2.0 | MIT | Main |
| libc | 0.2.189 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| libc | 0.2.190 | MIT OR Apache-2.0 | MIT | Main |
| libloading | 0.8.9 | ISC | ISC | Main |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | MIT | Main |
| lock_api | 0.4.14 | MIT OR Apache-2.0 | MIT | Main |
| log | 0.4.33 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| log | 0.4.34 | MIT OR Apache-2.0 | MIT | Main |
| managed | 0.8.0 | 0BSD | 0BSD | Main |
| memchr | 2.8.3 | Unlicense OR MIT | MIT | Main |
| memoffset | 0.9.1 | MIT | MIT | Auxiliary only |
| miniz_oxide | 0.9.1 | MIT OR Zlib OR Apache-2.0 | MIT | Main |
| multiversion_no_op | 1.0.0 | Apache-2.0 OR MIT | MIT | Main |
| nix | 0.31.3 | MIT | MIT | Main |
| once_cell | 1.21.4 | MIT OR Apache-2.0 | MIT | Main |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| parking_lot | 0.12.5 | MIT OR Apache-2.0 | MIT | Main |
| parking_lot_core | 0.9.12 | MIT OR Apache-2.0 | MIT | Main |
| pkg-config | 0.3.34 | MIT OR Apache-2.0 | MIT | Main |
| portable-atomic | 1.15.0 | Apache-2.0 OR MIT | MIT | Auxiliary only |
| portable-atomic-util | 0.2.7 | Apache-2.0 OR MIT | MIT | Auxiliary only |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 | MIT | Main |
| quick-xml | 0.41.0 | MIT | MIT | Main |
| quote | 1.0.47 | MIT OR Apache-2.0 | MIT | Main |
| r-efi | 5.3.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | MIT | Main |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | MIT | Main |
| raw-window-handle | 0.5.2 | MIT OR Apache-2.0 OR Zlib | MIT | Auxiliary only |
| raw-window-handle | 0.6.2 | MIT OR Apache-2.0 OR Zlib | MIT | Auxiliary only |
| redox_syscall | 0.5.18 | MIT | MIT | Main |
| regex | 1.13.1 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| regex-automata | 0.4.18 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| rustix | 1.1.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | MIT | Auxiliary only |
| rustix | 1.1.5 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | MIT | Main |
| rustversion | 1.0.23 | MIT OR Apache-2.0 | MIT | Main |
| scoped-tls | 1.0.1 | MIT/Apache-2.0 | MIT | Auxiliary only |
| scopeguard | 1.2.0 | MIT OR Apache-2.0 | MIT | Main |
| serde | 1.0.229 | MIT OR Apache-2.0 | MIT | Main |
| serde_core | 1.0.229 | MIT OR Apache-2.0 | MIT | Main |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 | MIT | Main |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | MIT | Main |
| serde_spanned | 1.1.3 | MIT OR Apache-2.0 | MIT | Main |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | MIT | Main |
| shlex | 2.0.1 | MIT OR Apache-2.0 | MIT | Main |
| simd-adler32 | 0.3.10 | MIT | MIT | Main |
| simdutf8 | 0.1.5 | MIT OR Apache-2.0 | MIT | Main |
| smallvec | 1.15.2 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| smallvec | 1.16.3 | MIT OR Apache-2.0 | MIT | Main |
| smoltcp | 0.12.0 | 0BSD | 0BSD | Main |
| socket2 | 0.6.1 | MIT OR Apache-2.0 | MIT | Main |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 | MIT | Main |
| syn | 2.0.119 | MIT OR Apache-2.0 | MIT | Main |
| syn | 3.0.3 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| syn | 3.0.7 | MIT OR Apache-2.0 | MIT | Main |
| tar | 0.4.46 | MIT OR Apache-2.0 | MIT | Main |
| thiserror | 2.0.20 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | MIT | Main |
| thiserror-impl | 2.0.20 | MIT OR Apache-2.0 | MIT | Auxiliary only |
| thiserror-impl | 2.0.21 | MIT OR Apache-2.0 | MIT | Main |
| tiny-keccak | 2.0.2 | CC0-1.0 | CC0-1.0 | Main |
| toml | 1.2.1+spec-1.1.0 | MIT OR Apache-2.0 | MIT | Main |
| toml_datetime | 1.1.3+spec-1.1.0 | MIT OR Apache-2.0 | MIT | Main |
| toml_parser | 1.1.5+spec-1.1.0 | MIT OR Apache-2.0 | MIT | Main |
| toml_writer | 1.2.0+spec-1.1.0 | MIT OR Apache-2.0 | MIT | Main |
| typed-path | 0.13.0 | MIT OR Apache-2.0 | MIT | Main |
| typenum | 1.20.1 | MIT OR Apache-2.0 | MIT | Main |
| unicode-ident | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | MIT AND Unicode-3.0 | Auxiliary only |
| unicode-ident | 1.0.26 | (MIT OR Apache-2.0) AND Unicode-3.0 | MIT AND Unicode-3.0 | Main |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT | MIT | Auxiliary only |
| version_check | 0.9.5 | MIT/Apache-2.0 | MIT | Main |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | MIT | Main |
| wasip2 | 1.0.4+wasi-0.2.12 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | MIT | Main |
| wasm-bindgen | 0.2.130 | MIT OR Apache-2.0 | MIT | Main |
| wasm-bindgen-macro | 0.2.130 | MIT OR Apache-2.0 | MIT | Main |
| wasm-bindgen-macro-support | 0.2.130 | MIT OR Apache-2.0 | MIT | Main |
| wasm-bindgen-shared | 0.2.130 | MIT OR Apache-2.0 | MIT | Main |
| wayland-backend | 0.3.17 | MIT | MIT | Main |
| wayland-protocols | 0.32.13 | MIT | MIT | Main |
| wayland-scanner | 0.31.11 | MIT | MIT | Main |
| wayland-server | 0.31.14 | MIT | MIT | Main |
| wayland-sys | 0.31.11 | MIT | MIT | Main |
| windows-link | 0.2.1 | MIT OR Apache-2.0 | MIT | Main |
| windows-sys | 0.60.2 | MIT OR Apache-2.0 | MIT | Main |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 | MIT | Main |
| windows-targets | 0.53.5 | MIT OR Apache-2.0 | MIT | Main |
| windows_aarch64_gnullvm | 0.53.1 | MIT OR Apache-2.0 | MIT | Main |
| windows_aarch64_msvc | 0.53.1 | MIT OR Apache-2.0 | MIT | Main |
| windows_i686_gnu | 0.53.1 | MIT OR Apache-2.0 | MIT | Main |
| windows_i686_gnullvm | 0.53.1 | MIT OR Apache-2.0 | MIT | Main |
| windows_i686_msvc | 0.53.1 | MIT OR Apache-2.0 | MIT | Main |
| windows_x86_64_gnu | 0.53.1 | MIT OR Apache-2.0 | MIT | Main |
| windows_x86_64_gnullvm | 0.53.1 | MIT OR Apache-2.0 | MIT | Main |
| windows_x86_64_msvc | 0.53.1 | MIT OR Apache-2.0 | MIT | Main |
| winnow | 1.0.5 | MIT | MIT | Main |
| wit-bindgen | 0.57.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | MIT | Main |
| x11rb | 0.13.2 | MIT OR Apache-2.0 | MIT | Main |
| x11rb-protocol | 0.13.2 | MIT OR Apache-2.0 | MIT | Main |
| xim | 0.5.0 | MIT | MIT | Main |
| xim-ctext | 0.4.1 | MIT | MIT | Main |
| xim-parser | 0.2.2 | MIT | MIT | Main |
| zerocopy | 0.8.63 | BSD-2-Clause OR Apache-2.0 OR MIT | MIT | Main |
| zerocopy-derive | 0.8.63 | BSD-2-Clause OR Apache-2.0 OR MIT | MIT | Main |
| zeroize | 1.9.1 | Apache-2.0 OR MIT | MIT | Main |
| zeroize_derive | 1.5.0 | Apache-2.0 OR MIT | MIT | Main |
| zip | 9.5.1 | MIT | MIT | Main |
| zmij | 1.0.23 | MIT | MIT | Main |

Auxiliary lockfiles: `vendor/wayland-backend/Cargo.lock`.

<!-- END GENERATED RUST DEPENDENCIES -->

## Shared Runtime and native sources

Runtime is maintained in this repository.

| Component | Version / source | Terms and distribution |
| --- | --- | --- |
| smoltcp | 0.12.0, `vendor/smoltcp` | 0BSD; retain original notice. |
| wayland-backend | 0.3.17, `vendor/wayland-backend` | MIT; includes documented Trames platform adaptations. |
| ext4-view | 1.0.0, `vendor/ext4-view` | MIT OR Apache-2.0; MIT selected. |
| musl | 1.2.5, `crates/trames-native/upstream/musl-1.2.5` | MIT and file-level Arm notices; retain `COPYRIGHT`. Trames wrappers have their own GPL terms. |
| Bionic / gdtoa | Android 13, `crates/trames-native/upstream/bionic-android13` | Apache/BSD/Lucent notices in the original files and `NOTICE.txt`. |
| glibc source subset | 2.41, `crates/trames-native/upstream/glibc-2.41` | LGPL-2.1-or-later; retain original notices and corresponding source for redistributed derivatives. The native build does not compile these C files into the host library. |
| Wayland protocol XML | Versions pinned by Cargo.lock | Protocol-level copyrights accompany generated protocol code. |
| xkeyboard-config data | Runtime-pinned data | Preserve `crates/trames-wayland/data/COPYING.xkeyboard-config`. |
| xim-rs workspace license | Fixed original upstream revisions | MIT; retained at `crates/trames-wayland/data/COPYING.xim-rs` for crate archives that omit it. |

Native adaptations and Rust translations do not erase upstream rights. GPL/LGPL
source obligations apply to the components carrying those terms; they do not
change merely because another project component offers a commercial license.

## Guest distributions and optional integrations

Alpine/Debian root filesystems, Android images and separately installed guest
programs keep their own package licenses, including GPL and LGPL where present.
Redistributing an image requires its package notices and applicable corresponding
source. An external guest program is not automatically a host-linked library.
For optional native-driver, graphics or video bundles, retain the original
bundle notices and exact source/build inputs in addition to the Rust notices.

## CI tools

GitHub Actions used by this repository: `actions/checkout@v4`, `actions/upload-artifact@v4`. Their upstream action implementations are MIT-licensed build services, not linked product libraries.

## Updating and checking this record

Use Python 3.9 or later:

```sh
python3 scripts/prepare-third-party-notices.py --check
```

After changing dependencies, review the new exact package source and license
texts, then update `third-party/licenses.json`. Run the script without `--check`
to refresh this table, the full notice bundle and `third-party/inputs.json`.
The generator checks original-text hashes and Cargo source checksums, rejects
unreviewed package versions, and downloads nothing. Its input fingerprints catch
lockfile drift even when a package is used only by a benchmark or another target.
The selected branch is a recorded license choice, not a change to upstream terms.
