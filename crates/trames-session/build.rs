// SPDX-License-Identifier: GPL-3.0-or-later
fn main() {
    println!("cargo:rustc-check-cfg=cfg(trames_interpreter_conformance)");
}
