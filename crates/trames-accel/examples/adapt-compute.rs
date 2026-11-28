// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold adapter validation helper; production uses the same in-memory recipe.
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let bytes = std::fs::read(&args[1]).unwrap();
    let next =
        trames_accel::compute_elf::adapt(&bytes, args.get(3).is_none_or(|s| s != "original"))
            .expect("adaptable ELF");
    std::fs::write(&args[2], next).unwrap();
}
