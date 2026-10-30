// SPDX-License-Identifier: GPL-3.0-or-later
fn main() {
    println!("cargo:rerun-if-changed=native/dns.c");
    cc::Build::new().file("native/dns.c").compile("trames_dns");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple")
        || std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu")
    {
        println!("cargo:rustc-link-lib=resolv");
    }
}
