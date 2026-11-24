// SPDX-License-Identifier: GPL-3.0-or-later
fn main() {
    println!("cargo:rerun-if-changed=native/dns.c");
    let mut build = cc::Build::new();
    build.file("native/dns.c");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        build.define("TRAMES_TARGET_MUSL", None);
    }
    build.compile("trames_dns");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple")
        || std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu")
    {
        println!("cargo:rustc-link-lib=resolv");
    }
}
