// SPDX-License-Identifier: GPL-3.0-or-later
fn main() {
    println!("cargo:rerun-if-changed=native/image.mm");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("apple") {
        return;
    }
    cc::Build::new()
        .cpp(true)
        .file("native/image.mm")
        .flag("-std=c++17")
        .flag("-fobjc-arc")
        .warnings(true)
        .warnings_into_errors(true)
        .compile("trames_graphics");
    for name in ["Metal", "CoreVideo", "IOSurface", "Foundation"] {
        println!("cargo:rustc-link-lib=framework={name}");
    }
}
