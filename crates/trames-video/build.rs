// SPDX-License-Identifier: GPL-3.0-or-later
fn main() {
    println!("cargo:rerun-if-changed=native/video.mm");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("apple") {
        return;
    }
    cc::Build::new()
        .cpp(true)
        .file("native/video.mm")
        .flag("-std=c++17")
        .flag("-fobjc-arc")
        .warnings(true)
        .warnings_into_errors(true)
        .compile("trames_video");
    for framework in [
        "VideoToolbox",
        "CoreMedia",
        "CoreVideo",
        "Metal",
        "IOSurface",
        "Foundation",
    ] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
