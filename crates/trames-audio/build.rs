// SPDX-License-Identifier: GPL-3.0-or-later
fn main() {
    println!("cargo:rerun-if-changed=native/audio.mm");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("apple") {
        return;
    }
    cc::Build::new()
        .cpp(true)
        .file("native/audio.mm")
        .flag("-std=c++17")
        .flag("-fobjc-arc")
        .warnings_into_errors(true)
        .compile("trames_audio");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=CoreAudio");
    }
    for framework in ["AudioToolbox", "AVFoundation", "Foundation", "AudioUnit"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
