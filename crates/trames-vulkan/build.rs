// SPDX-License-Identifier: GPL-3.0-or-later
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};
fn archive_directory(archive: &Path, name: &str, arch: &str) -> PathBuf {
    println!("cargo:rerun-if-changed={}", archive.display());
    let bytes = std::fs::read(archive).expect("read native archive");
    if bytes.starts_with(b"!<arch>\n") {
        return archive.parent().unwrap().to_owned();
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join(name);
    std::fs::create_dir_all(&out).expect("create thin archive directory");
    let status = Command::new("xcrun")
        .arg("lipo")
        .arg(archive)
        .args(["-thin", arch, "-output"])
        .arg(out.join(archive.file_name().unwrap()))
        .status()
        .expect("xcrun lipo is required for universal native archives");
    assert!(status.success(), "failed to thin {name} for {arch}");
    out
}
fn main() {
    println!("cargo:rustc-check-cfg=cfg(trames_moltenvk)");
    println!("cargo:rerun-if-env-changed=TRAMES_MOLTENVK_STATIC_DIR");
    if let Some(directory) = env::var_os("TRAMES_MOLTENVK_STATIC_DIR") {
        let target = env::var("TARGET").unwrap();
        assert!(
            target.contains("apple"),
            "MoltenVK static linking is Apple-only"
        );
        assert!(
            Path::new(&directory).join("libMoltenVK.a").is_file(),
            "missing pinned native MoltenVK archive"
        );
        let archive = Path::new(&directory).join("libMoltenVK.a");
        // Apple's simulator XCFramework contains a fat archive; rustc's native
        // static bundler needs an ordinary archive for the selected CPU. Keep
        // the verified upstream bytes unchanged and thin only into OUT_DIR.
        let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
            "aarch64" => "arm64",
            "x86_64" => "x86_64",
            _ => panic!("unsupported MoltenVK target architecture"),
        };
        let directory = archive_directory(&archive, "moltenvk", arch);
        {
            // rustc links with -nodefaultlibs. MoltenVK's original Clang-built
            // availability checks need Apple's compiler-rt on macOS as well as
            // iOS. Bundle the SDK's matching original architecture too.
            let ios = target.contains("ios");
            let simulator = ios && (target.ends_with("-sim") || target.starts_with("x86_64-"));
            let (sdk, runtime) = if simulator {
                ("iphonesimulator", "clang_rt.iossim")
            } else if ios {
                ("iphoneos", "clang_rt.ios")
            } else {
                ("macosx", "clang_rt.osx")
            };
            let result = Command::new("xcrun")
                .args(["--sdk", sdk, "clang", "--print-runtime-dir"])
                .output()
                .expect("locate Apple compiler runtime");
            assert!(
                result.status.success(),
                "cannot locate Apple compiler runtime"
            );
            let path = PathBuf::from(String::from_utf8(result.stdout).unwrap().trim())
                .join(format!("lib{runtime}.a"));
            assert!(
                path.is_file(),
                "missing original Apple compiler runtime: {}",
                path.display()
            );
            let directory = archive_directory(&path, "compiler-rt", arch);
            println!("cargo:rustc-link-search=native={}", directory.display());
            println!("cargo:rustc-link-lib=static={runtime}");
        }
        println!("cargo:rustc-cfg=trames_moltenvk");
        println!(
            "cargo:rustc-link-search=native={}",
            Path::new(&directory).display()
        );
        println!("cargo:rustc-link-lib=static=MoltenVK");
        println!("cargo:rustc-link-lib=c++");
        if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            println!("cargo:rustc-link-lib=framework=IOKit");
        }
        for framework in [
            "Metal",
            "Foundation",
            "QuartzCore",
            "IOSurface",
            "CoreGraphics",
            "CoreVideo",
            "MetalPerformanceShaders",
        ] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
        println!(
            "cargo:rustc-link-lib=framework={}",
            if target.contains("ios") {
                "UIKit"
            } else {
                "AppKit"
            }
        );
    }
}
