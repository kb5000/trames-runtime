// SPDX-License-Identifier: GPL-3.0-or-later
//! Assemble the original pinned Arm routines, with symbol/object-format adaptation.
use std::{collections::BTreeMap, env, fs, path::Path, process::Command};
fn compile_parser() {
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    let apple = target.contains("apple");
    let out = env::var_os("OUT_DIR").unwrap();
    let out = Path::new(&out);
    let input = "upstream/musl-1.2.5/internal/floatscan.c";
    println!("cargo:rerun-if-changed={input}");
    println!("cargo:rerun-if-changed=parse");
    let original = fs::read_to_string(input).expect("pinned floatscan");
    assert_eq!(original.matches("1000000000.0L").count(), 1);
    // Retain the original algorithm; select its 53-bit intermediate branch on
    // every host. ARM64 GNU long double otherwise invokes software binary128.
    let mut source = original
        .replace("long double", "double")
        .replace("LDBL_", "DBL_")
        .replace("1000000000.0L", "1000000000.0")
        .replace("__floatscan", "trames_native_floatscan");
    for (old, new) in [
        ("scalbnl", "scalbn"),
        ("fmodl", "fmod"),
        ("copysignl", "copysign"),
        ("fabsl", "fabs"),
    ] {
        source = source.replace(old, new);
    }
    fs::write(out.join("floatscan.c"), source).unwrap();
    let integer = "upstream/musl-1.2.5/internal/intscan.c";
    println!("cargo:rerun-if-changed={integer}");
    fs::write(
        out.join("intscan.c"),
        fs::read_to_string(integer)
            .unwrap()
            .replace("__intscan", "trames_native_intscan"),
    )
    .unwrap();
    println!("cargo:rerun-if-changed=allocator");
    println!("cargo:rerun-if-changed=upstream/musl-1.2.5/mallocng");
    println!("cargo:rerun-if-changed=upstream/musl-1.2.5/provenance.json");
    assert!(Command::new("python3")
        .arg("allocator/generate.py")
        .arg(out.join("allocator.c"))
        .status()
        .expect("checked original mallocng lowering")
        .success());
    let compiler_key = format!("CC_{}", target.replace('-', "_"));
    let compiler = env::var(&compiler_key).unwrap_or_else(|_| {
        if apple {
            "clang".into()
        } else if target != host && target.starts_with("aarch64") {
            "aarch64-linux-gnu-gcc".into()
        } else {
            "cc".into()
        }
    });
    println!("cargo:rerun-if-env-changed={compiler_key}");
    for (name, path) in [
        ("floatscan", out.join("floatscan.c")),
        ("intscan", out.join("intscan.c")),
        ("driver", Path::new("parse/driver.c").to_owned()),
        ("allocator", out.join("allocator.c")),
    ] {
        let mut command = Command::new(&compiler);
        if apple && target != host {
            command.arg(if target.ends_with("-sim") {
                "--target=arm64-apple-ios17.0-simulator"
            } else {
                "--target=arm64-apple-ios17.0"
            });
        }
        command.args([
            "-O2",
            "-fPIC",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fvisibility=hidden",
            "-ffp-contract=off",
            "-c",
        ]);
        if name != "allocator" {
            command.arg("-Iparse/shim");
        }
        assert!(command
            .arg(path)
            .arg("-o")
            .arg(out.join(format!("{name}.o")))
            .status()
            .expect("C compiler for signed-in native parser")
            .success());
    }
    let archive_key = format!("AR_{}", target.replace('-', "_"));
    let archive = env::var(&archive_key).unwrap_or_else(|_| {
        if apple && !host.contains("apple") {
            "llvm-ar".into()
        } else {
            "ar".into()
        }
    });
    println!("cargo:rerun-if-env-changed={archive_key}");
    assert!(Command::new(archive)
        .arg("crs")
        .arg(out.join("libtrames_parse.a"))
        .arg(out.join("floatscan.o"))
        .arg(out.join("intscan.o"))
        .arg(out.join("driver.o"))
        .arg(out.join("allocator.o"))
        .status()
        .expect("native parser archiver")
        .success());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=trames_parse");
    if !apple && env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("musl") {
        println!("cargo:rustc-link-lib=m");
    }
}
fn main() {
    compile_parser();
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64") {
        return;
    }
    let apple = env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple");
    for name in ["memcpy", "memset"] {
        let path = format!("upstream/musl-1.2.5/aarch64/{name}.S");
        println!("cargo:rerun-if-changed={path}");
        let source = fs::read_to_string(path).expect("vendored musl source");
        let mut aliases = BTreeMap::new();
        let symbol = format!("{}trames_native_{name}", if apple { "_" } else { "" });
        aliases.insert(name.to_owned(), symbol);
        let mut asm = String::new();
        for line in source.lines() {
            let trimmed = line.trim();
            if let Some(define) = trimmed.strip_prefix("#define ") {
                let words: Vec<_> = define.split_whitespace().collect();
                assert_eq!(words.len(), 2, "only register aliases are accepted");
                aliases.insert(words[0].to_owned(), words[1].to_owned());
                continue;
            }
            // This upstream conditional is unset; retain its DCZID runtime check.
            if trimmed == "#ifndef SKIP_ZVA_CHECK" || trimmed == "#endif" {
                continue;
            }
            assert!(
                !trimmed.starts_with('#'),
                "unexpected upstream preprocessing"
            );
            if apple && (trimmed.starts_with(".type ") || trimmed.starts_with(".size ")) {
                continue;
            }
            let mut word = String::new();
            for ch in line.chars().chain(std::iter::once('\n')) {
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    word.push(ch);
                } else {
                    let mut replacement = word.as_str();
                    while let Some(alias) = aliases.get(replacement) {
                        replacement = alias;
                    }
                    asm.push_str(replacement);
                    word.clear();
                    asm.push(ch);
                }
            }
        }
        if apple {
            // Mach-O's assembler-local prefix is L, not ELF's .L. Keeping
            // .L makes ThinLTO treat conditional targets as external symbols.
            asm = asm.replace(".L", &format!("Ltrames_native_{name}_"));
        }
        fs::write(
            Path::new(&env::var_os("OUT_DIR").unwrap()).join(format!("{name}.s")),
            asm,
        )
        .expect("write static assembly");
    }
}
