#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build one source-checked static ARM64 client; never called recursively by Cargo."""
import hashlib,json,os,pathlib,shutil,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'target/guest-cli';OUTPUT.mkdir(parents=True,exist_ok=True)
def source_hash():
    paths=[ROOT/'Cargo.lock',ROOT/'rust-toolchain.toml']+sorted((ROOT/'crates/trames-control').rglob('*.rs'))+[ROOT/'crates/trames-control/Cargo.toml']
    h=hashlib.sha256()
    for p in sorted(paths):
        if p.is_file():h.update(str(p.relative_to(ROOT)).encode()+b'\0'+p.read_bytes())
    return h.hexdigest()
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
binary=OUTPUT/'trames';record=OUTPUT/'manifest.json'
if binary.is_file() and record.is_file():
    data=json.loads(record.read_text())
    if data.get('source_sha256')==source_hash() and data.get('binary_sha256')==digest(binary):
        print('Reused source-checked guest CLI:',binary);raise SystemExit(0)
subprocess.run(['rustup','target','add','aarch64-unknown-linux-musl'],cwd=ROOT,check=True)
sysroot=pathlib.Path(subprocess.check_output(['rustc','--print','sysroot'],cwd=ROOT,text=True).strip())
host=next(line[6:] for line in subprocess.check_output(['rustc','-vV'],cwd=ROOT,text=True).splitlines() if line.startswith('host: '))
linker=sysroot/'lib/rustlib'/host/'bin/rust-lld'
if not linker.is_file():raise SystemExit('rust-lld is required from the pinned Rust toolchain')
env=dict(os.environ)
for key in ['SDKROOT','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','IPHONEOS_DEPLOYMENT_TARGET','MACOSX_DEPLOYMENT_TARGET']:env.pop(key,None)
env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER']=str(linker)
env['RUSTFLAGS']='-C link-self-contained=yes -C target-feature=+crt-static -C strip=symbols'
before=source_hash()
subprocess.run(['cargo','build','--locked','--release','--target','aarch64-unknown-linux-musl','-p','trames-control','--bin','trames'],cwd=ROOT,env=env,check=True)
target=pathlib.Path(env.get('CARGO_TARGET_DIR',str(ROOT/'target')))
if not target.is_absolute():target=ROOT/target
built=target/'aarch64-unknown-linux-musl/release/trames'
header=built.read_bytes()[:64]
if header[:4]!=b'\x7fELF' or int.from_bytes(header[18:20],'little')!=183:raise SystemExit('Expected an AArch64 Linux ELF')
if source_hash()!=before:raise SystemExit("Guest CLI sources changed during compilation; retry")
shutil.copy2(built,binary)
record.write_text(json.dumps({'target':'aarch64-unknown-linux-musl','source_sha256':source_hash(),'binary_sha256':digest(binary)},indent=2)+'\n')
print('Built static guest CLI:',binary)
