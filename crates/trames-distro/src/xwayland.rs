// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

/// Install the small guest launcher before starting guest processes.
pub fn install_xwayland_launcher(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    install(reader, vfs, b"/usr/bin/trames-xwayland", 1024 * 1024)
}

/// Original Xwayland/glamor with the bundled DRM-less EGL transport. Keep the
/// apk-owned server available for the explicit SHM path and package upgrades.
pub fn install_xwayland_native(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    install(
        reader,
        vfs,
        b"/usr/libexec/trames/Xwayland-native",
        16 * 1024 * 1024,
    )
}

fn install(
    reader: &mut impl Read,
    vfs: &mut Vfs,
    path: &[u8],
    limit: usize,
) -> Result<bool, Error> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Invalid("Xwayland executable too large"));
    }
    trames_elf::load_with_interpreter(&bytes, trames_memory::DEFAULT_MEMORY_LIMIT, |path| {
        if path != MUSL_LOADER {
            return Err(trames_elf::ElfError::Invalid(
                "unexpected Xwayland interpreter",
            ));
        }
        vfs.executable(path)
            .map_err(|e| trames_elf::ElfError::Interpreter(e.0))
    })
    .map_err(|_| Error::Invalid("invalid AArch64 Xwayland executable"))?;
    if vfs.executable(path).is_ok_and(|old| old == bytes) {
        return Ok(false);
    }
    let staging = [path, b".new"].concat();
    let staging = staging.as_slice();
    vfs.import_reader_replace(staging, &mut bytes.as_slice())?;
    let result = (|| {
        vfs.chown_at(AT_FDCWD, staging, 0, 0, false)?;
        vfs.chmod_at(AT_FDCWD, staging, 0o755)?;
        vfs.rename_at(AT_FDCWD, staging, AT_FDCWD, path, 0)?;
        Ok(true)
    })();
    if result.is_err() {
        let _ = vfs.unlink_at(AT_FDCWD, staging, false);
    }
    result
}
