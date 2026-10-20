// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

/// Install the small guest launcher before starting guest processes. The X
/// server and X11 clients continue to be ordinary Alpine-signed packages.
pub fn install_xwayland_launcher(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    let mut bytes = Vec::new();
    reader.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::Invalid("Xwayland launcher too large"));
    }
    trames_elf::load_with_interpreter(&bytes, trames_memory::DEFAULT_MEMORY_LIMIT, |path| {
        if path != MUSL_LOADER {
            return Err(trames_elf::ElfError::Invalid(
                "unexpected launcher interpreter",
            ));
        }
        vfs.executable(path)
            .map_err(|e| trames_elf::ElfError::Interpreter(e.0))
    })
    .map_err(|_| Error::Invalid("invalid AArch64 Xwayland launcher"))?;
    let path = b"/usr/bin/trames-xwayland";
    if vfs.executable(path).is_ok_and(|old| old == bytes) {
        return Ok(false);
    }
    let staging = b"/usr/bin/.trames-xwayland.new";
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
