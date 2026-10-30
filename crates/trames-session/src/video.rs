// SPDX-License-Identifier: GPL-3.0-or-later
//! Frame exports publish ordinary shared FD objects on the calling CPU worker.
use trames_graphics::{Format, ImageFds};
use trames_memory::{Access, CpuMemory, MemoryError};
pub(super) fn image_call(
    context: &trames_video::Context,
    files: &dyn ImageFds,
    memory: &mut impl CpuMemory,
    op: u64,
    at: u64,
    size: u64,
) -> Result<u64, MemoryError> {
    if size != 128 {
        return Ok((-22i64) as u64);
    }
    let record = memory.read_array::<128>(at)?;
    let a: [u64; 16] =
        std::array::from_fn(|i| u64::from_le_bytes(record[i * 8..i * 8 + 8].try_into().unwrap()));
    let (images, output) = if op == trames_video::EXPORT_FRAME {
        let frame = match context.frame(a[0]) {
            Ok(frame) => frame,
            Err(e) => return Ok(e as u64),
        };
        match (frame.plane(0), frame.plane(1)) {
            (Ok(y), Ok(uv)) => (vec![y, uv], a[1]),
            _ => return Ok((-5i64) as u64),
        }
    } else {
        let Some(format) = u32::try_from(a[0]).ok().and_then(Format::from_vk) else {
            return Ok((-22i64) as u64);
        };
        let (Ok(width), Ok(height)) = (u32::try_from(a[1]), u32::try_from(a[2])) else {
            return Ok((-22i64) as u64);
        };
        match context.allocate_image(format, width, height) {
            Ok(image) => (vec![image], a[3]),
            Err(e) => return Ok(-(e.raw_os_error().unwrap_or(5) as i64) as u64),
        }
    };
    memory.check(output, 64, Access::Write)?;
    let mut fds = Vec::new();
    for image in &images {
        match files.insert(image.clone()) {
            Ok(fd) => fds.push(fd),
            Err(e) => {
                for fd in fds {
                    files.close(fd);
                }
                return Ok(-(e.raw_os_error().unwrap_or(5) as i64) as u64);
            }
        }
    }
    let values = if images.len() == 2 {
        let y = images[0].info();
        let uv = images[1].info();
        [
            y.width as u64,
            y.height as u64,
            fds[0] as u64,
            fds[1] as u64,
            y.pitch,
            uv.pitch,
            y.size,
            uv.size,
        ]
    } else {
        let info = images[0].info();
        [
            fds[0] as u64,
            info.width as u64,
            info.height as u64,
            info.pitch,
            info.size,
            0,
            0,
            0,
        ]
    };
    let mut bytes = [0; 64];
    for (value, bytes) in values.into_iter().zip(bytes.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
    if let Err(error) = memory.write(output, &bytes) {
        for fd in fds {
            files.close(fd);
        }
        return Err(error);
    }
    Ok(0)
}
