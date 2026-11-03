// SPDX-License-Identifier: GPL-3.0-or-later
//! Native device controls use the caller's original live Files authority.
use trames_memory::{CpuMemory, MemoryError};
use trames_vfs::NativeEvents;

#[derive(Clone)]
pub(super) struct Audio {
    pub context: trames_audio::Context,
    pub events: NativeEvents,
}
fn notification(
    events: Option<&NativeEvents>,
    memory: &impl CpuMemory,
    address: u64,
) -> Result<Option<trames_audio::Notify>, MemoryError> {
    // Preserve the original FD lookup before reading the rest of the record.
    let fd = memory.read_u64(address)?;
    Ok(u32::try_from(fd)
        .ok()
        .and_then(|fd| events?.event(fd).ok())
        .map(|event| std::sync::Arc::new(move || event.notify()) as trames_audio::Notify))
}
pub(super) fn audio(
    context: &trames_audio::Context,
    events: Option<&NativeEvents>,
    memory: &mut impl CpuMemory,
    op: u64,
    address: u64,
    size: u64,
) -> Result<u64, MemoryError> {
    let notify = if op == trames_audio::OPEN && size == 128 {
        let Some(notify) = notification(events, memory, address)? else {
            return Ok((-22i64) as u64);
        };
        Some(notify)
    } else {
        None
    };
    context.invoke(memory, op, address, size, notify)
}
pub(super) fn video(
    context: &trames_video::Context,
    events: Option<&NativeEvents>,
    images: Option<&std::sync::Arc<dyn trames_graphics::ImageFds>>,
    memory: &mut impl CpuMemory,
    op: u64,
    address: u64,
    size: u64,
) -> Result<u64, MemoryError> {
    if matches!(
        op,
        trames_video::EXPORT_FRAME | trames_video::ALLOCATE_IMAGE
    ) {
        return crate::video::image_call(
            context,
            &**images.expect("native image FD authority"),
            memory,
            op,
            address,
            size,
        );
    }
    let notify = if op == trames_video::CREATE_SURFACE && size == 128 {
        let Some(notify) = notification(events, memory, address)? else {
            return Ok((-22i64) as u64);
        };
        Some(notify)
    } else {
        None
    };
    context.invoke(memory, op, address, size, notify)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    use trames_vfs::{Vfs, O_NONBLOCK};
    #[test]
    fn late_device_notification_uses_original_event_and_preserves_fd_before_record_fault_order() {
        let mut vfs = Vfs::default();
        let events = vfs.native_events();
        let factory = vfs.descriptor_factory();
        let fd = std::thread::spawn(move || factory.eventfd(0, O_NONBLOCK).unwrap())
            .join()
            .unwrap();
        let original = vfs.direct_descriptors().get(fd).unwrap();
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
            .write_array(0x1ff8, (fd as u64).to_le_bytes())
            .unwrap();
        let notify = notification(Some(&events), &memory, 0x1ff8)
            .unwrap()
            .unwrap();
        vfs.close(fd).unwrap();
        assert_eq!(vfs.eventfd(77, 0).unwrap(), fd);
        std::thread::spawn(move || notify()).join().unwrap();
        assert_eq!(original.read(8).unwrap(), 1u64.to_le_bytes());
        assert_eq!(vfs.read(fd, 8).unwrap(), 77u64.to_le_bytes());
        let video = trames_video::Context::default();
        memory
            .write_array(0x1ff8, (u32::MAX as u64).to_le_bytes())
            .unwrap();
        assert_eq!(
            super::video(
                &video,
                Some(&events),
                None,
                &mut memory,
                trames_video::CREATE_SURFACE,
                0x1ff8,
                128
            )
            .unwrap() as i64,
            -22
        );
        memory
            .write_array(0x1ff8, (fd as u64).to_le_bytes())
            .unwrap();
        assert!(super::video(
            &video,
            Some(&events),
            None,
            &mut memory,
            trames_video::CREATE_SURFACE,
            0x1ff8,
            128
        )
        .is_err());
        assert!(!vfs.has_native_event_sources());
    }
}
