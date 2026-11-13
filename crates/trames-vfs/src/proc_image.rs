// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux proc image bytes, shared by local CPU reads and original-mm exports.
//! A reader supplies checked anonymous page fragments; None defers before any
//! guest output or OFD offset change. No loaded argv/envp vector is consulted.
use trames_memory::{CpuMemory, ImageRanges, PAGE_SIZE};

pub struct ProcImage(pub ImageRanges);
impl ProcImage {
    pub fn command_line(
        &self,
        offset: u64,
        count: usize,
        mut read: impl FnMut(u64, &mut [u8]) -> Option<usize>,
    ) -> Option<Vec<u8>> {
        let (start, end) = self.0.arguments;
        let (env_start, env_end) = self.0.environment;
        if count == 0 || env_end == 0 || start >= end {
            return Some(Vec::new());
        }
        let limit = if env_start == end && env_end >= env_start {
            env_end
        } else {
            end
        };
        if offset >= limit - start {
            return Some(Vec::new());
        }
        let count = (count as u64).min(limit - start - offset) as usize;
        let mut last = [0];
        if read(end - 1, &mut last)? == 1 && last[0] != 0 {
            // setproctitle may overwrite the final argv NUL and the adjacent
            // environment. Linux observes at most one guest page from argv[0].
            if offset >= PAGE_SIZE {
                return Some(Vec::new());
            }
            let mut title = read_range(start, PAGE_SIZE as usize, &mut read)?;
            if let Some(end) = title.iter().position(|b| *b == 0) {
                title.truncate(end + 1);
            }
            let offset = (offset as usize).min(title.len());
            return Some(title[offset..title.len().min(offset.saturating_add(count))].to_vec());
        }
        if offset >= end - start {
            return Some(Vec::new());
        }
        read_range(
            start + offset,
            (count as u64).min(end - start - offset) as usize,
            read,
        )
    }
    pub fn environment(
        &self,
        offset: u64,
        count: usize,
        read: impl FnMut(u64, &mut [u8]) -> Option<usize>,
    ) -> Option<Vec<u8>> {
        let (start, end) = self.0.environment;
        if count == 0 || offset >= end.saturating_sub(start) {
            return Some(Vec::new());
        }
        read_range(
            start + offset,
            (count as u64).min(end - start - offset) as usize,
            read,
        )
    }
    /// The caller already owns this exact mm's CPU memory. This adapter adds
    /// neither an execution View nor another permission/concurrency policy.
    pub fn local_reader(memory: &impl CpuMemory, address: u64, out: &mut [u8]) -> Option<usize> {
        memory
            .proc_read_chunk(address, out)
            .map(|result| if result.is_ok() { out.len() } else { 0 })
    }
}
fn read_range(
    mut address: u64,
    mut count: usize,
    mut read: impl FnMut(u64, &mut [u8]) -> Option<usize>,
) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    while count != 0 {
        let chunk = count.min((PAGE_SIZE - address % PAGE_SIZE) as usize);
        let at = bytes.len();
        bytes.resize(at + chunk, 0);
        let got = read(address, &mut bytes[at..])?;
        debug_assert!(got <= chunk);
        bytes.truncate(at + got);
        if got == 0 {
            break;
        }
        address += got as u64;
        count -= got;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    #[test]
    fn image_bytes_follow_mutations_and_setproctitle_instead_of_pointer_arrays() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, b"one\0two\0E=1\0x=2\0").unwrap();
        let image = ProcImage(ImageRanges {
            start_stack: 0,
            arguments: (0x1000, 0x1008),
            environment: (0x1008, 0x1010),
        });
        let line = |m: &Memory, offset, count| {
            image
                .command_line(offset, count, |a, out| ProcImage::local_reader(m, a, out))
                .unwrap()
        };
        assert_eq!(line(&memory, 0, 100), b"one\0two\0");
        assert_eq!(line(&memory, 4, 100), b"two\0");
        memory.write(0x1000, b"new\0").unwrap();
        assert_eq!(line(&memory, 0, 100), b"new\0two\0");
        memory.write(0x1000, b"long new title\0").unwrap();
        assert_eq!(line(&memory, 0, 100), b"long new title\0");
        assert_eq!(line(&memory, 5, 4), b"new ");
        assert!(line(&memory, PAGE_SIZE, 100).is_empty());
        memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        let view = memory.parallel_view(&mut Default::default()).unwrap();
        assert_eq!(
            image
                .command_line(0, 100, |a, out| ProcImage::local_reader(&view, a, out))
                .unwrap(),
            b"long new title\0"
        );
    }
    #[test]
    fn environment_reads_live_bytes_partially_and_does_not_touch_pages_for_eof() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1ffc, b"E=1\0").unwrap();
        let image = ProcImage(ImageRanges {
            start_stack: 0,
            arguments: (0, 0),
            environment: (0x1ffc, 0x2004),
        });
        let env = |m: &Memory| {
            image
                .environment(0, 100, |a, out| ProcImage::local_reader(m, a, out))
                .unwrap()
        };
        assert_eq!(env(&memory), b"E=1\0");
        memory.write(0x1ffc, b"E=2\0").unwrap();
        assert_eq!(env(&memory), b"E=2\0");
        assert!(image
            .environment(8, 100, |_, _| panic!("EOF reads no pages"))
            .unwrap()
            .is_empty());
        assert!(image
            .environment(0, 0, |_, _| panic!("zero read touches no pages"))
            .unwrap()
            .is_empty());
        assert!(
            image.environment(0, 100, |_, _| None).is_none(),
            "missing capability defers"
        );
    }
}
