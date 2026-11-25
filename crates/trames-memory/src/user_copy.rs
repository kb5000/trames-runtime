// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned fragments of one faultable user copy. This adds no memory policy:
//! every new fragment uses the caller's ordinary CpuMemory read/write model.
use crate::{CpuMemory, MemoryError, PAGE_SIZE};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

#[derive(Default)]
pub struct CopiedInput {
    fragments: Mutex<BTreeMap<(u64, usize), Vec<u8>>>,
}
impl CopiedInput {
    pub fn clear(&self) {
        self.fragments.lock().unwrap().clear();
    }
    pub fn read(
        &self,
        memory: &impl CpuMemory,
        address: u64,
        output: &mut [u8],
    ) -> Result<(), MemoryError> {
        if !memory.async_faults_possible() {
            return memory.read(address, output);
        }
        let mut copied = 0;
        while copied < output.len() {
            let at = address
                .checked_add(copied as u64)
                .ok_or(MemoryError::InvalidRange)?;
            let count = (output.len() - copied).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
            let key = (at, count);
            let cached = self.fragments.lock().unwrap().get(&key).cloned();
            if let Some(bytes) = cached {
                output[copied..copied + count].copy_from_slice(&bytes);
            } else {
                memory.read(at, &mut output[copied..copied + count])?;
                self.fragments
                    .lock()
                    .unwrap()
                    .insert(key, output[copied..copied + count].to_vec());
            }
            copied += count;
        }
        Ok(())
    }
}
/// One common output stays inline; additional writes only allocate when a
/// provider actually emits more than one independently addressed fragment.
#[derive(Default)]
pub struct CopiedOutput {
    first: Option<Write>,
    rest: VecDeque<Write>,
}
struct Write {
    address: u64,
    bytes: Bytes,
    copied: usize,
    scalar: bool,
}
enum Bytes {
    Inline { bytes: [u8; 64], len: usize },
    Owned(Vec<u8>),
}
impl Bytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { bytes, len } => &bytes[..*len],
            Self::Owned(bytes) => bytes,
        }
    }
}
impl CopiedOutput {
    fn append(&mut self, write: Write) {
        if self.first.is_none() {
            self.first = Some(write);
        } else {
            self.rest.push_back(write);
        }
    }
    pub fn push(&mut self, address: u64, bytes: Vec<u8>) {
        self.append(Write {
            address,
            bytes: Bytes::Owned(bytes),
            copied: 0,
            scalar: false,
        });
    }
    pub fn push_slice(&mut self, address: u64, data: &[u8]) {
        self.push_part(address, data, false);
    }
    /// One put_user-style store uses the ordinary memory model as one scalar;
    /// it is not converted into independent stores on either side of a page.
    pub fn push_scalar(&mut self, address: u64, data: &[u8]) {
        self.push_part(address, data, true);
    }
    fn push_part(&mut self, address: u64, data: &[u8], scalar: bool) {
        let bytes = if data.len() <= 64 {
            let mut bytes = [0; 64];
            bytes[..data.len()].copy_from_slice(data);
            Bytes::Inline {
                bytes,
                len: data.len(),
            }
        } else {
            Bytes::Owned(data.to_vec())
        };
        self.append(Write {
            address,
            bytes,
            copied: 0,
            scalar,
        });
    }
    pub fn is_empty(&self) -> bool {
        self.first.is_none()
    }
    pub fn progress(&mut self, memory: &mut impl CpuMemory) -> Result<(), MemoryError> {
        while let Some(write) = &mut self.first {
            let bytes = write.bytes.as_slice();
            while write.copied < bytes.len() {
                let at = write
                    .address
                    .checked_add(write.copied as u64)
                    .ok_or(MemoryError::InvalidRange)?;
                let count = if write.scalar {
                    bytes.len() - write.copied
                } else {
                    (bytes.len() - write.copied).min((PAGE_SIZE - at % PAGE_SIZE) as usize)
                };
                memory.write(at, &bytes[write.copied..write.copied + count])?;
                write.copied += count;
            }
            self.first = self.rest.pop_front();
        }
        Ok(())
    }
}
