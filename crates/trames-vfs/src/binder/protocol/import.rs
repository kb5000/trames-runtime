// SPDX-License-Identifier: GPL-3.0-or-later
//! Original packet/object cursor. Earlier FD/node leases remain accepted while
//! a later scatter buffer faults; the resumed import never resolves them again.
use super::super::input::Reader;
use super::*;

pub(super) struct Import {
    header: [u8; 64],
    size: usize,
    offset_size: usize,
    extra_limit: usize,
    data: Option<Vec<u8>>,
    packet: Option<Packet>,
    index: usize,
    previous_end: usize,
    parents: BTreeMap<usize, (usize, usize, usize, usize)>,
    last_fixup: Option<(usize, usize)>,
}
impl Import {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        let header: [u8; 64] = bytes[..64].try_into().unwrap();
        let size = checked_len(word(&header, 32), 4 * 1024 * 1024)?;
        let offset_size = checked_len(word(&header, 40), 4 * 1024 * 1024)?;
        if offset_size % 8 != 0 {
            return Err(Errno(22));
        }
        let extra_limit = if bytes.len() == 72 {
            checked_len(word(bytes, 64), 4 * 1024 * 1024)?
        } else {
            0
        };
        Ok(Self {
            header,
            size,
            offset_size,
            extra_limit,
            data: None,
            packet: None,
            index: 0,
            previous_end: 0,
            parents: BTreeMap::new(),
            last_fixup: None,
        })
    }
    pub fn progress<M: CpuMemory>(
        &mut self,
        request: &Ioctl,
        memory: &Reader<'_, M>,
    ) -> Result<Packet> {
        if self.data.is_none() && self.packet.is_none() {
            self.data = Some(read(memory, word(&self.header, 48), self.size)?);
            memory.accepted();
        }
        if self.packet.is_none() {
            let raw = read(memory, word(&self.header, 56), self.offset_size)?;
            let offsets = raw
                .chunks_exact(8)
                .map(|bytes| checked_len(word(bytes, 0), self.size))
                .collect::<Result<Vec<_>>>()?;
            self.packet = Some(Packet {
                header: self.header,
                data: self.data.take().unwrap(),
                offsets,
                extra: Vec::new(),
                objects: Vec::new(),
                relocations: Vec::new(),
            });
            memory.accepted();
        }
        let packet = self.packet.as_mut().unwrap();
        while self.index < packet.offsets.len() {
            let index = self.index;
            let offset = packet.offsets[index];
            if offset % 4 != 0 || offset < self.previous_end {
                return Err(Errno(22));
            }
            let raw = packet
                .data
                .get(offset..offset.checked_add(4).ok_or(Errno(22))?)
                .ok_or(Errno(22))?;
            let kind = dword(raw, 0);
            let object_size = match kind {
                TYPE_BINDER | TYPE_WEAK_BINDER | TYPE_HANDLE | TYPE_WEAK_HANDLE | TYPE_FD => 24,
                TYPE_PTR => 40,
                TYPE_FDA => 32,
                _ => return Err(Errno(22)),
            };
            let object = packet
                .data
                .get(offset..offset + object_size)
                .ok_or(Errno(22))?;
            match kind {
                TYPE_BINDER | TYPE_WEAK_BINDER | TYPE_HANDLE | TYPE_WEAK_HANDLE => {
                    let (node, lease) = if matches!(kind, TYPE_BINDER | TYPE_WEAK_BINDER) {
                        (
                            request.process.owned_node(
                                word(object, 8),
                                word(object, 16),
                                dword(object, 4),
                                request.tid,
                            )?,
                            None,
                        )
                    } else if kind == TYPE_HANDLE {
                        let lease = request.process.strong_reference(dword(object, 8))?;
                        (lease.0.clone(), Some(lease))
                    } else {
                        (request.process.reference_node(dword(object, 8))?, None)
                    };
                    packet.objects.push(Object::Node {
                        offset,
                        node,
                        strong: matches!(kind, TYPE_BINDER | TYPE_HANDLE),
                        _lease: lease,
                    });
                }
                TYPE_FD => {
                    let file = request.capture_fd(dword(object, 8))?;
                    packet.objects.push(Object::Fd {
                        extra: false,
                        offset: offset + 8,
                        file,
                        array: false,
                    });
                }
                TYPE_PTR => {
                    let length = checked_len(word(object, 16), self.extra_limit)?;
                    let at = align(packet.extra.len())?;
                    let end = at
                        .checked_add(length)
                        .filter(|end| *end <= self.extra_limit)
                        .ok_or(Errno(22))?;
                    let bytes = read(memory, word(object, 8), length)?;
                    memory.accepted();
                    packet.extra.resize(at, 0);
                    packet.extra.extend_from_slice(&bytes);
                    let parent = checked_len(word(object, 24), index)?;
                    let parent_offset = usize::try_from(word(object, 32)).map_err(|_| Errno(22))?;
                    if dword(object, 4) & !1 != 0 {
                        return Err(Errno(22));
                    }
                    if dword(object, 4) & 1 != 0 {
                        let (start, len, _, _) = *self.parents.get(&parent).ok_or(Errno(22))?;
                        if parent_offset % 8 != 0
                            || parent_offset.checked_add(8).is_none_or(|v| v > len)
                        {
                            return Err(Errno(22));
                        }
                        validate_parent(&self.parents, self.last_fixup, parent, parent_offset)?;
                        packet.relocations.push((start + parent_offset, at));
                    }
                    self.parents.insert(
                        index,
                        (
                            at,
                            length,
                            if dword(object, 4) & 1 != 0 {
                                parent
                            } else {
                                usize::MAX
                            },
                            parent_offset,
                        ),
                    );
                    packet.objects.push(Object::Buffer { offset, extra: at });
                    debug_assert_eq!(packet.extra.len(), end);
                    self.last_fixup = Some((index, 0));
                }
                TYPE_FDA => {
                    let count = checked_len(word(object, 8), self.extra_limit / 4)?;
                    let parent = checked_len(word(object, 16), index)?;
                    let parent_offset = usize::try_from(word(object, 24)).map_err(|_| Errno(22))?;
                    let (start, len, _, _) = *self.parents.get(&parent).ok_or(Errno(22))?;
                    if parent_offset % 4 != 0
                        || parent_offset.checked_add(count * 4).is_none_or(|n| n > len)
                    {
                        return Err(Errno(22));
                    }
                    validate_parent(&self.parents, self.last_fixup, parent, parent_offset)?;
                    for i in 0..count {
                        let at = start + parent_offset + i * 4;
                        let file = request.capture_fd(dword(&packet.extra, at))?;
                        packet.objects.push(Object::Fd {
                            extra: true,
                            offset: at,
                            file,
                            array: true,
                        });
                    }
                    self.last_fixup = Some((parent, parent_offset + count * 4));
                }
                _ => unreachable!(),
            }
            self.previous_end = offset + object_size;
            self.index += 1;
        }
        if align(packet.extra.len())? > self.extra_limit {
            return Err(Errno(22));
        }
        Ok(self.packet.take().unwrap())
    }
}
