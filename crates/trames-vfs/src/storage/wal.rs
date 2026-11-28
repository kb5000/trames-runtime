// SPDX-License-Identifier: GPL-3.0-or-later
//! Checksummed incremental frames over the last accepted v4 image. Copy spans
//! refer only to that image, never host paths or inode object contents.
use super::*;
use std::collections::HashMap;
pub(super) const CHECKPOINT_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const CHECKPOINT_RECORDS: u64 = 1024;
const MAGIC: &[u8; 8] = b"TRMWAL01";
const BLOCK: usize = 32;
const MAX_RECORD: u64 = MAX_MANIFEST * 2;

pub(super) fn encode(old: &[u8], new: &[u8]) -> Vec<u8> {
    let prefix = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let suffix = old[prefix..]
        .iter()
        .rev()
        .zip(new[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    if new.len() - prefix - suffix <= 4096 {
        let mut body = Vec::new();
        body.extend(checksum(old).to_le_bytes());
        body.extend(checksum(new).to_le_bytes());
        body.extend((new.len() as u64).to_le_bytes());
        if prefix > 0 {
            body.push(0);
            body.extend(0u64.to_le_bytes());
            body.extend((prefix as u64).to_le_bytes());
        }
        if prefix + suffix < new.len() {
            emit_literal(&mut body, &new[prefix..new.len() - suffix]);
        }
        if suffix > 0 {
            body.push(0);
            body.extend(((old.len() - suffix) as u64).to_le_bytes());
            body.extend((suffix as u64).to_le_bytes());
        }
        return frame(&body);
    }
    // Aligned anchors let insertions/deletions resynchronize without rewriting
    // all later inode/path records. Matching is exact; hashes grant no trust.
    let stride = BLOCK.max(old.len().div_ceil(65536).next_power_of_two());
    let mut anchors: HashMap<&[u8], Vec<usize>> = HashMap::new();
    for at in (0..old.len().saturating_sub(BLOCK - 1)).step_by(stride) {
        anchors.entry(&old[at..at + BLOCK]).or_default().push(at);
    }
    let mut body = Vec::new();
    body.extend(checksum(old).to_le_bytes());
    body.extend(checksum(new).to_le_bytes());
    body.extend((new.len() as u64).to_le_bytes());
    let (mut at, mut source, mut literal) = (0, 0, 0);
    while at < new.len() {
        let matched = if old.get(source..source + 1) == new.get(at..at + 1) {
            Some(source)
        } else {
            new.get(at..at + BLOCK).and_then(|key| {
                anchors.get(key).map(|positions| {
                    let i = positions.partition_point(|p| *p < source);
                    match (
                        i.checked_sub(1).map(|i| positions[i]),
                        positions.get(i).copied(),
                    ) {
                        (Some(a), Some(b)) => {
                            if source.abs_diff(a) < source.abs_diff(b) {
                                a
                            } else {
                                b
                            }
                        }
                        (Some(a), None) => a,
                        (_, Some(b)) => b,
                        _ => unreachable!(),
                    }
                })
            })
        };
        if let Some(start) = matched {
            let mut start = start;
            if let Some(positions) = new.get(at..at + BLOCK).and_then(|key| anchors.get(key)) {
                // Repeated records/zero runs may have many valid anchors. Only
                // nearby candidates are needed to prefer the longest span.
                let i = positions.partition_point(|p| *p < source);
                for candidate in positions[i.saturating_sub(2)..(i + 2).min(positions.len())]
                    .iter()
                    .copied()
                {
                    let a = old[candidate..]
                        .iter()
                        .zip(&new[at..])
                        .take_while(|(a, b)| a == b)
                        .count();
                    let b = old[start..]
                        .iter()
                        .zip(&new[at..])
                        .take_while(|(a, b)| a == b)
                        .count();
                    if a > b {
                        start = candidate;
                    }
                }
            }
            let length = old[start..]
                .iter()
                .zip(&new[at..])
                .take_while(|(a, b)| a == b)
                .count();
            if length >= BLOCK || at + length == new.len() {
                if literal < at {
                    emit_literal(&mut body, &new[literal..at]);
                }
                body.push(0);
                body.extend((start as u64).to_le_bytes());
                body.extend((length as u64).to_le_bytes());
                at += length;
                source = start + length;
                literal = at;
                continue;
            }
        }
        at += 1;
        source = source.saturating_add(1);
    }
    if literal < at {
        emit_literal(&mut body, &new[literal..at]);
    }
    // Incompressible changes use a single literal, bounding frame expansion.
    if body.len() > new.len() + 33 {
        body.truncate(24);
        emit_literal(&mut body, new);
    }
    frame(&body)
}
fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend((body.len() as u64).to_le_bytes());
    out.extend(body);
    out.extend(checksum(body).to_le_bytes());
    out
}
fn emit_literal(body: &mut Vec<u8>, bytes: &[u8]) {
    body.push(1);
    body.extend((bytes.len() as u64).to_le_bytes());
    body.extend(bytes);
}
#[derive(Clone)]
struct Span {
    bytes: Arc<Vec<u8>>,
    start: usize,
    length: usize,
}
struct Image {
    spans: Vec<Span>,
    length: usize,
    hash: u64,
}
fn materialize(spans: &[Span]) -> Vec<u8> {
    let length = spans.iter().map(|p| p.length).sum();
    let mut bytes = Vec::with_capacity(length);
    for span in spans {
        bytes.extend_from_slice(&span.bytes[span.start..span.start + span.length]);
    }
    bytes
}
fn push_span(out: &mut Vec<Span>, span: Span) {
    if let Some(last) = out
        .last_mut()
        .filter(|p| Arc::ptr_eq(&p.bytes, &span.bytes) && p.start + p.length == span.start)
    {
        last.length += span.length;
    } else {
        out.push(span);
    }
    // Bound metadata even for hostile copy fan-out. Flatten only this prefix;
    // its predecessor remains immutable until the current frame is complete.
    if out.len() >= 32768 {
        let bytes = materialize(out);
        let length = bytes.len();
        *out = vec![Span {
            bytes: Arc::new(bytes),
            start: 0,
            length,
        }];
    }
}
fn apply(old: &Image, body: &[u8]) -> Result<Image> {
    let mut d = Decoder { data: body, at: 0 };
    if d.u64()? != old.hash {
        return Err(Errno(22));
    }
    let hash = d.u64()?;
    let length = d.u64()?;
    if !(48..=MAX_MANIFEST).contains(&length) {
        return Err(Errno(22));
    }
    let length = length as usize;
    let mut ends = Vec::with_capacity(old.spans.len());
    let mut end = 0;
    for span in &old.spans {
        end += span.length;
        ends.push(end);
    }
    let (mut out, mut produced) = (Vec::new(), 0usize);
    while d.at < body.len() {
        match d.take(1)?[0] {
            0 => {
                let mut at = usize::try_from(d.u64()?).map_err(|_| Errno(22))?;
                let mut count = usize::try_from(d.u64()?).map_err(|_| Errno(22))?;
                if count == 0
                    || count > length - produced
                    || at > old.length
                    || count > old.length - at
                {
                    return Err(Errno(22));
                }
                produced += count;
                let mut index = ends.partition_point(|end| *end <= at);
                while count > 0 {
                    let span = &old.spans[index];
                    let base = if index == 0 { 0 } else { ends[index - 1] };
                    let offset = at - base;
                    let n = count.min(span.length - offset);
                    push_span(
                        &mut out,
                        Span {
                            bytes: span.bytes.clone(),
                            start: span.start + offset,
                            length: n,
                        },
                    );
                    at += n;
                    count -= n;
                    index += 1;
                }
            }
            1 => {
                let count = usize::try_from(d.u64()?).map_err(|_| Errno(22))?;
                if count == 0 || count > length - produced {
                    return Err(Errno(22));
                }
                push_span(
                    &mut out,
                    Span {
                        bytes: Arc::new(d.take(count)?.to_vec()),
                        start: 0,
                        length: count,
                    },
                );
                produced += count;
            }
            _ => return Err(Errno(22)),
        }
    }
    if produced != length {
        return Err(Errno(22));
    }
    Ok(Image {
        spans: out,
        length,
        hash,
    })
}
pub(super) fn replay(bytes: &mut Vec<u8>, wal: &[u8]) -> Result<usize> {
    let mut frames = Vec::new();
    let mut at = 0;
    while wal.len() - at >= 16 {
        if &wal[at..at + 8] != MAGIC {
            return Err(Errno(22));
        }
        let length = u64::from_le_bytes(wal[at + 8..at + 16].try_into().unwrap());
        if !(24..=MAX_RECORD).contains(&length) {
            return Err(Errno(22));
        }
        let end = at.checked_add(24 + length as usize).ok_or(Errno(22))?;
        if end > wal.len() {
            break;
        } // only an incomplete final frame is discarded
        let body = &wal[at + 16..end - 8];
        if checksum(body).to_le_bytes() != wal[end - 8..end] {
            return Err(Errno(22));
        }
        frames.push(body);
        at = end;
    }
    let current = checksum(bytes);
    // A checkpoint may have committed before the old WAL was truncated. Skip
    // its already-covered prefix; every remaining frame must form one chain.
    let first = frames
        .iter()
        .rposition(|b| b[8..16] == current.to_le_bytes())
        .map_or(0, |i| i + 1);
    if first < frames.len() {
        let length = bytes.len();
        let mut image = Image {
            spans: vec![Span {
                bytes: Arc::new(bytes.clone()),
                start: 0,
                length,
            }],
            length,
            hash: current,
        };
        // Frame checksums check their operations for corruption;
        // carry exact spans rather than rehashing/copying a whole image for
        // every tiny change. Validate the final materialized image once.
        for body in &frames[first..] {
            image = apply(&image, body)?;
        }
        let final_bytes = materialize(&image.spans);
        if checksum(&final_bytes) != image.hash {
            return Err(Errno(22));
        }
        *bytes = final_bytes;
    }
    Ok(at)
}
pub(super) fn recover(disk: &DiskStore, bytes: &mut Vec<u8>) -> Result<()> {
    let path = disk.root.join("manifest.wal");
    if !path.try_exists().map_err(host_errno)? {
        return Ok(());
    }
    regular(&path)?;
    let mut wal = Vec::new();
    // One large transaction can exceed the periodic threshold; bound recovery
    // by the maximum frame plus one checkpoint interval, before allocation.
    File::open(&path)
        .map_err(host_errno)?
        .take(MAX_RECORD + CHECKPOINT_BYTES + 25)
        .read_to_end(&mut wal)
        .map_err(host_errno)?;
    if wal.len() as u64 > MAX_RECORD + CHECKPOINT_BYTES + 24 {
        return Err(Errno(22));
    }
    replay(bytes, &wal)?;
    // open_disk publishes a fresh checkpoint before accepting guest mutations.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "emits independent Swift WAL/checkpoint fixtures from the Rust encoder"]
    fn emit_swift_reader_fixture() {
        let source = fs::read_to_string(std::env::var("TRAMES_WAL_BASE").unwrap()).unwrap();
        let text = source.trim().as_bytes();
        let old: Vec<u8> = text
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let mut next = old.clone();
        let mut journal = Vec::new();
        for mode in 0o40700u32..=0o40750 {
            let previous = next.clone();
            next[48..52].copy_from_slice(&mode.to_le_bytes());
            let end = next.len() - 8;
            let hash = checksum(&next[..end]);
            next[end..].copy_from_slice(&hash.to_le_bytes());
            journal.extend(encode(&previous, &next));
        }
        for (variable, bytes) in [("TRAMES_WAL_FIXTURE", journal), ("TRAMES_WAL_AFTER", next)] {
            let text = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>() + "\n";
            fs::write(std::env::var(variable).unwrap(), text).unwrap();
        }
    }
    #[test]
    fn delta_resynchronizes_insert_delete_and_small_metadata_updates() {
        let old: Vec<u8> = (0..65536)
            .map(|i| ((i * 37 + i / 256) % 251) as u8)
            .collect();
        for position in [0, 39, 64, 32123, 65520] {
            let mut new = old.clone();
            new.splice(
                position..position + 3,
                b"new variable record".iter().copied(),
            );
            let frame = encode(&old, &new);
            assert!(frame.len() < 2048, "{}", frame.len());
            let mut recovered = old.clone();
            replay(&mut recovered, &frame).unwrap();
            assert_eq!(recovered, new);
        }
    }
    #[test]
    fn a_long_delta_chain_retains_exact_source_spans() {
        let original: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        let mut accepted = original.clone();
        let mut journal = Vec::new();
        for i in 0..128 {
            let mut next = accepted.clone();
            next[i * 197] ^= 0x71;
            journal.extend(encode(&accepted, &next));
            accepted = next;
        }
        let mut recovered = original;
        replay(&mut recovered, &journal).unwrap();
        assert_eq!(recovered, accepted);
    }
    #[test]
    fn recovery_covers_torn_tail_stale_checkpoint_and_corruption() {
        let old = vec![1; 4096];
        let mut next = old.clone();
        next[55] = 9;
        let first = encode(&old, &next);
        let mut last = next.clone();
        last[500] = 10;
        let second = encode(&next, &last);
        let mut journal = first.clone();
        journal.extend(&second);
        for cut in first.len()..journal.len() {
            let mut recovered = old.clone();
            replay(&mut recovered, &journal[..cut]).unwrap();
            assert_eq!(recovered, next);
        }
        for mut recovered in [old, next, last.clone()] {
            replay(&mut recovered, &journal).unwrap();
            assert_eq!(recovered, last);
        }
        journal[30] ^= 1;
        assert!(replay(&mut vec![1; 4096], &journal).is_err());
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;
    struct Store(PathBuf);
    impl Store {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "trames-wal-{}-{}",
                std::process::id(),
                trames_memory::new_backing_identity()
            )))
        }
    }
    impl Drop for Store {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn small_namespace_edits_append_then_recover_torn_tail_and_checkpoint() {
        let store = Store::new();
        let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
        let baseline = fs::read(store.0.join("manifest")).unwrap();
        let mut full_bytes = 0u64;
        for i in 0..200 {
            v.import_file(format!("/small-{i:04}").as_bytes(), vec![i as u8; 32])
                .unwrap();
            full_bytes +=
                v.fs.borrow()
                    .disk
                    .as_ref()
                    .unwrap()
                    .checkpoint
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .bytes
                    .len() as u64;
        }
        assert_eq!(fs::read(store.0.join("manifest")).unwrap(), baseline);
        let final_bytes = super::super::test_image(&store.0).len();
        let journal = fs::metadata(store.0.join("manifest.wal")).unwrap().len();
        eprintln!(
            "200 small files: WAL {journal} bytes; equivalent full publications {full_bytes} bytes"
        );
        assert!(
            journal < (final_bytes * 200 / 4) as u64,
            "journal {journal}, full image {final_bytes}"
        );
        assert!(super::super::test_record_bytes(&store.0) < final_bytes as u64 / 4);
        let mut file = OpenOptions::new()
            .append(true)
            .open(store.0.join("manifest.wal"))
            .unwrap();
        file.write_all(MAGIC).unwrap();
        file.write_all(&4096u64.to_le_bytes()).unwrap();
        file.write_all(b"torn tail").unwrap();
        file.sync_all().unwrap();
        drop(file);
        drop(v);
        let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
        assert_eq!(fs::metadata(store.0.join("manifest.wal")).unwrap().len(), 0);
        for i in 0..200 {
            v.stat_at(AT_FDCWD, format!("/small-{i:04}").as_bytes())
                .unwrap();
        }
        let disk = v.fs.borrow().disk.clone().unwrap();
        disk.wal_records
            .store(CHECKPOINT_RECORDS, Ordering::Relaxed);
        let accepted = super::super::test_image(&store.0);
        v.mkdir_at(AT_FDCWD, b"/after-checkpoint", 0o755).unwrap();
        assert_eq!(fs::read(store.0.join("manifest")).unwrap(), accepted);
        drop(disk);
        drop(v);
        Vfs::open_disk(&store.0, Default::default())
            .unwrap()
            .stat_at(AT_FDCWD, b"/after-checkpoint")
            .unwrap();
    }
    #[test]
    fn corrupt_complete_frame_does_not_run_object_recovery() {
        let store = Store::new();
        let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
        v.import_file(b"/retained", vec![1]).unwrap();
        drop(v);
        let orphan = store.0.join("objects/ffffffffffffffff.dat");
        fs::write(&orphan, b"not garbage until metadata validates").unwrap();
        let path = store.0.join("manifest.wal");
        let mut journal = fs::read(&path).unwrap();
        journal[24] ^= 1;
        fs::write(path, journal).unwrap();
        assert_eq!(
            Vfs::open_disk(&store.0, Default::default()).err(),
            Some(Errno(22))
        );
        assert!(orphan.exists());
    }
}
