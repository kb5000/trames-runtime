// SPDX-License-Identifier: GPL-3.0-or-later
//! Nested projections prepare capability bytes once and publish at the leaf.
use super::*;
use std::{cell::RefCell, rc::Rc};

type Caps = Option<file_caps::FileCaps>;
struct Change {
    file: Arc<file_data::PlainFile>,
    expected: Caps,
    target: Caps,
    prepared: Option<Arc<file_data::PreparedCaps>>,
}
#[derive(Default)]
struct Plan {
    // Intermediate ID domains exist only during this checkpoint traversal.
    caps: BTreeMap<u64, Caps>,
    changes: BTreeMap<usize, Change>,
    published: bool,
}
thread_local! {
    static CURRENT: RefCell<Option<Rc<RefCell<Plan>>>> = const { RefCell::new(None) };
}
struct Binding;
impl Drop for Binding {
    fn drop(&mut self) {
        CURRENT.with(|current| current.replace(None));
    }
}
fn current() -> Option<Rc<RefCell<Plan>>> {
    CURRENT.with(|current| current.borrow().clone())
}
pub(in crate::overlay) fn run(call: impl FnOnce() -> Result<()>) -> Result<()> {
    if current().is_some() {
        return call();
    }
    let plan = Rc::new(RefCell::new(Plan::default()));
    CURRENT.with(|current| current.replace(Some(plan.clone())));
    let binding = Binding;
    let scope = resource_io::Scope::enter();
    let result = call();
    let pending = scope.finish();
    // Only immutable payloads survive suspension, never namespace/node locks
    // or the temporary metadata/ID projections made by this traversal.
    let prepared: Vec<_> = plan
        .borrow_mut()
        .changes
        .values_mut()
        .filter_map(|change| change.prepared.take())
        .collect();
    drop(binding);
    if let Some(pending) = pending {
        let wait = resource_io::holding(pending.wait, Arc::new(prepared));
        return Err(resource_io::memory_error(wait.fault(0)));
    }
    result
}
pub(crate) fn caps(identity: u64) -> Option<Caps> {
    let plan = current()?;
    let caps = plan.borrow().caps.get(&identity).copied();
    caps
}
pub(in crate::overlay) fn set(node: &NodeRef, expected: Caps, caps: Caps) -> Result<()> {
    let plan = current().ok_or(Errno(5))?;
    let n = node.borrow();
    let Content::File(data) = &n.content else {
        return Err(Errno(95));
    };
    if caps.is_some() && data.has_writable_mappings() {
        return Err(Errno(16));
    }
    let (file, target) = data.projection_caps(caps)?;
    let (_, expected) = data.projection_caps(expected)?;
    // This translates an already published grant into the backing layer's ID
    // domain. Initial capability setting/copy-up owns mapped writeback; the
    // final disk rename retains its original data durability barrier.
    let mut plan = plan.borrow_mut();
    let change = plan
        .changes
        .entry(Arc::as_ptr(&file) as usize)
        .or_insert_with(|| Change {
            expected,
            file,
            target,
            prepared: None,
        });
    change.target = target;
    // Node::file_caps sees this ID domain; ordinary observers on other
    // threads continue seeing the actual provider until final publication.
    plan.caps.insert(n.identity, caps);
    Ok(())
}
/// Stage only the final, fully composed ID conversion at the leaf backing
/// store. Intermediate nested-overlay conversions do not issue disk writes.
pub(crate) fn prepare() -> Result<()> {
    let Some(plan) = current() else {
        return Ok(());
    };
    let mut plan = plan.borrow_mut();
    if !plan.published {
        for change in plan.changes.values_mut() {
            if change.target != change.expected && change.prepared.is_none() {
                change.prepared = Some(change.file.prepare_projected_caps(change.target)?);
            }
        }
    }
    Ok(())
}
/// The caller has already admitted its manifest write. Acquire all object
/// transactions before any capability publication and release them on wait.
/// The callback has no resource admission left after these renames.
pub(crate) fn publish(call: impl FnOnce() -> Result<()>) -> Result<()> {
    let Some(plan) = current() else {
        return call();
    };
    if plan.borrow().published {
        return call();
    }
    let prepared: Vec<_> = plan
        .borrow()
        .changes
        .values()
        .filter_map(|change| {
            change
                .prepared
                .as_ref()
                .map(|stage| (stage.clone(), change.expected))
        })
        .collect();
    let mut leases = Vec::with_capacity(prepared.len());
    for (stage, _) in &prepared {
        match stage.file.begin_transaction() {
            Ok(lease) => leases.push(lease),
            Err(wait) => {
                return Err(resource_io::memory_error(
                    trames_memory::PageWait::resource(wait).fault(0),
                ))
            }
        }
    }
    // No byte lock spans staging or quota suspension. Once every admission is
    // available, use the original provider locks in the same stable order for
    // the final native commit, including rollback on a real manifest error.
    let mut guards = Vec::with_capacity(prepared.len());
    for (index, (stage, expected)) in prepared.iter().enumerate() {
        let _owner = leases[index].as_ref().map(|lease| lease.enter());
        guards.push(stage.lock(*expected)?);
    }
    let mut published: Vec<(usize, file_data::PublishedCaps)> = Vec::new();
    let result = (|| {
        for (index, guard) in guards.iter_mut().enumerate() {
            published.push((index, guard.publish()?));
        }
        call()
    })();
    if let Err(error) = result {
        let mut rollback_error = None;
        for (index, publication) in published.into_iter().rev() {
            if let Err(error) = guards[index].rollback(publication) {
                rollback_error.get_or_insert(error);
            }
        }
        if let Some(error) = rollback_error {
            return Err(error);
        }
        return Err(error);
    }
    plan.borrow_mut().published = true;
    Ok(())
}
/// A concurrent real data mutation revoked the original capability while we
/// staged bytes. Recompute from the live provider with no published effects.
pub(crate) fn retry() -> Errno {
    let wait = Arc::new(trames_memory::PageWait::default());
    wait.finish();
    resource_io::memory_error(wait.fault(0))
}

impl storage::FileData {
    pub(crate) fn projection_caps(&self, caps: Caps) -> Result<(Arc<file_data::PlainFile>, Caps)> {
        match self {
            Self::Plain(file) => Ok((file.clone(), caps)),
            Self::Mapped(data) => data.projection_caps(caps),
            Self::Layer(file) if file.upper => {
                let caps = caps
                    .map(|caps| caps.translate(|id| file.ids().stored(false, id)))
                    .transpose()?;
                file.read(|data| data.projection_caps(caps))
            }
            _ => Err(Errno(95)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Vfs, NodeRef, Arc<file_data::PlainFile>, file_caps::FileCaps) {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/data", 0o755).unwrap();
        v.mount(None, b"/data", Some(b"tmpfs"), 0, None).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/data/file", 0x42, 0o644).unwrap();
        v.write(fd, b"original").unwrap();
        v.close(fd).unwrap();
        let mut bytes = vec![0; 20];
        bytes[..4].copy_from_slice(&0x02000001u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&(1u32 << capabilities::SETUID).to_le_bytes());
        v.set_xattr(
            AT_FDCWD,
            Some(b"/data/file"),
            true,
            file_caps::NAME,
            Some(&bytes),
            0,
        )
        .unwrap();
        let node = v
            .node(&v.resolve(AT_FDCWD, b"/data/file").unwrap())
            .unwrap();
        let caps = node.borrow().file_caps().unwrap();
        let file = {
            let n = node.borrow();
            let Content::File(data) = &n.content else {
                panic!("file")
            };
            data.projection_caps(None).unwrap().0
        };
        (v, node, file, caps)
    }
    #[test]
    fn an_intermediate_projection_is_local_to_its_traversal_and_error_discards_it() {
        let (_v, node, file, original) = fixture();
        let translated = original.translate(|_| Ok(1000)).unwrap();
        assert_eq!(
            run(|| {
                set(&node, Some(original), Some(translated))?;
                assert_eq!(node.borrow().file_caps(), Some(translated));
                let other = node.clone();
                assert_eq!(
                    std::thread::spawn(move || other.borrow().file_caps())
                        .join()
                        .unwrap(),
                    Some(original)
                );
                prepare()?;
                assert_eq!(file.capabilities(), Some(original));
                Err(Errno(5))
            }),
            Err(Errno(5))
        );
        assert_eq!(node.borrow().file_caps(), Some(original));
        assert_eq!(file.capabilities(), Some(original));
    }
    #[test]
    fn a_revocation_after_projection_input_is_read_replans_before_any_publication() {
        let (_v, node, file, original) = fixture();
        let translated = original.translate(|_| Ok(1000)).unwrap();
        let scope = resource_io::Scope::enter();
        assert_eq!(
            run(|| {
                set(&node, Some(original), Some(translated))?;
                prepare()?;
                file.write_at(0, b"changed")?;
                publish(|| panic!("a stale grant cannot reach namespace publication"))
            }),
            Err(Errno(11))
        );
        assert!(scope.finish().unwrap().wait.ready());
        assert_eq!(node.borrow().file_caps(), None);
        assert_eq!(file.capabilities(), None);
    }
}
