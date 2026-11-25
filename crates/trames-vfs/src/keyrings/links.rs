// SPDX-License-Identifier: GPL-3.0-or-later
//! Keyring membership owns children; the existing registry lock serializes
//! graph mutations so concurrent opposite links cannot create an owning cycle.
use super::*;
pub(super) fn possessed(root: &Arc<Ring>, c: &Credentials, id: i32) -> bool {
    let mut pending = vec![(root.clone(), 0)];
    let mut seen = BTreeMap::new();
    while let Some((ring, depth)) = pending.pop() {
        if seen.get(&ring.id).is_some_and(|old| *old <= depth) {
            continue;
        }
        seen.insert(ring.id, depth);
        if ring.id == id {
            return true;
        }
        if depth >= 6 || !ring.allows(c, *ring.permissions.lock().unwrap(), true, SEARCH) {
            continue;
        }
        pending.extend(
            ring.links
                .lock()
                .unwrap()
                .values()
                .map(|r| (r.clone(), depth + 1)),
        );
    }
    false
}
fn check(ring: &Ring, c: &Credentials, possessed: bool, need: u32) -> Result<()> {
    if ring.allows(c, *ring.permissions.lock().unwrap(), possessed, need) {
        Ok(())
    } else {
        Err(Errno(13))
    }
}
impl SessionKeys {
    pub fn link(
        &self,
        registry: &KeyRegistry,
        c: &Credentials,
        source: i32,
        destination: i32,
        unlink: bool,
    ) -> Result<u64> {
        let (source, have_source) = self.resolve(registry, c, source, false)?;
        let (destination, have_destination) = self.resolve(registry, c, destination, !unlink)?;
        if !unlink {
            check(&source, c, have_source, LINK)?;
        }
        check(&destination, c, have_destination, WRITE)?;
        let _graph = registry.index.lock().unwrap();
        if unlink {
            let mut links = destination.links.lock().unwrap();
            if links.get(&source.name).is_none_or(|r| r.id != source.id) {
                return Err(Errno(2));
            }
            links.remove(&source.name);
        } else {
            let mut pending = vec![(source.clone(), 0)];
            let mut seen = BTreeMap::new();
            while let Some((ring, depth)) = pending.pop() {
                if ring.id == destination.id {
                    return Err(Errno(35));
                }
                if seen.get(&ring.id).is_some_and(|old| *old >= depth) {
                    continue;
                }
                seen.insert(ring.id, depth);
                let children = ring.links.lock().unwrap();
                if depth >= 6 && !children.is_empty() {
                    return Err(Errno(40));
                }
                pending.extend(children.values().map(|r| (r.clone(), depth + 1)));
            }
            destination
                .links
                .lock()
                .unwrap()
                .insert(source.name.clone(), source);
        }
        Ok(0)
    }
    pub fn clear(&self, registry: &KeyRegistry, c: &Credentials, id: i32) -> Result<u64> {
        let (ring, have) = self.resolve(registry, c, id, true)?;
        check(&ring, c, have, WRITE)?;
        let _graph = registry.index.lock().unwrap();
        ring.links.lock().unwrap().clear();
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn read(task: &SessionKeys, registry: &KeyRegistry, c: &Credentials, id: i32) -> Vec<i32> {
        let KeyResult::Bytes(bytes) = task.access(registry, c, id, KeyOperation::Read).unwrap()
        else {
            panic!("read result");
        };
        bytes
            .chunks_exact(4)
            .map(|p| i32::from_le_bytes(p.try_into().unwrap()))
            .collect()
    }
    #[test]
    fn dag_shortcuts_do_not_hide_overlong_subtrees_or_short_possession_paths() {
        let registry = KeyRegistry::default();
        let c = Credentials::user(1000, 1000);
        let tasks: Vec<_> = (0..10).map(|_| SessionKeys::default()).collect();
        let ids: Vec<_> = tasks
            .iter()
            .enumerate()
            .map(|(i, task)| {
                task.join(&registry, &c, Some(format!("dag-{i}").into_bytes()))
                    .unwrap() as i32
            })
            .collect();
        // Extending a leaf does not inspect its ancestors: Linux allows this
        // tree but refuses to link the overlong subtree beneath a new root.
        for i in 0..7 {
            tasks[i]
                .link(&registry, &c, ids[i + 1], ids[i], false)
                .unwrap();
        }
        assert_eq!(
            tasks[8].link(&registry, &c, ids[0], ids[8], false),
            Err(Errno(40))
        );
        tasks[0].link(&registry, &c, ids[6], ids[0], false).unwrap();
        assert_eq!(
            tasks[8].link(&registry, &c, ids[0], ids[8], false),
            Err(Errno(40)),
            "a shortcut cannot hide the longer path"
        );
        tasks[7]
            .access(
                &registry,
                &c,
                ids[7],
                KeyOperation::SetPermissions(0x3f000000),
            )
            .unwrap();
        assert!(
            tasks[0]
                .access(&registry, &c, ids[7], KeyOperation::Describe)
                .is_ok(),
            "a deep visit cannot hide the later short possession path"
        );
    }
    #[test]
    fn systemd_user_link_is_real_membership_and_survives_fork() {
        let registry = KeyRegistry::default();
        let c = Credentials::user(1000, 1000);
        let task = SessionKeys::default();
        task.join(&registry, &c, None).unwrap();
        let KeyResult::Number(user) = task
            .access(&registry, &c, -4, KeyOperation::Lookup(true))
            .unwrap()
        else {
            panic!("user ring");
        };
        task.link(&registry, &c, -4, -3, false).unwrap();
        task.link(&registry, &c, -4, -3, false).unwrap();
        assert_eq!(read(&task, &registry, &c, -3), [user as i32]);
        let child = task.fork();
        task.retire();
        assert_eq!(read(&child, &registry, &c, -3), [user as i32]);
        child.link(&registry, &c, user as i32, -3, true).unwrap();
        assert!(read(&child, &registry, &c, -3).is_empty());
        assert_eq!(
            child.link(&registry, &c, user as i32, -3, true),
            Err(Errno(2))
        );
    }
    #[test]
    fn linked_ring_possession_ends_at_unlink_and_owning_cycles_are_rejected() {
        let registry = KeyRegistry::default();
        let c = Credentials::user(1000, 1000);
        let a = SessionKeys::default();
        let b = SessionKeys::default();
        let first = a.join(&registry, &c, Some(b"a".to_vec())).unwrap() as i32;
        let second = b.join(&registry, &c, Some(b"b".to_vec())).unwrap() as i32;
        a.link(&registry, &c, second, first, false).unwrap();
        b.access(
            &registry,
            &c,
            second,
            KeyOperation::SetPermissions(0x3f000000),
        )
        .unwrap();
        assert!(a
            .access(&registry, &c, second, KeyOperation::Describe)
            .is_ok());
        assert_eq!(a.link(&registry, &c, first, second, false), Err(Errno(35)));
        a.clear(&registry, &c, first).unwrap();
        assert!(matches!(
            a.access(&registry, &c, second, KeyOperation::Describe),
            Err(Errno(13))
        ));
        b.retire();
        assert!(matches!(
            a.access(&registry, &c, second, KeyOperation::Describe),
            Err(Errno(126))
        ));
    }
    #[test]
    fn opposite_concurrent_links_never_publish_an_owning_cycle() {
        let registry = Arc::new(KeyRegistry::default());
        let c = Credentials::user(1000, 1000);
        let a = SessionKeys::default();
        let b = SessionKeys::default();
        let first = a.join(&registry, &c, Some(b"race-a".to_vec())).unwrap() as i32;
        let second = b.join(&registry, &c, Some(b"race-b".to_vec())).unwrap() as i32;
        for (task, id) in [(&a, first), (&b, second)] {
            task.access(&registry, &c, id, KeyOperation::SetPermissions(0x3f3f0000))
                .unwrap();
        }
        let begin = Arc::new(std::sync::Barrier::new(2));
        std::thread::scope(|scope| {
            let x = scope.spawn(|| {
                begin.wait();
                a.link(&registry, &c, first, second, false)
            });
            let y = scope.spawn(|| {
                begin.wait();
                b.link(&registry, &c, second, first, false)
            });
            let result = [x.join().unwrap(), y.join().unwrap()];
            assert_eq!(result.iter().filter(|v| v.is_ok()).count(), 1);
            assert!(result.contains(&Err(Errno(35))));
        });
    }
}
