// SPDX-License-Identifier: GPL-3.0-or-later
//! Job membership uses the original process group and family/index transactions.
//! No task CPU projection or owner service participates in these operations.
use super::*;
impl IoTask {
    /// Self job queries need only the original packed IDs and PID translation.
    pub fn job_query(&self, namespace: &PidNamespace, session: bool) -> u64 {
        let (group, sid) = self.lifecycle().job_ids();
        namespace.local(if session { sid } else { group }) as u64
    }
}
impl IoRoutes {
    pub fn job_call(
        &self,
        source: &Arc<IoTask>,
        number: u32,
        a: [u64; 6],
    ) -> Option<Result<u64, Errno>> {
        if source.tgid() == 0 || !matches!(number, 154..=157) {
            return None;
        }
        let pid = a[0] as u32;
        let pgid = a[1] as u32;
        if matches!(number, 155 | 156) {
            return Some((|| {
                let id = if pid == 0 {
                    source.tgid()
                } else {
                    self.namespace.global(pid).ok_or(Errno(3))?
                };
                if id == source.tgid() {
                    return Ok(source.job_query(&self.namespace, number == 156));
                }
                let task = self
                    .directory
                    .tasks(0, id)
                    .into_iter()
                    .next()
                    .ok_or(Errno(3))?;
                Ok(task.job_query(&self.namespace, number == 156))
            })());
        }
        let family = source.family()?;
        let families = family.registry()?;
        Some(families.job_change(|| {
            if number == 154 && pgid > i32::MAX as u32 {
                return Err(Errno(22));
            }
            let target = if number == 157 || pid == 0 {
                source.tgid()
            } else {
                self.namespace.global(pid).ok_or(Errno(3))?
            };
            // Family -> controlling reference -> job index. In particular a
            // source fork never waits for a reference whose writer wants Family.
            let controlling = (number == 157)
                .then(|| source.lifecycle().controlling())
                .flatten();
            let mut controlling = controlling.as_ref().map(|c| c.lock());
            // Actual job writes serialize on the existing membership index.
            let mut index = self.directory.groups.lock().unwrap();
            let targets: Vec<_> = index.get(&(1, target)).map_or_else(Vec::new, |g| {
                g.members
                    .read()
                    .unwrap()
                    .iter()
                    .filter_map(Weak::upgrade)
                    .filter(|t| t.identifies(1, target))
                    .collect()
            });
            let task = if target == source.tgid() {
                source.clone()
            } else {
                targets
                    .iter()
                    .find(|t| t.pid.load(Ordering::Relaxed) == target)
                    .cloned()
                    .ok_or(Errno(3))?
            };
            let original = task.family().cloned().ok_or(Errno(3))?;
            let session = source.session();
            if number == 154 && target != source.tgid() {
                if original.parent() != source.tgid() {
                    return Err(Errno(3));
                }
                if task.session() != session {
                    return Err(Errno(1));
                }
                if original.execed() {
                    return Err(Errno(13));
                }
            }
            let group = if number == 157 || pgid == 0 {
                target
            } else {
                self.namespace.global(pgid).ok_or(Errno(1))?
            };
            let has_group = |id| {
                index.get(&(2, id)).is_some_and(|g| {
                    g.members
                        .read()
                        .unwrap()
                        .iter()
                        .filter_map(Weak::upgrade)
                        .any(|t| t.identifies(2, id) && (number == 157 || t.session() == session))
                })
            };
            let next_session = if number == 157 {
                if source.group() == target || has_group(target) {
                    return Err(Errno(1));
                }
                source.tgid()
            } else {
                if task.session() != session
                    || target == session
                    || group != target && group != source.group() && !has_group(group)
                {
                    return Err(Errno(1));
                }
                session
            };
            for member in &targets {
                let namespace = member.inbox.namespace.get().unwrap_or(&self.namespace);
                member.retain_pid_references(
                    namespace,
                    [
                        member.pid.load(Ordering::Relaxed),
                        target,
                        group,
                        next_session,
                    ],
                );
            }
            if number == 157 {
                if let Some(controlling) = &mut controlling {
                    controlling.replace(None);
                }
            }
            task.lifecycle().set_job_ids(group, next_session);
            let next = index.entry((2, group)).or_insert_with(|| {
                Arc::new(Group {
                    members: Default::default(),
                })
            });
            let mut members = next.members.write().unwrap();
            members.retain(|m| m.upgrade().is_some_and(|t| t.identifies(2, group)));
            for member in targets {
                member.published_group.store(group, Ordering::Relaxed);
                member
                    .published_session
                    .store(next_session, Ordering::Relaxed);
                if !members.iter().any(|m| m.ptr_eq(&Arc::downgrade(&member))) {
                    members.push(Arc::downgrade(&member));
                }
            }
            Ok((
                original,
                group,
                if number == 157 {
                    self.namespace.local(source.tgid()) as u64
                } else {
                    0
                },
            ))
        }))
    }
}
