// SPDX-License-Identifier: GPL-3.0-or-later
//! Original task-body custody. CPU/View execution does not hold this guard.
use super::*;
use std::ops::{Deref, DerefMut};
use trames_shared::{Custody, OwnedRead, OwnedWrite};

type Slot<C> = Option<Box<Process<C>>>;
type Cell<C> = Custody<Slot<C>>;

pub(crate) struct Handle<C: Cpu>(
    Cell<C>,
    Arc<trames_kernel::task_control::Group>,
    trames_memory::MemoryReport,
);
impl<C: Cpu> Clone for Handle<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone(), self.2.clone())
    }
}
impl<C: Cpu> Handle<C> {
    fn new(process: Box<Process<C>>) -> Self {
        let group = process.signals.io.lifecycle().clone();
        let memory = process.memory.memory_report();
        Self(Custody::new(Some(process)), group, memory)
    }
    pub fn same(&self, other: &Self) -> bool {
        self.0.same(&other.0)
    }
    fn try_read_body(&self) -> Option<Read<C>> {
        let value = self.0.read_owned();
        value.is_some().then_some(Read { value })
    }
    pub fn read(&self) -> Read<C> {
        Read {
            value: self.0.read_owned(),
        }
    }
    pub fn write(&self) -> Write<C> {
        Write {
            value: self.0.write_owned(),
        }
    }
    /// Existing joined collection may wait for the object it is collecting.
    /// Source executors must continue to use nonblocking try_admit instead.
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn collect_admission(&self) -> Admission<C> {
        Admission {
            _permit: self.0.write_owned().into_admission(),
        }
    }
    pub fn try_admit(&self) -> Option<Admission<C>> {
        Some(Admission {
            _permit: self.0.try_admit()?,
        })
    }
    pub fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.0.subscribe(signal)
    }
}
pub(crate) struct Admission<C: Cpu> {
    _permit: trames_shared::Admission<Slot<C>>,
}

/// Keep original task/mm custody on this host thread only. Ordinary methods
/// reenter these permits; no Ref/RefMut is held across a handler call.
pub(crate) struct Cohort<C: Cpu> {
    // Each mm permit ends before its task permit. One allocation per cohort;
    // no wait signal or subscription is created on successful first admission.
    _permits: Vec<(trames_memory::MemoryAdmission, Admission<C>)>,
}
pub(crate) struct AdmissionWait {
    pub signal: Arc<trames_shared::IoSignal>,
    pub subscriptions: Vec<trames_shared::IoSubscription>,
}
fn obtain<T>(
    mut acquire: impl FnMut() -> Option<T>,
    subscribe: impl FnOnce(&Arc<trames_shared::IoSignal>) -> Vec<trames_shared::IoSubscription>,
    target: &std::sync::Weak<dyn trames_shared::IoWake>,
    pid: u32,
) -> Result<T, AdmissionWait> {
    if let Some(permit) = acquire() {
        return Ok(permit);
    }
    let signal = trames_shared::IoSignal::new(pid, target.clone());
    let subscriptions = subscribe(&signal);
    acquire().ok_or(AdmissionWait {
        signal,
        subscriptions,
    })
}
pub(crate) fn admit<C: Cpu>(
    jobs: &[Box<crate::run_queue::Job<C>>],
    target: &std::sync::Weak<dyn trames_shared::IoWake>,
) -> Result<Cohort<C>, AdmissionWait> {
    let mut cohort = Cohort {
        _permits: Vec::with_capacity(jobs.len()),
    };
    for job in jobs {
        let task = job.work.task.as_ref().expect("original checkpoint task");
        assert!(cohort.include(task, target)?, "original checkpoint body");
    }
    Ok(cohort)
}
impl<C: Cpu> Cohort<C> {
    pub fn include(
        &mut self,
        task: &Handle<C>,
        target: &std::sync::Weak<dyn trames_shared::IoWake>,
    ) -> Result<bool, AdmissionWait> {
        let Some(permit) = admit_one(task, 0, target)? else {
            return Ok(false);
        };
        self._permits.push(permit);
        Ok(true)
    }
}
/// A single source operation needs no cohort allocation. Both permits retain
/// the actual task/mm; failed admission keeps only original notifications.
pub(crate) fn admit_one<C: Cpu>(
    task: &Handle<C>,
    pid: u32,
    target: &std::sync::Weak<dyn trames_shared::IoWake>,
) -> Result<Option<(trames_memory::MemoryAdmission, Admission<C>)>, AdmissionWait> {
    let permit = obtain(
        || task.try_admit(),
        |signal| vec![task.subscribe(signal)],
        target,
        pid,
    )?;
    let Some(task) = task.try_read_body() else {
        return Ok(None);
    };
    let memory = obtain(
        || task.memory.try_admit(),
        |signal| task.memory.subscribe_custody(signal).into_iter().collect(),
        target,
        pid,
    )?;
    Ok(Some((memory, permit)))
}

/// Nonblocking admission on an already accepted resource's own notification.
/// Successful task admission removes its temporary subscription before trying
/// mm custody, so releasing our task permit cannot wake our own unrelated wait.
pub(crate) fn admit_on<C: Cpu>(
    task: &Handle<C>,
    signal: &Arc<trames_shared::IoSignal>,
) -> Result<
    Option<(trames_memory::MemoryAdmission, Admission<C>)>,
    Vec<trames_shared::IoSubscription>,
> {
    let permit = if let Some(permit) = task.try_admit() {
        permit
    } else {
        let subscription = task.subscribe(signal);
        match task.try_admit() {
            Some(permit) => {
                drop(subscription);
                permit
            }
            None => return Err(vec![subscription]),
        }
    };
    let Some(task) = task.try_read_body() else {
        return Ok(None);
    };
    let memory = if let Some(memory) = task.memory.try_admit() {
        memory
    } else {
        let subscription = task.memory.subscribe_custody(signal);
        match task.memory.try_admit() {
            Some(memory) => {
                drop(subscription);
                memory
            }
            None => return Err(subscription.into_iter().collect()),
        }
    };
    Ok(Some((memory, permit)))
}
pub(crate) struct Read<C: Cpu> {
    value: OwnedRead<Slot<C>>,
}
impl<C: Cpu> Deref for Read<C> {
    type Target = Process<C>;
    fn deref(&self) -> &Self::Target {
        self.value.as_deref().expect("original task body")
    }
}
impl<C: Cpu> AsRef<Process<C>> for Read<C> {
    fn as_ref(&self) -> &Process<C> {
        self
    }
}
pub(crate) struct Write<C: Cpu> {
    value: OwnedWrite<Slot<C>>,
}
impl<C: Cpu> Deref for Write<C> {
    type Target = Process<C>;
    fn deref(&self) -> &Self::Target {
        self.value.as_deref().expect("original task body")
    }
}
impl<C: Cpu> DerefMut for Write<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value.as_deref_mut().expect("original task body")
    }
}
impl<C: Cpu> Write<C> {
    fn into_handle(self) -> Handle<C> {
        let group = self.signals.io.lifecycle().clone();
        let memory = self.memory.memory_report();
        Handle(self.value.into_custody(), group, memory)
    }
    pub fn into_inner(mut self) -> Box<Process<C>> {
        self.value.take().expect("retired task body")
    }
}
impl<C: Cpu> From<Box<Process<C>>> for Handle<C> {
    fn from(process: Box<Process<C>>) -> Self {
        Self::new(process)
    }
}
impl<C: Cpu> From<Write<C>> for Handle<C> {
    fn from(process: Write<C>) -> Self {
        process.into_handle()
    }
}

// Membership protects IDs -> original handles only. No task-body lock,
// guest operation, callback or final resource destructor runs under this lock.
type Entries<C> = Arc<[(u32, Handle<C>)]>;
struct Members<C: Cpu> {
    tasks: BTreeMap<u32, Handle<C>>,
    snapshot: Option<Entries<C>>,
    groups: BTreeMap<usize, std::collections::BTreeSet<u32>>,
}
pub(super) struct Directory<C: Cpu>(
    Arc<parking_lot::Mutex<Members<C>>>,
    Arc<crate::exit_groups::ExitGroups>,
);
impl<C: Cpu> Default for Directory<C> {
    fn default() -> Self {
        Self(
            Arc::new(parking_lot::Mutex::new(Members {
                tasks: BTreeMap::new(),
                snapshot: None,
                groups: BTreeMap::new(),
            })),
            Arc::default(),
        )
    }
}
impl<C: Cpu> Clone for Directory<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone())
    }
}
impl<C: Cpu> Directory<C> {
    pub fn exits(&self) -> Arc<crate::exit_groups::ExitGroups> {
        self.1.clone()
    }
    pub fn handle(&self, id: &u32) -> Option<Handle<C>> {
        self.0.lock().tasks.get(id).cloned()
    }
    pub fn all(&self) -> Vec<(u32, Handle<C>)> {
        self.entries().iter().cloned().collect()
    }
    fn entries(&self) -> Entries<C> {
        let mut members = self.0.lock();
        if let Some(snapshot) = &members.snapshot {
            return snapshot.clone();
        }
        let snapshot: Entries<C> = members
            .tasks
            .iter()
            .map(|(&id, task)| (id, task.clone()))
            .collect();
        members.snapshot = Some(snapshot.clone());
        snapshot
    }
    /// Cold lookup uses original mm identity without taking unrelated task or
    /// memory custody. The selected body is revalidated after its admission.
    pub fn memory(&self, memory: &trames_memory::MemoryReport) -> Vec<(u32, Handle<C>)> {
        self.entries()
            .iter()
            .filter(|(_, task)| task.2.same_resource(memory))
            .cloned()
            .collect()
    }
    /// Original group membership includes cold/retiring tasks until their
    /// identity is actually removed. No unrelated task bodies are inspected.
    pub fn group(&self, group: &Arc<trames_kernel::task_control::Group>) -> Vec<(u32, Handle<C>)> {
        let members = self.0.lock();
        members
            .groups
            .get(&(Arc::as_ptr(group) as usize))
            .into_iter()
            .flatten()
            .map(|id| (*id, members.tasks[id].clone()))
            .collect()
    }
    // Cold projections are lookup hints, not accepted source capabilities.
    // Resolve the original body first, then validate its current PID while
    // custody prevents rekey/consumption. Never hold the directory while
    // waiting for a body. Retained source Handles keep their own semantics.
    fn read_entry(&self, id: u32, task: &Handle<C>) -> Option<Read<C>> {
        let body = task.try_read_body()?;
        self.contains_original(id, task).then_some(body)
    }
    fn write_entry(&self, id: u32, task: &Handle<C>) -> Option<Write<C>> {
        let body = task.write();
        (body.value.is_some() && self.contains_original(id, task)).then_some(body)
    }
    pub fn contains_original(&self, id: u32, task: &Handle<C>) -> bool {
        self.0
            .lock()
            .tasks
            .get(&id)
            .is_some_and(|old| old.0.same(&task.0))
    }
    pub fn publish(&self, id: u32, task: Handle<C>) -> Option<Handle<C>> {
        let memory = task.2.clone();
        let group = task.1.clone();
        let (old, snapshot) = {
            let mut members = self.0.lock();
            let old = members.remove(id);
            members
                .groups
                .entry(Arc::as_ptr(&task.1) as usize)
                .or_default()
                .insert(id);
            members.tasks.insert(id, task);
            (old, members.snapshot.take())
        };
        drop(snapshot);
        self.1.watch(&group);
        // A proc observer can request this image after its public identity but
        // before task membership. Publication closes that original-resource race.
        memory.wake_requested_reads();
        old
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    fn remove(&self, id: &u32) -> Option<Handle<C>> {
        let (old, snapshot) = {
            let mut members = self.0.lock();
            (members.remove(*id), members.snapshot.take())
        };
        drop(snapshot);
        old
    }
    fn remove_original(&self, id: u32, task: &Cell<C>) -> bool {
        let (old, snapshot) = {
            let mut members = self.0.lock();
            if !members.tasks.get(&id).is_some_and(|old| old.0.same(task)) {
                return false;
            }
            (members.remove(id), members.snapshot.take())
        };
        drop(snapshot);
        drop(old);
        true
    }
    pub fn retire(&self, id: u32, task: &Handle<C>) {
        self.remove_original(id, &task.0);
    }
    pub fn restore(&self, from: u32, id: u32, task: &Write<C>) -> Option<Handle<C>> {
        let memory = task.memory.memory_report();
        let (replaced, snapshot) = {
            let mut members = self.0.lock();
            if !members
                .tasks
                .get(&from)
                .is_some_and(|old| old.0.same(task.value.custody()))
            {
                return None;
            }
            if from == id && members.tasks[&id].2.same_resource(&memory) {
                return None;
            }
            let mut task = members.remove(from).expect("original member");
            task.2 = memory.clone();
            let replaced = members.remove(id);
            members
                .groups
                .entry(Arc::as_ptr(&task.1) as usize)
                .or_default()
                .insert(id);
            members.tasks.insert(id, task);
            (replaced, members.snapshot.take())
        };
        drop(snapshot);
        memory.wake_requested_reads();
        replaced
    }
}
impl<C: Cpu> Members<C> {
    fn remove(&mut self, id: u32) -> Option<Handle<C>> {
        let old = self.tasks.remove(&id)?;
        let group = Arc::as_ptr(&old.1) as usize;
        let members = self
            .groups
            .get_mut(&group)
            .expect("original group membership");
        assert!(members.remove(&id));
        if members.is_empty() {
            self.groups.remove(&group);
        }
        Some(old)
    }
}

/// The joined handler's local exclusion is not process membership. Source
/// executors retain Directory directly and can still resolve checked-out tasks.
pub(super) struct Table<C: Cpu> {
    directory: Directory<C>,
    excluded: std::rc::Rc<RefCell<std::collections::BTreeSet<u32>>>,
}
impl<C: Cpu> Default for Table<C> {
    fn default() -> Self {
        Self {
            directory: Directory::default(),
            excluded: Default::default(),
        }
    }
}
impl<C: Cpu> Table<C> {
    pub fn directory(&self) -> Directory<C> {
        self.directory.clone()
    }
    pub fn get(&self, id: &u32) -> Option<Read<C>> {
        self.directory.read_entry(*id, &self.handle(id)?)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn get_mut(&self, id: &u32) -> Option<Write<C>> {
        self.directory.write_entry(*id, &self.handle(id)?)
    }
    pub fn read(&self, id: &u32) -> Read<C> {
        self.get(id).expect("original task identity")
    }
    pub fn handle(&self, id: &u32) -> Option<Handle<C>> {
        if self.excluded.borrow().contains(id) {
            None
        } else {
            self.directory.handle(id)
        }
    }
    pub fn insert(&mut self, id: u32, process: impl Install<C>) -> Option<Write<C>> {
        process.install(self, id)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn checkout(&self, id: &u32) -> Option<Checkout<C>> {
        let task = self.handle(id)?;
        let value = self.directory.write_entry(*id, &task)?;
        assert!(self.excluded.borrow_mut().insert(*id));
        Some(Checkout {
            value: Some(value),
            directory: self.directory.clone(),
            id: *id,
            excluded: self.excluded.clone(),
        })
    }
    pub fn remove(&mut self, id: &u32) -> Option<Write<C>> {
        let task = self.directory.handle(id)?;
        let value = self.directory.write_entry(*id, &task)?;
        self.directory
            .remove_original(*id, &task.0)
            .then_some(value)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn contains_key(&self, id: &u32) -> bool {
        self.handle(id).is_some()
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn keys(&self) -> impl Iterator<Item = u32> {
        self.entries().map(|(id, _)| id)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn len(&self) -> usize {
        let members = self.directory.0.lock();
        members.tasks.len()
            - self
                .excluded
                .borrow()
                .iter()
                .filter(|id| members.tasks.contains_key(id))
                .count()
    }
    fn entries(&self) -> impl Iterator<Item = (u32, Handle<C>)> {
        let entries = self.directory.entries();
        let excluded = self.excluded.borrow().clone();
        (0..entries.len()).filter_map(move |index| {
            let (id, task) = &entries[index];
            (!excluded.contains(id)).then(|| (*id, task.clone()))
        })
    }
    pub fn values(&self) -> impl Iterator<Item = Read<C>> {
        self.iter().map(|(_, body)| body)
    }
    pub fn values_mut(&self) -> impl Iterator<Item = Write<C>> {
        self.iter_mut().map(|(_, body)| body)
    }
    pub fn iter(&self) -> impl Iterator<Item = (u32, Read<C>)> {
        let directory = self.directory.clone();
        self.entries()
            .filter_map(move |(id, task)| directory.read_entry(id, &task).map(|body| (id, body)))
    }
    pub fn iter_mut(&self) -> impl Iterator<Item = (u32, Write<C>)> {
        let directory = self.directory.clone();
        self.entries()
            .filter_map(move |(id, task)| directory.write_entry(id, &task).map(|body| (id, body)))
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn retain(&mut self, mut retain: impl FnMut(&u32, &Process<C>) -> bool) {
        for (id, task) in self.entries() {
            if let Some(body) = self.directory.read_entry(id, &task) {
                if !retain(&id, &body) {
                    self.directory.remove_original(id, &task.0);
                }
            }
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
pub(super) struct Checkout<C: Cpu> {
    value: Option<Write<C>>,
    directory: Directory<C>,
    id: u32,
    excluded: std::rc::Rc<RefCell<std::collections::BTreeSet<u32>>>,
}
#[cfg(all(test, trames_interpreter_conformance))]
impl<C: Cpu> Deref for Checkout<C> {
    type Target = Process<C>;
    fn deref(&self) -> &Process<C> {
        self.value.as_ref().expect("scoped original task")
    }
}
#[cfg(all(test, trames_interpreter_conformance))]
impl<C: Cpu> DerefMut for Checkout<C> {
    fn deref_mut(&mut self) -> &mut Process<C> {
        self.value.as_mut().expect("scoped original task")
    }
}
#[cfg(all(test, trames_interpreter_conformance))]
impl<C: Cpu> Drop for Checkout<C> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            self.directory
                .remove_original(self.id, value.value.custody());
            drop(value);
        }
        self.excluded.borrow_mut().remove(&self.id);
    }
}
pub(super) trait Install<C: Cpu> {
    fn install(self, table: &Table<C>, id: u32) -> Option<Write<C>>;
}
impl<C: Cpu> Install<C> for Box<Process<C>> {
    fn install(self, table: &Table<C>, id: u32) -> Option<Write<C>> {
        table
            .directory
            .publish(id, self.into())
            .map(|task| task.write())
    }
}
impl<C: Cpu> Install<C> for Write<C> {
    fn install(self, table: &Table<C>, id: u32) -> Option<Write<C>> {
        table
            .directory
            .publish(id, self.into())
            .map(|task| task.write())
    }
}
#[cfg(all(test, trames_interpreter_conformance))]
impl<C: Cpu> Install<C> for Checkout<C> {
    fn install(mut self, table: &Table<C>, id: u32) -> Option<Write<C>> {
        assert!(
            Arc::ptr_eq(&self.directory.0, &table.directory.0),
            "original task directory"
        );
        let task = self.value.take().expect("scoped original task");
        // Publish the new membership before releasing the body. An observer
        // must not newly resolve the old ID after seeing the new task state.
        let replaced = self.directory.restore(self.id, id, &task);
        drop(task);
        replaced.map(|task| task.write())
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use trames_cpu::Cpu;
    type Table = super::Table<Cpu>;
    fn task() -> Box<Process<Cpu>> {
        super::super::tests::process()
    }

    #[test]
    fn cold_snapshot_iteration_never_pairs_a_rekeyed_body_with_its_retired_pid() {
        for mutable in [false, true] {
            let mut table = Table::default();
            table.insert(2, task());
            let original = table.handle(&2).unwrap();
            let directory = table.directory();
            if mutable {
                let mut snapshot = table.iter_mut();
                directory.restore(2, 3, &original.write());
                assert!(
                    snapshot.next().is_none(),
                    "old PID exposed a rekeyed mutable body"
                );
            } else {
                let mut snapshot = table.iter();
                directory.restore(2, 3, &original.write());
                assert!(snapshot.next().is_none(), "old PID exposed a rekeyed body");
            }
            assert_eq!(table.iter().map(|(id, _)| id).collect::<Vec<_>>(), [3]);
        }
    }
    #[test]
    fn cold_value_snapshots_skip_removed_replaced_and_consumed_originals() {
        for mode in 0..3 {
            let mut table = Table::default();
            table.insert(2, task());
            let original = table.handle(&2).unwrap();
            let directory = table.directory();
            let mut reads = table.values();
            let mut writes = table.values_mut();
            directory.retire(2, &original);
            if mode == 1 {
                directory.publish(2, task().into());
            }
            if mode == 2 {
                drop(original.write().into_inner());
            }
            assert!(
                reads.next().is_none(),
                "retired original remained a current value"
            );
            assert!(writes.next().is_none(), "retired original remained mutable");
        }
    }
    #[test]
    fn cold_lookup_revalidates_after_waiting_for_original_body_custody() {
        for mutable in [false, true] {
            let mut table = Table::default();
            table.insert(2, task());
            let original = table.handle(&2).unwrap();
            let directory = table.directory();
            let held = original.write();
            let remote = directory.clone();
            let selected = original.clone();
            let (send, receive) = std::sync::mpsc::channel();
            let observer = std::thread::spawn(move || {
                let absent = if mutable {
                    remote.write_entry(2, &selected).is_none()
                } else {
                    remote.read_entry(2, &selected).is_none()
                };
                send.send(absent).unwrap();
            });
            // The observer may wait on a body, never on the directory lock.
            directory.restore(2, 3, &held);
            drop(held);
            assert!(receive.recv_timeout(Duration::from_secs(2)).unwrap());
            observer.join().unwrap();
            assert!(directory.read_entry(3, &original).is_some());
            assert_eq!(original.read().memory.coordinator_ownership().1, 1);
        }
    }
    #[test]
    fn cold_retain_does_not_visit_or_delete_a_replacement_from_its_old_snapshot() {
        let mut table = Table::default();
        table.insert(1, task());
        table.insert(2, task());
        let old = table.handle(&2).unwrap();
        let directory = table.directory();
        let mut visited = Vec::new();
        table.retain(|id, _| {
            visited.push(*id);
            if *id == 1 {
                directory.retire(2, &old);
                directory.publish(2, task().into());
                drop(old.write().into_inner());
            }
            *id == 1
        });
        assert_eq!(visited, [1]);
        assert!(table.contains_key(&2));
        assert_eq!(table.iter().count(), 2);
    }

    #[test]
    fn checkout_preserves_source_membership_and_never_holds_the_directory_lock() {
        let mut table = Table::default();
        table.insert(1, task());
        let original = table.handle(&1).unwrap();
        let ownership = original.read().memory.coordinator_ownership();
        let directory = table.directory();
        let scope = table.checkout(&1).unwrap();
        assert!(!table.contains_key(&1));
        let (send, receive) = std::sync::mpsc::channel();
        let executor = std::thread::spawn(move || {
            let parent = directory
                .handle(&1)
                .expect("source still sees the current task");
            assert!(directory.publish(2, task().into()).is_none());
            send.send(parent).unwrap();
        });
        let retained = receive
            .recv_timeout(Duration::from_secs(2))
            .expect("membership lookup/publication cannot wait for task-body custody");
        executor.join().unwrap();
        assert!(original.0.same(&retained.0));
        assert_eq!(table.keys().collect::<Vec<_>>(), vec![2]);
        table.insert(1, scope);
        assert_eq!(table.keys().collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(retained.read().memory.coordinator_ownership(), ownership);
    }

    #[test]
    fn original_group_index_tracks_cold_members_and_rekey_without_body_locks() {
        let mut k = super::super::tests::kernel();
        let mut root = super::super::tests::admitted_process(&k);
        k.publish_task(1, &root);
        let group = root.signals.io.lifecycle().clone();
        k.syscall(
            1,
            &mut root,
            220,
            [0x10900, 0, 0, 0, 0, 0],
            &mut trames_linux::CapturedOutput::default(),
        )
        .unwrap();
        k.processes.insert(1, root);
        let old = k.processes.handle(&1).unwrap();
        let caller = k.processes.handle(&2).unwrap();
        let directory = k.processes.directory();
        let held = old.write();
        let copy = directory.clone();
        let selected = group.clone();
        let lookup = std::thread::spawn(move || {
            copy.group(&selected)
                .into_iter()
                .map(|(id, _)| id)
                .collect::<Vec<_>>()
        });
        assert_eq!(lookup.join().unwrap(), vec![1, 2]);
        drop(held);
        old.write().state = State::Zombie(0);
        assert_eq!(
            directory.group(&group).len(),
            2,
            "cold leader remains an original member"
        );
        directory.retire(1, &old);
        directory.restore(2, 1, &caller.write());
        directory.retire(1, &old);
        let members = directory.group(&group);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].0, 1);
        assert!(members[0].1.same(&caller));
        directory.retire(1, &caller);
        assert!(directory.group(&group).is_empty());
    }
    #[test]
    fn checkout_rekey_preserves_original_body_and_cannot_overwrite_a_replacement() {
        let mut table = Table::default();
        table.insert(1, task());
        let original = table.handle(&1).unwrap();
        let scope = table.checkout(&1).unwrap();
        table.insert(9, scope);
        assert!(!table.contains_key(&1));
        assert!(original.0.same(&table.handle(&9).unwrap().0));
        for restore in [false, true] {
            let scope = table.checkout(&9).unwrap();
            let directory = table.directory();
            let replacement: Handle<Cpu> = task().into();
            directory.publish(9, replacement.clone());
            if restore {
                table.insert(9, scope);
            } else {
                drop(scope);
            }
            assert!(replacement.0.same(&directory.handle(&9).unwrap().0));
            assert_eq!(table.len(), 1);
        }
    }

    #[test]
    fn retiring_a_checked_out_task_cannot_be_undone_by_its_old_handler() {
        for restore in [false, true] {
            let mut table = Table::default();
            table.insert(1, task());
            let scope = table.checkout(&1).unwrap();
            let directory = table.directory();
            let original = directory.remove(&1).unwrap();
            assert_eq!(table.len(), 0);
            if restore {
                table.insert(1, scope);
            } else {
                drop(scope);
            }
            assert!(directory.handle(&1).is_none());
            assert_eq!(table.len(), 0);
            // An accepted handle remains valid even though task membership is
            // gone, and still retains exactly its one original Memory root.
            assert_eq!(original.read().memory.coordinator_ownership().1, 1);
        }
    }

    #[test]
    fn publication_and_snapshot_retirement_keep_each_original_memory_owner_once() {
        let mut table = Table::default();
        table.insert(1, task());
        let directory = table.directory();
        let first = directory.entries();
        let mut executors = Vec::new();
        for lane in 0..4 {
            let directory = directory.clone();
            executors.push(std::thread::spawn(move || {
                for n in 0..16 {
                    directory.publish(2 + lane * 16 + n, task().into());
                }
            }));
        }
        for executor in executors {
            executor.join().unwrap();
        }
        assert_eq!(first.len(), 1);
        let all = directory.entries();
        assert_eq!(all.len(), 65);
        for (_, task) in all.iter() {
            assert_eq!(task.read().memory.coordinator_ownership().1, 1);
        }
        table.retain(|id, _| *id == 1);
        assert_eq!(directory.entries().len(), 1);
        // A retained observer snapshot owns handles, never extra Memory roots.
        for (_, task) in all.iter() {
            assert_eq!(task.read().memory.coordinator_ownership().1, 1);
        }
    }
}
