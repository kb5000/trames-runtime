// SPDX-License-Identifier: GPL-3.0-or-later
//! Object state only. Scalar metadata uses relaxed atomics; owned compound
//! values use their own mutex. These cells never publish guest memory.
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::{net::SocketAddr, sync::atomic::*, time::Duration};

pub(crate) trait Value: Copy {
    type Storage: Send + Sync;
    fn storage(value: Self) -> Self::Storage;
    fn load(storage: &Self::Storage) -> Self;
    fn store(storage: &Self::Storage, value: Self);
    fn swap(storage: &Self::Storage, value: Self) -> Self;
    fn update(storage: &Self::Storage, f: impl FnMut(Self) -> Self) -> Self;
}
pub(crate) struct Cell<T: Value>(T::Storage);
impl<T: Value> Cell<T> {
    pub fn new(value: T) -> Self {
        Self(T::storage(value))
    }
    pub fn get(&self) -> T {
        T::load(&self.0)
    }
    pub fn set(&self, value: T) {
        T::store(&self.0, value);
    }
    pub fn replace(&self, value: T) -> T {
        T::swap(&self.0, value)
    }
    pub fn update(&self, f: impl FnMut(T) -> T) -> T {
        T::update(&self.0, f)
    }
}
impl<T: Value + Default> Default for Cell<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}
macro_rules! atomic {
    ($($value:ty => $storage:ty),*) => {$(
        impl Value for $value {
            type Storage = $storage;
            fn storage(value: Self) -> Self::Storage { <$storage>::new(value) }
            fn load(storage: &Self::Storage) -> Self { storage.load(Ordering::Relaxed) }
            fn store(storage: &Self::Storage, value: Self) { storage.store(value, Ordering::Relaxed); }
            fn swap(storage: &Self::Storage, value: Self) -> Self { storage.swap(value, Ordering::Relaxed) }
            fn update(storage: &Self::Storage, mut f: impl FnMut(Self) -> Self) -> Self {
                storage.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(f(v))).unwrap()
            }
        }
    )*};
}
atomic!(bool => AtomicBool, u8 => AtomicU8, u16 => AtomicU16, u32 => AtomicU32,
    u64 => AtomicU64, usize => AtomicUsize, i32 => AtomicI32);
impl Value for [u32; 2] {
    type Storage = AtomicU64;
    fn storage(v: Self) -> Self::Storage {
        AtomicU64::new(v[0] as u64 | ((v[1] as u64) << 32))
    }
    fn load(s: &Self::Storage) -> Self {
        let v = s.load(Ordering::Relaxed);
        [v as u32, (v >> 32) as u32]
    }
    fn store(s: &Self::Storage, v: Self) {
        s.store(v[0] as u64 | ((v[1] as u64) << 32), Ordering::Relaxed);
    }
    fn swap(s: &Self::Storage, v: Self) -> Self {
        let v = s.swap(v[0] as u64 | ((v[1] as u64) << 32), Ordering::Relaxed);
        [v as u32, (v >> 32) as u32]
    }
    fn update(s: &Self::Storage, mut f: impl FnMut(Self) -> Self) -> Self {
        let v = s
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                let v = f([v as u32, (v >> 32) as u32]);
                Some(v[0] as u64 | ((v[1] as u64) << 32))
            })
            .unwrap();
        [v as u32, (v >> 32) as u32]
    }
}
macro_rules! compound {
    ($($value:ty),*) => {$(
        impl Value for $value {
            type Storage = Mutex<Self>;
            fn storage(value: Self) -> Self::Storage { Mutex::new(value) }
            fn load(s: &Self::Storage) -> Self { *s.lock() }
            fn store(s: &Self::Storage, value: Self) { *s.lock() = value; }
            fn swap(s: &Self::Storage, value: Self) -> Self { std::mem::replace(&mut *s.lock(), value) }
            fn update(s: &Self::Storage, mut f: impl FnMut(Self) -> Self) -> Self { let mut v=s.lock(); let old=*v; *v=f(old); old }
        }
    )*};
}
compound!(SocketAddr, Option<SocketAddr>, Option<Duration>);

/// Preserves legitimate nested immutable state access, including when another
/// writer is queued. Writers remain exclusive; no mutable guard is reentered.
#[derive(Default)]
pub(crate) struct State<T>(RwLock<T>);
impl<T> State<T> {
    pub fn new(value: T) -> Self {
        Self(RwLock::new(value))
    }
    pub fn borrow(&self) -> RwLockReadGuard<'_, T> {
        self.0.read_recursive()
    }
    pub fn borrow_mut(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write()
    }
}
/// The userspace packet stack has one actual mutable fabric transaction. It
/// does not protect independent fabrics or the native TCP byte path.
pub(crate) trait AfterUnlock {
    fn take_callbacks(&mut self) -> Vec<Box<dyn FnOnce() + Send>> {
        vec![]
    }
    fn take_notifications(&mut self) -> Vec<std::sync::Arc<trames_shared::Readiness>>;
}
pub(crate) struct FabricState<T: AfterUnlock>(Mutex<T>);
pub(crate) struct FabricGuard<'a, T: AfterUnlock>(Option<parking_lot::MutexGuard<'a, T>>);
impl<T: AfterUnlock> std::ops::Deref for FabricGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0.as_ref().unwrap()
    }
}
impl<T: AfterUnlock> std::ops::DerefMut for FabricGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.0.as_mut().unwrap()
    }
}
impl<T: AfterUnlock> Drop for FabricGuard<'_, T> {
    fn drop(&mut self) {
        let mut wakes = self.0.as_mut().unwrap().take_notifications();
        let callbacks = self.0.as_mut().unwrap().take_callbacks();
        drop(self.0.take());
        for callback in callbacks {
            callback();
        }
        wakes.sort_unstable_by_key(std::sync::Arc::as_ptr);
        wakes.dedup_by(|a, b| std::sync::Arc::ptr_eq(a, b));
        for source in wakes {
            source.notify_locked();
        }
    }
}
impl<T: AfterUnlock> FabricState<T> {
    pub fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }
    pub fn borrow(&self) -> FabricGuard<'_, T> {
        FabricGuard(Some(self.0.lock()))
    }
    pub fn borrow_mut(&self) -> FabricGuard<'_, T> {
        FabricGuard(Some(self.0.lock()))
    }
}
