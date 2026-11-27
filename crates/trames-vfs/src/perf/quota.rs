// SPDX-License-Identifier: GPL-3.0-or-later
//! Per execution CPU sampling budget, using the existing actor's boundaries.
use super::*;
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};
struct Window {
    at: Instant,
    count: u64,
    spent: Duration,
}
pub(super) struct Quota(parking_lot::Mutex<Window>);
impl Default for Quota {
    fn default() -> Self {
        Self(parking_lot::Mutex::new(Window {
            at: Instant::now(),
            count: 0,
            spent: Duration::ZERO,
        }))
    }
}
thread_local! {static CURRENT:RefCell<Option<Arc<Quota>>>=const {RefCell::new(None)};}
pub(super) struct Guard(Option<Arc<Quota>>, std::marker::PhantomData<*mut ()>);
impl Guard {
    pub(super) fn enter(quota: Arc<Quota>) -> Self {
        Self(
            CURRENT.with(|current| current.replace(Some(quota))),
            Default::default(),
        )
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        CURRENT.with(|current| *current.borrow_mut() = self.0.take());
    }
}
pub(super) struct Ticket {
    quota: Option<Arc<Quota>>,
    at: Instant,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(quota) = &self.quota {
            quota.0.lock().spent += self.at.elapsed();
        }
    }
}
pub(super) fn measure() -> Ticket {
    Ticket {
        quota: CURRENT.with(|current| current.borrow().clone()),
        at: Instant::now(),
    }
}
pub(super) fn enter(settings: &Settings) -> Result<()> {
    let quota = CURRENT.with(|current| current.borrow().clone());
    let now = Instant::now();
    if let Some(quota) = &quota {
        let mut window = quota.0.lock();
        let elapsed = now.duration_since(window.at);
        if elapsed >= Duration::from_millis(100) {
            *window = Window {
                at: now,
                count: 0,
                spent: Duration::ZERO,
            };
        }
        let percent = settings.get(Setting::CpuTimePercent);
        let rate = settings.get(Setting::MaxSampleRate).max(1) as u64;
        if window.count >= rate.div_ceil(10)
            || percent != 0
                && percent != 100
                && window.spent >= Duration::from_millis(percent as u64)
        {
            return Err(Errno(11));
        }
        window.count += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_cpu_budget_tracks_dynamic_policy_and_does_not_throttle_another_cpu() {
        let settings = Settings::default();
        settings.set(Setting::MaxSampleRate, 10).unwrap();
        let first = Arc::new(Quota::default());
        let _guard = Guard::enter(first.clone());
        assert_eq!(enter(&settings), Ok(()));
        assert_eq!(enter(&settings), Err(Errno(11)));
        {
            let _other_cpu = Guard::enter(Arc::new(Quota::default()));
            assert_eq!(enter(&settings), Ok(()));
        }
        settings.set(Setting::MaxSampleRate, 100).unwrap();
        settings.set(Setting::CpuTimePercent, 1).unwrap();
        first.0.lock().spent = Duration::from_millis(1);
        assert_eq!(enter(&settings), Err(Errno(11)));
        settings.set(Setting::CpuTimePercent, 0).unwrap();
        assert_eq!(enter(&settings), Ok(()));
        first.0.lock().at = Instant::now() - Duration::from_millis(100);
        settings.set(Setting::CpuTimePercent, 1).unwrap();
        assert_eq!(enter(&settings), Ok(()));
    }
}
