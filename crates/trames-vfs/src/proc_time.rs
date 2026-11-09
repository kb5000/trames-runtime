// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only live execution time. One original actor owns begin/finish; cold
//! projections may only raise a completed total. A single relaxed word avoids
//! publishing a separately sampled start and accumulated-time pair.
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
const MAX: i128 = (1i128 << 61) - 1;
pub(super) struct Time {
    origin: Instant,
    value: AtomicU64,
}
impl Default for Time {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}
fn nanos(time: Duration) -> i128 {
    time.as_nanos().min(MAX as u128) as i128
}
fn completed(value: i128) -> u64 {
    (value.clamp(0, MAX) as u64) << 1
}
fn active(offset: i128) -> u64 {
    ((offset.clamp(-MAX, MAX) as i64 as u64) << 1) | 1
}
impl Time {
    pub fn new(origin: Instant) -> Self {
        Self {
            origin,
            value: AtomicU64::new(0),
        }
    }
    fn ticks(&self, at: Instant) -> i128 {
        nanos(at.saturating_duration_since(self.origin))
    }
    pub fn begin(&self, at: Instant) {
        let tick = self.ticks(at);
        let _ = self
            .value
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(active(tick - (value >> 1) as i128))
            });
    }
    pub fn finish(&self, began: Instant, elapsed: Duration) {
        let value = self.value.load(Ordering::Relaxed);
        let total = if value & 1 == 0 {
            (value >> 1) as i128
        } else {
            self.ticks(began) - ((value as i64) >> 1) as i128
        };
        self.value
            .store(completed(total + nanos(elapsed)), Ordering::Relaxed);
    }
    pub fn add(&self, elapsed: Duration) {
        let elapsed = nanos(elapsed);
        let _ = self
            .value
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(if value & 1 == 0 {
                    completed((value >> 1) as i128 + elapsed)
                } else {
                    active(((value as i64) >> 1) as i128 - elapsed)
                })
            });
    }
    pub fn publish(&self, elapsed: Duration) {
        let elapsed = completed(nanos(elapsed));
        let _ = self
            .value
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value & 1 == 0 && value < elapsed).then_some(elapsed)
            });
    }
    pub fn read_at(&self, at: Instant) -> Duration {
        let value = self.value.load(Ordering::Relaxed);
        let total = if value & 1 == 0 {
            (value >> 1) as i128
        } else {
            self.ticks(at) - ((value as i64) >> 1) as i128
        };
        Duration::from_nanos(total.clamp(0, MAX) as u64)
    }
    pub fn read(&self) -> Duration {
        let value = self.value.load(Ordering::Relaxed);
        if value & 1 == 0 {
            Duration::from_nanos(value >> 1)
        } else {
            self.read_at(Instant::now())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_time_preserves_original_total_and_ignores_cold_projection() {
        let origin = Instant::now();
        let time = Time::new(origin);
        time.add(Duration::from_secs(2));
        time.begin(origin + Duration::from_secs(5));
        assert_eq!(
            time.read_at(origin + Duration::from_secs(8)),
            Duration::from_secs(5)
        );
        time.publish(Duration::from_secs(100));
        assert_eq!(
            time.read_at(origin + Duration::from_secs(8)),
            Duration::from_secs(5)
        );
        time.finish(origin + Duration::from_secs(5), Duration::from_secs(4));
        assert_eq!(
            time.read_at(origin + Duration::from_secs(20)),
            Duration::from_secs(6)
        );
        time.publish(Duration::from_secs(1));
        assert_eq!(time.read(), Duration::from_secs(6));
        time.begin(origin + Duration::from_secs(21));
        time.finish(origin + Duration::from_secs(21), Duration::from_secs(3));
        assert_eq!(time.read(), Duration::from_secs(9));
    }
    #[test]
    fn live_time_handles_completed_time_before_its_clock_origin_and_extra_accounting() {
        let origin = Instant::now();
        let time = Time::new(origin);
        time.publish(Duration::from_secs(12));
        time.begin(origin + Duration::from_secs(1));
        time.add(Duration::from_secs(2));
        assert_eq!(
            time.read_at(origin + Duration::from_secs(2)),
            Duration::from_secs(15)
        );
        time.finish(origin + Duration::from_secs(1), Duration::from_secs(4));
        assert_eq!(time.read(), Duration::from_secs(18));
    }
}
