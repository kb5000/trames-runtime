// SPDX-License-Identifier: GPL-3.0-or-later
//! Frame callbacks follow the advertised output, not a frontend's polling rate.
use std::time::{Duration, Instant};

pub(crate) const REFRESH_MILLIHERTZ: i32 = 60_000;
const INTERVAL: Duration = Duration::from_nanos(1_000_000_000_000 / REFRESH_MILLIHERTZ as u64);

#[derive(Default)]
pub(crate) struct Pacer {
    presented: Option<(u64, u32, Instant)>,
    sent: Option<(Instant, u32)>,
}
impl Pacer {
    pub fn presented(&mut self, revision: u64, milliseconds: u32, now: Instant) {
        if self.presented.is_none_or(|(old, ..)| revision >= old) {
            self.presented = Some((revision, milliseconds, now));
        }
    }
    /// None means the requested commit has not been presented, rather than due.
    pub fn delay(&self, revision: u64, now: Instant) -> Option<Duration> {
        let (presented, ..) = self.presented?;
        if revision > presented {
            return None;
        }
        Some(self.sent.map_or(Duration::ZERO, |(at, _)| {
            (at + INTERVAL).saturating_duration_since(now)
        }))
    }
    pub fn take(&mut self, now: Instant) -> (u64, u32) {
        let (revision, milliseconds, presented_at) = self.presented.expect("presented callback");
        // Use the frontend's timestamp epoch, extrapolated only for a deferred
        // callback. Instant controls pacing; timestamps may wrap after 49 days.
        let mut stamp = milliseconds
            .wrapping_add(now.saturating_duration_since(presented_at).as_millis() as u32);
        if let Some((_, previous)) = self.sent {
            if stamp.wrapping_sub(previous) > i32::MAX as u32 {
                stamp = previous;
            }
        }
        self.sent = Some((now, stamp));
        (revision, stamp)
    }
}

impl crate::scene::Surface {
    pub(crate) fn flush_callbacks(&mut self, now: Instant) -> Option<Duration> {
        use wayland_server::Resource;
        let revision = self.callbacks.front()?.0;
        let delay = self.callback_pacer.delay(revision, now)?;
        if !delay.is_zero() {
            return Some(delay);
        }
        let (presented, milliseconds) = self.callback_pacer.take(now);
        while self
            .callbacks
            .front()
            .is_some_and(|(serial, _)| *serial <= presented)
        {
            for callback in self.callbacks.pop_front().unwrap().1 {
                if callback.is_alive() {
                    callback.done(milliseconds);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fast_polling_defers_callbacks_without_acknowledging_unpresented_commits() {
        let now = Instant::now();
        let mut p = Pacer::default();
        assert_eq!(p.delay(1, now), None);
        p.presented(1, 1000, now);
        assert_eq!(p.delay(1, now), Some(Duration::ZERO));
        assert_eq!(p.take(now), (1, 1000));
        p.presented(2, 1010, now + Duration::from_millis(10));
        assert_eq!(
            p.delay(2, now + Duration::from_millis(10)),
            Some(INTERVAL - Duration::from_millis(10))
        );
        assert_eq!(p.delay(3, now + INTERVAL), None);
        assert_eq!(p.delay(2, now + INTERVAL), Some(Duration::ZERO));
        assert_eq!(p.take(now + INTERVAL), (2, 1016));
        p.presented(1, 1000, now + INTERVAL); // old GPU completion cannot rewind it
        assert_eq!(p.delay(3, now + INTERVAL), None);
    }
    #[test]
    fn delayed_wakeups_do_not_catch_up_in_bursts_and_timestamps_wrap() {
        let now = Instant::now();
        let mut p = Pacer::default();
        p.presented(1, u32::MAX - 5, now);
        p.take(now);
        assert_eq!(p.take(now + Duration::from_millis(20)), (1, 14));
        assert_eq!(
            p.delay(1, now + Duration::from_millis(21)),
            Some(INTERVAL - Duration::from_millis(1))
        );
        p.presented(2, 10, now + Duration::from_secs(1));
        assert_eq!(p.take(now + Duration::from_secs(1)), (2, 14));
        assert_eq!(p.delay(2, now + Duration::from_secs(1)), Some(INTERVAL));
    }
}
