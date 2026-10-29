// SPDX-License-Identifier: GPL-3.0-or-later
//! Bind optional Linux vDSO data to the existing session clock, while stopped.
use std::time::{Duration, Instant};
use trames_engine::Cpu;
use trames_memory::{Memory, MemoryError};
pub(super) fn initialize<C: Cpu>(
    memory: &mut Memory,
    aux: &[u8],
    origin: Instant,
) -> Result<(), MemoryError> {
    let base = aux
        .chunks_exact(16)
        .find(|p| u64::from_le_bytes(p[..8].try_into().unwrap()) == trames_linux::vdso::AUXV)
        .map(|p| u64::from_le_bytes(p[8..].try_into().unwrap()));
    let Some(base) = base else {
        return Ok(());
    };
    let mut best = None;
    // Select the narrowest bounded calibration bracket. No recurring monitor,
    // shared fast-path lock or guest polling protocol is introduced.
    for _ in 0..8 {
        let before = Instant::now();
        let Some(sample) = C::clock_sample() else {
            break;
        };
        let after = Instant::now();
        let bracket = after.duration_since(before);
        let elapsed = after
            .saturating_duration_since(origin)
            .saturating_sub(bracket / 2);
        if best
            .as_ref()
            .is_none_or(|(previous, _)| bracket < *previous)
        {
            best = Some((
                bracket,
                trames_linux::vdso::TimeBase {
                    counter: sample.ticks,
                    frequency: sample.frequency,
                    seconds: elapsed.as_secs(),
                    nanos: elapsed.subsec_nanos() as u64,
                },
            ));
        }
    }
    let time = best
        .filter(|(width, _)| *width <= Duration::from_micros(1))
        .map(|(_, time)| time)
        .unwrap_or(trames_linux::vdso::TimeBase {
            counter: 0,
            frequency: 0,
            seconds: 0,
            nanos: 0,
        });
    trames_linux::vdso::initialize(memory, base, time)
}
