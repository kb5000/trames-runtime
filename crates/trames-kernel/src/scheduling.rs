// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest affinity and ready-queue policy; no execution engine or host threads.
/// Preserve round-robin queue priority while relocating an earlier flexible
/// task when a later pinned task needs its slot. Mask width is at most 32 CPUs.
pub fn assign_cpus(ready: impl IntoIterator<Item = (u32, u64)>, count: usize) -> Vec<(u32, usize)> {
    fn place(pid: u32, mask: u64, slots: &mut [Option<(u32, u64)>], visited: &mut u64) -> bool {
        let eligible = mask & !*visited;
        // Equal/full masks take the same lowest-free-slot fast path as before.
        if let Some(slot) = slots
            .iter()
            .enumerate()
            .find_map(|(i, p)| (eligible & (1 << i) != 0 && p.is_none()).then_some(i))
        {
            slots[slot] = Some((pid, mask));
            return true;
        }
        for slot in 0..slots.len() {
            if eligible & (1 << slot) == 0 {
                continue;
            }
            *visited |= 1 << slot;
            let (previous, previous_mask) = slots[slot].expect("occupied eligible slot");
            if place(previous, previous_mask, slots, visited) {
                slots[slot] = Some((pid, mask));
                return true;
            }
        }
        false
    }
    let mut slots = vec![None; count];
    let mut selected = Vec::new();
    for (pid, mask) in ready {
        if place(pid, mask, &mut slots, &mut 0) {
            selected.push(pid);
            if selected.len() == count {
                break;
            }
        }
    }
    selected
        .into_iter()
        .map(|pid| {
            let slot = slots
                .iter()
                .position(|p| p.is_some_and(|p| p.0 == pid))
                .expect("assigned task");
            (pid, slot)
        })
        .collect()
}
