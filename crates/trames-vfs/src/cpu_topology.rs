// SPDX-License-Identifier: GPL-3.0-or-later
//! One guest package and cluster, one hardware thread per virtual core.

pub(super) const FILES: &[&str] = &[
    "core_id",
    "cluster_id",
    "physical_package_id",
    "core_cpus",
    "core_cpus_list",
    "thread_siblings",
    "thread_siblings_list",
    "cluster_cpus",
    "cluster_cpus_list",
    "package_cpus",
    "package_cpus_list",
    "core_siblings",
    "core_siblings_list",
];

pub(super) fn list(count: usize) -> String {
    if count <= 1 {
        "0\n".to_owned()
    } else {
        format!("0-{}\n", count - 1)
    }
}

pub(super) fn value(cpu: usize, count: usize, name: &[u8]) -> Option<String> {
    match name {
        b"core_id" | b"thread_siblings_list" | b"core_cpus_list" => {
            return Some(format!("{cpu}\n"))
        }
        b"physical_package_id" | b"cluster_id" => return Some("0\n".into()),
        b"core_siblings_list" | b"package_cpus_list" | b"cluster_cpus_list" => {
            return Some(list(count))
        }
        _ => {}
    }
    let single = match name {
        b"thread_siblings" | b"core_cpus" => true,
        b"package_cpus" | b"core_siblings" | b"cluster_cpus" => false,
        _ => return None,
    };
    use std::fmt::Write;
    let mut result = String::new();
    for group in (0..count.div_ceil(32)).rev() {
        let mask = if single {
            if cpu / 32 == group {
                1u32 << (cpu % 32)
            } else {
                0
            }
        } else {
            u32::MAX >> (32 - (count - group * 32).min(32))
        };
        if !result.is_empty() {
            result.push(',');
        }
        write!(result, "{mask:08x}").unwrap();
    }
    result.push('\n');
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mask_words_follow_guest_numbering_across_word_boundaries() {
        for (cpu, count, name, expected) in [
            (0, 1, "package_cpus", "00000001\n"),
            (31, 32, "core_cpus", "80000000\n"),
            (32, 33, "core_cpus", "00000001,00000000\n"),
            (0, 33, "cluster_cpus", "00000001,ffffffff\n"),
            (63, 64, "core_siblings", "ffffffff,ffffffff\n"),
        ] {
            assert_eq!(value(cpu, count, name.as_bytes()).unwrap(), expected);
        }
    }
}
