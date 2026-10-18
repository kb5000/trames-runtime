// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded DNS wire service, backed by the supported host system resolver.
use std::net::IpAddr;
use std::sync::{mpsc, Arc, Mutex};
#[derive(Clone)]
pub(crate) struct Question {
    pub packet: Vec<u8>,
    pub name: String,
    pub kind: u16,
}
pub(crate) struct Resolver {
    jobs: Option<mpsc::SyncSender<(u64, String, u16)>>,
    results: mpsc::Receiver<(u64, Vec<IpAddr>, u8)>,
    next: u64,
}
// Resolve only the requested family. An A query must not wait for an unrelated
// AAAA timeout in the host resolver (and vice versa). The blocking call remains
// on the two bounded workers; guest memory/pointers never enter this API.
fn resolve(name: &str, kind: u16) -> (Vec<IpAddr>, u8) {
    use nix::libc;
    let Ok(name) = std::ffi::CString::new(name) else {
        return (vec![], 1);
    };
    // SAFETY: zero is a valid addrinfo hint, the CString is NUL terminated,
    // result is written by libc. Each owned result is freed exactly once.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = if kind == 1 {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut list = std::ptr::null_mut();
    let code = unsafe { libc::getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut list) };
    if code != 0 {
        return (vec![], if code == libc::EAI_NONAME { 3 } else { 2 });
    }
    struct Addresses(*mut libc::addrinfo);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeaddrinfo(self.0) }
        }
    }
    let owned = Addresses(list);
    let mut out = vec![];
    let mut cursor = owned.0;
    for _ in 0..64 {
        if cursor.is_null() {
            break;
        }
        // SAFETY: nodes/address storage belong to the live libc result list.
        // Family and length are checked before copying either sockaddr type.
        let node = unsafe { &*cursor };
        if !node.ai_addr.is_null() {
            if node.ai_family == libc::AF_INET
                && (node.ai_addrlen as usize) >= std::mem::size_of::<libc::sockaddr_in>()
            {
                let a = unsafe { &*(node.ai_addr as *const libc::sockaddr_in) };
                out.push(std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)).into());
            } else if node.ai_family == libc::AF_INET6
                && (node.ai_addrlen as usize) >= std::mem::size_of::<libc::sockaddr_in6>()
            {
                let a = unsafe { &*(node.ai_addr as *const libc::sockaddr_in6) };
                out.push(std::net::Ipv6Addr::from(a.sin6_addr.s6_addr).into());
            }
        }
        cursor = node.ai_next;
    }
    (out, 0)
}
impl Resolver {
    pub fn new() -> Self {
        let (jobs, rx) = mpsc::sync_channel::<(u64, String, u16)>(8);
        let rx = Arc::new(Mutex::new(rx));
        let (tx, results) = mpsc::sync_channel(8);
        let mut workers = 0;
        for _ in 0..2 {
            let rx = rx.clone();
            let tx = tx.clone();
            if std::thread::Builder::new()
                .name("trames-dns".into())
                .spawn(move || loop {
                    let Ok(job) = rx.lock().unwrap().recv() else {
                        break;
                    };
                    let (id, name, kind) = job;
                    let (mut addresses, code) = resolve(&name, kind);
                    addresses.sort();
                    addresses.dedup();
                    addresses.truncate(8);
                    if tx.send((id, addresses, code)).is_err() {
                        break;
                    }
                })
                .is_ok()
            {
                workers += 1;
            }
        }
        Self {
            jobs: (workers != 0).then_some(jobs),
            results,
            next: 1,
        }
    }
    pub fn query(&mut self, q: &Question) -> Option<u64> {
        let id = self.next;
        self.next = self.next.checked_add(1)?;
        self.jobs
            .as_ref()?
            .try_send((id, q.name.clone(), q.kind))
            .ok()?;
        Some(id)
    }
    pub fn result(&self) -> Option<(u64, Vec<IpAddr>, u8)> {
        self.results.try_recv().ok()
    }
}
pub(crate) fn parse(packet: &[u8]) -> std::result::Result<Question, u8> {
    if packet.len() < 12 || packet.len() > 4096 {
        return Err(1);
    }
    if packet[2] & 0xf8 != 0 || u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return Err(4);
    }
    let mut cursor = 12;
    let mut labels = Vec::new();
    loop {
        let n = *packet.get(cursor).ok_or(1)? as usize;
        cursor += 1;
        if n == 0 {
            break;
        }
        if n > 63 || cursor + n > packet.len() {
            return Err(1);
        }
        let label = &packet[cursor..cursor + n];
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(1);
        }
        labels.push(
            std::str::from_utf8(label)
                .map_err(|_| 1)?
                .to_ascii_lowercase(),
        );
        cursor += n;
    }
    if cursor + 4 > packet.len() {
        return Err(1);
    }
    let kind = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
    let class = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
    cursor += 4;
    let name = labels.join(".");
    if name.is_empty() || name.len() > 253 {
        return Err(1);
    }
    if !matches!(kind, 1 | 28) || class != 1 {
        return Err(4);
    }
    Ok(Question {
        packet: packet[..cursor].to_vec(),
        name,
        kind,
    })
}
pub(crate) fn answer(q: &[u8], addresses: &[IpAddr], code: u8, limit: usize) -> Vec<u8> {
    let question = parse(q).ok();
    let mut out = if let Some(q) = &question {
        q.packet.clone()
    } else {
        let mut h = vec![0; 12];
        if q.len() >= 2 {
            h[..2].copy_from_slice(&q[..2]);
        }
        h
    };
    out[2] = 0x80 | (q.get(2).copied().unwrap_or(0) & 1);
    out[3] = 0x80 | code;
    out[4..6].copy_from_slice(&u16::from(question.is_some()).to_be_bytes());
    out[6..12].fill(0);
    let mut count = 0u16;
    if code == 0 {
        if let Some(q) = question {
            for &a in addresses.iter().take(8) {
                if a.is_ipv4() != (q.kind == 1) {
                    continue;
                }
                let data = match a {
                    IpAddr::V4(a) => a.octets().to_vec(),
                    IpAddr::V6(a) => a.octets().to_vec(),
                };
                if out.len() + 12 + data.len() > limit {
                    out[2] |= 2;
                    break;
                }
                out.extend_from_slice(&[0xc0, 0x0c]);
                out.extend_from_slice(&q.kind.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&30u32.to_be_bytes());
                out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                out.extend_from_slice(&data);
                count += 1;
            }
        }
    }
    out[6..8].copy_from_slice(&count.to_be_bytes());
    out
}
