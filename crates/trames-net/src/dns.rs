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
    jobs: Option<mpsc::SyncSender<(u64, Question)>>,
    results: mpsc::Receiver<(u64, Response)>,
    next: u64,
}
pub(crate) enum Response {
    Addresses(Vec<IpAddr>, u8),
    Wire(Vec<u8>),
}
impl Response {
    pub fn answer(self, question: &[u8], limit: usize) -> Vec<u8> {
        match self {
            Self::Addresses(addresses, code) => answer(question, &addresses, code, limit),
            Self::Wire(packet) if packet.len() <= limit => packet,
            Self::Wire(_) => {
                // Keep compression pointers valid: never slice an RR mid-record.
                // TCP clients can retry a truncated UDP answer in the usual way.
                let mut packet = answer(question, &[], 0, limit);
                packet[2] |= 2;
                packet
            }
        }
    }
}
unsafe extern "C" {
    fn trames_dns_send(query: *const u8, query_len: i32, reply: *mut u8, reply_len: i32) -> i32;
}
fn resolve_records(question: &Question) -> Response {
    let mut packet = vec![0; 65535];
    // SAFETY: C receives only bounded, owned wire buffers on this DNS worker.
    // It uses a per-call resolver context (or musl's stateless res_send), never
    // guest memory or a shared mutable resolver object.
    let size = unsafe {
        trames_dns_send(
            question.packet.as_ptr(),
            question.packet.len() as i32,
            packet.as_mut_ptr(),
            packet.len() as i32,
        )
    };
    if size < 12
        || size as usize > packet.len()
        || packet[..2] != question.packet[..2]
        || packet[2] & 0x80 == 0
    {
        return Response::Addresses(vec![], 2);
    }
    packet.truncate(size as usize);
    Response::Wire(packet)
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
        let (jobs, rx) = mpsc::sync_channel::<(u64, Question)>(8);
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
                    let (id, question) = job;
                    let response = if matches!(question.kind, 1 | 28) {
                        let (mut addresses, code) = resolve(&question.name, question.kind);
                        addresses.sort();
                        addresses.dedup();
                        addresses.truncate(8);
                        Response::Addresses(addresses, code)
                    } else {
                        resolve_records(&question)
                    };
                    if tx.send((id, response)).is_err() {
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
        self.jobs.as_ref()?.try_send((id, q.clone())).ok()?;
        Some(id)
    }
    pub fn result(&self) -> Option<(u64, Response)> {
        self.results.try_recv().ok()
    }
}
pub(crate) fn parse(packet: &[u8]) -> std::result::Result<Question, u8> {
    let (question, class) = parse_question(packet)?;
    if class != 1 || question.kind == 0 {
        return Err(4);
    }
    Ok(question)
}
// Wire validity is independent of the record types our host resolver supports.
// Even NOTIMP replies must echo a valid question so resolvers can match them.
fn parse_question(packet: &[u8]) -> std::result::Result<(Question, u16), u8> {
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
    // Only the validated question is forwarded. Counts must describe those
    // actual bytes; an EDNS OPT trailer must not leave ARCOUNT=1 without data.
    let mut packet = packet[..cursor].to_vec();
    packet[6..12].fill(0);
    Ok((Question { packet, name, kind }, class))
}
pub(crate) fn answer(q: &[u8], addresses: &[IpAddr], code: u8, limit: usize) -> Vec<u8> {
    let question = parse_question(q).ok().map(|(question, _)| question);
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
        if let Some(q) = question.filter(|q| matches!(q.kind, 1 | 28)) {
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

#[cfg(test)]
mod tests {
    use super::*;
    fn query(kind: u16, class: u16) -> Vec<u8> {
        let mut q = vec![
            0x12, 0x34, 1, 0x20, 0, 1, 0, 0, 0, 0, 0, 0, 9, b'l', b'o', b'c', b'a', b'l', b'h',
            b'o', b's', b't', 0,
        ];
        q.extend_from_slice(&kind.to_be_bytes());
        q.extend_from_slice(&class.to_be_bytes());
        q
    }
    #[test]
    fn unsupported_records_echo_the_question_without_claiming_an_answer() {
        for (kind, class) in [(65, 3), (16, 3), (255, 3), (0, 1)] {
            let q = query(kind, class);
            assert!(matches!(parse(&q), Err(4)));
            let r = answer(&q, &[], 4, 512);
            assert_eq!(&r[..2], &q[..2]);
            assert_eq!(&r[2..12], &[0x81, 0x84, 0, 1, 0, 0, 0, 0, 0, 0]);
            assert_eq!(&r[12..], &q[12..]);
        }
    }
    #[test]
    fn record_queries_reach_the_host_and_large_wire_replies_require_tcp() {
        for kind in [16, 33, 64, 65, 255] {
            assert_eq!(parse(&query(kind, 1)).unwrap().kind, kind);
        }
        let q = query(65, 1);
        let mut packet = answer(&q, &[], 0, 512);
        packet[7] = 1;
        packet.resize(600, 0);
        assert_eq!(Response::Wire(packet.clone()).answer(&q, 4096), packet);
        let truncated = Response::Wire(packet).answer(&q, 512);
        assert_eq!(truncated.len(), q.len());
        assert_ne!(truncated[2] & 2, 0);
        assert_eq!(&truncated[12..], &q[12..]);
        assert_eq!(&truncated[6..12], &[0; 6]);
    }
    #[test]
    fn error_echo_strips_additional_records_and_rejects_truncated_questions() {
        let mut q = query(65, 1);
        let question_end = q.len();
        q[11] = 1;
        q.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0]);
        let forwarded = parse(&q).unwrap().packet;
        assert_eq!(forwarded.len(), question_end);
        assert_eq!(&forwarded[6..12], &[0; 6]);
        let r = answer(&q, &[], 4, 512);
        assert_eq!(r.len(), question_end);
        assert_eq!(&r[12..], &q[12..question_end]);
        assert_eq!(&r[6..12], &[0; 6]);
        let malformed = &q[..question_end - 1];
        let r = answer(malformed, &[], 1, 512);
        assert_eq!(r.len(), 12);
        assert_eq!(&r[4..6], &[0, 0]);
        assert_eq!(r[3] & 15, 1);
    }
    #[test]
    fn native_udp_and_tcp_return_local_nodata_with_matchable_replies() {
        for stream in [false, true] {
            let network = crate::Network::new(crate::NetworkMode::Outbound);
            let socket = network.socket(2, if stream { 1 } else { 2 }, 0).unwrap();
            socket.connect(crate::direct_dns::ROUTABLE_ADDRESS).unwrap();
            let q = query(65, 1);
            let mut request = Vec::new();
            if stream {
                request.extend_from_slice(&(q.len() as u16).to_be_bytes());
            }
            request.extend_from_slice(&q);
            socket.send(&request, 0, None).unwrap();
            let r = socket.recv(512, 0).unwrap().data;
            let packet = if stream {
                assert_eq!(u16::from_be_bytes([r[0], r[1]]) as usize, r.len() - 2);
                &r[2..]
            } else {
                &r[..]
            };
            assert_eq!(packet.len(), q.len());
            assert_eq!(&packet[12..], &q[12..]);
            assert_eq!(&packet[4..6], &[0, 1]);
            assert_eq!(packet[3] & 15, 0);
            assert_eq!(&packet[6..12], &[0; 6]);
        }
    }
}
