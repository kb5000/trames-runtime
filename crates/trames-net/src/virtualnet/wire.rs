// SPDX-License-Identifier: GPL-3.0-or-later
//! Private framed streams. Real backpressure and stable event readiness, no pump thread.
use crate::ethernet::Frame;
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, IoSlice, Read},
    os::{
        fd::{AsFd, BorrowedFd},
        unix::net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use trames_shared::{HostEvents, HostFd, HostSubscription, IoSignal, IoWake};
const MAX_FRAME: usize = 65597;
const QUEUE_BYTES: usize = 2 * crate::MAX_TRANSFER;
const HELLO: [u8; 4] = *b"TL2\x01";
struct NoWake;
impl IoWake for NoWake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
/// One stable readable poller for a link, including blocked writers. Holds no guest state.
pub struct WireWait {
    events: Arc<HostEvents>,
    fd: HostFd,
    _target: Arc<dyn IoWake>,
}
impl AsFd for WireWait {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl WireWait {
    fn new() -> io::Result<Arc<Self>> {
        let events = HostEvents::new()?;
        let fd = events.event_fd()?;
        Ok(Arc::new(Self {
            events,
            fd,
            _target: Arc::new(NoWake),
        }))
    }
    pub(crate) fn drain(&self) {
        let _ = self.events.wait(Some(Instant::now()));
    }
    pub(super) fn wake(&self) {
        self.events.arm();
        self.events.wake();
    }
    fn subscribe(&self, fd: HostFd, write: bool) -> io::Result<Interest> {
        let signal = IoSignal::new(0, Arc::downgrade(&self._target));
        let lease = self.events.subscribe(fd, write, &signal)?;
        Ok(Interest { signal, lease })
    }
}
struct Interest {
    signal: Arc<IoSignal>,
    lease: HostSubscription,
}
impl Interest {
    fn rearm(&self) -> io::Result<()> {
        self.lease.rearm()
    }
}
fn stream_fd(s: &Arc<UnixStream>) -> io::Result<HostFd> {
    Ok(HostFd::retained(s.as_fd().try_clone_to_owned()?, s.clone()))
}
struct Message {
    header: [u8; 4],
    frame: Frame,
    offset: usize,
}
impl Message {
    fn new(frame: Frame) -> Self {
        Self {
            header: (frame.0.len() as u32).to_le_bytes(),
            frame,
            offset: 0,
        }
    }
    fn len(&self) -> usize {
        4 + self.frame.0.len()
    }
}
struct Outbound {
    stream: Arc<UnixStream>,
    hello: [u8; 8],
    hello_offset: usize,
    queue: VecDeque<Message>,
    bytes: usize,
    blocked: Option<Interest>,
}
impl Outbound {
    fn connect(path: &Path, id: u8) -> io::Result<Self> {
        let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_send_buffer_size(crate::MAX_BUFFER)?;
        #[cfg(target_vendor = "apple")]
        socket.set_nosigpipe(true)?;
        match socket.connect(&socket2::SockAddr::unix(path)?) {
            Ok(()) => (),
            Err(e) if e.raw_os_error() == Some(nix::libc::EINPROGRESS) => (),
            Err(e) => return Err(e),
        }
        let mut hello = [0; 8];
        hello[..4].copy_from_slice(&HELLO);
        hello[4] = id;
        Ok(Self {
            stream: Arc::new(socket.into()),
            hello,
            hello_offset: 0,
            queue: VecDeque::new(),
            bytes: 0,
            blocked: None,
        })
    }
    fn enqueue(&mut self, frame: Frame) -> bool {
        let m = Message::new(frame);
        if self.bytes + m.len() > QUEUE_BYTES {
            return false;
        }
        self.bytes += m.len();
        self.queue.push_back(m);
        true
    }
    fn pending(&self) -> bool {
        self.hello_offset < 8 || !self.queue.is_empty()
    }
    fn flush(&mut self, wait: &WireWait) -> io::Result<()> {
        if let Some(blocked) = &self.blocked {
            if !blocked.signal.ready() {
                return Ok(());
            }
        }
        self.blocked.take();
        for _ in 0..64 {
            if !self.pending() {
                return Ok(());
            }
            let mut vectors: [IoSlice<'_>; 32] = std::array::from_fn(|_| IoSlice::new(&[]));
            let mut count = 0;
            if self.hello_offset < 8 {
                vectors[count] = IoSlice::new(&self.hello[self.hello_offset..]);
                count += 1;
            }
            for m in self.queue.iter().take(15) {
                if m.offset < 4 {
                    vectors[count] = IoSlice::new(&m.header[m.offset..]);
                    count += 1;
                    vectors[count] = IoSlice::new(&m.frame.0);
                    count += 1;
                } else {
                    vectors[count] = IoSlice::new(&m.frame.0[m.offset - 4..]);
                    count += 1;
                }
            }
            #[cfg(target_vendor = "apple")]
            let flags = 0;
            #[cfg(not(target_vendor = "apple"))]
            let flags = nix::libc::MSG_NOSIGNAL;
            let sent = socket2::SockRef::from(&*self.stream)
                .send_vectored_with_flags(&vectors[..count], flags);
            match sent {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(mut n) => {
                    let h = n.min(8 - self.hello_offset);
                    self.hello_offset += h;
                    n -= h;
                    while n != 0 {
                        let m = self.queue.front_mut().unwrap();
                        let used = n.min(m.len() - m.offset);
                        m.offset += used;
                        n -= used;
                        if m.offset == m.len() {
                            self.bytes -= m.len();
                            self.queue.pop_front();
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.blocked = Some(wait.subscribe(stream_fd(&self.stream)?, true)?);
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
struct Inbound {
    stream: Arc<UnixStream>,
    read: Interest,
    buffer: Vec<u8>,
    start: usize,
    peer: Option<u8>,
}
impl Inbound {
    fn new(stream: UnixStream, wait: &WireWait) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        socket2::SockRef::from(&stream).set_recv_buffer_size(crate::MAX_BUFFER)?;
        let stream = Arc::new(stream);
        let read = wait.subscribe(stream_fd(&stream)?, false)?;
        read.signal.notify(); // Newly accepted bytes may already precede registration.
        Ok(Self {
            stream,
            read,
            buffer: vec![],
            start: 0,
            peer: None,
        })
    }
    fn buffered(&self) -> bool {
        let bytes = &self.buffer[self.start..];
        if self.peer.is_none() {
            bytes.len() >= 8
        } else {
            bytes.len() >= 4
                && bytes.len() >= 4 + u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
        }
    }
    fn receive(&mut self, local: u8, limit: usize, out: &mut Vec<(u8, Frame)>) -> io::Result<()> {
        if out.len() >= limit {
            return Ok(());
        }
        let notified = self.read.signal.ready();
        if notified {
            self.read.signal.reset();
        }
        let mut reads = 0;
        while out.len() < limit {
            let bytes = &self.buffer[self.start..];
            if self.peer.is_none() && bytes.len() >= 8 {
                if bytes[..4] != HELLO
                    || !(2..=254).contains(&bytes[4])
                    || bytes[4] == local
                    || bytes[5..8] != [0; 3]
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.peer = Some(bytes[4]);
                self.start += 8;
                continue;
            }
            if let Some(peer) = self.peer {
                if bytes.len() >= 4 {
                    let n = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
                    if !(14..=MAX_FRAME).contains(&n) {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    if bytes.len() >= 4 + n {
                        let frame = Frame::new(&bytes[4..4 + n])
                            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                        out.push((peer, frame));
                        self.start += 4 + n;
                        continue;
                    }
                }
            }
            if reads == 8 {
                break;
            }
            let mut temp = [0u8; 65536];
            match (&*self.stream).read(&mut temp) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    self.buffer.extend_from_slice(&temp[..n]);
                    reads += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        if self.start != 0 {
            self.buffer.drain(..self.start);
            self.start = 0;
        }
        if notified {
            self.read.rearm()
        } else {
            Ok(())
        }
    }
}
pub(super) struct Wire {
    _discovery: super::discovery::Discovery,
    listener: Arc<UnixListener>,
    accept: Interest,
    pub wait: Arc<WireWait>,
    pub path: PathBuf,
    pub id: u8,
    pub nat: bool,
    incoming: Vec<Inbound>,
    outgoing: BTreeMap<u8, Outbound>,
}
impl Wire {
    #[cfg(test)]
    pub fn bind(path: PathBuf, id: u8, nat: bool) -> io::Result<Self> {
        Self::bind_named(path, id, nat, None)
    }
    pub fn bind_named(path: PathBuf, id: u8, nat: bool, name: Option<&str>) -> io::Result<Self> {
        let listener = Arc::new(UnixListener::bind(&path)?);
        let result = (|| {
            let discovery = super::discovery::Discovery::bind(path.parent().unwrap(), id, name)?;
            listener.set_nonblocking(true)?;
            let wait = WireWait::new()?;
            let accept = wait.subscribe(
                HostFd::retained(listener.as_fd().try_clone_to_owned()?, listener.clone()),
                false,
            )?;
            Ok(Self {
                _discovery: discovery,
                listener,
                accept,
                wait,
                path: path.clone(),
                id,
                nat,
                incoming: vec![],
                outgoing: BTreeMap::new(),
            })
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result
    }
    pub fn enqueue(&mut self, peer: u8, frame: Frame) -> bool {
        if peer == self.id || !(2..=254).contains(&peer) {
            return false;
        }
        if !self.outgoing.contains_key(&peer) {
            let path = self.path.parent().unwrap().join(format!("p{peer}"));
            let Ok(tx) = Outbound::connect(&path, self.id) else {
                return false;
            };
            self.outgoing.insert(peer, tx);
        }
        self.outgoing.get_mut(&peer).unwrap().enqueue(frame)
    }
    pub fn flush(&mut self) -> usize {
        let mut dropped = 0;
        self.outgoing.retain(|_, tx| match tx.flush(&self.wait) {
            Ok(()) => true,
            Err(_) => {
                dropped += tx.queue.len();
                false
            }
        });
        dropped
    }
    pub fn receive(&mut self, limit: usize) -> Vec<(u8, Frame)> {
        // Active callers already attempt nonblocking socket I/O. Consult the
        // poller only for an actually blocked writer; ordinary receives do not
        // need a second readiness syscall before their deciding read.
        if self
            .outgoing
            .values()
            .any(|tx| tx.blocked.as_ref().is_some_and(|b| !b.signal.ready()))
        {
            self.wait.drain();
        }
        let notified = self.accept.signal.ready();
        if notified {
            self.accept.signal.reset();
        }
        while self.incoming.len() < 254 {
            match self.listener.accept() {
                Ok((s, _)) => {
                    if let Ok(rx) = Inbound::new(s, &self.wait) {
                        self.incoming.push(rx)
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        if notified && self.incoming.len() < 254 {
            let _ = self.accept.rearm();
        }
        let mut out = vec![];
        self.incoming
            .retain_mut(|rx| rx.receive(self.id, limit, &mut out).is_ok());
        out
    }
    pub fn runnable(&self) -> bool {
        self.accept.signal.ready() && self.incoming.len() < 254
            || self
                .incoming
                .iter()
                .any(|rx| rx.buffered() || rx.read.signal.ready())
            || self
                .outgoing
                .values()
                .any(|tx| tx.pending() && tx.blocked.as_ref().is_none_or(|b| b.signal.ready()))
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn blocked_stream_preserves_order_frames_and_actual_writable_wakeup() {
        let dir = std::env::temp_dir().join(format!("tn-wire-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let mut a = Wire::bind(dir.join("p2"), 2, false).unwrap();
        let mut b = Wire::bind(dir.join("p3"), 3, false).unwrap();
        for n in 0u32..800 {
            let mut data = vec![0x5a; 1400];
            data[..4].copy_from_slice(&n.to_le_bytes());
            assert!(a.enqueue(
                3,
                Frame::build([2, 1, 2, 3, 4, 5], [2, 6, 7, 8, 9, 10], 0x88b5, &data)
            ));
        }
        assert_eq!(a.flush(), 0);
        assert!(
            a.outgoing[&3].blocked.is_some(),
            "test must actually hit backpressure"
        );
        // All queued source bytes remain owned, rather than being silently dropped.
        let mut received = 0u32;
        let end = Instant::now() + Duration::from_secs(3);
        while received < 800 {
            for (peer, frame) in b.receive(64) {
                assert_eq!(peer, 2);
                assert_eq!(frame.protocol(), 0x88b5);
                assert_eq!(
                    u32::from_le_bytes(frame.payload()[..4].try_into().unwrap()),
                    received
                );
                received += 1;
            }
            a.wait.drain();
            assert_eq!(a.flush(), 0);
            assert!(Instant::now() < end, "wire did not wake the blocked sender");
        }
        assert!(a.outgoing[&3].queue.is_empty());
        assert!(!a.runnable());
        drop((a, b));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn malformed_peer_frame_is_rejected_without_allocating_its_claimed_length() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("tn-bad-wire-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let mut b = Wire::bind(dir.join("p3"), 3, false).unwrap();
        let mut client = UnixStream::connect(dir.join("p3")).unwrap();
        client
            .write_all(&[b'T', b'L', b'2', 1, 2, 0, 0, 0, 255, 255, 255, 255])
            .unwrap();
        assert!(b.receive(64).is_empty());
        assert!(b.incoming.is_empty());
        assert!(!b.runnable());
        drop((client, b));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
