// SPDX-License-Identifier: GPL-3.0-or-later
//! Host-side library benchmark. No guest CPU, filesystem or physical NIC involved.
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::PathBuf,
    sync::{
        Arc, Barrier, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use trames_net::{Fabric, NetError, Network, NetworkMode, Socket};
use trames_shared::{HostProtocol, IoSignal, IoWake};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Path {
    Bsd,
    Native,
    Ethernet,
    Link,
}
impl Path {
    fn name(self) -> &'static str {
        match self {
            Self::Bsd => "host_bsd",
            Self::Native => "trames_native",
            Self::Ethernet => "internal_ethernet",
            Self::Link => "internal_unix_link",
        }
    }
}
#[derive(Clone, Copy, Debug)]
enum Protocol {
    Tcp,
    Udp,
}
impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}
struct NoWake;
impl IoWake for NoWake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
struct Context {
    path: Path,
    networks: Vec<Network>,
    drivers: Vec<Arc<dyn HostProtocol>>,
    signal: Arc<IoSignal>,
    _wake: Arc<dyn IoWake>,
    _fabrics: Vec<Fabric>,
    directory: Option<PathBuf>,
    concurrent: AtomicBool,
}
impl Context {
    fn new(path: Path, serial: u64) -> Arc<Self> {
        let wake: Arc<dyn IoWake> = Arc::new(NoWake);
        let signal = IoSignal::new(1, Arc::downgrade(&wake));
        let mut fabrics = vec![];
        let mut networks = vec![];
        let mut directory = None;
        match path {
            Path::Bsd => (),
            Path::Native => networks.push(Network::new(NetworkMode::Full)),
            Path::Ethernet => {
                let f = Fabric::new().unwrap();
                for id in [2, 3] {
                    networks.push(Network::virtual_network(&f, id, NetworkMode::Outbound).unwrap());
                }
                fabrics.push(f);
            }
            Path::Link => {
                let dir =
                    std::env::temp_dir().join(format!("tnbench-{}-{serial}", std::process::id()));
                std::fs::create_dir(&dir).unwrap();
                for id in [2, 3] {
                    let f = Fabric::new().unwrap();
                    f.attach(&dir, id, false).unwrap();
                    networks.push(Network::virtual_network(&f, id, NetworkMode::Outbound).unwrap());
                    fabrics.push(f);
                }
                directory = Some(dir);
            }
        }
        let drivers = if path == Path::Link {
            networks.iter().map(Network::protocol).collect()
        } else {
            vec![]
        };
        Arc::new(Self {
            path,
            networks,
            drivers,
            signal,
            _wake: wake,
            _fabrics: fabrics,
            directory,
            concurrent: AtomicBool::new(false),
        })
    }
    fn pump(&self) {
        for d in &self.drivers {
            d.progress(&self.signal).unwrap();
        }
    }
    fn retry(&self, end: Instant) {
        if !self.concurrent.load(Ordering::Relaxed) {
            self.pump();
        }
        assert!(
            Instant::now() < end,
            "{} benchmark stalled",
            self.path.name()
        );
        std::thread::yield_now();
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        self.drivers.clear();
        self.networks.clear();
        self._fabrics.clear();
        if let Some(dir) = self.directory.take() {
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
enum Endpoint {
    Tcp(TcpStream),
    Udp(UdpSocket),
    Runtime(Arc<Socket>),
}
fn net_result<T>(r: Result<T, NetError>) -> io::Result<T> {
    r.map_err(|e| {
        if e.0 == 11 {
            io::ErrorKind::WouldBlock.into()
        } else {
            io::Error::other(format!("Trames {e}"))
        }
    })
}
impl Endpoint {
    fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => (&*s).write(bytes),
            Self::Udp(s) => s.send(bytes),
            Self::Runtime(s) => net_result(s.send(bytes, 0, None)),
        }
    }
    fn recv(&self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = match self {
            Self::Tcp(s) => (&*s).read(bytes),
            Self::Udp(s) => s.recv(bytes),
            Self::Runtime(s) => net_result(s.recv(bytes.len(), 0)).map(|r| {
                assert!(!r.truncated);
                if !r.data.is_empty() {
                    assert_eq!(r.data[0], 0x5a);
                    assert_eq!(*r.data.last().unwrap(), 0x5a);
                }
                r.data.len()
            }),
        }?;
        if !matches!(self, Self::Runtime(_)) && n != 0 {
            assert_eq!(bytes[0], 0x5a);
            assert_eq!(bytes[n - 1], 0x5a);
        }
        Ok(n)
    }
}
struct Pair {
    a: Endpoint,
    b: Endpoint,
    ctx: Arc<Context>,
    protocol: Protocol,
}
impl Pair {
    fn new(ctx: &Arc<Context>, protocol: Protocol, flow: usize) -> Self {
        let (a, b) = if ctx.path == Path::Bsd {
            match protocol {
                Protocol::Tcp => {
                    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                    let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                    let b = listener.accept().unwrap().0;
                    for s in [&a, &b] {
                        s.set_nodelay(true).unwrap();
                        s.set_nonblocking(true).unwrap();
                        socket2::SockRef::from(s)
                            .set_send_buffer_size(262144)
                            .unwrap();
                        socket2::SockRef::from(s)
                            .set_recv_buffer_size(262144)
                            .unwrap();
                    }
                    (Endpoint::Tcp(a), Endpoint::Tcp(b))
                }
                Protocol::Udp => {
                    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
                    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
                    a.connect(b.local_addr().unwrap()).unwrap();
                    b.connect(a.local_addr().unwrap()).unwrap();
                    for s in [&a, &b] {
                        s.set_nonblocking(true).unwrap();
                        socket2::SockRef::from(s)
                            .set_send_buffer_size(262144)
                            .unwrap();
                        socket2::SockRef::from(s)
                            .set_recv_buffer_size(262144)
                            .unwrap();
                    }
                    (Endpoint::Udp(a), Endpoint::Udp(b))
                }
            }
        } else {
            let a = &ctx.networks[0];
            let b = ctx.networks.last().unwrap();
            let kind = match protocol {
                Protocol::Tcp => 1,
                Protocol::Udp => 2,
            };
            let client = a.socket(2, kind, 0).unwrap();
            let listener = b.socket(2, kind, 0).unwrap();
            for s in [&client, &listener] {
                s.set_option(1, 7, 262144).unwrap();
                s.set_option(1, 8, 262144).unwrap();
            }
            let bind: SocketAddr = if ctx.path == Path::Native {
                "127.0.0.1:0".parse().unwrap()
            } else {
                format!("10.0.0.3:{}", 34000 + flow).parse().unwrap()
            };
            listener.bind(bind).unwrap();
            let target = listener.local_addr().unwrap();
            let server = match protocol {
                Protocol::Udp => {
                    client.connect(target).unwrap();
                    listener.connect(client.local_addr().unwrap()).unwrap();
                    listener
                }
                Protocol::Tcp => {
                    listener.listen(8).unwrap();
                    let end = Instant::now() + Duration::from_secs(5);
                    match client.connect(target) {
                        Ok(()) | Err(NetError(115)) => (),
                        other => panic!("connect: {other:?}"),
                    }
                    loop {
                        ctx.pump();
                        match client.connect_complete() {
                            Ok(true) => break,
                            Ok(false) | Err(NetError(11)) => ctx.retry(end),
                            other => panic!("connect: {other:?}"),
                        }
                    }
                    loop {
                        ctx.pump();
                        match listener.accept() {
                            Ok((s, _)) => break s,
                            Err(NetError(11)) => ctx.retry(end),
                            Err(e) => panic!("accept: {e}"),
                        }
                    }
                }
            };
            if matches!(protocol, Protocol::Tcp) {
                for s in [&client, &server] {
                    s.set_option(6, 1, 1).unwrap();
                }
            }
            (Endpoint::Runtime(client), Endpoint::Runtime(server))
        };
        Self {
            a,
            b,
            ctx: ctx.clone(),
            protocol,
        }
    }
    fn exact_send(&self, endpoint: &Endpoint, bytes: &[u8], end: Instant) {
        let mut n = 0;
        while n < bytes.len() {
            match endpoint.send(&bytes[n..]) {
                Ok(0) => panic!("zero send"),
                Ok(k) => {
                    if matches!(self.protocol, Protocol::Udp) {
                        assert_eq!(k, bytes.len());
                    }
                    n += k;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.ctx.retry(end),
                Err(e) => panic!("send: {e}"),
            }
        }
    }
    fn exact_recv(&self, endpoint: &Endpoint, buf: &mut [u8], end: Instant) {
        let mut n = 0;
        while n < buf.len() {
            match endpoint.recv(&mut buf[n..]) {
                Ok(0) => panic!("unexpected EOF"),
                Ok(k) => {
                    if matches!(self.protocol, Protocol::Udp) {
                        assert_eq!(k, buf.len());
                    }
                    n += k;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.ctx.retry(end),
                Err(e) => panic!("recv: {e}"),
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Case {
    protocol: Protocol,
    kind: &'static str,
    size: usize,
    flows: usize,
    window: usize,
}
fn row(case: Case, ctx: &Arc<Context>, sample: usize, seconds: f64, iterations: usize) {
    let pairs: Vec<_> = (0..case.flows)
        .map(|i| Pair::new(ctx, case.protocol, i))
        .collect();
    if case.kind == "rtt" {
        let pair = &pairs[0];
        let data = vec![0x5a; case.size];
        let mut buf = vec![0; case.size];
        let mut times = Vec::with_capacity(iterations);
        ctx.concurrent.store(true, Ordering::Relaxed);
        let elapsed = std::thread::scope(|scope| {
            let echo = scope.spawn(|| {
                let data = vec![0x5a; case.size];
                let mut buf = vec![0; case.size];
                let end = Instant::now() + Duration::from_secs(15);
                for _ in 0..(64 + iterations) {
                    pair.exact_recv(&pair.b, &mut buf, end);
                    pair.exact_send(&pair.b, &data, end);
                }
            });
            let end = Instant::now() + Duration::from_secs(15);
            for _ in 0..64 {
                pair.exact_send(&pair.a, &data, end);
                pair.exact_recv(&pair.a, &mut buf, end);
            }
            let start = Instant::now();
            for _ in 0..iterations {
                let t = Instant::now();
                pair.exact_send(&pair.a, &data, end);
                pair.exact_recv(&pair.a, &mut buf, end);
                times.push(t.elapsed().as_nanos());
            }
            let elapsed = start.elapsed().as_secs_f64();
            echo.join().unwrap();
            elapsed
        });
        times.sort_unstable();
        println!(
            "{},{},{},{},{},{},{:.6},{},{},{},{},{:.3},{:.3},ok",
            ctx.path.name(),
            case.protocol.name(),
            case.kind,
            case.size,
            case.flows,
            sample,
            elapsed,
            case.size * iterations * 2,
            case.size * iterations * 2,
            iterations * 2,
            iterations * 2,
            times[iterations / 2] as f64 / 1000.,
            times[(iterations * 99 / 100).min(iterations - 1)] as f64 / 1000.
        );
    } else if case.kind == "burst" {
        let pair = &pairs[0];
        let data = vec![0x5a; case.size];
        let mut buf = vec![0; case.size];
        let warm = Instant::now() + Duration::from_secs(5);
        pair.exact_send(&pair.a, &data, warm);
        pair.exact_recv(&pair.b, &mut buf, warm);
        let start = Instant::now();
        let end = start + Duration::from_secs(5);
        for _ in 0..case.window {
            pair.exact_send(&pair.a, &data, end);
        }
        let drain = Instant::now() + Duration::from_millis(50);
        let mut received = 0;
        while Instant::now() < drain {
            match pair.b.recv(&mut buf) {
                Ok(n) => {
                    assert_eq!(n, case.size);
                    received += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ctx.pump();
                    std::thread::yield_now();
                }
                Err(e) => panic!("burst recv: {e}"),
            }
        }
        // Packet counters for a burst are sent,received; throughput uses bytes,packets.
        println!(
            "{},{},{},{},{},{},{:.6},{},{},{},{},0,0,ok",
            ctx.path.name(),
            case.protocol.name(),
            case.kind,
            case.size,
            case.flows,
            sample,
            start.elapsed().as_secs_f64(),
            case.window * case.size,
            received * case.size,
            case.window,
            received
        );
    } else {
        // Resolve neighbors and warm both directions before the timed window.
        for pair in &pairs {
            let data = [0x5a; 64];
            let mut buf = [0; 64];
            let end = Instant::now() + Duration::from_secs(5);
            pair.exact_send(&pair.a, &data, end);
            pair.exact_recv(&pair.b, &mut buf, end);
            pair.exact_send(&pair.b, &data, end);
            pair.exact_recv(&pair.a, &mut buf, end);
        }
        ctx.concurrent.store(true, Ordering::Relaxed);
        let ready = Arc::new(Barrier::new(2 * case.flows + 1));
        let go = Arc::new(Barrier::new(2 * case.flows + 1));
        let started = Arc::new(OnceLock::<Instant>::new());
        let count = std::thread::scope(|scope| {
            let handles: Vec<_> = pairs
                .into_iter()
                .map(|pair| {
                    let (ready, go, started) = (ready.clone(), go.clone(), started.clone());
                    scope.spawn(move || {
                        let sent = AtomicU64::new(0);
                        let done = AtomicBool::new(false);
                        std::thread::scope(|scope| {
                            let receiver = scope.spawn(|| {
                                let mut buf = vec![0; case.size];
                                let mut bytes = 0u64;
                                let mut units = 0usize;
                                ready.wait();
                                go.wait();
                                let start = *started.get().unwrap();
                                let end = start + Duration::from_secs_f64(seconds + 2.);
                                let mut last = start;
                                loop {
                                    let complete = done.load(Ordering::Acquire);
                                    if complete
                                        && (bytes == sent.load(Ordering::Relaxed)
                                            || matches!(case.protocol, Protocol::Udp)
                                                && last.elapsed() >= Duration::from_millis(20))
                                    {
                                        break;
                                    }
                                    if Instant::now() >= end {
                                        break;
                                    }
                                    match pair.b.recv(&mut buf) {
                                        Ok(0) => panic!("unexpected EOF"),
                                        Ok(n) => {
                                            bytes += n as u64;
                                            units += 1;
                                            last = Instant::now();
                                            if matches!(case.protocol, Protocol::Udp) {
                                                assert_eq!(n, case.size);
                                            }
                                        }
                                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            if complete {
                                                pair.ctx.pump();
                                            }
                                            std::thread::yield_now();
                                        }
                                        Err(e) => panic!("bulk receive: {e}"),
                                    }
                                }
                                (bytes, units, last.duration_since(start).as_secs_f64())
                            });
                            let data = vec![0x5a; case.size];
                            ready.wait();
                            go.wait();
                            let start = *started.get().unwrap();
                            let mut units = 0usize;
                            while start.elapsed().as_secs_f64() < seconds {
                                match pair.a.send(&data) {
                                    Ok(0) => panic!("zero send"),
                                    Ok(n) => {
                                        if matches!(case.protocol, Protocol::Udp) {
                                            assert_eq!(n, case.size);
                                        }
                                        sent.fetch_add(n as u64, Ordering::Relaxed);
                                        units += 1;
                                    }
                                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                        std::thread::yield_now();
                                    }
                                    Err(e) => panic!("bulk send: {e}"),
                                }
                            }
                            let elapsed = start.elapsed().as_secs_f64();
                            done.store(true, Ordering::Release);
                            let (received, received_units, last) = receiver.join().unwrap();
                            let complete = matches!(case.protocol, Protocol::Udp)
                                || received == sent.load(Ordering::Relaxed);
                            (
                                received,
                                units,
                                elapsed.max(last),
                                received_units,
                                complete,
                                sent.load(Ordering::Relaxed),
                            )
                        })
                    })
                })
                .collect();
            ready.wait();
            started.set(Instant::now()).unwrap();
            go.wait();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        let accepted: u64 = count.iter().map(|r| r.5).sum();
        let bytes: u64 = count.iter().map(|r| r.0).sum();
        let sent: usize = count.iter().map(|r| r.1).sum();
        let received: usize = count.iter().map(|r| r.3).sum();
        let elapsed = count.iter().map(|r| r.2).fold(0., f64::max);
        let status = if count.iter().all(|r| r.4) {
            "ok"
        } else {
            "incomplete"
        };
        println!(
            "{},{},{},{},{},{},{:.6},{},{},{},{},0,0,{}",
            ctx.path.name(),
            case.protocol.name(),
            case.kind,
            case.size,
            case.flows,
            sample,
            elapsed,
            accepted,
            bytes,
            sent,
            received,
            status
        );
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let samples = args.first().map_or(3, |s| s.parse::<usize>().unwrap());
    let seconds = args.get(1).map_or(0.5, |s| s.parse::<f64>().unwrap());
    let iterations = args.get(2).map_or(2000, |s| s.parse::<usize>().unwrap());
    assert!(samples > 0 && seconds > 0. && iterations > 0);
    let filter = args.get(3).map(String::as_str).unwrap_or("");
    eprintln!("benchmark-pid: {}", std::process::id());
    let mut cases = vec![];
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        cases.push(Case {
            protocol,
            kind: "rtt",
            size: 64,
            flows: 1,
            window: 1,
        });
    }
    for flows in [1, 4] {
        cases.push(Case {
            protocol: Protocol::Tcp,
            kind: "bulk",
            size: 65536,
            flows,
            window: 4,
        });
        cases.push(Case {
            protocol: Protocol::Udp,
            kind: "bulk",
            size: 1400,
            flows,
            window: 8,
        });
    }
    for (kind, size, window) in [("bulk", 64, 8), ("bulk", 60000, 1), ("burst", 64, 64)] {
        cases.push(Case {
            protocol: Protocol::Udp,
            kind,
            size,
            flows: 1,
            window,
        });
    }
    println!(
        "path,protocol,test,payload_bytes,flows,sample,seconds,sent_bytes,received_bytes,sent_units,received_units,p50_us,p99_us,status"
    );
    let paths = [Path::Bsd, Path::Native, Path::Ethernet, Path::Link];
    let mut serial = 0;
    for case in cases {
        for sample in 0..samples {
            for offset in 0..paths.len() {
                let path = paths[(sample + offset) % paths.len()];
                let key = format!(
                    "{}:{}:{}:{}",
                    path.name(),
                    case.protocol.name(),
                    case.kind,
                    case.flows
                );
                if !filter.is_empty() && key != filter {
                    continue;
                }
                serial += 1;
                eprintln!(
                    "benchmark: {} {} {} size={} flows={} sample={}",
                    path.name(),
                    case.protocol.name(),
                    case.kind,
                    case.size,
                    case.flows,
                    sample
                );
                let ctx = Context::new(path, serial);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    row(case, &ctx, sample, seconds, iterations)
                }));
                if result.is_err() {
                    println!(
                        "{},{},{},{},{},{},0,0,0,0,0,0,0,failed",
                        path.name(),
                        case.protocol.name(),
                        case.kind,
                        case.size,
                        case.flows,
                        sample
                    );
                }
            }
        }
    }
}
