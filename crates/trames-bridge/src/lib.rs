// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded asynchronous NDJSON device, isolated per embedding session and open.
//! Native effects require a host reply. Guest uid 0 never grants host authority.
pub mod hash;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
pub const VERSION: u32 = 1;
pub const MAX_FRAME: usize = 32768;
const MAX_OUTPUT: usize = 65536;
const MAX_CONNECTIONS: usize = 16;
const MAX_PENDING: usize = 32;
const TIMEOUT: Duration = Duration::from_secs(120);
const METHODS: &[&str] = &[
    "clipboard.read",
    "clipboard.write",
    "url.open",
    "files.list",
    "files.import",
    "files.export",
    "device.info",
    "host.cli",
    "host.exec",
    "ports.list",
    "ports.add",
    "ports.remove",
    "mounts.list",
    "mounts.add",
    "mounts.remove",
];
/// Low-frequency host authority. Native API thunks do not use these channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Channel {
    Info = 0,
    HostControl = 1,
    HostExec = 2,
    Files = 3,
    Ports = 4,
    Mounts = 5,
    Clipboard = 6,
}
impl Channel {
    pub const ALL: [Self; 7] = [
        Self::Info,
        Self::HostControl,
        Self::HostExec,
        Self::Files,
        Self::Ports,
        Self::Mounts,
        Self::Clipboard,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::HostControl => "host-control",
            Self::HostExec => "host-exec",
            Self::Files => "file-transfer",
            Self::Ports => "port-forward",
            Self::Mounts => "mount-control",
            Self::Clipboard => "clipboard",
        }
    }
    fn permits(self, method: &str) -> bool {
        if method == "bridge.info" || method == "device.info" || method == "request.cancel" {
            return true;
        }
        match self {
            Self::Info => method.starts_with("accel."),
            Self::HostControl => matches!(method, "url.open" | "host.cli"),
            Self::Clipboard => matches!(method, "clipboard.read" | "clipboard.write"),
            Self::HostExec => method == "host.exec",
            Self::Files => method.starts_with("files."),
            Self::Ports => method.starts_with("ports."),
            Self::Mounts => method.starts_with("mounts."),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Policy(u16);
impl Default for Policy {
    fn default() -> Self {
        Self(1)
    }
}
impl Policy {
    pub fn new(host_ui: bool, host_exec: bool, files: bool, ports: bool, mounts: bool) -> Self {
        Self(
            1 | (u16::from(host_ui) << 1)
                | (u16::from(host_exec) << 2)
                | (u16::from(files) << 3)
                | (u16::from(ports) << 4)
                | (u16::from(mounts) << 5),
        )
    }
    pub fn with_cli(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= 1 << 7;
        } else {
            self.0 &= !(1 << 7);
        }
        self
    }
    pub fn with_clipboard(mut self, enabled: bool) -> Self {
        if enabled {
            self.0 |= 1 << 6;
        } else {
            self.0 &= !(1 << 6);
        }
        self
    }
    pub fn allows(self, channel: Channel) -> bool {
        if channel == Channel::HostControl {
            self.0 & (2 | (1 << 7)) != 0
        } else {
            self.0 & (1 << channel as u8) != 0
        }
    }
    fn permits(self, channel: Channel, method: &str) -> bool {
        self.allows(channel)
            && channel.permits(method)
            && if method == "host.cli" {
                self.0 & (1 << 7) != 0
            } else if channel == Channel::HostControl
                && !matches!(method, "bridge.info" | "device.info" | "request.cancel")
            {
                self.0 & 2 != 0
            } else {
                true
            }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub id: u64,
    pub method: String,
    pub params: Value,
}
#[derive(Serialize, Deserialize)]
pub struct HostRequest {
    pub ticket: u64,
    pub request: Request,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostReply {
    pub version: u32,
    pub ticket: u64,
    #[serde(default, deserialize_with = "present_value")]
    pub result: Option<Value>,
    pub error: Option<RpcError>,
}
fn present_value<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}
fn failure(id: Option<u64>, code: &str, message: &str) -> Value {
    json!({"version": VERSION,"id": id,"error":{"code":code,"message":message}})
}
#[derive(Default)]
struct Stream {
    input: Vec<u8>,
    output: VecDeque<u8>,
    readiness: Arc<trames_shared::Readiness>,
    epoch: [u64; 2],
    slot: usize,
    channel: Option<Channel>,
}
struct Pending {
    connection: u64,
    request: Request,
    deadline: Instant,
    dispatched: bool,
}
#[derive(Default)]
struct State {
    next: u64,
    policy: Policy,
    host_wake: Option<Arc<trames_shared::HostWake>>,
    host_pending: bool,
    streams: BTreeMap<u64, Stream>,
    pending: BTreeMap<u64, Pending>,
    accel: hash::Registry,
    changed: [Option<Arc<trames_shared::Readiness>>; MAX_CONNECTIONS],
}
#[derive(Clone, Default)]
pub struct Broker(Arc<Mutex<State>>, Arc<std::sync::atomic::AtomicBool>);
pub struct Connection {
    broker: Broker,
    id: u64,
    readiness: Arc<trames_shared::Readiness>,
}
struct Guard<'a>(
    Option<MutexGuard<'a, State>>,
    &'a std::sync::atomic::AtomicBool,
);
impl std::ops::Deref for Guard<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        self.0.as_ref().unwrap()
    }
}
impl std::ops::DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.0.as_mut().unwrap()
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.1.store(
            self.0
                .as_ref()
                .unwrap()
                .pending
                .values()
                .any(|p| !p.dispatched),
            std::sync::atomic::Ordering::Relaxed,
        );
        let notifications = std::mem::take(&mut self.0.as_mut().unwrap().changed);
        let wake = if std::mem::take(&mut self.0.as_mut().unwrap().host_pending) {
            self.0.as_ref().unwrap().host_wake.clone()
        } else {
            None
        };
        drop(self.0.take());
        if let Some(wake) = wake {
            wake.notify();
        }
        for ready in notifications.into_iter().flatten() {
            ready.notify_locked();
        }
    }
}
impl State {
    fn changed(&mut self, connection: u64, direction: usize) {
        if let Some(stream) = self.streams.get_mut(&connection) {
            stream.epoch[direction] = stream.epoch[direction].wrapping_add(1);
            self.changed[stream.slot].get_or_insert_with(|| stream.readiness.clone());
        }
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        if let Ok(mut s) = self.broker.lock() {
            if let Some(stream) = s.streams.remove(&self.id) {
                s.changed[stream.slot] = Some(self.readiness.clone());
            }
            s.pending.retain(|_, p| p.connection != self.id);
            s.host_pending = true;
        }
    }
}
fn next(s: &mut State) -> Result<u64, u32> {
    s.next = s.next.checked_add(1).ok_or(28u32)?;
    Ok(s.next)
}
fn output(s: &mut State, connection: u64, value: Value) -> Result<(), u32> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| 5u32)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME {
        return Err(90);
    }
    let stream = s.streams.get_mut(&connection).ok_or(9u32)?;
    if stream.output.len() + bytes.len() > MAX_OUTPUT {
        return Err(11);
    }
    stream.output.extend(bytes);
    s.changed(connection, 0);
    Ok(())
}
fn expire(s: &mut State, now: Instant) {
    let expired: Vec<_> = s
        .pending
        .iter()
        .filter(|(_, p)| p.deadline <= now)
        .map(|(&t, _)| t)
        .collect();
    for t in expired {
        let p = &s.pending[&t];
        if output(
            s,
            p.connection,
            failure(Some(p.request.id), "timeout", "Native request expired"),
        )
        .is_ok()
        {
            s.pending.remove(&t);
        }
    }
}
impl Broker {
    fn lock(&self) -> Result<Guard<'_>, u32> {
        self.0
            .lock()
            .map(|guard| Guard(Some(guard), &self.1))
            .map_err(|_| 5)
    }
    pub fn host_ready(&self) -> bool {
        self.1.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn bind_host_wake(&self, wake: Arc<trames_shared::HostWake>) {
        if let Ok(mut s) = self.lock() {
            s.host_wake = Some(wake);
        }
    }
    pub fn enabled(&self, channel: Channel) -> bool {
        self.0.lock().is_ok_and(|s| s.policy.allows(channel))
    }
    pub fn configure(&self, policy: Policy) -> Result<(), u32> {
        let mut s = self.lock()?;
        s.policy = policy;
        s.host_pending = true;
        let denied: Vec<_> = s
            .pending
            .iter()
            .filter(|(_, p)| {
                s.streams
                    .get(&p.connection)
                    .and_then(|stream| stream.channel)
                    .is_some_and(|c| !policy.permits(c, &p.request.method))
            })
            .map(|(&t, _)| t)
            .collect();
        for ticket in denied {
            if let Some(p) = s.pending.remove(&ticket) {
                output(
                    &mut s,
                    p.connection,
                    failure(
                        Some(p.request.id),
                        "permission_denied",
                        "Host capability was revoked",
                    ),
                )?;
            }
        }
        Ok(())
    }
    /// Trusted host-only connection used by embedders/tests, never selected by mknod.
    pub fn connect(&self) -> Result<Arc<Connection>, u32> {
        self.connection(None)
    }
    pub fn connect_channel(&self, channel: Channel) -> Result<Arc<Connection>, u32> {
        self.connection(Some(channel))
    }
    fn connection(&self, channel: Option<Channel>) -> Result<Arc<Connection>, u32> {
        let mut s = self.lock()?;
        if channel.is_some_and(|channel| !s.policy.allows(channel)) {
            return Err(13);
        }
        if s.streams.len() >= MAX_CONNECTIONS {
            return Err(24);
        }
        let id = next(&mut s)?;
        let occupied = s
            .streams
            .values()
            .fold(0u32, |mask, stream| mask | (1 << stream.slot));
        let slot = (!occupied).trailing_zeros() as usize;
        let readiness = Arc::new(trames_shared::Readiness::default());
        s.streams.insert(
            id,
            Stream {
                input: Vec::new(),
                output: VecDeque::new(),
                readiness: readiness.clone(),
                epoch: [0; 2],
                slot,
                channel,
            },
        );
        let connection = Arc::new(Connection {
            broker: self.clone(),
            id,
            readiness,
        });
        let driver: Arc<dyn trames_shared::ReadinessDriver> = connection.clone();
        connection.readiness.set_driver(Arc::downgrade(&driver));
        Ok(connection)
    }
    /// A request is claimed only after checking the caller's output capacity.
    pub fn poll(&self, capacity: usize) -> Result<Option<Vec<u8>>, u32> {
        let mut s = self.lock()?;
        expire(&mut s, Instant::now());
        let Some((&ticket, p)) = s
            .pending
            .iter()
            .find(|(_, p)| !p.dispatched && p.deadline > Instant::now())
        else {
            return Ok(None);
        };
        let data = serde_json::to_vec(&HostRequest {
            ticket,
            request: p.request.clone(),
        })
        .map_err(|_| 5u32)?;
        if data.len() > capacity {
            return Err(90);
        }
        s.pending.get_mut(&ticket).ok_or(5u32)?.dispatched = true;
        Ok(Some(data))
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.0
            .lock()
            .ok()?
            .pending
            .values()
            .map(|p| p.deadline)
            .min()
    }
    pub fn active(&self, ticket: u64) -> bool {
        let Ok(mut s) = self.lock() else {
            return false;
        };
        expire(&mut s, Instant::now());
        s.pending
            .get(&ticket)
            .is_some_and(|p| p.deadline > Instant::now())
    }
    /// One bounded streaming control frame; backpressure stays on this open.
    pub fn stream(&self, ticket: u64, value: Value, done: bool) -> Result<(), u32> {
        let mut s = self.lock()?;
        expire(&mut s, Instant::now());
        let p = s.pending.get(&ticket).ok_or(2u32)?;
        let connection = p.connection;
        let id = p.request.id;
        output(
            &mut s,
            connection,
            json!({"version":VERSION,"id":id,"result":value}),
        )?;
        if done {
            s.pending.remove(&ticket);
        }
        Ok(())
    }
    pub fn reply(&self, bytes: &[u8]) -> Result<(), u32> {
        if bytes.len() > MAX_FRAME {
            return Err(90);
        }
        let r: HostReply = serde_json::from_slice(bytes).map_err(|_| 22u32)?;
        if r.version != VERSION
            || r.result.is_some() == r.error.is_some()
            || r.error
                .as_ref()
                .is_some_and(|e| e.code.len() > 64 || e.message.len() > 1024)
        {
            return Err(22);
        }
        let mut s = self.lock()?;
        expire(&mut s, Instant::now());
        let p = s.pending.get(&r.ticket).ok_or(2u32)?;
        if p.deadline <= Instant::now() {
            return Err(2);
        }
        if !p.dispatched {
            return Err(22);
        }
        let value = if let Some(error) = r.error {
            json!({"version":VERSION,"id":p.request.id,"error":error})
        } else {
            json!({"version":VERSION,"id":p.request.id,"result":r.result})
        };
        let connection = p.connection;
        output(&mut s, connection, value)?;
        s.pending.remove(&r.ticket);
        Ok(())
    }
}
impl Connection {
    /// Pure readiness observation: a run queue may hold its own metadata lock.
    /// Expired replies are readable lazily; only a body/host operation publishes
    /// bytes and emits notifications, after releasing the broker's mutex.
    pub fn peek(&self, events: u16) -> (u16, [u64; 2]) {
        let Ok(s) = self.broker.0.lock() else {
            return (8, [0; 2]);
        };
        let Some(stream) = s.streams.get(&self.id) else {
            return (32, [0; 2]);
        };
        let now = Instant::now();
        let expired = s
            .pending
            .values()
            .filter(|p| p.connection == self.id && p.deadline <= now)
            .count() as u64;
        let mut ready = 0;
        if !stream.output.is_empty() || expired != 0 {
            ready |= events & 1;
        }
        if stream.input.len() < MAX_FRAME && stream.output.len() < MAX_OUTPUT - 8192 {
            ready |= events & 4;
        }
        (
            ready,
            [stream.epoch[0].wrapping_add(expired), stream.epoch[1]],
        )
    }
    pub fn poll(&self, events: u16) -> u16 {
        self.peek(events).0
    }
    pub fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.readiness.subscribe(signal)
    }
    pub fn next_deadline(&self) -> Option<Instant> {
        let s = self.broker.0.lock().ok()?;
        let now = Instant::now();
        s.pending
            .values()
            .filter(|p| p.connection == self.id && p.deadline > now)
            .map(|p| p.deadline)
            .min()
    }
    pub fn read(&self, count: usize) -> Result<Vec<u8>, u32> {
        let mut s = self.broker.lock()?;
        expire(&mut s, Instant::now());
        let stream = s.streams.get_mut(&self.id).ok_or(9u32)?;
        if stream.output.is_empty() && count != 0 {
            return Err(11);
        }
        let bytes: Vec<_> = stream
            .output
            .drain(..count.min(stream.output.len()))
            .collect();
        if !bytes.is_empty() {
            s.host_pending = true;
            s.changed(self.id, 1);
        }
        Ok(bytes)
    }

    pub fn write(&self, bytes: &[u8]) -> Result<usize, u32> {
        let mut s = self.broker.lock()?;
        expire(&mut s, Instant::now());
        let mut consumed = 0;
        while consumed < bytes.len().min(MAX_OUTPUT) {
            let stream = s.streams.get(&self.id).ok_or(9u32)?;
            if stream.output.len() > MAX_OUTPUT - 8192 {
                return if consumed == 0 { Err(11) } else { Ok(consumed) };
            }
            let rest = &bytes[consumed..bytes.len().min(MAX_OUTPUT)];
            let end = rest.iter().position(|&b| b == b'\n').map(|n| n + 1);
            let length = end.unwrap_or(rest.len());
            if length > MAX_FRAME - stream.input.len() {
                s.streams.get_mut(&self.id).ok_or(9u32)?.input.clear();
                s.changed(self.id, 1);
                return if consumed == 0 { Err(90) } else { Ok(consumed) };
            }
            let stream = s.streams.get_mut(&self.id).ok_or(9u32)?;
            stream.input.extend_from_slice(&rest[..length]);
            consumed += length;
            s.changed(self.id, 1);
            if end.is_some() {
                let frame = std::mem::take(&mut s.streams.get_mut(&self.id).ok_or(9u32)?.input);
                submit(&mut s, self.id, &frame)?;
            }
        }
        Ok(consumed)
    }
}
impl trames_shared::ReadinessDriver for Connection {
    fn external(&self) -> bool {
        self.next_deadline().is_some()
    }
    fn notification_only(&self) -> bool {
        true
    }
    fn attach(&self, _: Arc<trames_shared::HostEvents>) -> std::io::Result<()> {
        Ok(())
    }
}

fn submit(s: &mut State, connection: u64, frame: &[u8]) -> Result<(), u32> {
    let request: Request = match serde_json::from_slice(frame) {
        Ok(r) => r,
        Err(_) => {
            output(
                s,
                connection,
                failure(
                    None,
                    "invalid_request",
                    "Expected one versioned JSON request",
                ),
            )?;
            return Ok(());
        }
    };
    let id = Some(request.id);
    if s.streams
        .get(&connection)
        .and_then(|stream| stream.channel)
        .is_some_and(|channel| !s.policy.permits(channel, &request.method))
    {
        output(
            s,
            connection,
            failure(
                id,
                "permission_denied",
                "Method is outside this device capability",
            ),
        )?;
        return Ok(());
    }
    if request.version != VERSION || !request.params.is_object() || request.method.len() > 64 {
        output(
            s,
            connection,
            failure(id, "invalid_request", "Unsupported version or parameters"),
        )?;
    } else if s
        .pending
        .values()
        .any(|p| p.connection == connection && p.request.id == request.id)
    {
        output(
            s,
            connection,
            failure(id, "duplicate_id", "Request id is already pending"),
        )?;
    } else if request.method == "request.cancel" {
        let target = request.params.get("id").and_then(Value::as_u64);
        let ticket = s
            .pending
            .iter()
            .find(|(_, p)| p.connection == connection && Some(p.request.id) == target)
            .map(|(&t, _)| t);
        if let Some(t) = ticket {
            s.host_pending = true;
            let p = s.pending.remove(&t).ok_or(5u32)?;
            output(
                s,
                connection,
                failure(Some(p.request.id), "cancelled", "Request cancelled"),
            )?;
        }
        output(
            s,
            connection,
            json!({"version":VERSION,"id":id,"result":{"cancelled":ticket.is_some()}}),
        )?;
    } else if request.method == "bridge.info" {
        let channel = s.streams.get(&connection).and_then(|stream| stream.channel);
        let methods: Vec<_> = METHODS
            .iter()
            .filter(|method| channel.is_none_or(|channel| s.policy.permits(channel, method)))
            .collect();
        output(
            s,
            connection,
            json!({"version":VERSION,"id":id,"result":{"protocol":VERSION,"methods":methods,"max_frame":MAX_FRAME,"consent":"host_authorized"}}),
        )?;
    } else if request.method.starts_with("accel.") {
        let value = match request.method.as_str() {
            "accel.list" => json!({"abi":hash::ABI_VERSION,"sha256":s.accel}),
            "accel.enable" | "accel.disable"
                if request.params.get("id").and_then(Value::as_str) == Some("sha256") =>
            {
                s.accel.enabled = request.method == "accel.enable";
                json!({"enabled":s.accel.enabled})
            }
            "accel.sha256" => match request.params.get("text").and_then(Value::as_str) {
                Some(text) => match s.accel.sha256(text.as_bytes()) {
                    Ok(d) => json!({"digest":d}),
                    Err(e) => {
                        output(
                            s,
                            connection,
                            failure(id, e, "Native SHA-256 unavailable; use guest sha256sum"),
                        )?;
                        return Ok(());
                    }
                },
                None => {
                    output(
                        s,
                        connection,
                        failure(id, "invalid_params", "Expected UTF-8 text"),
                    )?;
                    return Ok(());
                }
            },
            _ => {
                output(
                    s,
                    connection,
                    failure(id, "method_not_found", "Unknown accelerator"),
                )?;
                return Ok(());
            }
        };
        output(
            s,
            connection,
            json!({"version":VERSION,"id":id,"result":value}),
        )?;
    } else if !METHODS.contains(&request.method.as_str()) {
        output(
            s,
            connection,
            failure(id, "method_not_found", "Unknown capability"),
        )?;
    } else if s.pending.len() >= MAX_PENDING
        || s.pending
            .values()
            .filter(|p| p.connection == connection)
            .count()
            >= 8
    {
        output(
            s,
            connection,
            failure(id, "busy", "Native request limit reached"),
        )?;
    } else {
        s.host_pending = true;
        let ticket = next(s)?;
        s.pending.insert(
            ticket,
            Pending {
                connection,
                request,
                deadline: Instant::now() + TIMEOUT,
                dispatched: false,
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(c: &Connection, id: u64, method: &str, params: Value) {
        let mut b =
            serde_json::to_vec(&json!({"version":VERSION,"id":id,"method":method,"params":params}))
                .unwrap();
        b.push(b'\n');
        assert_eq!(c.write(&b), Ok(b.len()));
    }
    fn read(c: &Connection) -> Vec<Value> {
        let bytes = c.read(MAX_OUTPUT).unwrap();
        bytes
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(|b| serde_json::from_slice(b).unwrap())
            .collect()
    }
    fn poll(b: &Broker) -> Value {
        serde_json::from_slice(&b.poll(65536).unwrap().unwrap()).unwrap()
    }
    #[test]
    fn replies_notify_original_connection_after_unlock_and_pure_peek_never_notifies() {
        use trames_shared::{IoSignal, IoWake};
        struct Wake {
            connection: std::sync::Weak<Connection>,
            replies: Mutex<Vec<Value>>,
        }
        impl IoWake for Wake {
            fn wake_io(&self, _: &Arc<IoSignal>) {
                if let Some(c) = self.connection.upgrade() {
                    if c.peek(1).0 == 1 {
                        self.replies.lock().unwrap().extend(read(&c));
                    }
                }
            }
        }
        let broker = Broker::default();
        let c = broker.connect().unwrap();
        let target = Arc::new(Wake {
            connection: Arc::downgrade(&c),
            replies: Mutex::default(),
        });
        let w: Arc<dyn IoWake> = target.clone();
        let signal = IoSignal::new(7, Arc::downgrade(&w));
        let subscription = c.subscribe(&signal);
        assert!(!subscription.external());
        request(&c, 73, "clipboard.read", json!({}));
        assert!(subscription.external());
        signal.reset();
        let host = poll(&broker);
        broker
            .reply(
                &serde_json::to_vec(
                    &json!({"version":1,"ticket":host["ticket"],"result":{"text":"original"}}),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(signal.ready());
        assert_eq!(target.replies.lock().unwrap()[0]["id"], 73);
        assert!(!subscription.external());
        signal.reset();
        request(&c, 74, "clipboard.read", json!({}));
        let ticket = poll(&broker)["ticket"].as_u64().unwrap();
        broker
            .0
            .lock()
            .unwrap()
            .pending
            .get_mut(&ticket)
            .unwrap()
            .deadline = Instant::now();
        signal.reset();
        let epoch = c.peek(1).1;
        assert_eq!(c.peek(1).0, 1);
        assert_eq!(
            c.next_deadline(),
            None,
            "past deadlines must not create polling retries"
        );
        assert!(
            !subscription.external(),
            "an expired request has no remaining native producer"
        );
        assert!(
            !signal.ready(),
            "readiness observation must not reenter the run queue"
        );
        assert_eq!(c.peek(1).1, epoch);
        drop(subscription);
        assert_eq!(read(&c)[0]["error"]["code"], "timeout");
    }
    #[test]
    fn output_backpressure_uses_original_stream_wakeup_and_edge_epochs() {
        struct Wake;
        impl trames_shared::IoWake for Wake {
            fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {}
        }
        let broker = Broker::default();
        let c = broker.connect().unwrap();
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake);
        let signal = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
        let _subscription = c.subscribe(&signal);
        let frame = b"{\"version\":1,\"id\":1,\"method\":\"bridge.info\",\"params\":{}}\n";
        while c.poll(4) != 0 {
            assert_eq!(c.write(frame), Ok(frame.len()));
        }
        signal.reset();
        let before = c.peek(5).1;
        assert_eq!(c.write(frame), Err(11));
        assert!(!signal.ready());
        c.read(MAX_OUTPUT / 2).unwrap();
        assert!(signal.ready());
        assert_eq!(c.poll(4), 4);
        assert_ne!(c.peek(5).1[1], before[1]);
        assert_eq!(c.write(frame), Ok(frame.len()));
    }
    #[test]
    fn coalesced_frames_partial_tail_and_full_pending_queue_allow_cancel() {
        let b = Broker::default();
        let c = b.connect().unwrap();
        let mut bytes = Vec::new();
        for id in 0..8 {
            let frame = json!({"version":1,"id":id,"method":"clipboard.read","params":{}});
            bytes.extend(serde_json::to_vec(&frame).unwrap());
            bytes.push(b'\n');
        }
        assert_eq!(c.write(&bytes), Ok(bytes.len()));
        assert_eq!(c.poll(4), 4);
        let cancel =
            b"{\"version\":1,\"id\":9,\"method\":\"request.cancel\",\"params\":{\"id\":0}}\n";
        assert_eq!(c.write(&cancel[..21]), Ok(21));
        assert_eq!(c.write(&cancel[21..]), Ok(cancel.len() - 21));
        let values = read(&c);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["error"]["code"], "cancelled");
        assert_eq!(values[1]["result"]["cancelled"], true);
        assert_eq!(b.0.lock().unwrap().pending.len(), 7);
    }
    #[test]
    fn expired_ticket_loses_authority_even_when_timeout_output_is_full() {
        let b = Broker::default();
        let c = b.connect().unwrap();
        request(&c, 1, "clipboard.read", json!({}));
        let ticket = poll(&b)["ticket"].as_u64().unwrap();
        {
            let mut state = b.0.lock().unwrap();
            state
                .streams
                .get_mut(&c.id)
                .unwrap()
                .output
                .extend(vec![0; MAX_OUTPUT]);
            state.pending.get_mut(&ticket).unwrap().deadline = Instant::now();
        }
        assert!(!b.active(ticket));
        assert!(b.poll(65536).unwrap().is_none());
        assert_eq!(
            b.reply(
                &serde_json::to_vec(&json!({"version":1,"ticket":ticket,"result":null})).unwrap()
            ),
            Err(2)
        );
        c.read(MAX_OUTPUT).unwrap();
        assert_eq!(read(&c)[0]["error"]["code"], "timeout");
    }
    #[test]
    fn native_effect_requires_a_claimed_reply_and_capacity_does_not_consume() {
        let b = Broker::default();
        let c = b.connect().unwrap();
        request(&c, 1, "clipboard.read", json!({}));
        assert_eq!(c.read(1), Err(11));
        assert_eq!(b.poll(1), Err(90));
        let r = poll(&b);
        let t = r["ticket"].as_u64().unwrap();
        assert!(b.active(t));
        assert!(b.poll(65536).unwrap().is_none());
        assert_eq!(
            b.reply(&serde_json::to_vec(&json!({"version":1,"ticket":t,"result":null})).unwrap()),
            Ok(())
        );
        assert_eq!(read(&c), vec![json!({"version":1,"id":1,"result":null})]);
        assert!(!b.active(t));
        assert_eq!(
            b.reply(&serde_json::to_vec(&json!({"version":1,"ticket":t,"result":{}})).unwrap()),
            Err(2)
        );
    }
    #[test]
    fn fragmented_frames_and_malformed_input_never_reach_host() {
        let b = Broker::default();
        let c = b.connect().unwrap();
        let text=b"{\"version\":1,\"id\":2,\"method\":\"clipboard.write\",\"params\":{\"text\":\"hello\"}}\n";
        for byte in text {
            assert_eq!(c.write(&[*byte]), Ok(1));
        }
        let r = poll(&b);
        assert_eq!(r["request"]["params"]["text"], "hello");
        assert_eq!(c.write(b"bad\n"), Ok(4));
        assert_eq!(read(&c)[0]["error"]["code"], "invalid_request");
        assert_eq!(c.write(&vec![b'x'; MAX_FRAME + 1]), Err(90));
        request(&c, 3, "shell.execute", json!({}));
        assert_eq!(read(&c)[0]["error"]["code"], "method_not_found");
        assert!(b.poll(65536).unwrap().is_none());
    }
    #[test]
    fn cancellation_expiration_and_drop_reject_late_replies() {
        let b = Broker::default();
        let c = b.connect().unwrap();
        request(&c, 1, "url.open", json!({"url":"https://example.com"}));
        let t = poll(&b)["ticket"].as_u64().unwrap();
        request(&c, 2, "request.cancel", json!({"id":1}));
        assert_eq!(read(&c)[0]["error"]["code"], "cancelled");
        assert!(!b.active(t));
        request(&c, 3, "device.info", json!({}));
        let t = poll(&b)["ticket"].as_u64().unwrap();
        b.0.lock().unwrap().pending.get_mut(&t).unwrap().deadline = Instant::now();
        assert!(!b.active(t));
        assert_eq!(read(&c)[0]["error"]["code"], "timeout");
        request(&c, 4, "clipboard.read", json!({}));
        let t = poll(&b)["ticket"].as_u64().unwrap();
        drop(c);
        assert!(!b.active(t));
        assert!(b.0.lock().unwrap().streams.is_empty());
    }
    #[test]
    fn connections_and_sessions_cannot_cancel_each_others_requests() {
        let b = Broker::default();
        let c = b.connect().unwrap();
        let other = b.connect().unwrap();
        request(&c, 1, "clipboard.read", json!({}));
        let t = poll(&b)["ticket"].as_u64().unwrap();
        request(&other, 2, "request.cancel", json!({"id":1}));
        assert_eq!(read(&other)[0]["result"]["cancelled"], false);
        assert!(b.active(t));
        assert!(!Broker::default().active(t));
        let denial =
            json!({"version":1,"ticket":t,"error":{"code":"denied","message":"User denied"}});
        b.reply(&serde_json::to_vec(&denial).unwrap()).unwrap();
        assert_eq!(read(&c)[0]["error"]["code"], "denied");
        assert_eq!(other.read(1), Err(11));
    }
    #[test]
    fn request_limits_duplicate_ids_and_output_backpressure_are_bounded() {
        let b = Broker::default();
        let c = b.connect().unwrap();
        for id in 0..8 {
            request(&c, id, "clipboard.read", json!({}));
        }
        request(&c, 0, "clipboard.read", json!({}));
        request(&c, 9, "clipboard.read", json!({}));
        let replies = read(&c);
        assert_eq!(replies[0]["error"]["code"], "duplicate_id");
        assert_eq!(replies[1]["error"]["code"], "busy");
        assert_eq!(b.0.lock().unwrap().pending.len(), 8);
        let t = poll(&b)["ticket"].as_u64().unwrap();
        let reply =
            serde_json::to_vec(&json!({"version":1,"ticket":t,"result":{"text":"ok"}})).unwrap();
        b.0.lock()
            .unwrap()
            .streams
            .get_mut(&c.id)
            .unwrap()
            .output
            .extend(vec![0; MAX_OUTPUT]);
        assert_eq!(b.reply(&reply), Err(11));
        assert!(b.active(t));
        c.read(MAX_OUTPUT).unwrap();
        b.reply(&reply).unwrap();
        assert_eq!(read(&c)[0]["result"]["text"], "ok");
        let mut connections = vec![c];
        for _ in 1..MAX_CONNECTIONS {
            connections.push(b.connect().unwrap());
        }
        assert!(matches!(b.connect(), Err(24)));
        drop(connections);
        assert!(b.connect().is_ok());
    }
    #[test]
    fn clipboard_cli_and_host_exec_have_independent_authority() {
        let b = Broker::default();
        b.configure(Policy::new(true, false, false, false, false))
            .unwrap();
        assert!(!b.enabled(Channel::Clipboard));
        let control = b.connect_channel(Channel::HostControl).unwrap();
        request(&control, 1, "clipboard.read", json!({}));
        assert!(String::from_utf8(control.read(32768).unwrap())
            .unwrap()
            .contains("permission_denied"));
        request(&control, 2, "host.cli", json!({"argv":["--version"]}));
        assert!(String::from_utf8(control.read(32768).unwrap())
            .unwrap()
            .contains("permission_denied"));
        b.configure(Policy::default().with_clipboard(true)).unwrap();
        assert!(!b.enabled(Channel::HostControl));
        assert!(!b.enabled(Channel::HostExec));
        let clip = b.connect_channel(Channel::Clipboard).unwrap();
        request(&clip, 3, "clipboard.write", json!({"text":"剪贴板 🧪"}));
        assert!(b.poll(MAX_FRAME).unwrap().is_some());
        b.configure(Default::default()).unwrap();
        assert!(String::from_utf8(clip.read(32768).unwrap())
            .unwrap()
            .contains("permission_denied"));
        request(&clip, 4, "clipboard.read", json!({}));
        assert!(String::from_utf8(clip.read(32768).unwrap())
            .unwrap()
            .contains("permission_denied"));
    }
}
