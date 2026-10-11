// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded asynchronous NDJSON device, isolated per embedding session and open.
//! Native effects require a host reply. Guest uid 0 never grants host authority.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
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
];
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub id: u64,
    pub method: String,
    pub params: Value,
}
#[derive(Serialize)]
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
    streams: BTreeMap<u64, Stream>,
    pending: BTreeMap<u64, Pending>,
    accel: trames_accel::Registry,
}
#[derive(Clone, Default)]
pub struct Broker(Arc<Mutex<State>>);
pub struct Connection {
    broker: Broker,
    id: u64,
}
impl Drop for Connection {
    fn drop(&mut self) {
        if let Ok(mut s) = self.broker.0.lock() {
            s.streams.remove(&self.id);
            s.pending.retain(|_, p| p.connection != self.id);
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
    pub fn connect(&self) -> Result<Arc<Connection>, u32> {
        let mut s = self.0.lock().map_err(|_| 5u32)?;
        if s.streams.len() >= MAX_CONNECTIONS {
            return Err(24);
        }
        let id = next(&mut s)?;
        s.streams.insert(id, Stream::default());
        Ok(Arc::new(Connection {
            broker: self.clone(),
            id,
        }))
    }
    /// A request is claimed only after checking the caller's output capacity.
    pub fn poll(&self, capacity: usize) -> Result<Option<Vec<u8>>, u32> {
        let mut s = self.0.lock().map_err(|_| 5u32)?;
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
    pub fn active(&self, ticket: u64) -> bool {
        let Ok(mut s) = self.0.lock() else {
            return false;
        };
        expire(&mut s, Instant::now());
        s.pending
            .get(&ticket)
            .is_some_and(|p| p.deadline > Instant::now())
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
        let mut s = self.0.lock().map_err(|_| 5u32)?;
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
    pub fn poll(&self, events: u16) -> u16 {
        let Ok(mut s) = self.broker.0.lock() else {
            return 8;
        };
        expire(&mut s, Instant::now());
        let Some(stream) = s.streams.get(&self.id) else {
            return 32;
        };
        let mut ready = 0;
        if !stream.output.is_empty() {
            ready |= events & 1;
        }
        if stream.input.len() < MAX_FRAME && stream.output.len() < MAX_OUTPUT - 8192 {
            ready |= events & 4;
        }
        ready
    }
    pub fn read(&self, count: usize) -> Result<Vec<u8>, u32> {
        let mut s = self.broker.0.lock().map_err(|_| 5u32)?;
        expire(&mut s, Instant::now());
        let stream = s.streams.get_mut(&self.id).ok_or(9u32)?;
        if stream.output.is_empty() && count != 0 {
            return Err(11);
        }
        Ok(stream
            .output
            .drain(..count.min(stream.output.len()))
            .collect())
    }
    pub fn write(&self, bytes: &[u8]) -> Result<usize, u32> {
        let mut s = self.broker.0.lock().map_err(|_| 5u32)?;
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
                return if consumed == 0 { Err(90) } else { Ok(consumed) };
            }
            let stream = s.streams.get_mut(&self.id).ok_or(9u32)?;
            stream.input.extend_from_slice(&rest[..length]);
            consumed += length;
            if end.is_some() {
                let frame = std::mem::take(&mut stream.input);
                submit(&mut s, self.id, &frame)?;
            }
        }
        Ok(consumed)
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
        output(
            s,
            connection,
            json!({"version":VERSION,"id":id,"result":{"protocol":VERSION,"methods":METHODS,"max_frame":MAX_FRAME,"consent":"per_request"}}),
        )?;
    } else if request.method.starts_with("accel.") {
        let value = match request.method.as_str() {
            "accel.list" => json!({"abi":trames_accel::ABI_VERSION,"sha256":s.accel}),
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
}
