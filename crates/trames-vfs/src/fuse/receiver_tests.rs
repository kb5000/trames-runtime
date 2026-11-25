// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::{Mutex, Weak};

struct Receiver {
    connection: Weak<Connection>,
    result: Mutex<Option<Result<Vec<u8>>>>,
}
impl ReplyReceiver for Receiver {
    fn complete(&self, result: Result<Vec<u8>>) {
        // A page completion can enqueue follow-on IO and cancel its original
        // request. Neither operation may re-enter a held connection lock.
        let connection = self.connection.upgrade().unwrap();
        assert!(connection.queue.try_lock().is_ok());
        *self.result.lock().unwrap() = Some(result);
    }
}
fn receive_page(c: &Arc<Connection>) -> (Arc<Receiver>, Request) {
    let receiver = Arc::new(Receiver {
        connection: Arc::downgrade(c),
        result: Mutex::default(),
    });
    let target: Arc<dyn ReplyReceiver> = receiver.clone();
    let mut body = [0; 40];
    body[16..20].copy_from_slice(&4096u32.to_le_bytes());
    let request = c
        .request_received(15, 10, Caller::default(), &body, Arc::downgrade(&target))
        .unwrap();
    (receiver, request)
}
fn reply(id: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16 + payload.len());
    bytes.extend(((16 + payload.len()) as u32).to_le_bytes());
    bytes.extend(0i32.to_le_bytes());
    bytes.extend(id.to_le_bytes());
    bytes.extend(payload);
    bytes
}
fn id(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[8..16].try_into().unwrap())
}
fn ready() -> Arc<Connection> {
    let c = Connection::new(Caller::default());
    let init = c.read(8192).unwrap();
    let mut body = [0; 64];
    body[..4].copy_from_slice(&7u32.to_le_bytes());
    body[4..8].copy_from_slice(&31u32.to_le_bytes());
    c.write(&reply(id(&init), &body)).unwrap();
    c
}
struct Cancellation {
    connection: Weak<Connection>,
    count: Arc<std::sync::atomic::AtomicUsize>,
    receiver: Option<Arc<Receiver>>,
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.upgrade() {
            assert!(
                connection.queue.try_lock().is_ok(),
                "cancellation cleanup must run outside the daemon queue"
            );
        }
        if let Some(receiver) = &self.receiver {
            assert!(receiver.result.lock().unwrap().is_some());
        }
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}
fn cancellation(c: &Arc<Connection>, count: &Arc<std::sync::atomic::AtomicUsize>) -> Box<dyn Send> {
    Box::new(Cancellation {
        connection: Arc::downgrade(c),
        count: count.clone(),
        receiver: None,
    })
}
fn ordinary_read(c: &Arc<Connection>) -> Request {
    let mut body = [0; 40];
    body[16..20].copy_from_slice(&4u32.to_le_bytes());
    c.request(15, 10, Caller::default(), &body).unwrap()
}
#[test]
fn fatal_interrupt_withdraws_unread_requests_but_waits_for_delivered_original_reply() {
    for delivered in [false, true] {
        let c = ready();
        let request = ordinary_read(&c);
        let input = delivered.then(|| c.read(8192).unwrap());
        request.interrupt_fatal();
        if let Some(input) = input {
            assert!(!request.ready());
            c.write(&reply(id(&input), b"data")).unwrap();
            assert_eq!(request.take(), Some(Ok(b"data".to_vec())));
        } else {
            assert_eq!(request.take(), Some(Err(Errno(4))));
            assert_eq!(c.read(8192), Err(Errno(11)));
        }
    }
}
#[test]
fn delivered_cancellation_keeps_original_credit_until_reply_or_disconnect() {
    for abort in [false, true] {
        let c = ready();
        let request = ordinary_read(&c);
        let input = c.read(8192).unwrap();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        assert!(request
            .retain_cancellation(cancellation(&c, &count))
            .is_none());
        drop(request);
        assert_eq!(count.load(Ordering::Relaxed), 0);
        if abort {
            c.abort();
        } else {
            c.write(&reply(id(&input), b"data")).unwrap();
        }
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn unread_cancellation_releases_original_credit_when_the_request_is_withdrawn() {
    let c = ready();
    let request = ordinary_read(&c);
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    assert!(request
        .retain_cancellation(cancellation(&c, &count))
        .is_none());
    drop(request);
    assert_eq!(count.load(Ordering::Relaxed), 1);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn consumed_reply_cannot_capture_a_later_cancellation_credit() {
    let c = ready();
    let request = ordinary_read(&c);
    let input = c.read(8192).unwrap();
    c.write(&reply(id(&input), b"data")).unwrap();
    assert_eq!(request.take(), Some(Ok(b"data".to_vec())));
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let released = request.retain_cancellation(cancellation(&c, &count));
    assert!(released.is_some());
    assert_eq!(count.load(Ordering::Relaxed), 0);
    drop(released);
    assert_eq!(count.load(Ordering::Relaxed), 1);
}
#[test]
fn page_receiver_completes_before_original_cancellation_credit_is_released() {
    let c = ready();
    let (receiver, request) = receive_page(&c);
    let input = c.read(8192).unwrap();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    assert!(request
        .retain_cancellation(Box::new(Cancellation {
            connection: Arc::downgrade(&c),
            count: count.clone(),
            receiver: Some(receiver.clone())
        }))
        .is_none());
    drop(request);
    c.write(&reply(id(&input), b"page")).unwrap();
    assert_eq!(count.load(Ordering::Relaxed), 1);
}
#[test]
fn page_receivers_bind_before_publication_and_run_once_outside_transport_locks() {
    let c = ready();
    let (receiver, request) = receive_page(&c);
    let input = c.read(8192).unwrap();
    c.write(&reply(id(&input), b"page")).unwrap();
    assert_eq!(
        receiver.result.lock().unwrap().take(),
        Some(Ok(b"page".to_vec()))
    );
    assert_eq!(
        request.take(),
        None,
        "the owned byte reply has one consumer"
    );
    assert_eq!(c.write(&reply(id(&input), b"again")), Err(Errno(2)));
}
#[test]
fn malformed_and_disconnected_page_requests_complete_the_original_receiver() {
    for abort in [false, true] {
        let c = ready();
        let (receiver, _request) = receive_page(&c);
        let input = c.read(8192).unwrap();
        if abort {
            c.abort();
        } else {
            assert_eq!(c.write(&reply(id(&input), &vec![0; 4097])), Err(Errno(22)));
        }
        assert_eq!(
            receiver.result.lock().unwrap().take(),
            Some(Err(Errno(if abort { 103 } else { 5 })))
        );
    }
}
#[test]
fn receiver_lifetime_cannot_keep_an_abandoned_page_alive() {
    let c = ready();
    let (receiver, request) = receive_page(&c);
    let input = c.read(8192).unwrap();
    let weak = Arc::downgrade(&receiver);
    drop(receiver);
    assert!(weak.upgrade().is_none());
    c.write(&reply(id(&input), b"late")).unwrap();
    drop(request);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
