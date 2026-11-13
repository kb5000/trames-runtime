// SPDX-License-Identifier: GPL-3.0-or-later
//! ABI-level subsystem scenarios, with independent real Files/mm resources.
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
struct Client {
    vfs: Vfs,
    memory: Memory,
    fd: u32,
    tid: u32,
}
impl Client {
    fn new(root: &Vfs, owner: u32, device: &[u8]) -> Self {
        let mut vfs = root.clone();
        vfs.set_lock_owner(owner);
        vfs.set_runtime_info(owner, RuntimeInfo::default());
        let fd = vfs.open_at(AT_FDCWD, device, 2, 0).unwrap();
        let mut memory = Memory::default();
        memory.map(0x1000, 0x30000, Permissions::RW).unwrap();
        let file = vfs.mapping_file(fd).unwrap();
        let pages = file
            .binder_pages(0x100000, 0, 0x10000, false)
            .unwrap()
            .unwrap();
        memory
            .map_backed(
                0x100000,
                pages,
                true,
                Permissions {
                    read: true,
                    write: false,
                    execute: false,
                },
                false,
            )
            .unwrap();
        Self {
            vfs,
            memory,
            fd,
            tid: owner,
        }
    }
    fn process(&self) -> Arc<Connection> {
        let file = self.vfs.binder_file(self.fd).unwrap().unwrap();
        let Some(events::SharedControl::Binder(process)) = &file.open.control else {
            unreachable!()
        };
        process.clone()
    }
    fn control(&mut self, cmd: u32, bytes: &[u8]) -> Result<()> {
        self.memory.write(0x1000, bytes).unwrap();
        let file = self.vfs.binder_file(self.fd)?.unwrap();
        match Ioctl::start(
            file,
            self.vfs.descriptor_factory(),
            self.tid,
            cmd,
            0x1000,
            &mut self.memory,
        )? {
            Started::Complete(_) => Ok(()),
            _ => panic!("control must complete"),
        }
    }
    fn start(&mut self, commands: &[u8], capacity: u64) -> Result<Ioctl> {
        self.memory.write(0x2000, commands).unwrap();
        let mut header = [0; 48];
        put(&mut header, 0, commands.len() as u64);
        put(&mut header, 16, 0x2000);
        put(&mut header, 24, capacity);
        put(&mut header, 40, 0x8000);
        self.memory.write(0x1000, &header).unwrap();
        let file = self.vfs.binder_file(self.fd)?.unwrap();
        match Ioctl::start(
            file,
            self.vfs.descriptor_factory(),
            self.tid,
            WRITE_READ,
            0x1000,
            &mut self.memory,
        )? {
            Started::Read(request) => Ok(request),
            _ => panic!("expected read half"),
        }
    }
    fn write(&mut self, commands: &[u8]) {
        let mut request = self.start(commands, 0).unwrap();
        assert_eq!(request.finish(&mut self.memory), Ok(Some(0)));
    }
    fn receive(&mut self) -> Option<Vec<(u32, Vec<u8>)>> {
        let mut request = self.start(&[], 4096).unwrap();
        request.finish(&mut self.memory).unwrap()?;
        let size = self.memory.read_u64(0x1020).unwrap() as usize;
        let mut bytes = vec![0; size];
        self.memory.read(0x8000, &mut bytes).unwrap();
        let mut records = Vec::new();
        let mut at = 0;
        while at < size {
            let cmd = dword(&bytes, at);
            let len = ((cmd >> 16) & 0x3fff) as usize;
            records.push((cmd, bytes[at + 4..at + 4 + len].to_vec()));
            at += 4 + len;
        }
        let acknowledgements: Vec<_> = records
            .iter()
            .filter_map(|(cmd, data)| match *cmd {
                BR_INCREFS => Some(command(INCREFS_DONE, data)),
                BR_ACQUIRE => Some(command(ACQUIRE_DONE, data)),
                _ => None,
            })
            .flatten()
            .collect();
        if !acknowledgements.is_empty() {
            self.write(&acknowledgements);
        }
        Some(records)
    }
    fn transaction(&mut self) -> (u32, Vec<u8>) {
        for _ in 0..16 {
            let records = self.receive().expect("transaction must be ready");
            if let Some(record) = records.into_iter().find(|(cmd, _)| {
                matches!(
                    *cmd,
                    BR_TRANSACTION | BR_REPLY | BR_DEAD_REPLY | BR_FAILED_REPLY
                )
            }) {
                return record;
            }
        }
        panic!("transaction not found")
    }
    fn send(&mut self, handle: u32, flags: u32, data: &[u8], offsets: &[u64], reply: bool) {
        self.memory.write(0x10000, data).unwrap();
        let offsets: Vec<_> = offsets.iter().flat_map(|n| n.to_le_bytes()).collect();
        self.memory.write(0x18000, &offsets).unwrap();
        let mut header = [0; 64];
        put32(&mut header, 0, handle);
        put32(&mut header, 16, 42);
        put32(&mut header, 20, flags);
        put(&mut header, 32, data.len() as u64);
        put(&mut header, 40, offsets.len() as u64);
        put(&mut header, 48, 0x10000);
        put(&mut header, 56, 0x18000);
        self.write(&command(if reply { REPLY } else { TRANSACTION }, &header));
    }
    fn enter(&mut self) {
        self.write(&command(ENTER_LOOPER, &[]));
    }
    fn manager(&mut self) {
        self.control(SET_CONTEXT_MGR, &[0; 4]).unwrap();
        self.enter();
    }
    fn payload(&self, header: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; word(header, 32) as usize];
        self.memory.read(word(header, 48), &mut bytes).unwrap();
        bytes
    }
    fn free(&mut self, header: &[u8]) {
        self.write(&command(FREE_BUFFER, &word(header, 48).to_le_bytes()));
    }
}
fn flat(kind: u32, pointer: u64, cookie: u64) -> Vec<u8> {
    let mut out = vec![0; 24];
    put32(&mut out, 0, kind);
    put32(&mut out, 4, 0x100);
    put(&mut out, 8, pointer);
    put(&mut out, 16, cookie);
    out
}

#[test]
fn contexts_protocol_mapping_and_disabled_selinux_queries() {
    let root = Vfs::default();
    for name in [
        b"/dev/binder".as_slice(),
        b"/dev/hwbinder",
        b"/dev/vndbinder",
    ] {
        let mut client = Client::new(&root, 1, name);
        client.manager();
        client.control(VERSION, &[0; 4]).unwrap();
        assert_eq!(
            client.memory.read_array::<4>(0x1000).unwrap(),
            8u32.to_le_bytes()
        );
        assert_eq!(client.control(SET_CONTEXT_MGR, &[0; 4]), Err(Errno(16)));
        assert_eq!(
            client.control(io(1, b'b', 16, 4), &1u32.to_le_bytes()),
            Err(Errno(22))
        );
        assert!(client.memory.write(0x100000, b"no").is_err());
        assert!(client
            .memory
            .protect(0x100000, PAGE_SIZE, Permissions::RW)
            .is_err());
        let child = client.memory.try_fork().unwrap();
        assert!(child.read_array::<1>(0x100000).is_err());
        assert!(client
            .vfs
            .stat_at(AT_FDCWD, b"/sys/fs/selinux/enforce")
            .is_err());
        let fd = client
            .vfs
            .open_at(AT_FDCWD, b"/proc/cmdline", 0, 0)
            .unwrap();
        assert_eq!(client.vfs.read(fd, 256).unwrap(), b"selinux=0\n");
        let fd = client
            .vfs
            .open_at(AT_FDCWD, b"/proc/filesystems", 0, 0)
            .unwrap();
        assert!(!String::from_utf8(client.vfs.read(fd, 4096).unwrap())
            .unwrap()
            .contains("selinuxfs"));
    }
    let independent = Vfs::default();
    Client::new(&independent, 1, b"/dev/binder").manager();
}
#[test]
fn worker_path_views_retain_original_context_and_mmap_release_not_physical_snapshots() {
    let mut root = Vfs::default();
    root.set_runtime_info(1, RuntimeInfo::default());
    let first = root.path_queries();
    let second = root.path_queries();
    let mut epoch = FileEpoch::default();
    let files = epoch.capture(&root, true);
    let fd = first
        .open_at_resolve(AT_FDCWD, b"/dev/binder", 2, 0, 0, &files)
        .unwrap()
        .unwrap();
    let file = root.binder_file(fd).unwrap().unwrap();
    let Started::Complete(_) = Ioctl::start(
        file,
        root.descriptor_factory(),
        1,
        SET_CONTEXT_MGR,
        0x1000,
        &mut {
            let mut m = Memory::default();
            m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            m
        },
    )
    .unwrap() else {
        panic!()
    };
    let fd2 = second
        .open_at_resolve(AT_FDCWD, b"/dev/binder", 2, 0, 0, &files)
        .unwrap()
        .unwrap();
    let file = root.binder_file(fd2).unwrap().unwrap();
    let Some(events::SharedControl::Binder(process)) = &file.open.control else {
        panic!()
    };
    assert!(process.target(0).is_ok());
    let epoll = root.epoll_create(0).unwrap();
    root.epoll_ctl(epoll, 1, fd2, 0x80000001, 42).unwrap();
    let mapping = root.mapping_file(fd).unwrap();
    let pages = mapping
        .binder_pages(0x100000, 0, PAGE_SIZE, false)
        .unwrap()
        .unwrap();
    let retained = pages.clone();
    let mut memory = Memory::default();
    memory
        .map_backed(
            0x100000,
            pages,
            true,
            Permissions {
                read: true,
                write: false,
                execute: false,
            },
            false,
        )
        .unwrap();
    drop(mapping);
    root.close(fd).unwrap();
    memory.unmap(0x100000, PAGE_SIZE).unwrap();
    assert!(
        process.target(0).is_err(),
        "retained CPU byte pages cannot retain the removed VMA's Binder process"
    );
    drop(retained);
}
#[test]
fn retired_binder_addresses_accept_new_cookies_after_actual_reference_release() {
    let root = Vfs::default();
    let mut owner = Client::new(&root, 10, b"/dev/hwbinder");
    let mut receiver = Client::new(&root, 20, b"/dev/hwbinder");
    receiver.manager();
    for generation in 1..=32 {
        let cookie = 0x2000 + generation * 16;
        owner.send(
            0,
            ACCEPT_FDS,
            &flat(TYPE_BINDER, 0x1110, cookie),
            &[0],
            false,
        );
        let (_, request) = receiver.transaction();
        let handle = dword(&receiver.payload(&request), 8);
        receiver.write(&command(INCREFS, &handle.to_le_bytes()));
        receiver.write(&command(ACQUIRE, &handle.to_le_bytes()));
        receiver.send(0, 0, b"accepted", &[], true);
        receiver.free(&request);
        let (_, reply) = owner.transaction();
        owner.free(&reply);
        assert!(matches!(
            owner.process().owned_node(0x1110, cookie + 1, 0x100, 10),
            Err(Errno(22))
        ));
        receiver.write(&command(RELEASE, &handle.to_le_bytes()));
        receiver.write(&command(DECREFS, &handle.to_le_bytes()));
        while owner.receive().is_some() {}
        assert!(!owner
            .process()
            .state
            .lock()
            .unwrap()
            .nodes
            .contains_key(&0x1110));
    }
}
#[test]
fn binder_readiness_is_per_original_thread_and_retired_poll_cannot_retarget_tid_reuse() {
    struct Reader(u32);
    impl SignalReader for Reader {
        fn global_tid(&self) -> Option<u32> {
            Some(self.0)
        }
        fn poll(&self, _: u64) -> (u16, [u64; 2]) {
            (0, [0; 2])
        }
        fn take(&self, _: u64) -> Option<[u8; 128]> {
            None
        }
        fn subscribe(&self, _: &Arc<IoSignal>) -> Vec<IoSubscription> {
            Vec::new()
        }
    }
    let root = Vfs::default();
    let owner = Client::new(&root, 10, b"/dev/binder");
    let process = owner.process();
    let main = owner
        .vfs
        .direct_descriptors()
        .with_signal_reader(Some(Arc::new(Reader(10))))
        .get(owner.fd)
        .unwrap();
    let worker = owner
        .vfs
        .direct_descriptors()
        .with_signal_reader(Some(Arc::new(Reader(11))))
        .get(owner.fd)
        .unwrap();
    let before = main.peek_poll(1);
    process.bytes(11, BR_COMPLETE);
    assert_eq!(
        main.peek_poll(1),
        before,
        "another thread's completion is not readable or a new edge here"
    );
    assert_eq!(worker.peek_poll(1).0, 1);
    process.thread_exit(11);
    assert_eq!(worker.peek_poll(1).0, 0x18);
    let new = owner
        .vfs
        .direct_descriptors()
        .with_signal_reader(Some(Arc::new(Reader(11))))
        .get(owner.fd)
        .unwrap();
    process.bytes(11, BR_COMPLETE);
    assert_eq!(new.peek_poll(1).0, 1);
    assert_eq!(
        worker.peek_poll(1).0,
        0x18,
        "accepted old poll cannot select a new task with the same TID"
    );
    assert_eq!(main.peek_poll(1), before);
}
#[test]
fn parcel_reference_commands_survive_remote_death_and_ignore_bad_user_counts() {
    let root = Vfs::default();
    let mut service = Client::new(&root, 10, b"/dev/binder");
    let mut client = Client::new(&root, 20, b"/dev/binder");
    service.manager();
    client.send(0, ACCEPT_FDS, b"object", &[], false);
    let (_, request) = service.transaction();
    service.send(0, 0, &flat(TYPE_BINDER, 0x1110, 0x2220), &[0], true);
    service.free(&request);
    let (_, reply) = client.transaction();
    let handle = dword(&client.payload(&reply), 8);
    service.process().close();
    for cmd in [INCREFS, ACQUIRE, RELEASE, DECREFS] {
        client.write(&command(cmd, &handle.to_le_bytes()));
    }
    client.send(handle, 0, b"dead", &[], false);
    assert_eq!(client.transaction().0, BR_DEAD_REPLY);
    client.free(&reply);
    for cmd in [INCREFS, ACQUIRE, RELEASE, DECREFS] {
        client.write(&command(cmd, &u32::MAX.to_le_bytes()));
    }
    client.write(&command(FREE_BUFFER, &0u64.to_le_bytes()));
    client.write(&command(ACQUIRE_DONE, &[0; 16]));
}
#[test]
fn completion_read_cannot_start_unrelated_process_rpc_inside_caller_locks() {
    let root = Vfs::default();
    let mut caller = Client::new(&root, 10, b"/dev/binder");
    let mut manager = Client::new(&root, 20, b"/dev/binder");
    let mut client = Client::new(&root, 30, b"/dev/binder");
    manager.manager();
    caller.enter();
    let node = caller
        .process()
        .owned_node(0x1110, 0x2220, 0x100, 10)
        .unwrap();
    let reference = client.process().reference(node, 3).unwrap();
    caller.send(0, ONE_WAY, b"outgoing", &[], false);
    client.send(reference.handle, ONE_WAY, b"unrelated RPC", &[], false);
    let records = caller.receive().unwrap();
    assert!(records.iter().any(|(cmd, _)| *cmd == BR_COMPLETE));
    assert!(!records.iter().any(|(cmd, _)| *cmd == BR_TRANSACTION));
    let (_, request) = caller.transaction();
    assert_eq!(caller.payload(&request), b"unrelated RPC");
    caller.free(&request);
    drop(BufferReference(reference, true));
}
#[test]
fn outgoing_rpc_waiter_does_not_suppress_server_pool_growth() {
    let root = Vfs::default();
    let mut service = Client::new(&root, 10, b"/dev/hwbinder");
    let mut downstream = Client::new(&root, 20, b"/dev/hwbinder");
    downstream.manager();
    service.send(0, ACCEPT_FDS, b"downstream", &[], false);
    service.receive().unwrap(); // Original caller consumed its completion.
    let mut waiting = service.start(&[], 4096).unwrap();
    assert_eq!(waiting.finish(&mut service.memory), Ok(None));
    service.tid = 11;
    service.enter();
    service
        .control(SET_MAX_THREADS, &1u32.to_le_bytes())
        .unwrap();
    let node = service
        .process()
        .owned_node(0x1110, 0x2220, 0x100, 11)
        .unwrap();
    let reference = downstream.process().reference(node, 3).unwrap();
    let records = service.receive().unwrap();
    assert!(records.iter().any(|(cmd, _)| *cmd == BR_SPAWN));
    drop(BufferReference(reference, true));
    drop(waiting);
}
#[test]
fn returned_temporary_object_acquisitions_precede_reply_completion() {
    let root = Vfs::default();
    let mut server = Client::new(&root, 10, b"/dev/hwbinder");
    let mut client = Client::new(&root, 20, b"/dev/hwbinder");
    server.manager();
    client.send(0, ACCEPT_FDS, b"new object", &[], false);
    let (_, request) = server.transaction();
    server.send(0, 0, &flat(TYPE_BINDER, 0x1110, 0x2220), &[0], true);
    let records = server.receive().unwrap();
    let commands: Vec<_> = records
        .into_iter()
        .map(|(cmd, _)| cmd)
        .filter(|cmd| *cmd != BR_NOOP)
        .collect();
    assert_eq!(commands, [BR_INCREFS, BR_ACQUIRE, BR_COMPLETE]);
    server.free(&request);
    let (_, reply) = client.transaction();
    client.free(&reply);
}
#[test]
fn queued_transaction_holds_guest_object_until_target_buffer_is_freed() {
    let root = Vfs::default();
    let mut owner = Client::new(&root, 10, b"/dev/binder");
    let mut client = Client::new(&root, 20, b"/dev/binder");
    client.manager();
    owner.send(
        0,
        ACCEPT_FDS,
        &flat(TYPE_BINDER, 0x1110, 0x2220),
        &[0],
        false,
    );
    let (_, exported) = client.transaction();
    let handle = dword(&client.payload(&exported), 8);
    client.write(&command(ACQUIRE, &handle.to_le_bytes()));
    client.send(0, 0, b"ready", &[], true);
    client.free(&exported);
    let (_, reply) = owner.transaction();
    owner.free(&reply);
    client.send(handle, ONE_WAY, b"in flight", &[], false);
    client.write(&command(RELEASE, &handle.to_le_bytes()));
    let records = owner.receive().unwrap();
    assert!(!records
        .iter()
        .any(|(cmd, _)| matches!(*cmd, BR_RELEASE | BR_DECREFS)));
    let transaction = records
        .iter()
        .find(|(cmd, _)| *cmd == BR_TRANSACTION)
        .unwrap()
        .1
        .clone();
    assert_eq!(
        (word(&transaction, 0), word(&transaction, 8)),
        (0x1110, 0x2220)
    );
    assert!(matches!(
        owner.process().owned_node(0x1110, 0x3330, 0x100, 10),
        Err(Errno(22))
    ));
    owner.free(&transaction);
    let mut releases = Vec::new();
    while let Some(records) = owner.receive() {
        releases.extend(
            records
                .into_iter()
                .map(|(cmd, _)| cmd)
                .filter(|cmd| matches!(*cmd, BR_RELEASE | BR_DECREFS)),
        );
    }
    assert_eq!(releases, [BR_RELEASE, BR_DECREFS]);
    assert!(owner
        .process()
        .owned_node(0x1110, 0x3330, 0x100, 10)
        .is_ok());
}
#[test]
fn malformed_or_unallocatable_replies_unwind_both_original_threads_and_allow_next_call() {
    for device in [b"/dev/binder".as_slice(), b"/dev/hwbinder"] {
        let root = Vfs::default();
        let mut service = Client::new(&root, 10, device);
        service.manager();
        let mut client = Client::new(&root, 20, device);
        for case in 0..4 {
            client.send(
                0,
                if case == 2 { 0 } else { ACCEPT_FDS },
                b"request",
                &[],
                false,
            );
            let (_, request) = service.transaction();
            match case {
                0 => {
                    let mut fd = flat(TYPE_FD, u32::MAX as u64, 0);
                    put32(&mut fd, 4, 0);
                    service.send(0, 0, &fd, &[0], true);
                }
                1 => service.send(0, 0, &TYPE_BINDER.to_le_bytes(), &[0], true),
                2 => {
                    let fd = flat(TYPE_FD, service.fd as u64, 0);
                    service.send(0, 0, &fd, &[0], true);
                }
                _ => service.send(0, 0, &vec![1; 0x10001], &[], true),
            }
            let records = service.receive().unwrap();
            assert!(records.iter().any(|r| r.0 == BR_COMPLETE));
            assert!(!records.iter().any(|r| r.0 == BR_FAILED_REPLY));
            assert_eq!(client.transaction().0, BR_FAILED_REPLY);
            service.free(&request);
            assert!(client.process().state.lock().unwrap().threads[&20]
                .stack
                .is_empty());
            assert!(service.process().state.lock().unwrap().threads[&10]
                .stack
                .is_empty());
            client.send(0, ACCEPT_FDS, b"retry", &[], false);
            let (_, request) = service.transaction();
            service.send(0, 0, b"ok", &[], true);
            service.free(&request);
            let (cmd, reply) = client.transaction();
            assert_eq!(cmd, BR_REPLY);
            assert_eq!(client.payload(&reply), b"ok");
            client.free(&reply);
        }
    }
}
#[test]
fn synchronous_call_reply_and_original_buffer_reuse() {
    let root = Vfs::default();
    let mut service = Client::new(&root, 10, b"/dev/binder");
    service.manager();
    let mut client = Client::new(&root, 20, b"/dev/binder");
    for _ in 0..64 {
        client.send(0, ACCEPT_FDS, b"request", &[], false);
        let (cmd, request) = service.transaction();
        assert_eq!(cmd, BR_TRANSACTION);
        assert_eq!(service.payload(&request), b"request");
        assert_eq!(dword(&request, 24), 20);
        assert_eq!(dword(&request, 16), 42);
        service.send(0, 0, b"reply", &[], true);
        service.free(&request);
        let (cmd, reply) = client.transaction();
        assert_eq!(cmd, BR_REPLY);
        assert_eq!(client.payload(&reply), b"reply");
        client.free(&reply);
        assert!(client.process().state.lock().unwrap().threads[&20]
            .stack
            .is_empty());
        assert!(service.process().state.lock().unwrap().threads[&10]
            .stack
            .is_empty());
    }
}
#[test]
fn nested_callback_uses_waiting_caller_without_a_second_cpu_slot() {
    let root = Vfs::default();
    let mut a = Client::new(&root, 10, b"/dev/binder");
    let mut b = Client::new(&root, 20, b"/dev/binder");
    b.manager();
    a.send(
        0,
        ACCEPT_FDS,
        &flat(TYPE_BINDER, 0x1110, 0x2220),
        &[0],
        false,
    );
    let (_, request) = b.transaction();
    let object = b.payload(&request);
    assert_eq!(dword(&object, 0), TYPE_HANDLE);
    let handle = dword(&object, 8);
    b.write(&command(ACQUIRE, &handle.to_le_bytes()));
    b.send(handle, 0, b"callback", &[], false);
    let (cmd, callback) = a.transaction();
    assert_eq!(cmd, BR_TRANSACTION);
    assert_eq!(word(&callback, 0), 0x1110);
    assert_eq!(a.payload(&callback), b"callback");
    a.send(0, 0, b"nested reply", &[], true);
    a.free(&callback);
    let (cmd, reply) = b.transaction();
    assert_eq!(cmd, BR_REPLY);
    assert_eq!(b.payload(&reply), b"nested reply");
    b.free(&reply);
    b.send(0, 0, b"outer reply", &[], true);
    b.free(&request);
    let (cmd, reply) = a.transaction();
    assert_eq!(cmd, BR_REPLY);
    a.free(&reply);
    assert!(a.process().state.lock().unwrap().threads[&10]
        .stack
        .is_empty());
    assert!(b.process().state.lock().unwrap().threads[&20]
        .stack
        .is_empty());
}
#[test]
fn one_way_order_waits_for_buffer_free_but_other_nodes_progress() {
    let root = Vfs::default();
    let mut a = Client::new(&root, 10, b"/dev/binder");
    let mut b = Client::new(&root, 20, b"/dev/binder");
    b.manager();
    a.send(0, ONE_WAY, b"one", &[], false);
    a.send(0, ONE_WAY, b"two", &[], false);
    let (_, one) = b.transaction();
    assert_eq!(b.payload(&one), b"one");
    assert!(b.receive().is_none());
    b.free(&one);
    let (_, two) = b.transaction();
    assert_eq!(b.payload(&two), b"two");
    b.free(&two);
    let other = b.process().owned_node(0x8880, 0x9990, 0x100, 20).unwrap();
    let reference = a.process().reference(other, 1).unwrap();
    a.send(0, ONE_WAY, b"held", &[], false);
    let (_, held) = b.transaction();
    a.send(reference.handle, ONE_WAY, b"independent", &[], false);
    let (_, independent) = b.transaction();
    assert_eq!(b.payload(&independent), b"independent");
    b.free(&independent);
    b.free(&held);
}
#[test]
fn transferred_fd_retains_ofd_across_close_reuse_and_is_cloexec() {
    let root = Vfs::default();
    let mut a = Client::new(&root, 10, b"/dev/binder");
    let mut b = Client::new(&root, 20, b"/dev/binder");
    b.manager();
    let fd = a.vfs.memfd_create(b"binder-data", 3).unwrap();
    a.vfs.write(fd, b"shared").unwrap();
    a.vfs.seek(fd, 0, 0).unwrap();
    a.send(0, ONE_WAY, &flat(TYPE_FD, fd as u64, 0), &[0], false);
    a.vfs.close(fd).unwrap();
    assert_eq!(a.vfs.eventfd(99, 0).unwrap(), fd);
    let (_, header) = b.transaction();
    let received = dword(&b.payload(&header), 8);
    assert_eq!(b.vfs.read(received, 6).unwrap(), b"shared");
    assert!(b.vfs.descriptor(received).unwrap().cloexec.get());
    b.free(&header);
    assert_eq!(b.vfs.seek(received, 0, 0).unwrap(), 0); // flat FD survives free
}
#[test]
fn service_exit_wakes_sync_call_and_death_clear_ack_is_ordered() {
    let root = Vfs::default();
    let mut a = Client::new(&root, 10, b"/dev/binder");
    let mut b = Client::new(&root, 20, b"/dev/binder");
    b.manager();
    a.enter();
    a.write(&command(ACQUIRE, &0u32.to_le_bytes()));
    let mut notification = 0u32.to_le_bytes().to_vec();
    notification.extend_from_slice(&0x1234u64.to_le_bytes());
    a.write(&command(REQUEST_DEATH, &notification));
    a.send(0, 0, b"pending", &[], false);
    let (_, header) = b.transaction();
    b.vfs.binder_exit(20, true);
    let (cmd, _) = a.transaction();
    assert_eq!(cmd, BR_DEAD_REPLY);
    let events = a.receive().unwrap();
    assert!(events
        .iter()
        .any(|(cmd, data)| *cmd == BR_DEAD_BINDER && word(data, 0) == 0x1234));
    a.write(&command(CLEAR_DEATH, &notification));
    assert!(a.receive().is_none());
    a.write(&command(DEAD_DONE, &0x1234u64.to_le_bytes()));
    assert!(a
        .receive()
        .unwrap()
        .iter()
        .any(|(cmd, _)| *cmd == BR_CLEAR_DEATH));
    assert_eq!(b.process().check_owner(20), Err(Errno(111)));
    drop(header);
}
#[test]
fn malformed_offsets_do_not_publish_partial_fd_or_node_transfers() {
    let root = Vfs::default();
    let mut a = Client::new(&root, 10, b"/dev/binder");
    let mut b = Client::new(&root, 20, b"/dev/binder");
    b.manager();
    for offsets in [&[1u64][..], &[0, 0], &[24], &[u64::MAX]] {
        a.send(0, 0, &flat(TYPE_BINDER, 0x1110, 0x2220), offsets, false);
        let (cmd, _) = a.transaction();
        assert_eq!(cmd, BR_FAILED_REPLY);
        assert!(b.receive().is_none());
    }
    assert!(b.process().state.lock().unwrap().buffers.is_empty());
    assert!(b.process().state.lock().unwrap().handles.is_empty());
}
#[test]
fn partial_commands_publish_consumed_bytes_and_mapping_unmap_rejects_delivery() {
    let root = Vfs::default();
    let mut a = Client::new(&root, 10, b"/dev/binder");
    let mut b = Client::new(&root, 20, b"/dev/binder");
    b.manager();
    let mut commands = command(ENTER_LOOPER, &[]);
    commands.extend_from_slice(&FREE_BUFFER.to_le_bytes());
    assert!(matches!(a.start(&commands, 0), Err(Errno(22))));
    assert_eq!(a.memory.read_u64(0x1008).unwrap(), 4);
    b.memory.unmap(0x100000, 0x10000).unwrap();
    a.send(0, 0, b"unmapped", &[], false);
    assert_eq!(a.transaction().0, BR_DEAD_REPLY);
}
#[test]
fn fd_buffer_mapping_and_process_resources_are_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<Connection>();
    check::<SharedFd>();
    check::<Ioctl>();
}
#[test]
fn sg_parent_pointers_and_fd_arrays_use_original_shared_descriptions() {
    let root = Vfs::default();
    let mut a = Client::new(&root, 10, b"/dev/binder");
    let mut b = Client::new(&root, 20, b"/dev/binder");
    b.manager();
    let fd = a.vfs.eventfd(73, 0).unwrap();
    let mut parent = [0; 16];
    put32(&mut parent, 8, fd);
    a.memory.write(0x19000, &parent).unwrap();
    a.memory.write(0x1a000, b"childbuf").unwrap();
    let mut data = vec![0; 112];
    put32(&mut data, 0, TYPE_PTR);
    put(&mut data, 8, 0x19000);
    put(&mut data, 16, 16);
    put32(&mut data, 40, TYPE_PTR);
    put32(&mut data, 44, 1);
    put(&mut data, 48, 0x1a000);
    put(&mut data, 56, 8);
    put(&mut data, 64, 0);
    put(&mut data, 72, 0);
    put32(&mut data, 80, TYPE_FDA);
    put(&mut data, 88, 1);
    put(&mut data, 96, 0);
    put(&mut data, 104, 8);
    a.memory.write(0x10000, &data).unwrap();
    let offsets = [0u64, 40, 80];
    a.memory
        .write(
            0x18000,
            &offsets
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let mut header = [0; 72];
    put32(&mut header, 20, ONE_WAY);
    put(&mut header, 32, data.len() as u64);
    put(&mut header, 40, 24);
    put(&mut header, 48, 0x10000);
    put(&mut header, 56, 0x18000);
    put(&mut header, 64, 24);
    a.write(&command(TRANSACTION_SG, &header));
    let (_, received) = b.transaction();
    let payload = b.payload(&received);
    let parent = b.memory.read_array::<16>(word(&payload, 8)).unwrap();
    let child = word(&parent, 0);
    assert_eq!(child, word(&payload, 48));
    assert_eq!(b.memory.read_array::<8>(child).unwrap(), *b"childbuf");
    let received_fd = dword(&parent, 8);
    assert_eq!(b.vfs.read(received_fd, 8).unwrap(), 73u64.to_le_bytes());
    let alias = b.vfs.dup(received_fd, 0, false).unwrap();
    b.vfs.close(received_fd).unwrap();
    b.vfs.dup3(alias, received_fd, 0).unwrap();
    b.vfs.write(alias, &99u64.to_le_bytes()).unwrap();
    b.free(&received);
    assert_eq!(b.vfs.read(received_fd, 8).unwrap(), 99u64.to_le_bytes());
    a.write(&command(TRANSACTION_SG, &header));
    let (_, received) = b.transaction();
    let payload = b.payload(&received);
    let parent = b.memory.read_array::<16>(word(&payload, 8)).unwrap();
    let automatic = dword(&parent, 8);
    assert!(b.vfs.flags(automatic).is_ok());
    b.free(&received);
    assert_eq!(b.vfs.flags(automatic), Err(Errno(9)));
}
#[test]
fn racing_buffer_references_keep_handle_membership_and_node_events_ordered() {
    let root = Vfs::default();
    let mut owner = Client::new(&root, 1, b"/dev/binder");
    let receiver = Client::new(&root, 2, b"/dev/binder");
    let owner_process = owner.process();
    let receiver_process = receiver.process();
    let node = owner_process.owned_node(0x1110, 0x2220, 0x100, 1).unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let node = node.clone();
            let process = receiver_process.clone();
            scope.spawn(move || {
                for _ in 0..200 {
                    let reference = process.reference(node.clone(), 3).unwrap();
                    assert!(process.target(reference.handle).is_ok());
                    drop(BufferReference(reference, true));
                }
            });
        }
    });
    assert!(receiver_process.state.lock().unwrap().handles.is_empty());
    let state = node.state.lock().unwrap();
    assert_eq!((state.strong, state.weak), (0, 0));
    drop(state);
    let mut strong = false;
    let mut weak = false;
    while let Some(records) = owner.receive() {
        for (cmd, _) in records {
            match cmd {
                BR_INCREFS => {
                    assert!(!weak);
                    weak = true;
                }
                BR_ACQUIRE => {
                    assert!(weak && !strong);
                    strong = true;
                }
                BR_RELEASE => {
                    assert!(strong);
                    strong = false;
                }
                BR_DECREFS => {
                    assert!(weak && !strong);
                    weak = false;
                }
                _ => {}
            }
        }
    }
    assert!(!weak && !strong);
}
#[test]
fn failed_fd_import_reclaims_async_slot_and_signal_cancellation_keeps_write_effects() {
    let root = Vfs::default();
    let mut a = Client::new(&root, 10, b"/dev/binder");
    let mut b = Client::new(&root, 20, b"/dev/binder");
    b.manager();
    let fd = a.vfs.eventfd(1, 0).unwrap();
    b.vfs.set_descriptor_limit(4);
    a.send(0, ONE_WAY, &flat(TYPE_FD, fd as u64, 0), &[0], false);
    let mut request = b.start(&[], 4096).unwrap();
    assert_eq!(request.finish(&mut b.memory), Err(Errno(24)));
    drop(request);
    b.vfs.set_descriptor_limit(32);
    a.send(0, ONE_WAY, b"next", &[], false);
    let (_, received) = b.transaction();
    assert_eq!(b.payload(&received), b"next");
    b.free(&received);
    let mut waiting = b.start(&[], 4096).unwrap();
    assert_eq!(waiting.finish(&mut b.memory), Ok(None));
    drop(waiting);
    assert!(!b.process().state.lock().unwrap().threads[&20].waiting);
    a.send(0, 0, b"original", &[], false);
    let (_, received) = b.transaction();
    b.send(0, 0, b"answer", &[], true);
    b.free(&received);
    let (_, reply) = a.transaction();
    assert_eq!(a.payload(&reply), b"answer");
    a.free(&reply);
}
