// SPDX-License-Identifier: GPL-3.0-or-later
//! Protocol/resource regressions queued for the consolidated FUSE validation.
use super::*;
use trames_memory::{Access, CpuMemory, MemoryError, PageWait};

struct Faults<'a> {
    memory: &'a mut Memory,
    blocked: u64,
    write: bool,
    wait: Arc<PageWait>,
}
impl Faults<'_> {
    fn check_fault(
        &self,
        at: u64,
        len: usize,
        write: bool,
    ) -> std::result::Result<(), MemoryError> {
        if write == self.write
            && at < self.blocked + PAGE_SIZE
            && at.saturating_add(len as u64) > self.blocked
            && !self.wait.ready()
        {
            Err(self.wait.fault(at.max(self.blocked)))
        } else {
            Ok(())
        }
    }
}
impl CpuMemory for Faults<'_> {
    fn mapped_at_or_after(&self, address: u64) -> bool {
        self.memory.mapped_at_or_after(address)
    }
    fn async_faults_possible(&self) -> bool {
        true
    }
    fn read(&self, at: u64, bytes: &mut [u8]) -> std::result::Result<(), MemoryError> {
        self.check_fault(at, bytes.len(), false)?;
        self.memory.read(at, bytes)
    }
    fn write(&mut self, at: u64, bytes: &[u8]) -> std::result::Result<(), MemoryError> {
        self.check_fault(at, bytes.len(), true)?;
        self.memory.write(at, bytes)
    }
    fn check(&self, at: u64, len: usize, access: Access) -> std::result::Result<(), MemoryError> {
        self.memory.check(at, len, access)
    }
    fn check_translation(&self, at: u64) -> std::result::Result<(), MemoryError> {
        self.memory.check_translation(at)
    }
    fn fetch_u32(&self, at: u64) -> std::result::Result<u32, MemoryError> {
        self.memory.fetch_u32(at)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.memory.instruction_identity()
    }
    fn instruction_page_identity(
        &self,
        address: u64,
    ) -> std::result::Result<(u64, u64, u64), MemoryError> {
        self.memory.instruction_page_identity(address)
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> std::result::Result<T, MemoryError> {
        unreachable!("Binder copy")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> std::result::Result<u128, MemoryError> {
        unreachable!("Binder copy")
    }
    fn exclusive_write(
        &mut self,
        _: u64,
        _: &[u8],
        _: Option<u128>,
    ) -> std::result::Result<bool, MemoryError> {
        unreachable!("Binder copy")
    }
}
fn authority(client: &Client) -> (SharedFd, DescriptorFactory, u32) {
    (
        client.vfs.binder_file(client.fd).unwrap().unwrap(),
        client.vfs.descriptor_factory(),
        client.tid,
    )
}
fn start(
    (file, factory, tid): (SharedFd, DescriptorFactory, u32),
    cmd: u32,
    address: u64,
    memory: &mut impl CpuMemory,
) -> Ioctl {
    match Ioctl::start(file, factory, tid, cmd, address, memory).unwrap() {
        Started::Read(call) => call,
        Started::Complete(_) => panic!("expected the original retained copy"),
    }
}
fn header(memory: &mut Memory, address: u64, commands: u64, len: u64, capacity: u64, output: u64) {
    let mut bytes = [0; 48];
    put(&mut bytes, 0, len);
    put(&mut bytes, 16, commands);
    put(&mut bytes, 24, capacity);
    put(&mut bytes, 40, output);
    memory.write(address, &bytes).unwrap();
}

#[test]
fn input_fault_keeps_completed_commands_and_publishes_the_header_only_at_the_end() {
    let root = Vfs::default();
    let mut client = Client::new(&root, 10, b"/dev/binder");
    let process = client.process();
    process.state.lock().unwrap().requested_threads = 1;
    let mut commands = command(REGISTER_LOOPER, &[]);
    commands.extend_from_slice(&command(FREE_BUFFER, &0u64.to_le_bytes()));
    client.memory.write(0x1ff8, &commands).unwrap();
    header(
        &mut client.memory,
        0x1000,
        0x1ff8,
        commands.len() as u64,
        0,
        0,
    );
    let original = authority(&client);
    let mut memory = Faults {
        memory: &mut client.memory,
        blocked: 0x2000,
        write: false,
        wait: Arc::default(),
    };
    let mut call = start(original, WRITE_READ, 0x1000, &mut memory);
    assert!(call.take_fault().is_some());
    assert_eq!(process.state.lock().unwrap().requested_threads, 0);
    assert_eq!(
        memory.memory.read_u64(0x1008).unwrap(),
        0,
        "no intermediate header copy"
    );
    memory
        .memory
        .write_array(0x1ff8, 0xffff_ffffu32.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.finish(&mut memory), Ok(Some(0)));
    assert_eq!(
        memory.memory.read_u64(0x1008).unwrap(),
        commands.len() as u64
    );
    assert!(
        process
            .state
            .lock()
            .unwrap()
            .threads
            .get(&10)
            .unwrap()
            .registered
    );
}

#[test]
fn a_later_sg_fault_keeps_the_first_fd_and_payload_after_numeric_reuse() {
    let root = Vfs::default();
    let mut client = Client::new(&root, 10, b"/dev/binder");
    let mut service = Client::new(&root, 20, b"/dev/binder");
    service.manager();
    let fd = client.vfs.eventfd(73, 0).unwrap();
    let mut data = flat(TYPE_FD, fd as u64, 0);
    data.resize(64, 0);
    put32(&mut data, 24, TYPE_PTR);
    put(&mut data, 32, 0x1a000);
    put(&mut data, 40, 8);
    client.memory.write(0x10000, &data).unwrap();
    client
        .memory
        .write(
            0x18000,
            &[0u64, 24]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    client.memory.write(0x1a000, b"original").unwrap();
    let mut transaction = [0; 72];
    put32(&mut transaction, 20, ONE_WAY);
    put(&mut transaction, 32, 64);
    put(&mut transaction, 40, 16);
    put(&mut transaction, 48, 0x10000);
    put(&mut transaction, 56, 0x18000);
    put(&mut transaction, 64, 8);
    let commands = command(TRANSACTION_SG, &transaction);
    client.memory.write(0x2000, &commands).unwrap();
    header(
        &mut client.memory,
        0x1000,
        0x2000,
        commands.len() as u64,
        0,
        0,
    );
    let original = authority(&client);
    let mut memory = Faults {
        memory: &mut client.memory,
        blocked: 0x1a000,
        write: false,
        wait: Arc::default(),
    };
    let mut call = start(original, WRITE_READ, 0x1000, &mut memory);
    assert!(call.take_fault().is_some());
    client.vfs.close(fd).unwrap();
    assert_eq!(client.vfs.eventfd(999, 0).unwrap(), fd);
    memory
        .memory
        .write_array(0x10000, 0xffff_ffffu32.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.finish(&mut memory), Ok(Some(0)));
    let (_, received) = service.transaction();
    let payload = service.payload(&received);
    assert_eq!(
        service.vfs.read(dword(&payload, 8), 8).unwrap(),
        73u64.to_le_bytes()
    );
    assert_eq!(
        service.memory.read_array::<8>(word(&payload, 32)).unwrap(),
        *b"original"
    );
    service.free(&received);
}

#[test]
fn transaction_output_keeps_installed_fds_and_publishes_free_and_stack_after_copy() {
    let root = Vfs::default();
    let mut client = Client::new(&root, 10, b"/dev/binder");
    let mut service = Client::new(&root, 20, b"/dev/binder");
    service.manager();
    let fd = client.vfs.eventfd(73, 0).unwrap();
    client.send(0, ACCEPT_FDS, &flat(TYPE_FD, fd as u64, 0), &[0], false);
    header(&mut service.memory, 0x1000, 0, 0, 4096, 0x1fe0);
    let process = service.process();
    let original = authority(&service);
    let mut memory = Faults {
        memory: &mut service.memory,
        blocked: 0x2000,
        write: true,
        wait: Arc::default(),
    };
    let mut call = start(original, WRITE_READ, 0x1000, &mut memory);
    assert_eq!(call.finish(&mut memory), Ok(None));
    assert!(call.take_fault().is_some());
    let buffer = process
        .state
        .lock()
        .unwrap()
        .buffers
        .values()
        .next()
        .unwrap()
        .clone();
    let address = word(&buffer.header, 48);
    let installed = u32::from_le_bytes(memory.memory.read_array::<4>(address + 8).unwrap());
    assert!(!buffer.received.load(Ordering::Relaxed));
    assert_eq!(process.free_buffer(address), Err(Errno(22)));
    assert!(process
        .state
        .lock()
        .unwrap()
        .threads
        .get(&20)
        .unwrap()
        .stack
        .is_empty());
    memory.memory.write(0x1fe0, b"KEEP").unwrap();
    memory.wait.finish();
    assert_eq!(call.finish(&mut memory), Ok(Some(0)));
    assert_eq!(memory.memory.read_array::<4>(0x1fe0).unwrap(), *b"KEEP");
    assert_eq!(memory.memory.read_u64(0x1020).unwrap(), 72);
    assert_eq!(
        u32::from_le_bytes(memory.memory.read_array::<4>(address + 8).unwrap()),
        installed
    );
    assert!(buffer.received.load(Ordering::Relaxed));
    assert_eq!(
        process
            .state
            .lock()
            .unwrap()
            .threads
            .get(&20)
            .unwrap()
            .stack
            .len(),
        1
    );
    assert_eq!(service.vfs.read(installed, 8).unwrap(), 73u64.to_le_bytes());
}

#[test]
fn extended_error_clears_only_its_original_thread_once_and_retains_the_output_prefix() {
    let root = Vfs::default();
    let mut client = Client::new(&root, 10, b"/dev/binder");
    let process = client.process();
    {
        let mut state = process.state.lock().unwrap();
        state.threads.entry(10).or_default().error = (1, BR_FAILED_REPLY, -22);
        state.threads.entry(11).or_default().error = (7, BR_DEAD_REPLY, -3);
    }
    let original = authority(&client);
    let mut memory = Faults {
        memory: &mut client.memory,
        blocked: 0x2000,
        write: true,
        wait: Arc::default(),
    };
    let mut call = start(original, GET_EXTENDED_ERROR, 0x1ffe, &mut memory);
    assert!(call.take_fault().is_some());
    assert_eq!(
        process
            .state
            .lock()
            .unwrap()
            .threads
            .get(&10)
            .unwrap()
            .error,
        (0, BR_OK, 0)
    );
    process
        .state
        .lock()
        .unwrap()
        .threads
        .get_mut(&10)
        .unwrap()
        .error = (2, BR_DEAD_REPLY, -3);
    memory.memory.write(0x1ffe, b"XY").unwrap();
    memory.wait.finish();
    assert_eq!(call.finish(&mut memory), Ok(Some(0)));
    assert_eq!(memory.memory.read_array::<2>(0x1ffe).unwrap(), *b"XY");
    assert_eq!(
        u32::from_le_bytes(memory.memory.read_array::<4>(0x2002).unwrap()),
        BR_FAILED_REPLY
    );
    assert_eq!(
        u32::from_le_bytes(memory.memory.read_array::<4>(0x2006).unwrap()) as i32,
        -22
    );
    assert_eq!(
        process
            .state
            .lock()
            .unwrap()
            .threads
            .get(&10)
            .unwrap()
            .error,
        (2, BR_DEAD_REPLY, -3)
    );
    assert_eq!(
        process
            .state
            .lock()
            .unwrap()
            .threads
            .get(&11)
            .unwrap()
            .error,
        (7, BR_DEAD_REPLY, -3)
    );
}

#[test]
fn native_command_operands_can_extend_past_the_declared_write_length() {
    let root = Vfs::default();
    let mut client = Client::new(&root, 10, b"/dev/binder");
    client
        .memory
        .write(0x2000, &command(FREE_BUFFER, &0u64.to_le_bytes()))
        .unwrap();
    header(&mut client.memory, 0x1000, 0x2000, 4, 0, 0);
    let mut call = start(authority(&client), WRITE_READ, 0x1000, &mut client.memory);
    assert_eq!(call.finish(&mut client.memory), Ok(Some(0)));
    assert_eq!(client.memory.read_u64(0x1008).unwrap(), 12);
}
