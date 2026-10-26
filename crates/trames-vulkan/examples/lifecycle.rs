// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual-driver regression; run after building the standard compute fixture.
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    thread,
    time::{Duration, Instant},
};
use trames_memory::{Memory, MemoryError, PageBacking, Permissions, PAGE_SIZE};
use trames_vulkan::{Backend, Invocation};

const PACKET: u64 = 0x1000;
const OUT: u64 = 0x2000;
const COUNT: u64 = 0x2080;
const RESULT: u64 = 0xa000;
struct FallibleOutput {
    fail: Cell<bool>,
    bytes: RefCell<[u8; PAGE_SIZE as usize]>,
}
impl PageBacking for FallibleOutput {
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        out.copy_from_slice(&self.bytes.borrow()[offset..offset + out.len()]);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.fail.get() {
            return Err(MemoryError::BackingIo(5));
        }
        self.bytes.borrow_mut()[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn version(&self) -> u64 {
        0
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}
fn request(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> Invocation {
    try_request(b, m, op, args).unwrap()
}
fn try_request(
    b: &mut Backend,
    m: &mut Memory,
    op: u64,
    args: &[u64],
) -> Result<Invocation, MemoryError> {
    let mut packet = [0; 128];
    for (i, value) in args.iter().enumerate() {
        packet[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    m.write(PACKET, &packet).unwrap();
    b.invoke(m, op, PACKET, 128)
}
fn complete(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) {
    assert_eq!(request(b, m, op, args), Invocation::Complete(0));
}
fn word(m: &Memory, address: u64) -> u64 {
    let mut bytes = [0; 8];
    m.read(address, &mut bytes).unwrap();
    u64::from_le_bytes(bytes)
}
fn words(m: &mut Memory, address: u64, values: &[u64]) {
    m.write(
        address,
        &values
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>(),
    )
    .unwrap();
}
fn start(b: &mut Backend, m: &mut Memory, device: u64, layout: u64, shader: u64) -> u64 {
    m.write(RESULT, &[0; 8]).unwrap();
    match request(
        b,
        m,
        27,
        &[device, layout, shader, 0x3300, RESULT, 0, 0, 0, 0],
    ) {
        Invocation::Pending(job) => job,
        other => panic!("expected native compile task, got {other:?}"),
    }
}
fn poll(b: &mut Backend, m: &mut Memory, job: u64) -> Result<u64, trames_memory::MemoryError> {
    let began = Instant::now();
    loop {
        match b.poll(m, job) {
            Ok(None) => {}
            Ok(Some(value)) => return Ok(value),
            Err(error) => return Err(error),
        }
        assert!(
            began.elapsed() < Duration::from_secs(30),
            "native pipeline did not complete"
        );
        thread::sleep(Duration::from_micros(50));
    }
}
fn main() {
    let code = std::fs::read(std::env::args().nth(1).expect("provide compute.spv")).unwrap();
    assert!(code.len() < 4 * PAGE_SIZE as usize);
    let mut m = Memory::new(128 << 10);
    m.map(0x1000, 8 * PAGE_SIZE, Permissions::RW).unwrap();
    let mut b = Backend::new();
    complete(&mut b, &mut m, 1, &[OUT]);
    let instance = word(&m, OUT);
    m.write(COUNT, &1u32.to_le_bytes()).unwrap();
    complete(&mut b, &mut m, 3, &[instance, COUNT, OUT]);
    let physical = word(&m, OUT);
    complete(&mut b, &mut m, 6, &[physical, COUNT, 0]);
    complete(&mut b, &mut m, 6, &[physical, COUNT, 0x2100]);
    let mut count = [0; 4];
    m.read(COUNT, &mut count).unwrap();
    let family = (0..u32::from_le_bytes(count))
        .find(|i| word(&m, 0x2100 + u64::from(*i) * 24) & 2 != 0)
        .unwrap();
    complete(&mut b, &mut m, 8, &[physical, u64::from(family), OUT]);
    let device = word(&m, OUT);
    m.write(0x4000, &code).unwrap();
    complete(
        &mut b,
        &mut m,
        21,
        &[device, 0x4000, code.len() as u64, OUT],
    );
    let shader = word(&m, OUT);
    words(&mut m, 0x3000, &[0, 7, 1, 0x20]);
    complete(&mut b, &mut m, 23, &[device, 0x3000, 1, OUT]);
    let descriptor = word(&m, OUT);
    words(&mut m, 0x3100, &[descriptor]);
    words(&mut m, 0x3200, &[0x20, 0, 4]);
    complete(&mut b, &mut m, 25, &[device, 0x3100, 1, 0x3200, 1, OUT]);
    let layout = word(&m, OUT);
    m.write(0x3300, b"main\0").unwrap();
    // Repeated output unmaps must neither publish IDs nor exhaust the finite
    // resource table. The compiler may finish at any point before polling.
    for _ in 0..260 {
        m.map(RESULT, PAGE_SIZE, Permissions::RW).unwrap();
        let job = start(&mut b, &mut m, device, layout, shader);
        m.unmap(RESULT, PAGE_SIZE).unwrap();
        assert!(poll(&mut b, &mut m, job).is_err());
        assert_eq!(b.poll(&mut m, job).unwrap(), Some((-4i64) as u64));
    }
    println!("260 live-output unmaps: faults, no ID publication/table exhaustion");
    let output = Rc::new(FallibleOutput {
        fail: Cell::new(false),
        bytes: RefCell::new([0; PAGE_SIZE as usize]),
    });
    m.map_backed(RESULT, vec![output.clone()], true, Permissions::RW, false)
        .unwrap();
    for _ in 0..260 {
        output.fail.set(false);
        let job = start(&mut b, &mut m, device, layout, shader);
        output.fail.set(true);
        assert_eq!(poll(&mut b, &mut m, job), Err(MemoryError::BackingIo(5)));
        assert_eq!(word(&m, RESULT), 0);
    }
    m.unmap(RESULT, PAGE_SIZE).unwrap();
    println!("260 post-preflight backing I/O failures: native outputs rolled back");
    m.map(RESULT, PAGE_SIZE, Permissions::RW).unwrap();
    if let (Some(vertex), Some(fragment)) = (std::env::args().nth(2), std::env::args().nth(3)) {
        graphics(&mut b, &mut m, device, &vertex, &fragment);
    }
    let job = start(&mut b, &mut m, device, layout, shader);
    // Host retention protects compilation even if a guest prematurely removes
    // its shader ID; this exercises the emulator boundary, not valid Vulkan use.
    complete(&mut b, &mut m, 22, &[device, shader]);
    assert_eq!(poll(&mut b, &mut m, job).unwrap(), 0);
    let pipeline = word(&m, RESULT);
    complete(&mut b, &mut m, 28, &[device, pipeline]);
    println!("in-flight shader removal: retained native dependency completes");
    m.write(0x4000, &code).unwrap();
    complete(
        &mut b,
        &mut m,
        21,
        &[device, 0x4000, code.len() as u64, OUT],
    );
    let shader = word(&m, OUT);
    let job = start(&mut b, &mut m, device, layout, shader);
    b.abandon(job);
    complete(&mut b, &mut m, 9, &[device]);
    assert_eq!(b.poll(&mut m, job).unwrap(), Some((-4i64) as u64));
    assert_eq!(word(&m, RESULT), 0);
    complete(&mut b, &mut m, 2, &[instance]);
    println!("abandoned compiler/device teardown: no result publication");
}

fn graphics(b: &mut Backend, m: &mut Memory, device: u64, vertex: &str, fragment: &str) {
    complete(b, m, 25, &[device, 0, 0, 0, 0, OUT]);
    let layout = word(m, OUT);
    let mut modules = Vec::new();
    for path in [vertex, fragment] {
        let code = std::fs::read(path).unwrap();
        assert!(code.len() < 4 * PAGE_SIZE as usize);
        m.write(0x4000, &code).unwrap();
        complete(b, m, 21, &[device, 0x4000, code.len() as u64, OUT]);
        modules.push(word(m, OUT));
    }
    complete(b, m, 66, &[device, 37, 1, 0, 0, 2, 0, 0, OUT]);
    let pass = word(m, OUT);
    words(m, 0x3400, &[pass, 3, 0, 0, 15]);
    let args = [
        device, layout, modules[0], modules[1], 0x3300, 0x3300, 0x3400, RESULT,
    ];
    words(m, 0x3600, &[0, 0]);
    for _ in 0..260 {
        m.write(RESULT, &[0; 8]).unwrap();
        let Invocation::Pending(job) = request(b, m, 70, &args) else {
            panic!("graphics must compile asynchronously")
        };
        m.unmap(RESULT, PAGE_SIZE).unwrap();
        assert!(poll(b, m, job).is_err());
        m.map(RESULT, PAGE_SIZE, Permissions::RW).unwrap();
    }
    println!("260 graphics output unmaps: no pipeline publication/table exhaustion");
    m.unmap(RESULT, PAGE_SIZE).unwrap();
    let output = Rc::new(FallibleOutput {
        fail: Cell::new(false),
        bytes: RefCell::new([0; PAGE_SIZE as usize]),
    });
    m.map_backed(RESULT, vec![output.clone()], true, Permissions::RW, false)
        .unwrap();
    for _ in 0..260 {
        output.fail.set(false);
        m.write(RESULT, &[0; 8]).unwrap();
        let Invocation::Pending(job) = request(b, m, 70, &args) else {
            panic!("graphics must compile asynchronously")
        };
        output.fail.set(true);
        assert_eq!(poll(b, m, job), Err(MemoryError::BackingIo(5)));
        assert_eq!(word(m, RESULT), 0);
        assert_eq!(
            try_request(b, m, 60, &[device, 37, 32, 32, 0x11, RESULT]),
            Err(MemoryError::BackingIo(5))
        );
        assert_eq!(
            try_request(b, m, 92, &[device, 0, 0, 0, 2, 2, 2, 0, 0x3600, RESULT]),
            Err(MemoryError::BackingIo(5))
        );
    }
    println!("260 graphics pipeline, 260 image and 260 sampler backing failures: unpublished native outputs rolled back");
    output.fail.set(false);
    m.unmap(RESULT, PAGE_SIZE).unwrap();
    m.map(RESULT, PAGE_SIZE, Permissions::RW).unwrap();
    m.write(RESULT, &[0; 8]).unwrap();
    let Invocation::Pending(job) = request(b, m, 70, &args) else {
        panic!("graphics must compile asynchronously")
    };
    // Defensive emulator boundary: retain native dependencies while a caller
    // violates Vulkan's required creation/destruction synchronization.
    complete(b, m, 67, &[device, pass]);
    for shader in modules {
        complete(b, m, 22, &[device, shader]);
    }
    assert_eq!(poll(b, m, job).unwrap(), 0);
    let pipeline = word(m, RESULT);
    complete(b, m, 28, &[device, pipeline]);
    complete(b, m, 26, &[device, layout]);
    println!("in-flight graphics pass/shader removal: dependencies retained until completion");
}
