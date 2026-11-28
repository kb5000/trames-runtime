// SPDX-License-Identifier: GPL-3.0-or-later
use trames_engine::{Cpu as Backend,SliceOutcome};
use trames_memory::{Memory,Permissions,PAGE_SIZE};
#[test]
fn common_linux_vdso_executes_with_both_software_backends_in_one_counter_domain() {
    check::<trames_jit::Cpu>();check::<trames_interpreter::Cpu>();
}
fn check<C:Backend>() {
    let sample=C::clock_sample().expect("ARM64 Linux counter ABI");
    eprintln!("backend={} counter_frequency={}",std::any::type_name::<C>(),sample.frequency);
    let mut m=Memory::default();
    m.map(0x1000,PAGE_SIZE,Permissions::RW).unwrap();
    m.write_array(0x1000,0xd4000001u32.to_le_bytes()).unwrap();
    m.protect(0x1000,PAGE_SIZE,Permissions::RX).unwrap();
    m.map(0x2000,PAGE_SIZE,Permissions::RW).unwrap();
    let base=trames_linux::vdso::install(&mut m).unwrap();
    trames_linux::vdso::initialize(&mut m,base,trames_linux::vdso::TimeBase{counter:sample.ticks,frequency:sample.frequency,seconds:123,nanos:450_000_000}).unwrap();
    let mut c=C::new(base+0x600,0x2ff0);let mut e=C::Engine::default();
    for clock in [1,4,6] {
        c.set_pc(base+0x600);c.set_x(0,clock);c.set_x(1,0x2000);c.set_x(30,0x1000);
        let before=trames_interpreter::counter::read();
        assert!(matches!(c.run(&mut e,&mut m,1024),SliceOutcome::Syscall{..}));
        let after=trames_interpreter::counter::read();
        assert_eq!(c.pc(),0x1004);assert_eq!(c.x(0),0);
        let seconds=u64::from_le_bytes(m.read_array::<8>(0x2000).unwrap());
        let nanos=u64::from_le_bytes(m.read_array::<8>(0x2008).unwrap());
        let actual=seconds as u128*1_000_000_000+nanos as u128;
        let convert=|ticks:u64|123_450_000_000u128+(ticks-sample.ticks) as u128*1_000_000_000/sample.frequency as u128;
        assert!((convert(before)..=convert(after)).contains(&actual),"{actual} not bracketed by {}..{}",convert(before),convert(after));
    }
}
