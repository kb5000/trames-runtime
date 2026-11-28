// SPDX-License-Identifier: GPL-3.0-or-later
//! Matched finite CPU-only programs; the independent interpreter runs untimed
//! after each sample and checks the full architectural state.
use serde_json::json;
use std::time::Instant;
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_execution::Registers;
use trames_jit::{Cpu, Engine};
use trames_memory::{Memory, Permissions, PAGE_SIZE};

const CODE: u64 = 0x1000;
const TRIPS: u64 = 65536;
fn state() -> trames_execution::Aarch64State {
    let mut s = trames_execution::Aarch64State {pc:CODE,sp:0x2ff0,..Default::default()};
    for i in 0..32 {s.vectors[i]=(u128::MAX/33)*(i as u128+1);}
    s.registers[6]=0x839af23d903e6811;
    s
}
fn main() {
    const {assert!(trames_jit::NATIVE_COMPILED);}
    let caps=trames_jit::host_features().unwrap();
    assert_eq!(caps.hwcap & ((1<<10)|(1<<12)|(1<<14)|(1<<20)|(1<<23)),(1<<10)|(1<<12)|(1<<14)|(1<<20)|(1<<23));
    assert_eq!(caps.hwcap2 & ((1<<13)|(1<<14)),(1<<13)|(1<<14));
    for (name,sequence) in [
        ("widen-narrow",vec![0x0f0ba420,0x0e214800,0x0e220020,0x4f0c9c20]),
        ("indexed-arithmetic",vec![0x6f720820,0x6f724820,0x0f72b820,0x6f72d820]),
        ("reciprocal",vec![0x4ea1d820,0x4e20fc20,0x6ea1d820,0x4ea0fc20]),
        ("extension-arithmetic",vec![0x4e829420,0x4e82a420,0x6e42fc20,0x4e22ec20,0x6e82cc20,0x4e421420]),
        ("integer-control",vec![0x91000400]),
        ("fp-control",vec![0x1e612800]),
    ] {
        let body=sequence.iter().copied().cycle().take(28).collect::<Vec<u32>>();
        let mut words=body.clone();
        words.push(0xf1000442);
        let delta=-(words.len() as i32);
        words.push(0x54000001|(((delta as u32)&0x7ffff)<<5));
        words.push(0xd4000001);
        let logical=(body.len() as u64+2)*TRIPS+1;
        let mut memory=Memory::default();memory.map(CODE,PAGE_SIZE,Permissions::RW).unwrap();
        for (i,w) in words.iter().enumerate() {memory.write_array(CODE+4*i as u64,w.to_le_bytes()).unwrap();}
        memory.protect(CODE,PAGE_SIZE,Permissions::RX).unwrap();
        memory.map(0x10000,PAGE_SIZE,Permissions::RW).unwrap();
        memory.write(0x10000,&[0xa5;PAGE_SIZE as usize]).unwrap();
        let mut reference_memory=memory.clone();
        let mut c=Cpu::new(CODE,0); let mut r=trames_interpreter::Cpu::new(CODE,0);
        let mut initial=state();
        initial.registers[1]=0x10037;initial.registers[3]=0;initial.registers[5]=0;
        initial.vectors[21]=1f32.to_bits() as u128;initial.vectors[22]=0;
        if name=="reciprocal" {initial.vectors[1]=(1f32.to_bits() as u128)*0x00000001000000010000000100000001;}
        if name=="extension-arithmetic" {for r in 1..3 {initial.vectors[r]=0x3c003c003c003c003c003c003c003c00;}}
        if name=="fp-control" {initial.vectors[0]=0;initial.vectors[1]=1f64.to_bits() as u128;}
        c.restore_architectural_state(&initial);r.restore_architectural_state(&initial);
        let mut e=Engine::default(); let mut re=trames_interpreter::Engine::default();
        let mut samples=Vec::new();
        for sample in 0..6 {
            c.set_pc(CODE);c.set_x(2,TRIPS);r.pc=CODE;r.set_x(2,TRIPS);
            <Cpu as Backend>::begin_execution(&mut e).unwrap();
            let start=Instant::now();let out=c.run_slice(&mut e,&mut memory,16_777_216);
            let ns=start.elapsed().as_nanos();<Cpu as Backend>::finish_execution(&mut e);
            assert!(matches!(out,SliceOutcome::Syscall{instructions} if instructions==logical),"{name}: {out:?}");
            // Deliberately outside timing. Both variants execute identical
            // reference work after every sample; no reference work is counted.
            let expected=r.run_with_engine(&mut re,&mut reference_memory,16_777_216);
            assert!(matches!(expected,SliceOutcome::Syscall{instructions} if instructions==logical));
            assert_eq!(c.architectural_state(),r.architectural_state(),"{name}");
            assert_eq!(memory.read_array::<4096>(0x10000).unwrap(),reference_memory.read_array::<4096>(0x10000).unwrap());
            samples.push(json!({"warmup":sample==0,"ns":ns,"instructions":logical}));
        }
        for (i,w) in words.iter().enumerate() {assert_eq!(memory.fetch_u32(CODE+4*i as u64).unwrap(),*w);}
        let mut times=samples.iter().skip(1).map(|s|s["ns"].as_u64().unwrap()).collect::<Vec<_>>();times.sort_unstable();
        let s=c.architectural_state();let mem=e.memory_stats();
        println!("{}",json!({"workload":name,"words":words,"trips":TRIPS,"mode":"direct",
            "logical_guest_instructions":logical,"median_ns":times[2],"samples":samples,
            "registers":s.registers,"vectors":s.vectors.map(|v|format!("{v:032x}")),
            "pc":s.pc,"sp":s.sp,"nzcv":s.nzcv,"fpsr":s.fpsr,"fpcr":s.fpcr,
            "tls":s.tpidr_el0,"tls2":s.tpidr2_el0,"data":memory.read_array::<192>(0x10000).unwrap().to_vec(),
            "diagnostics":{"fallback":e.stats.fallback_instructions,"native":e.stats.native_instructions,
                "memory":mem.instructions,"staged":mem.staged,"entries":e.link_stats().entries}}));
    }
}
