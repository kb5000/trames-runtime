// SPDX-License-Identifier: GPL-3.0-or-later
//! Finite matched CPU workloads, not distro/syscall or bare-metal benchmarks.
use serde_json::json;
use std::{hint::black_box, time::Instant};
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_execution::Registers;
use trames_jit::{Cpu, Engine};
use trames_memory::{parallel::{Registry, View}, CpuMemory, Memory, Permissions, PAGE_SIZE};

const CODE: u64 = 0x1000;
const DATA: u64 = 0x10000;
const TRIPS: u64 = 1_048_576;
const ONES: u128 = 0x00000001000000010000000100000001;

fn main() {
    const { assert!(trames_jit::NATIVE_COMPILED); }
    for kind in 0..6 {
        let (name, words, width, stream) = match kind {
            0 => ("vector-i32-hot", vec![0x3dc00020,0x4ea38400,0x3d800020,0xf1000442,0x54ffff81,0xd4000001],16,false),
            1 => ("vector-f32-hot", vec![0x3dc00020,0x4e23d400,0x3d800020,0xf1000442,0x54ffff81,0xd4000001],16,false),
            2 => ("vector-pair-i32-hot", vec![0xad407c20,0x4ea38400,0x4ea387ff,0xad007c20,0xf1000442,0x54ffff61,0xd4000001],32,false),
            3 => ("vector-i32-stream-16m", vec![0x3dc00020,0x4ea38400,0x3c810420,0xf1000442,0x54ffff81,0xd4000001],16,true),
            4 => ("scalar-memory-control", vec![0xf9400020,0x91000400,0xf9000020,0xf1000442,0x54ffff81,0xd4000001],8,false),
            _ => ("fp-arithmetic-control", vec![0x1e612800,0xf1000442,0x54ffffc1,0xd4000001],0,false),
        };
        let logical = (words.len() as u64 - 1) * TRIPS + 1;
        let length = if stream {TRIPS * width} else {PAGE_SIZE};
        let mut m = Memory::default();
        m.map(CODE,PAGE_SIZE,Permissions::RW).unwrap();
        m.map(DATA,length,Permissions::RW).unwrap();
        m.write(DATA,&vec![0;length as usize]).unwrap();
        for (i,w) in words.iter().enumerate() {
            m.write_array(CODE+i as u64*4,u32::to_le_bytes(*w)).unwrap();
        }
        m.protect(CODE,PAGE_SIZE,Permissions::RX).unwrap();
        let mut cpu = Cpu::new(CODE,DATA+PAGE_SIZE-16);
        cpu.set_x(1,DATA);
        let mut state = cpu.architectural_state();
        state.vectors[3] = if kind==1 {(1f32.to_bits() as u128)*ONES} else {ONES};
        state.vectors[1] = 1f64.to_bits() as u128;
        cpu.restore_architectural_state(&state);
        let mut engine = Engine::default();
        let mut registry = Registry::default();
        let mut view = m.parallel_view(&mut registry).unwrap();
        // Sole actor, retained mm roots and no host bytes or mapping changes
        // until the view is dropped. Same worker-private contract in both builds.
        assert!(unsafe {View::try_private_epoch(&mut [&mut view])});
        let mut samples = Vec::new();
        for sample in 0..6 {
            cpu.set_pc(CODE);
            cpu.set_x(2,TRIPS);
            if stream {cpu.set_x(1,DATA);}
            let start = Instant::now();
            <Cpu as Backend>::begin_execution(&mut engine).unwrap();
            let out = cpu.run_parallel(&mut engine,&mut view,8_388_608);
            <Cpu as Backend>::finish_execution(&mut engine);
            let ns = start.elapsed().as_nanos();
            assert!(matches!(out,SliceOutcome::Syscall{instructions} if instructions==logical),"{name}: {out:?}");
            assert_eq!(cpu.pc(),CODE+words.len() as u64*4);
            assert_eq!(cpu.x(2),0);
            black_box(cpu.architectural_state());
            samples.push(json!({"warmup":sample==0,"ns":ns,"instructions":logical}));
        }
        let mut bytes = vec![0;length as usize];
        view.read(DATA,&mut bytes).unwrap();
        if kind<4 {
            let n = if stream {6} else {6*TRIPS};
            let expected = if kind==1 {((n as f32).to_bits() as u128)*ONES} else {(n as u128)*ONES};
            if stream {
                assert!(bytes.chunks_exact(16).all(|b| b==expected.to_le_bytes()));
                assert_eq!(cpu.x(1),DATA+length);
            } else {
                assert_eq!(&bytes[..16],&expected.to_le_bytes());
                if kind==2 {assert_eq!(&bytes[16..32],&expected.to_le_bytes());}
                assert!(bytes[width as usize..].iter().all(|b|*b==0));
            }
        } else if kind==4 {
            assert_eq!(&bytes[..8],&(6*TRIPS).to_le_bytes());
            assert!(bytes[8..].iter().all(|b|*b==0));
        } else {
            assert_eq!(cpu.architectural_state().vectors[0],(6.0*TRIPS as f64).to_bits() as u128);
            assert!(bytes.iter().all(|b|*b==0));
        }
        for (i,w) in words.iter().enumerate() {assert_eq!(view.fetch_u32(CODE+i as u64*4).unwrap(),*w);}
        let checksum=bytes.iter().fold(0xcbf29ce484222325u64,|h,b|(h^*b as u64).wrapping_mul(0x100000001b3));
        let mut committed=vec![0;bytes.len()];
        drop(view);
        m.commit_parallel().unwrap();
        m.read(DATA,&mut committed).unwrap();
        assert_eq!(bytes,committed);
        let mut times=samples.iter().skip(1).map(|s|s["ns"].as_u64().unwrap()).collect::<Vec<_>>();
        times.sort_unstable();
        let stats=engine.memory_stats();
        println!("{}",json!({"workload":name,"mode":"worker-private","trips":TRIPS,
            "words":words,"data_bytes":length,"checksum":checksum,"logical_guest_instructions":logical,
            "median_ns":times[2],"samples":samples,"final_x1":cpu.x(1),"final_pc":cpu.pc(),
            "vectors":cpu.architectural_state().vectors.map(|v|format!("{v:032x}")),
            "diagnostics":{"fallback":engine.stats.fallback_instructions,"memory":stats.instructions,
                "hardware":stats.hardware,"direct":stats.direct,"staged":stats.staged,
                "fused_entries":stats.fused_entries,"address_reuses":engine.compilation_stats().address_reuses}}));
    }
}
