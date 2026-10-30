// SPDX-License-Identifier: GPL-3.0-or-later
//! ELF, initial Linux stack, CPU slices, and syscall dispatch composition.
// Retained OFDs expand the worker graph checked by Rust's auto-trait solver.
#![recursion_limit = "256"]
use std::fmt;
use trames_elf::{ElfError, LoadedElf};
use trames_engine::{Cpu, CpuFault};
use trames_linux::{GuestOutput, Linux};
mod clock;
mod futex;
mod gpu;
mod process;
mod run_queue;
mod signal_actions;
mod terminal;
mod video;
mod worker_syscalls;
mod workers;
#[cfg(all(test, trames_interpreter_conformance))]
use trames_memory::Permissions;
use trames_memory::{Memory, MemoryError, DEFAULT_MEMORY_LIMIT, PAGE_SIZE};

/// Guest resident-page budgets. Untouched anonymous zeros/reservations have no
/// resident charge. File mappings and fork COW remain conservative; CLONE_VM
/// shares one accounting domain. Mapping metadata has its independent bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLimits {
    pub per_process: usize,
    pub total: usize,
}
impl Default for MemoryLimits {
    fn default() -> Self {
        Self {
            per_process: DEFAULT_MEMORY_LIMIT,
            total: 1024 * 1024 * 1024,
        }
    }
}
impl MemoryLimits {
    /// No product resident-byte quota: the guest architectural address ceiling
    /// bounds accounting arithmetic. The host adapter supplies physical memory
    /// reports and pressure reclamation. This allocates/reserves no RAM, does
    /// not raise independent descriptor limits, and changes no iPad defaults.
    pub const fn host_managed() -> Self {
        Self {
            per_process: trames_memory::ADDRESS_LIMIT as usize,
            total: trames_memory::ADDRESS_LIMIT as usize,
        }
    }
    pub fn is_host_managed(self) -> bool {
        self == Self::host_managed()
    }
    fn gpu_budget(self) -> trames_vulkan::Budget {
        if self.is_host_managed() {
            trames_vulkan::Budget::host_managed()
        } else {
            trames_vulkan::Budget::for_guest_memory(self.total)
        }
    }
    fn reported(
        self,
        used: usize,
        host: Option<trames_linux::HostMemoryInfo>,
    ) -> trames_linux::HostMemoryInfo {
        if self.is_host_managed() {
            let host = host.unwrap_or_default();
            return trames_linux::HostMemoryInfo {
                total: host.total,
                free: host.free.min(host.total),
                available: host.available.min(host.total),
            };
        }
        let free = self.total.saturating_sub(used);
        trames_linux::HostMemoryInfo {
            total: self.total,
            free,
            available: free,
        }
    }
    pub fn validate(self) -> Result<(), RuntimeError> {
        if self.per_process == 0
            || self.total < self.per_process
            || self.total as u64 > trames_memory::ADDRESS_LIMIT
            || !self.per_process.is_multiple_of(PAGE_SIZE as usize)
            || !self.total.is_multiple_of(PAGE_SIZE as usize)
        {
            return Err(RuntimeError::Configuration(
                "memory budgets must be positive page multiples, process <= total <= guest address space",
            ));
        }
        Ok(())
    }
}

#[derive(Default, Clone, Copy)]
pub struct RuntimeOptions {
    pub memory_limits: MemoryLimits,
    /// Explicit host opt-in to the bounded NativeCall v1 pure profile.
    pub pure_accelerator: bool,
    /// Experimental bsearch wrapper routing; default retains original musl.
    pub native_bsearch: bool,
    /// Experimental original-source allocator routing; default stays guest.
    pub native_allocator: bool,
    /// Experimental standard Vulkan ICD compute bridge; host opt-in only.
    pub vulkan_accelerator: bool,
    /// VideoToolbox-backed guest VA-API; independent of the GPU execution profile.
    pub video_accelerator: bool,
}

pub use trames_linux::image::{STACK_SIZE, STACK_TOP};
pub const DEFAULT_INSTRUCTION_LIMIT: u64 = 10_000_000;

#[derive(Debug)]
pub enum RuntimeError {
    Elf(ElfError),
    Memory(MemoryError),
    Arguments(&'static str),
    Configuration(&'static str),
    Cpu(CpuFault),
    Backend(String),
    BudgetExceeded(u64),
    Deadlock,
    Cancelled,
}
impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf(e) => e.fmt(f),
            Self::Memory(e) => e.fmt(f),
            Self::Cpu(e) => e.fmt(f),
            Self::Backend(e) => write!(f, "execution backend: {e}"),
            Self::Arguments(s) => write!(f, "initial stack: {s}"),
            Self::Configuration(s) => write!(f, "runtime configuration: {s}"),
            Self::BudgetExceeded(n) => write!(f, "guest instruction limit exceeded ({n})"),
            Self::Deadlock => write!(
                f,
                "all virtual processes are blocked without an event source"
            ),
            Self::Cancelled => write!(f, "session cancelled by its host"),
        }
    }
}
impl std::error::Error for RuntimeError {}
impl From<ElfError> for RuntimeError {
    fn from(e: ElfError) -> Self {
        Self::Elf(e)
    }
}
impl From<MemoryError> for RuntimeError {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}

pub use trames_vulkan::Display as VulkanDisplay;
pub struct Runtime<C: Cpu> {
    pub memory_limits: MemoryLimits,
    pub vulkan_display: VulkanDisplay,
    pub cpu: C,
    pub engine: C::Engine,
    pub memory: Memory,
    pub linux: Linux,
    pub terminal: Option<terminal::Terminal>,
    pub metrics: RuntimeMetrics,
    pub profile_syscalls: bool,
    /// Virtual CPU worker limit; 1 retains the existing local fast path.
    pub cpu_count: usize,
}
/// Host monotonic timings; these are diagnostics, never guest clock values.
#[derive(Default, Debug)]
pub struct RuntimeMetrics {
    pub instructions: u64,
    pub parallel_snapshots: trames_memory::parallel::Metrics,
    pub gpu_compiles: u64,
    pub gpu_peak_pending: usize,
    /// Sum over pending-call windows; overlapping waits may count retirement twice.
    pub gpu_peer_instructions: u64,
    pub gpu_wait_time: std::time::Duration,
    pub gpu_transfers: trames_vulkan::TransferMetrics,
    pub cpu_count: usize,
    pub parallel_rounds: u64,
    /// Pending calls returned at a whole-cohort join, collected only with
    /// profile_syscalls. Several pending calls can share one join; these are
    /// occurrences, not unique first-stop causes or worker-local completions.
    pub cohort_return_syscalls: std::collections::BTreeMap<u32, u64>,
    pub cohort_return_native: std::collections::BTreeMap<(u64, u64), u64>,
    /// Mapping checkpoint groups and actual address spaces quiesced locally.
    pub vm_checkpoint_groups: u64,
    pub vm_checkpoint_spaces: u64,
    /// Calls requiring an mm checkpoint: brk, munmap, mremap, mmap, mprotect,
    /// mincore, destructive madvise, advisory madvise. Counts are not pauses.
    pub vm_checkpoint_calls: [u64; 8],
    /// Group wall times: quiescence, owner queue, commit, syscalls, rebuild, resume, exclusive CPU.
    /// Disjoint groups can overlap, so summed durations are not session wall time.
    pub vm_checkpoint_time: [std::time::Duration; 7],
    /// Quiescence samples below 5/20/100/500/1000/2000/5000 us, then >=5000 us.
    pub vm_checkpoint_wait_bins: [u64; 8],
    /// Exclusive windows used, CPU runs, and extra mapping calls coalesced.
    pub vm_checkpoint_batch: [u64; 3],
    pub vm_local_syscalls: u64,
    /// Host control checks that retain the current jobs and translations.
    pub persistent_control_checks: u64,
    pub worker_slices: u64,
    /// Worker-local CPU slices, including polls and native returns; no messages
    /// or barriers are required between these slices.
    pub worker_chunks: u64,
    /// Completed on CPU workers without coordinator RPC; included in syscalls.
    pub worker_syscalls: u64,
    /// Worker-local shared-resource I/O; included in worker_syscalls, no RPC.
    pub worker_direct_syscalls: u64,
    /// Valid private/shared WAKE/WAKE_BITSET calls completed locally, including zero returns.
    pub worker_futex_wakes: u64,
    /// Tickets actually woken by local wake/requeue calls.
    pub worker_futex_woken: u64,
    /// Successful local REQUEUE/CMP_REQUEUE calls, including zero returns.
    pub worker_futex_requeues: u64,
    pub worker_futex_waits: u64,
    pub worker_task_resumes: u64,
    pub worker_task_yields: u64,
    pub worker_io_waits: u64,
    pub worker_service_waits: u64,
    pub worker_file_syscalls: u64,
    pub worker_socket_syscalls: u64,
    pub worker_timer_syscalls: u64,
    pub worker_poll_syscalls: u64,
    pub worker_uring_syscalls: u64,
    pub worker_fd_syscalls: u64,
    pub worker_gpu_calls: u64,
    pub worker_gpu_waits: u64,
    /// FD services requested while peer workers retain their running views.
    pub service_requests: u64,
    /// Host disk reads submitted during CPU epochs (not all guest reads).
    pub disk_reads: u64,
    pub peak_disk_reads: usize,
    pub disk_read_bytes: u64,
    /// Completed in-epoch services; also included in total syscalls.
    pub serviced_syscalls: u64,
    /// Summed parked caller time, excluded from worker CPU elapsed accounting.
    pub service_wait_time: std::time::Duration,
    /// Peak tracking is collected with profile_syscalls; parked RPC callers
    /// are excluded. Production avoids its shared counter updates.
    pub peak_parallel_cpus: usize,
    /// Global native-overlap instrumentation, collected with profile_syscalls.
    /// Production calls otherwise avoid its cross-worker atomic RMW operations.
    pub peak_parallel_native_calls: usize,
    pub parallel_memory_time: std::time::Duration,
    pub parallel_dispatch_time: std::time::Duration,
    /// Time to drain peers after the first exit or a requested timed checkpoint.
    pub parallel_stop_time: std::time::Duration,
    pub cpu_time: std::time::Duration,
    pub syscall_time: std::time::Duration,
    pub idle_time: std::time::Duration,
    pub syscalls: u64,
    pub proc_refreshes: u64,
    pub context_switches: u64,
    pub decode_lookups: u64,
    pub instructions_decoded: u64,
    pub decode_misses: u64,
    pub native: trames_accel::native::Metrics,
}
pub use terminal::Terminal;
#[derive(Debug, PartialEq, Eq)]
pub struct Exit {
    pub code: u8,
    pub instructions: u64,
}

#[cfg(all(test, trames_interpreter_conformance))]
fn initial_stack(
    elf: &mut LoadedElf,
    argv: &[String],
    envp: &[String],
) -> Result<u64, RuntimeError> {
    initial_stack_bytes::<trames_cpu::Cpu>(
        elf,
        &argv
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect::<Vec<_>>(),
        &envp
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect::<Vec<_>>(),
        &trames_vfs::Credentials::default(),
        RuntimeOptions::default(),
        None,
    )
}
fn initial_stack_bytes<C: Cpu>(
    elf: &mut LoadedElf,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    credentials: &trames_vfs::Credentials,
    options: RuntimeOptions,
    exec_filename: Option<&[u8]>,
) -> Result<u64, RuntimeError> {
    let mut extra = vec![
        (
            trames_video::AUXV_KEY,
            if options.video_accelerator {
                trames_video::PROFILE
            } else {
                0
            },
        ),
        (
            trames_vulkan::AUXV_KEY,
            if options.vulkan_accelerator {
                trames_vulkan::PROFILE
            } else {
                0
            },
        ),
        (
            trames_accel::native::AUXV_KEY,
            if options.pure_accelerator {
                trames_accel::native::PROFILE
            } else {
                0
            },
        ),
        (
            trames_accel::native::FEATURES_AUXV_KEY,
            if options.pure_accelerator {
                trames_accel::native::FEATURES
            } else {
                0
            },
        ),
        (
            trames_accel::callbacks::AUXV_KEY,
            if options.pure_accelerator {
                trames_accel::callbacks::PROFILE
            } else {
                0
            },
        ),
        (
            trames_accel::callbacks::SEARCH_AUXV_KEY,
            u64::from(options.pure_accelerator && options.native_bsearch),
        ),
        (
            trames_accel::numeric::AUXV_KEY,
            if options.pure_accelerator {
                trames_accel::numeric::PROFILE
            } else {
                0
            },
        ),
        (
            trames_accel::integer::AUXV_KEY,
            if options.pure_accelerator {
                trames_accel::integer::PROFILE
            } else {
                0
            },
        ),
        (
            trames_accel::allocator::AUXV_KEY,
            if options.pure_accelerator && options.native_allocator {
                trames_accel::allocator::PROFILE
            } else {
                0
            },
        ),
    ];
    if C::clock_sample().is_some() {
        let base = trames_linux::vdso::install(&mut elf.memory)?;
        extra.push((trames_linux::vdso::AUXV, base));
    }
    trames_linux::image::build_initial_stack(
        elf,
        argv,
        envp,
        credentials,
        C::features(),
        &extra,
        exec_filename,
    )
    .map_err(|error| match error {
        trames_linux::image::ImageError::Arguments(reason) => RuntimeError::Arguments(reason),
        trames_linux::image::ImageError::Memory(error) => RuntimeError::Memory(error),
    })
}

impl<C: Cpu> Runtime<C> {
    pub fn enable_terminal(&mut self, terminal: Terminal) -> Result<(), trames_vfs::Errno> {
        self.linux.vfs.enable_terminal()?;
        self.terminal = Some(terminal);
        Ok(())
    }
    pub(crate) fn load_guest(
        bytes: &[u8],
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
        vfs: &trames_vfs::Vfs,
        options: RuntimeOptions,
    ) -> Result<Self, RuntimeError> {
        Self::load_guest_execfn(bytes, argv, envp, vfs, options, None)
    }
    pub(crate) fn load_guest_execfn(
        bytes: &[u8],
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
        vfs: &trames_vfs::Vfs,
        options: RuntimeOptions,
        exec_filename: Option<&[u8]>,
    ) -> Result<Self, RuntimeError> {
        options.memory_limits.validate()?;
        if options.video_accelerator {
            vfs.enable_video_device();
        }
        let mut elf =
            trames_elf::load_with_interpreter(bytes, options.memory_limits.per_process, |path| {
                vfs.executable(path).map_err(|e| ElfError::Interpreter(e.0))
            })?;
        let mut linux = Linux::new(elf.brk_base);
        linux.arguments = argv.to_vec();
        linux.environment = envp.to_vec();
        linux.executable_path = argv.first().cloned().unwrap_or_default();
        linux.command_name = linux
            .executable_path
            .rsplit(|b| *b == b'/')
            .next()
            .unwrap_or_default()
            .iter()
            .copied()
            .take(15)
            .collect();
        if exec_filename.is_none() {
            if let Ok(file) =
                vfs.executable_file_at(trames_vfs::AT_FDCWD, &linux.executable_path, 0)
            {
                linux.executable_path = vfs.executable_display(&file);
                linux.executable_file = Some(file);
            } else if let Ok(path) = vfs.resolve(trames_vfs::AT_FDCWD, &linux.executable_path) {
                linux.executable_path = path.into_bytes();
            }
        }
        let sp = initial_stack_bytes::<C>(
            &mut elf,
            argv,
            envp,
            &vfs.credentials,
            options,
            exec_filename,
        )?;
        for i in 0..argv.len() {
            linux
                .argument_pointers
                .push(elf.memory.read_u64(sp + 8 + i as u64 * 8)?);
        }
        let mut aux = sp + 8 * (2 + argv.len() + envp.len() + 1) as u64;
        loop {
            let key = elf.memory.read_u64(aux)?;
            let value = elf.memory.read_u64(aux + 8)?;
            linux.auxiliary.extend(key.to_le_bytes());
            linux.auxiliary.extend(value.to_le_bytes());
            aux += 16;
            if key == 0 {
                break;
            }
        }
        let mut cpu = C::new(elf.start_entry, sp);
        cpu.set_native_calls(options.pure_accelerator);
        cpu.set_vulkan_calls(options.vulkan_accelerator);
        cpu.set_video_calls(options.video_accelerator);
        Ok(Self {
            memory_limits: options.memory_limits,
            vulkan_display: VulkanDisplay::default(),
            cpu,
            engine: Default::default(),
            memory: elf.memory,
            linux,
            terminal: None,
            metrics: RuntimeMetrics::default(),
            profile_syscalls: false,
            cpu_count: std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(if C::PARALLEL { 32 } else { 1 }),
        })
    }
    pub fn load(bytes: &[u8], argv: &[String], envp: &[String]) -> Result<Self, RuntimeError> {
        Self::load_with_vfs(bytes, argv, envp, trames_vfs::Vfs::default())
    }
    pub fn load_with_vfs(
        bytes: &[u8],
        argv: &[String],
        envp: &[String],
        vfs: trames_vfs::Vfs,
    ) -> Result<Self, RuntimeError> {
        Self::load_with_options(bytes, argv, envp, vfs, RuntimeOptions::default())
    }
    pub fn load_with_options(
        bytes: &[u8],
        argv: &[String],
        envp: &[String],
        vfs: trames_vfs::Vfs,
        options: RuntimeOptions,
    ) -> Result<Self, RuntimeError> {
        let argv: Vec<_> = argv.iter().map(|s| s.as_bytes().to_vec()).collect();
        let envp: Vec<_> = envp.iter().map(|s| s.as_bytes().to_vec()).collect();
        let mut runtime = Self::load_guest(bytes, &argv, &envp, &vfs, options)?;
        runtime.linux.vfs = vfs;
        Ok(runtime)
    }

    pub fn run(
        &mut self,
        output: &mut impl GuestOutput,
        instruction_limit: u64,
    ) -> Result<Exit, RuntimeError> {
        if !C::EXACT_INSTRUCTIONS && instruction_limit != u64::MAX {
            return Err(RuntimeError::Configuration(
                "exact instruction budgets are unavailable for this execution backend",
            ));
        }
        process::run(self, output, instruction_limit)
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Runtime = crate::Runtime<Cpu>;

    use super::*;
    #[test]
    fn host_managed_memory_selects_native_heap_accounting_without_changing_caps() {
        let host = MemoryLimits::host_managed().gpu_budget();
        assert_eq!(host.limit(), u64::MAX);
        assert_eq!(host.used(), 0);
        let bounded = MemoryLimits::default().gpu_budget();
        assert_eq!(bounded.limit(), 128 << 20);
        assert_eq!(bounded.used(), 0);
    }
    #[test]
    fn memory_budget_validation_accepts_large_limits_without_preallocation() {
        let limits = MemoryLimits {
            per_process: 2 << 30,
            total: 4 << 30,
        };
        limits.validate().unwrap();
        let memory = Memory::new(limits.per_process);
        assert_eq!(memory.limit(), 2 << 30);
        assert_eq!(memory.mapped_bytes(), 0);
        for limits in [
            MemoryLimits {
                per_process: 0,
                total: 4096,
            },
            MemoryLimits {
                per_process: 8192,
                total: 4096,
            },
            MemoryLimits {
                per_process: 4097,
                total: 8192,
            },
            MemoryLimits {
                per_process: 4096,
                total: 8193,
            },
            MemoryLimits {
                per_process: 4096,
                total: trames_memory::ADDRESS_LIMIT as usize + 4096,
            },
        ] {
            assert!(limits.validate().is_err());
        }
    }
    #[test]
    fn initial_session_retains_configured_task_capacity_when_linux_is_moved() {
        // getrlimit(RLIMIT_NPROC, 0x2000); exit_group(0).
        let words = [
            0xd28000c0u32,
            0xd2840001,
            0xd2801468,
            0xd4000001,
            0xd2800000,
            0xd2800bc8,
            0xd4000001,
        ];
        let mut memory = Memory::default();
        memory.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in words.into_iter().enumerate() {
            memory
                .write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut linux = Linux::new(0);
        linux.task_limit = 1024;
        let mut runtime = Runtime {
            memory_limits: MemoryLimits::default(),
            vulkan_display: VulkanDisplay::default(),
            cpu: Cpu::new(0x1000, 0),
            engine: Default::default(),
            memory,
            linux,
            terminal: None,
            metrics: RuntimeMetrics::default(),
            profile_syscalls: false,
            cpu_count: 1,
        };
        assert_eq!(
            runtime
                .run(&mut trames_linux::CapturedOutput::default(), 100)
                .unwrap()
                .code,
            0
        );
        assert_eq!(
            runtime.memory.read_array::<8>(0x2000).unwrap(),
            1024u64.to_le_bytes()
        );
    }
    #[test]
    fn virtual_devices_work_without_any_proc_access_or_snapshot_refresh() {
        // openat(AT_FDCWD,"/dev/zero",0); read(fd,path,8); exit(0)
        let words = [
            0x92800c60u32,
            0xd2800708,
            0xd4000001,
            0xd2800102,
            0xd28007e8,
            0xd4000001,
            0xd2800000,
            0xd2800ba8,
            0xd4000001,
        ];
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in words.iter().enumerate() {
            memory
                .write(0x1000 + i as u64 * 4, &word.to_le_bytes())
                .unwrap();
        }
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        memory.write(0x2100, b"/dev/zero\0").unwrap();
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.set_x(1, 0x2100);
        let mut runtime = Runtime {
            memory_limits: MemoryLimits::default(),
            cpu,
            engine: Default::default(),
            memory,
            linux: Linux::new(0),
            terminal: None,
            metrics: RuntimeMetrics::default(),
            profile_syscalls: false,
            cpu_count: 1,
            vulkan_display: VulkanDisplay::default(),
        };
        let exit = runtime
            .run(&mut trames_linux::CapturedOutput::default(), 100)
            .unwrap();
        assert_eq!(exit.code, 0);
        assert_eq!(runtime.memory.read_array::<8>(0x2100).unwrap(), [0; 8]);
        assert_eq!(runtime.metrics.proc_refreshes, 1); // initial mount setup only
    }
    fn elf() -> LoadedElf {
        LoadedElf {
            memory: Memory::default(),
            entry: 0x4000,
            phdr: Some(0x4040),
            phnum: 2,
            start_entry: 0x4000,
            interpreter_base: 0,
            brk_base: 0x5000,
        }
    }
    #[test]
    fn stack_layout_contains_argv_envp_auxv_and_aligned_sp() {
        let mut e = elf();
        let sp = initial_stack(
            &mut e,
            &["program".into(), "value".into()],
            &["KEY=1".into()],
        )
        .unwrap();
        assert_eq!(sp % 16, 0);
        assert_eq!(e.memory.read_u64(sp).unwrap(), 2);
        let arg0 = e.memory.read_u64(sp + 8).unwrap();
        let mut name = [0; 8];
        e.memory.read(arg0, &mut name).unwrap();
        assert_eq!(&name, b"program\0");
        let arg1 = e.memory.read_u64(sp + 16).unwrap();
        let env0 = e.memory.read_u64(sp + 32).unwrap();
        assert_eq!(arg1, arg0 + 8);
        assert_eq!(env0, arg1 + 6);
        assert_eq!(env0 + 6, STACK_TOP);
        assert_eq!(e.memory.read_u64(sp + 24).unwrap(), 0);
        assert_eq!(e.memory.read_u64(sp + 40).unwrap(), 0);
        assert_eq!(e.memory.read_u64(sp + 48).unwrap(), 6);
        assert_eq!(e.memory.read_u64(sp + 56).unwrap(), PAGE_SIZE);
        let mut capabilities = [None, None];
        for i in 0..32 {
            let key = e.memory.read_u64(sp + 48 + i * 16).unwrap();
            let value = e.memory.read_u64(sp + 56 + i * 16).unwrap();
            match key {
                16 => capabilities[0] = Some(value),
                26 => capabilities[1] = Some(value),
                0 => break,
                _ => {}
            }
        }
        assert_eq!(
            capabilities,
            [Some(trames_cpu::HWCAP), Some(trames_cpu::HWCAP2)]
        );
        // PAC, SVE and MTE are not advertised; BF16 has functional execution.
        assert_eq!(trames_cpu::HWCAP & ((1 << 22) | (1 << 30) | (1 << 31)), 0);
        assert_eq!(trames_cpu::HWCAP2 & (1 << 18), 0);
        assert_ne!(trames_cpu::HWCAP2 & (1 << 14), 0);
        assert!(e.memory.fetch_u32(sp).is_err());
        assert!(e.memory.read_u64(STACK_TOP - STACK_SIZE - 8).is_err());
    }
    #[test]
    fn argument_limits_and_nuls_fail() {
        assert!(initial_stack(&mut elf(), &[], &[]).is_err());
        assert!(initial_stack(&mut elf(), &["a\0b".into()], &[]).is_err());
        assert!(initial_stack(&mut elf(), &["x".repeat(STACK_SIZE as usize)], &[]).is_err());
    }
    #[test]
    fn endless_guest_is_bounded() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &0x14000000u32.to_le_bytes()).unwrap();
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut cpu = Cpu::default();
        cpu.pc = 0x1000;
        let mut runtime = Runtime {
            memory_limits: MemoryLimits::default(),
            cpu,
            engine: Default::default(),
            memory,
            linux: Linux::new(0x2000),
            terminal: None,
            metrics: RuntimeMetrics::default(),
            profile_syscalls: false,
            cpu_count: 1,
            vulkan_display: VulkanDisplay::default(),
        };
        let mut out = trames_linux::CapturedOutput::default();
        assert!(matches!(
            runtime.run(&mut out, 17),
            Err(RuntimeError::BudgetExceeded(17))
        ));
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod accelerator_tests {
    use super::*;
    type Runtime = crate::Runtime<trames_cpu::Cpu>;
    fn runtime(len: u64, permissions: Permissions) -> Runtime {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(0x2000, PAGE_SIZE, permissions).unwrap();
        let words = [
            0xd2800030u32,
            0xf2a00030,
            0xd2800071,
            trames_accel::native::INSTRUCTION,
            0xd65f03c0,
            0xd503201f,
            0xd503201f,
            0xd503201f,
            0xd2800000,
            0xd2800ba8,
            0xd4000001,
        ];
        for (i, word) in words.into_iter().enumerate() {
            memory
                .write(0x1000 + i as u64 * 4, &word.to_le_bytes())
                .unwrap();
        }
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut cpu = trames_cpu::Cpu::new(0x1000, 0x3000);
        cpu.set_native_calls(true);
        cpu.set_x(0, 0x2000);
        cpu.set_x(1, 0x91);
        cpu.set_x(2, len);
        cpu.set_x(19, 0xabcdef);
        cpu.set_x(30, 0x1020);
        cpu.tpidr_el0 = 0x9988;
        Runtime {
            memory_limits: MemoryLimits::default(),
            cpu,
            engine: Default::default(),
            memory,
            linux: Linux::new(0),
            terminal: None,
            metrics: RuntimeMetrics::default(),
            profile_syscalls: false,
            cpu_count: 1,
            vulkan_display: VulkanDisplay::default(),
        }
    }
    #[test]
    fn committed_call_retires_once_and_preserves_guest_context() {
        let mut r = runtime(32, Permissions::RW);
        let exit = r
            .run(&mut trames_linux::CapturedOutput::default(), 20)
            .unwrap();
        assert_eq!(
            exit,
            Exit {
                code: 0,
                instructions: 8
            }
        );
        assert_eq!(r.memory.read_array::<32>(0x2000).unwrap(), [0x91; 32]);
        assert_eq!(r.cpu.x(19), 0xabcdef);
        assert_eq!(r.cpu.sp, 0x3000);
        assert_eq!(r.cpu.tpidr_el0, 0x9988);
        assert_eq!(r.metrics.native.calls, 1);
    }
    #[test]
    fn budget_checkpoint_fallback_and_fault_do_not_fake_retirement() {
        let mut r = runtime(32, Permissions::RW);
        assert!(matches!(
            r.run(&mut trames_linux::CapturedOutput::default(), 3),
            Err(RuntimeError::BudgetExceeded(3))
        ));
        assert_eq!(r.metrics.native.calls, 0);
        assert_eq!(r.cpu.pc, 0x100c);
        assert_eq!(r.memory.read_array::<32>(0x2000).unwrap(), [0; 32]);
        let mut r = runtime(
            trames_accel::native::MAX_BULK_BYTES as u64 + 1,
            Permissions::R,
        );
        assert!(matches!(
            r.run(&mut trames_linux::CapturedOutput::default(), 4),
            Err(RuntimeError::BudgetExceeded(4))
        ));
        assert_eq!(r.metrics.native.fallbacks, 1);
        assert_eq!(r.cpu.pc, 0x1010);
        assert_eq!(r.cpu.x(0), 0x2000);
        assert_eq!(r.cpu.x(1), 1);
        let mut r = runtime(32, Permissions::R);
        let exit = r
            .run(&mut trames_linux::CapturedOutput::default(), 4)
            .unwrap();
        assert_eq!(
            exit,
            Exit {
                code: 139,
                instructions: 3
            }
        );
        assert_eq!(r.cpu.pc, 0x100c);
        assert_eq!(r.cpu.x(1), 0x91);
        assert_eq!(r.metrics.native.faults, 1);
    }
}

#[cfg(test)]
mod host_memory_reporting_tests {
    use super::*;
    use trames_linux::HostMemoryInfo;

    #[test]
    fn host_management_uses_host_reports_without_a_fixed_resident_pool() {
        let limits = MemoryLimits::host_managed();
        limits.validate().unwrap();
        assert!(limits.per_process > 24usize << 30);
        assert!(limits.is_host_managed());
        let sample = HostMemoryInfo {
            total: 24usize << 30,
            free: 3usize << 30,
            available: 8usize << 30,
        };
        assert_eq!(limits.reported(5usize << 30, Some(sample)), sample);
        assert_eq!(limits.reported(0, None), HostMemoryInfo::default());
    }
    #[test]
    fn explicit_budgets_ignore_host_capacity_and_keep_saturating_guest_availability() {
        let limits = MemoryLimits {
            per_process: 1usize << 30,
            total: 4usize << 30,
        };
        let host = HostMemoryInfo {
            total: 24usize << 30,
            free: 20usize << 30,
            available: 22usize << 30,
        };
        assert!(!limits.is_host_managed());
        assert_eq!(
            limits.reported(1usize << 30, Some(host)),
            HostMemoryInfo {
                total: 4usize << 30,
                free: 3usize << 30,
                available: 3usize << 30
            }
        );
        assert_eq!(limits.reported(5usize << 30, Some(host)).free, 0);
    }
}
