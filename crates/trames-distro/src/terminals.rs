// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared host PTY masters for iPad and Mac. Shells use the image's original binaries.
//! The init pipe is private: children inherit only their slave, never a master.
pub const QUEUE_LIMIT: usize = 65536;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use trames_vfs::{Vfs, AT_FDCWD, O_CLOEXEC, O_NONBLOCK};

// Monitor mode prevents ash's asynchronous children inheriting ignored SIGINT.
// The private console enables normal job control. setsid then opens the slave
// in its own session. Retry interrupted reads when a launcher child exits.
pub const INIT: &str = "set -m; trap '' CHLD; while :; do if IFS= read -r tty <&3; then setsid /bin/sh -c 'exec /bin/sh -il <\"$1\" >\"$1\" 2>&1' sh \"$tty\" 3<&- & fi; done";
pub const LIMIT: usize = 32;
pub struct Channel {
    pub input: VecDeque<u8>,
    pub output: VecDeque<u8>,
    pub size: Option<(u16, u16)>,
    pub phase: &'static str,
    pub error: Option<String>,
}
impl Default for Channel {
    fn default() -> Self {
        Self {
            input: VecDeque::new(),
            output: VecDeque::new(),
            size: None,
            phase: "starting",
            error: None,
        }
    }
}
struct Master {
    fd: u32,
    pair: Arc<trames_vfs::Pty>,
}
pub struct NativeTerminals {
    vfs: Vfs,
    control: u32,
    masters: BTreeMap<u64, Master>,
}
impl NativeTerminals {
    pub fn new(root: &mut Vfs) -> Result<Self, String> {
        let [reader, writer] = root.pipe(0).map_err(|e| e.to_string())?;
        if reader != 3 {
            return Err("init control descriptor 3 is unavailable".into());
        }
        let mut vfs = root.clone();
        root.close(writer).map_err(|e| e.to_string())?;
        vfs.close(reader).map_err(|e| e.to_string())?;
        Ok(Self {
            vfs,
            control: writer,
            masters: BTreeMap::new(),
        })
    }
    pub fn for_systemd(root: &mut Vfs) -> Result<Self, String> {
        Self::for_systemd_launcher(root, INIT)
    }
    pub fn for_systemd_launcher(root: &mut Vfs, launcher: &str) -> Result<Self, String> {
        const FIFO: &[u8] = b"/run/trames-terminal-control";
        root.mknod_at(AT_FDCWD, FIFO, 0o10600, 0)
            .map_err(|e| e.to_string())?;
        let mut vfs = root.clone();
        let control = vfs
            .open_at(AT_FDCWD, FIFO, 2 | O_NONBLOCK | O_CLOEXEC, 0)
            .map_err(|e| e.to_string())?;
        // PID 1 closes inherited FDs. Its ordinary getty service opens this
        // per-boot FIFO instead, then runs the same multi-terminal launcher.
        let script = format!("exec 3</run/trames-terminal-control; {launcher}");
        let escaped = script
            .replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
            .replace('"', "\\\"")
            .replace('$', "$$")
            .replace('%', "%%");
        let unit = format!("[Service]\nExecStart=\nExecStart=/bin/sh -c \"{escaped}\"\n");
        crate::systemd::file(
            root,
            b"/run/systemd/system/console-getty.service.d/60-terminals.conf",
            unit.as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            vfs,
            control,
            masters: BTreeMap::new(),
        })
    }
    fn open(&mut self, rows: u16, columns: u16) -> Result<Master, String> {
        if self.masters.len() >= LIMIT {
            return Err("terminal limit reached".into());
        }
        let fd = self
            .vfs
            .open_at(AT_FDCWD, b"/dev/ptmx", 2 | O_NONBLOCK | O_CLOEXEC, 0)
            .map_err(|e| e.to_string())?;
        let result = (|| {
            let pair = self
                .vfs
                .pty(fd)
                .map_err(|e| e.to_string())?
                .ok_or("PTY master missing")?
                .pair
                .clone();
            pair.locked
                .store(false, std::sync::atomic::Ordering::Relaxed);
            pair.resize_from_host(rows, columns);
            let path = format!("/dev/pts/{}\n", pair.number);
            if self
                .vfs
                .write(self.control, path.as_bytes())
                .map_err(|e| e.to_string())?
                != path.len()
            {
                return Err("init control pipe full".into());
            }
            Ok(Master { fd, pair })
        })();
        if result.is_err() {
            let _ = self.vfs.close(fd);
        }
        result
    }
    pub fn subscribe(&self, signal: &Arc<trames_vfs::IoSignal>) -> Vec<trames_vfs::IoSubscription> {
        self.masters
            .values()
            .map(|master| master.pair.subscribe(signal))
            .collect()
    }
    pub fn pump(&mut self, channels: &mut BTreeMap<u64, Channel>) -> bool {
        let before = self.masters.len();
        for (&id, channel) in channels.iter_mut() {
            if !self.masters.contains_key(&id) && channel.phase == "starting" {
                let (rows, columns) = channel.size.take().unwrap_or((24, 80));
                match self.open(rows, columns) {
                    Ok(master) => {
                        self.masters.insert(id, master);
                    }
                    Err(error) => {
                        channel.phase = "failed";
                        channel.error = Some(error);
                    }
                }
            }
        }
        self.masters.retain(|id, master| {
            let Some(channel) = channels.get_mut(id) else {
                // A close can race init's queued open. Retain the master until
                // that slave has opened, preventing its path/number being reused
                // for another request while the old command is still queued.
                if master
                    .pair
                    .slaves
                    .load(std::sync::atomic::Ordering::Relaxed)
                    == 0
                    && master.pair.poll(true, 0) & 16 == 0
                {
                    return true;
                }
                let _ = self.vfs.close(master.fd);
                return false;
            };
            if master
                .pair
                .slaves
                .load(std::sync::atomic::Ordering::Relaxed)
                != 0
                && channel.phase == "starting"
            {
                channel.phase = "running";
            }
            if let Some((rows, columns)) = channel.size.take() {
                master.pair.resize_from_host(rows, columns);
            }
            if !channel.input.is_empty() {
                let bytes: Vec<_> = channel.input.iter().take(4096).copied().collect();
                if let Ok((count, signals)) = master.pair.master_write(&bytes) {
                    channel.input.drain(..count);
                    master.pair.queue_host_signals(signals);
                }
            }
            master.pair.flush_echo();
            let room = QUEUE_LIMIT - channel.output.len();
            if room != 0 {
                match master.pair.master_read(room) {
                    Ok(bytes) => channel.output.extend(bytes),
                    Err(e) if e.0 == 5 => {
                        channel.phase = "exited";
                    }
                    Err(e) if e.0 == 11 => {}
                    Err(e) => {
                        channel.phase = "failed";
                        channel.error = Some(e.to_string());
                    }
                }
            }
            true
        });
        self.masters.len() != before
    }
}

/// Quote actual argv values twice: once for the child shell, once for the launcher.
pub fn launcher(command: &[String]) -> String {
    launcher_at(command, None)
}
pub fn launcher_at(command: &[String], cwd: Option<&str>) -> String {
    fn quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
    let command = command
        .iter()
        .map(|s| quote(s))
        .collect::<Vec<_>>()
        .join(" ");
    let prefix = cwd
        .map(|cwd| format!("cd {} && ", quote(cwd)))
        .unwrap_or_default();
    let child = format!("{prefix}exec {command} <\"$1\" >\"$1\" 2>&1");
    format!("set -m; trap '' CHLD; while :; do if IFS= read -r tty <&3; then setsid /bin/sh -c {} sh \"$tty\" 3<&- & fi; done",quote(&child))
}
