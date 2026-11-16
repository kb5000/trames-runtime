// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-invocation device client. Blocking poll yields through the normal kernel.
use crate::{Backend, Error, Options, Result, MAX_FRAME, VERSION};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    sync::atomic::{AtomicI32, Ordering},
    time::{Duration, Instant},
};
static SIGNAL: AtomicI32 = AtomicI32::new(0);
extern "C" fn interrupted(signal: i32) {
    SIGNAL.store(signal, Ordering::Relaxed);
}
struct Signals(Vec<(i32, libc::sighandler_t)>);
impl Signals {
    fn install() -> Self {
        SIGNAL.store(0, Ordering::Relaxed);
        let mut old = vec![];
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGPIPE] {
            // SAFETY: a standalone command owns its process signal dispositions. The handler only stores an atomic flag.
            let handler = if signal == libc::SIGPIPE {
                libc::SIG_IGN
            } else {
                interrupted as *const () as libc::sighandler_t
            };
            old.push((signal, unsafe { libc::signal(signal, handler) }));
        }
        Self(old)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (s, h) in &self.0 {
            // SAFETY: restore the process dispositions captured above.
            unsafe { libc::signal(*s, *h) };
        }
    }
}
struct Device {
    file: File,
    buffer: Vec<u8>,
    deadline: Option<Instant>,
}
fn timeout(deadline: Option<Instant>) -> Result<i32> {
    match deadline {
        None => Ok(-1),
        Some(d) => {
            let left = d
                .checked_duration_since(Instant::now())
                .ok_or_else(|| Error::new("timeout", "Host operation timed out", 124))?;
            Ok(left.as_millis().max(1).min(i32::MAX as u128) as i32)
        }
    }
}
fn poll(fds: &mut [libc::pollfd], deadline: Option<Instant>) -> Result<()> {
    let n = unsafe {
        // SAFETY: the array remains initialized and writable for its stated length.
        libc::poll(
            fds.as_mut_ptr(),
            fds.len() as libc::nfds_t,
            timeout(deadline)?,
        )
    };
    if n < 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e.into());
        }
    } else if n == 0 {
        return Err(Error::new("timeout", "Host operation timed out", 124));
    }
    Ok(())
}
impl Device {
    fn open(name: &str, deadline: Option<Instant>) -> Result<Self> {
        if ![
            "info",
            "host-control",
            "host-exec",
            "clipboard",
            "file-transfer",
            "port-forward",
            "mount-control",
        ]
        .contains(&name)
        {
            return Err(Error::usage("Unknown control device"));
        }
        let path = format!("/dev/trames/{name}");
        let file=OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK).open(&path).map_err(|e|if e.kind()==io::ErrorKind::NotFound{Error::unavailable(format!("The command is installed, but {path} is missing")).hint("Check host interoperability settings; restart with an updated runtime when convenient.")}else{e.into()})?;
        Ok(Self {
            file,
            buffer: vec![],
            deadline,
        })
    }
    fn frame(id: u64, method: &str, params: Value) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(
            &json!({"version":VERSION,"id":id,"method":method,"params":params}),
        )?;
        bytes.push(b'\n');
        if bytes.len() > MAX_FRAME {
            return Err(Error::usage("Control request exceeds the host frame size"));
        }
        Ok(bytes)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let mut at = 0;
        while at < bytes.len() {
            let mut fd = [libc::pollfd {
                fd: self.file.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            }];
            poll(&mut fd, self.deadline)?;
            match self.file.write(&bytes[at..]) {
                Ok(0) => return Err(Error::unavailable("Control device closed while writing")),
                Ok(n) => at += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
    fn receive(&mut self) -> Result<Value> {
        loop {
            if let Some(v) = self.take_frame()? {
                return Ok(v);
            }
            let mut fd = [libc::pollfd {
                fd: self.file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            poll(&mut fd, self.deadline)?;
            self.read()?;
        }
    }
    fn read(&mut self) -> Result<()> {
        let mut bytes = [0; 4096];
        match self.file.read(&mut bytes) {
            Ok(0) => return Err(Error::unavailable("Control device closed before its reply")),
            Ok(n) => {
                self.buffer.extend_from_slice(&bytes[..n]);
                if self.buffer.len() > MAX_FRAME * 2 {
                    return Err(Error::unavailable("Invalid oversized control reply"));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
    fn take_frame(&mut self) -> Result<Option<Value>> {
        let Some(n) = self.buffer.iter().position(|&b| b == b'\n') else {
            if self.buffer.len() > MAX_FRAME {
                return Err(Error::unavailable("Control reply exceeds its frame size"));
            }
            return Ok(None);
        };
        if n >= MAX_FRAME {
            return Err(Error::unavailable("Control reply exceeds its frame size"));
        }
        let value = serde_json::from_slice(&self.buffer[..n])?;
        self.buffer.drain(..=n);
        Ok(Some(value))
    }
}
fn response(value: Value) -> Result<Value> {
    if let Some(error) = value.get("error") {
        let code = error["code"].as_str().unwrap_or("host_error");
        return Err(Error::new(
            code,
            error["message"].as_str().unwrap_or("Host operation failed"),
            match code {
                "permission_denied" => 77,
                "method_not_found" | "unsupported" => 69,
                "timeout" => 124,
                "cancelled" => 130,
                _ => 1,
            },
        ));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| Error::unavailable("Host reply has no result"))
}
#[derive(Default)]
pub struct Guest {
    info: Option<Value>,
    pub timeout: Option<Duration>,
}
impl Guest {
    fn require(&mut self, device: &str) -> Result<()> {
        if device == "info" {
            return Ok(());
        }
        let cap = match device {
            "host-control" => None,
            "host-exec" => Some("host-exec"),
            "clipboard" => Some("clipboard"),
            "file-transfer" => Some("files"),
            "port-forward" => Some("ports"),
            "mount-control" => Some("mounts"),
            _ => None,
        };
        if let Some(key) = cap {
            let info = self.info()?;
            let c = &info["capabilities"][key];
            if c["supported"] == false {
                return Err(Error::unavailable(format!(
                    "{key} is unsupported on this host"
                )));
            }
            if c["allowed"] == false {
                return Err(Error::denied(format!(
                    "{key} is not allowed for this environment"
                )));
            }
        }
        Ok(())
    }
}
impl Backend for Guest {
    fn configure(&mut self, o: &Options) {
        self.timeout = o.timeout;
    }
    fn info(&mut self) -> Result<Value> {
        if let Some(info) = &self.info {
            return Ok(info.clone());
        }
        let info = self.call("info", "session.info", json!({}))?;
        self.info = Some(info.clone());
        Ok(info)
    }
    fn call(&mut self, device: &str, method: &str, params: Value) -> Result<Value> {
        self.require(device)?;
        if method == "files.list" {
            if let Some(path) = params["path"].as_str() {
                let shares = self.call(device, method, json!({}))?;
                let path = if let Some(spec) = path.strip_prefix("share:") {
                    let (alias, relative) = spec.split_once('/').unwrap_or((spec, ""));
                    crate::copy::checked_relative(relative)?;
                    let share = shares["shares"]
                        .as_array()
                        .and_then(|rows| rows.iter().find(|s| s["alias"] == alias))
                        .ok_or_else(|| Error::denied("Unknown or restricted share"))?;
                    std::path::PathBuf::from(share["guest_path"].as_str().ok_or_else(||Error::unavailable("This Files provider only supports single-file copy; list its directory in the native Files app"))?).join(relative)
                } else {
                    std::path::PathBuf::from(path)
                };
                let mut entries = std::fs::read_dir(path)?
                    .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                entries.sort();
                return Ok(json!({"entries":entries}));
            }
        }
        let deadline = if matches!(method, "files.import" | "files.export") {
            self.timeout.map(|t| Instant::now() + t)
        } else {
            Some(Instant::now() + self.timeout.unwrap_or(Duration::from_secs(30)))
        };
        let mut fd = Device::open(device, deadline)?;
        fd.write(&Device::frame(1, method, params)?)?;
        response(fd.receive()?)
    }
    fn copy(&mut self, src: &str, dst: &str, o: &crate::copy::Options) -> Result<Value> {
        let shares = self.call("file-transfer", "files.list", json!({}))?;
        let provider = |text: &str| -> Result<Option<(String, String)>> {
            let Some(text) = text.strip_prefix("share:") else {
                return Ok(None);
            };
            let (alias, relative) = text.split_once('/').unwrap_or((text, ""));
            crate::copy::checked_relative(relative)?;
            let share = shares["shares"]
                .as_array()
                .and_then(|rows| {
                    rows.iter()
                        .find(|s| s["alias"] == alias || s["provider_id"] == alias)
                })
                .ok_or_else(|| Error::denied("Unknown or restricted share"))?;
            Ok(share["provider_id"]
                .as_str()
                .map(|id| (id.to_owned(), relative.to_owned())))
        };
        match (provider(src)?, provider(dst)?) {
            (Some((id, path)), None) | (None, Some((id, path))) => {
                if o.recursive || o.no_clobber || o.interactive {
                    return Err(Error::usage("This Files provider supports single-file transfers; -r/-n/-i are unavailable"));
                }
                let export = dst.starts_with("share:");
                let guest = if export { src } else { dst };
                if guest.starts_with("share:") {
                    return Err(Error::usage(
                        "Copy between a guest path and one Files provider",
                    ));
                }
                let guest = std::path::absolute(guest)?;
                self.call(
                    "file-transfer",
                    if export {
                        "files.export"
                    } else {
                        "files.import"
                    },
                    json!({"grant":id,"path":path,"guest":guest}),
                )
            }
            (Some(_), Some(_)) => Err(Error::usage("Files provider copies need one guest path")),
            (None, None) => crate::ui::copy_listed(&shares, src, dst, o),
        }
    }
    fn stream(
        &mut self,
        device: &str,
        method: &str,
        argv: &[String],
        o: &Options,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<u8> {
        self.timeout = o.timeout;
        self.require(device)?;
        let info = self.info()?;
        if info["features"]["exec_bytes"] != true || info["features"]["exec_stdin"] != true {
            return Err(Error::unavailable(
                "This runtime needs the updated host-command stream adapter",
            )
            .hint("Update Trames and restart this environment when convenient."));
        }
        let _signals = Signals::install();
        let deadline = o.timeout.map(|t| Instant::now() + t);
        let mut fd = Device::open(device, deadline)?;
        let mut outgoing = VecDeque::from(Device::frame(
            1,
            method,
            json!({"argv":argv,"encoding":"base64","stdin":true}),
        )?);
        let mut ready = false;
        let mut input = io::stdin();
        let mut input_open = true;
        let mut sent_eof = false;
        let mut in_flight = None;
        let mut next = 2u64;
        let mut cancel = false;
        loop {
            let signal = SIGNAL.swap(0, Ordering::Relaxed);
            if signal != 0 && !cancel {
                cancel = true;
                input_open = false;
                outgoing.extend(Device::frame(u64::MAX, "request.cancel", json!({"id":1}))?);
                fd.deadline = Some(Instant::now() + Duration::from_secs(2));
            }
            if ready && !input_open && !sent_eof && in_flight.is_none() && !cancel {
                let id = next;
                next += 1;
                outgoing.extend(Device::frame(id, "host.input", json!({"id":1,"eof":true}))?);
                in_flight = Some(id);
                sent_eof = true;
            }
            let mut fds = [
                libc::pollfd {
                    fd: fd.file.as_raw_fd(),
                    events: libc::POLLIN
                        | if outgoing.is_empty() {
                            0
                        } else {
                            libc::POLLOUT
                        },
                    revents: 0,
                },
                libc::pollfd {
                    fd: if ready
                        && input_open
                        && in_flight.is_none()
                        && outgoing.is_empty()
                        && !cancel
                    {
                        input.as_raw_fd()
                    } else {
                        -1
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            if let Err(e) = poll(&mut fds, fd.deadline) {
                return Err(if cancel {
                    Error::new("cancelled", "Host operation interrupted", 130)
                } else {
                    e
                });
            }
            if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                fd.read()?;
                while let Some(frame) = fd.take_frame()? {
                    let id = frame["id"].as_u64();
                    let result = match response(frame) {
                        Ok(v) => v,
                        Err(e) if id != Some(1) => {
                            input_open = false;
                            in_flight = None;
                            if o.verbose {
                                writeln!(err, "trames: input closed: {e}")?;
                            }
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    if id == in_flight {
                        in_flight = None;
                        if result["closed"] == true {
                            input_open = false;
                            sent_eof = true;
                        }
                    }
                    if id != Some(1) {
                        continue;
                    }
                    if result["ready"] == true {
                        ready = true;
                    }
                    for channel in ["stdout", "stderr"] {
                        let key = format!("{channel}_base64");
                        if let Some(data) = result[&key].as_str() {
                            if o.json {
                                writeln!(
                                    out,
                                    "{}",
                                    json!({"schema_version":1,"type":channel,"encoding":"base64","data":data})
                                )?;
                            } else {
                                let bytes = crate::decode(data)?;
                                if channel == "stdout" {
                                    out.write_all(&bytes)?;
                                    out.flush()?;
                                } else {
                                    err.write_all(&bytes)?;
                                    err.flush()?;
                                }
                            }
                        }
                    }
                    if result["done"] == true {
                        let code = result["exit_code"].as_i64().unwrap_or(1).clamp(0, 255) as u8;
                        if o.json {
                            writeln!(
                                out,
                                "{}",
                                json!({"schema_version":1,"type":"exit","exit_code":code})
                            )?;
                        }
                        return Ok(code);
                    }
                }
            }
            if fds[0].revents & libc::POLLOUT != 0 && !outgoing.is_empty() {
                match fd.file.write(outgoing.as_slices().0) {
                    Ok(0) => return Err(Error::unavailable("Control device closed")),
                    Ok(n) => {
                        outgoing.drain(..n);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                let mut bytes = [0; 8192];
                match input.read(&mut bytes) {
                    Ok(0) => input_open = false,
                    Ok(n) => {
                        let id = next;
                        next += 1;
                        outgoing.extend(Device::frame(
                            id,
                            "host.input",
                            json!({"id":1,"data":crate::encode(&bytes[..n])}),
                        )?);
                        in_flight = Some(id);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
}
