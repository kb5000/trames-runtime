// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{copy, envelope, Error, Result, CAPABILITIES};
use serde_json::{json, Value};
use std::{
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
    time::{Duration, Instant},
};
#[derive(Clone, Default)]
pub struct Options {
    pub json: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub timeout: Option<Duration>,
    pub chinese: bool,
}
impl Options {
    pub fn parse(args: &[String]) -> Result<(Self, Vec<String>)> {
        let chinese = std::env::var("TRAMES_LANGUAGE")
            .or_else(|_| std::env::var("LC_ALL"))
            .or_else(|_| std::env::var("LC_MESSAGES"))
            .or_else(|_| std::env::var("LANG"))
            .unwrap_or_default()
            .starts_with("zh");
        let mut o = Self {
            chinese,
            ..Self::default()
        };
        let mut rest = vec![];
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--" => {
                    rest.extend_from_slice(&args[i..]);
                    break;
                }
                "--json" => o.json = true,
                "--quiet" | "-q" => o.quiet = true,
                "--verbose" => o.verbose = true,
                "--no-color" => (),
                "--timeout" => {
                    i += 1;
                    let t = args
                        .get(i)
                        .ok_or_else(|| Error::usage("--timeout needs a duration"))?;
                    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
                    let n: u64 = t[..split]
                        .parse()
                        .map_err(|_| Error::usage("Invalid timeout"))?;
                    let ms = match &t[split..] {
                        "ms" => n,
                        "" | "s" => n
                            .checked_mul(1000)
                            .ok_or_else(|| Error::usage("Timeout overflow"))?,
                        "m" => n
                            .checked_mul(60000)
                            .ok_or_else(|| Error::usage("Timeout overflow"))?,
                        _ => return Err(Error::usage("Use a duration such as 30s, 2m or 500ms")),
                    };
                    if ms == 0 {
                        return Err(Error::usage("Timeout must be positive"));
                    }
                    o.timeout = Some(Duration::from_millis(ms));
                }
                _ => rest.push(args[i].clone()),
            }
            i += 1;
        }
        Ok((o, rest))
    }
    pub fn text<'a>(&self, en: &'a str, zh: &'a str) -> &'a str {
        if self.chinese {
            zh
        } else {
            en
        }
    }
}
pub trait Backend {
    fn configure(&mut self, _options: &Options) {}
    fn call(&mut self, device: &str, method: &str, params: Value) -> Result<Value>;
    fn info(&mut self) -> Result<Value> {
        self.call("info", "session.info", json!({}))
    }
    fn stream(
        &mut self,
        device: &str,
        method: &str,
        argv: &[String],
        options: &Options,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<u8>;
    fn permission(&mut self, args: &[String]) -> Result<Value> {
        if !args.is_empty() && args != ["show"] {
            return Err(Error::new(
                "read_only",
                "Guest permissions are read-only; change them on the host",
                77,
            ));
        }
        Ok(self.info()?["capabilities"].clone())
    }
    fn copy(&mut self, src: &str, dst: &str, o: &copy::Options) -> Result<Value> {
        copy_shared(self, src, dst, o)
    }
}
pub(crate) fn copy_shared<B: Backend + ?Sized>(
    backend: &mut B,
    src: &str,
    dst: &str,
    o: &copy::Options,
) -> Result<Value> {
    let shares = backend.call("file-transfer", "files.list", json!({}))?;
    copy_listed(&shares, src, dst, o)
}
pub(crate) fn copy_listed(
    shares: &Value,
    src: &str,
    dst: &str,
    o: &copy::Options,
) -> Result<Value> {
    let resolve = |path: &str| -> Result<PathBuf> {
        let Some(path) = path.strip_prefix("share:") else {
            return Ok(path.into());
        };
        let (alias, relative) = path.split_once('/').unwrap_or((path, ""));
        copy::checked_relative(relative)?;
        let share = shares["shares"]
            .as_array()
            .and_then(|v| v.iter().find(|s| s["alias"] == alias))
            .ok_or_else(|| {
                Error::denied(format!(
                    "Share '{alias}' is not available to this environment"
                ))
            })?;
        let root = share["guest_path"].as_str().ok_or_else(|| {
            Error::unavailable("This provider needs its native file transfer adapter")
        })?;
        Ok(PathBuf::from(root).join(relative))
    };
    let source = resolve(src)?;
    let dest = resolve(dst)?;
    Ok(json!({"bytes":copy::run(&source,&dest,o)?}))
}
const HELP:&str="Usage: trames COMMAND [OPTIONS]\n\nInspect\n  status                         Current environment and host connection\n  doctor                         Diagnose the injected command and control devices\n  permissions                    View effective permissions (guest is read-only)\n\nExchange\n  clipboard get | set [TEXT]      Clipboard text; set also reads piped stdin\n  files ls [PATH] | path SHARE    Authorized shares and files\n  files cp [-r] SOURCE DEST       Use share:NAME/PATH for host shares\n  mount ls | add SHARE TARGET | rm TARGET\n  port ls | publish HOST:GUEST | unpublish HOST\n\nHost actions\n  host cli -- ARGS...             Invoke permitted host Trames commands\n  host exec -- /PATH [ARG...]     Execute a host program, preserving its streams\n  host open URL | gui             Open a web URL or the host manager\n\nTools\n  completion bash|zsh|fish         Print shell completions\n  debug rpc DEVICE METHOD JSON   Inspect low-level controls\n\nOptions: --help, --version, --json, --quiet, --no-color, --timeout 30s\nExamples:\n  printf hello | trames clipboard set\n  trames files cp report.pdf share:project/report.pdf\n  trames host exec -- /usr/bin/uname -s\n";
const HELP_ZH:&str="用法：trames 命令 [选项]\n\n查看环境\n  status                         当前环境与宿主连接\n  doctor                         检查命令注入和控制设备\n  permissions                    查看有效权限（guest 只读）\n\n文件与共享\n  clipboard get | set [文本]      剪贴板；set 可读取管道输入\n  files ls [路径] | path 共享名   查看授权目录及文件\n  files cp [-r] 来源 目标         宿主共享路径：share:名称/路径\n  mount ls | add 共享名 目录 | rm 目录\n  port ls | publish 宿主端口:内部端口 | unpublish 宿主端口\n\n宿主操作\n  host cli -- 参数...             调用宿主 Trames\n  host exec -- /程序 [参数...]    执行宿主程序，保留标准流和退出码\n  host open URL | gui             打开网页或宿主管理器\n\n工具\n  completion bash|zsh|fish         输出补全脚本\n  debug rpc 设备 方法 JSON        底层控制诊断\n\n选项：--help、--version、--json、--quiet、--no-color、--timeout 30s\n示例：printf '你好' | trames clipboard set\n";
fn help(group: Option<&str>, o: &Options, out: &mut dyn Write) -> Result<()> {
    let text = o.text(HELP, HELP_ZH);
    if let Some(group) = group {
        let lines: Vec<_> = text
            .lines()
            .filter(|l| l.trim_start().starts_with(group))
            .collect();
        if !lines.is_empty() {
            writeln!(out, "{} trames {group}", o.text("Usage:", "用法："))?;
            for line in lines {
                writeln!(out, "{line}")?;
            }
            writeln!(
                out,
                "{}",
                o.text(
                    "Use --json for scripts. Permissions are managed on the host.",
                    "脚本可使用 --json；权限由宿主端管理。"
                )
            )?;
            return Ok(());
        }
    }
    out.write_all(text.as_bytes())?;
    Ok(())
}
fn arg<'a>(args: &'a [String], index: usize, message: &str) -> Result<&'a str> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| Error::usage(message))
}
fn flags(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}
fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}
fn port(text: &str) -> Result<u16> {
    text.parse()
        .ok()
        .filter(|n| *n != 0)
        .ok_or_else(|| Error::usage("Port must be in 1..65535"))
}
pub fn run(b: &mut dyn Backend, args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let parsed = Options::parse(args);
    let (o, args) = match parsed {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(err, "trames: {e}");
            return e.status;
        }
    };
    b.configure(&o);
    let command = args.iter().take(2).cloned().collect::<Vec<_>>().join(".");
    match execute(b, &args, &o, out, err) {
        Ok(code) => code,
        Err(e) => {
            if o.json {
                let _ = writeln!(out, "{}", envelope(&command, Err(&e)));
            } else {
                let msg = if o.chinese {
                    match e.code.as_str() {
                        "permission_denied" => "当前环境不允许此操作。",
                        "unavailable" | "protocol" => "此环境的宿主控制功能不可用。",
                        "timeout" => "操作超时。",
                        "cancelled" => "操作已取消。",
                        _ => &e.message,
                    }
                } else {
                    &e.message
                };
                let _ = writeln!(err, "trames: {msg}");
                if o.chinese && msg != e.message {
                    let _ = writeln!(err, "{}", e.message);
                }
                if let Some(hint) = e.hint {
                    let _ = writeln!(
                        err,
                        "{}",
                        if o.chinese {
                            "请在宿主端检查当前环境的互通权限；设置在下次启动时生效。"
                        } else {
                            &hint
                        }
                    );
                }
            }
            e.status
        }
    }
}
fn emit(
    out: &mut dyn Write,
    command: &str,
    data: Value,
    o: &Options,
    text: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<u8> {
    if o.json {
        writeln!(out, "{}", envelope(command, Ok(data)))?;
    } else {
        text(out)?;
    }
    Ok(0)
}
fn execute(
    b: &mut dyn Backend,
    args: &[String],
    o: &Options,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<u8> {
    if args.is_empty()
        || args[0] == "help"
        || args
            .iter()
            .take_while(|s| s.as_str() != "--")
            .any(|a| a == "--help" || a == "-h")
    {
        help(
            args.first().map(String::as_str).filter(|s| *s != "help"),
            o,
            out,
        )?;
        return Ok(0);
    }
    if matches!(args[0].as_str(), "--version" | "-V" | "version") {
        return emit(
            out,
            "version",
            json!({"version":env!("CARGO_PKG_VERSION"),"protocol":1}),
            o,
            |w| {
                writeln!(w, "Trames guest CLI {}", env!("CARGO_PKG_VERSION"))?;
                Ok(())
            },
        );
    }
    match args[0].as_str() {
        "status" | "info" => {
            let data = b.info()?;
            emit(out, "status", data.clone(), o, |w| {
                writeln!(
                    w,
                    "{}  {} ({})\n{}  {}\n{}  {}\n{}  {}",
                    o.text("Environment", "环境"),
                    data["environment"]["name"].as_str().unwrap_or("unknown"),
                    data["environment"]["type"].as_str().unwrap_or("linux"),
                    o.text("Host       ", "宿主"),
                    data["platform"].as_str().unwrap_or("unknown"),
                    o.text("Bridge     ", "连接"),
                    data["connection"].as_str().unwrap_or("ready"),
                    o.text("Network    ", "网络"),
                    data["network"].as_str().unwrap_or("unknown")
                )?;
                Ok(())
            })
        }
        "doctor" => {
            let data = b.info();
            let ok = data.is_ok();
            let report = match data {
                Ok(v) => json!({"connection":"ready","info":v}),
                Err(e) => json!({"connection":"unavailable","error":e.json()}),
            };
            emit(out, "doctor", report, o, |w| {
                writeln!(
                    w,
                    "{}",
                    if ok {
                        o.text("Control connection: ready", "宿主控制连接：正常")
                    } else {
                        o.text("Control connection: unavailable. The command is installed; check /dev/trames/info and restart with an updated runtime when convenient.","宿主控制连接不可用。命令已安装，请检查 /dev/trames/info，并在方便时使用新版运行时重启环境。")
                    }
                )?;
                Ok(())
            })?;
            Ok(if ok { 0 } else { 69 })
        }
        "permissions" => {
            let data = b.permission(&args[1..])?;
            emit(out, "permissions", data.clone(), o, |w| {
                for (key, title) in CAPABILITIES {
                    let v = &data[*key];
                    let state = if v["supported"] == false {
                        "unsupported"
                    } else if v["allowed"].as_bool().unwrap_or(false) {
                        "allowed"
                    } else {
                        "not allowed"
                    };
                    writeln!(
                        w,
                        "{title:<20} {}",
                        if o.chinese {
                            match state {
                                "unsupported" => "不支持",
                                "allowed" => "允许",
                                _ => "不允许",
                            }
                        } else {
                            state
                        }
                    )?;
                }
                Ok(())
            })
        }
        "clipboard" => match arg(args, 1, "Usage: trames clipboard get | set [TEXT]")? {
            "get" => {
                let data = b.call("clipboard", "clipboard.read", json!({}))?;
                emit(out, "clipboard.get", data.clone(), o, |w| {
                    w.write_all(data["text"].as_str().unwrap_or("").as_bytes())?;
                    Ok(())
                })
            }
            "set" => {
                let text = if args.len() == 3 {
                    args[2].clone()
                } else if args.len() == 2 && !io::stdin().is_terminal() {
                    let mut text = String::new();
                    io::stdin().take(16385).read_to_string(&mut text)?;
                    text
                } else {
                    return Err(Error::usage("Usage: printf 'text' | trames clipboard set; or trames clipboard set 'text'"));
                };
                if text.len() > 16384 {
                    return Err(Error::new(
                        "too_large",
                        "This host clipboard control accepts at most 16 KiB",
                        1,
                    ));
                }
                let data = b.call("clipboard", "clipboard.write", json!({"text":text}))?;
                emit(out, "clipboard.set", data, o, |_| Ok(()))
            }
            _ => Err(Error::usage("Usage: trames clipboard get | set [TEXT]")),
        },
        "files" => match args.get(1).map(String::as_str).unwrap_or("ls") {
            "ls" => {
                let data = b.call(
                    "file-transfer",
                    "files.list",
                    args.get(2).map_or(json!({}), |p| json!({"path":p})),
                )?;
                emit(out, "files.ls", data.clone(), o, |w| {
                    if let Some(shares) = data["shares"].as_array() {
                        for s in shares {
                            writeln!(
                                w,
                                "{:<20} {:<38} {}",
                                s["alias"].as_str().unwrap_or("?"),
                                s["guest_path"].as_str().unwrap_or("provider"),
                                if s["readonly"] == true {
                                    "read-only"
                                } else {
                                    "read/write"
                                }
                            )?;
                        }
                    } else if let Some(entries) = data["entries"].as_array() {
                        for entry in entries {
                            writeln!(w, "{}", entry.as_str().unwrap_or("?"))?;
                        }
                    } else {
                        writeln!(w, "{data}")?;
                    }
                    Ok(())
                })
            }
            "path" => {
                let name = arg(args, 2, "Usage: trames files path SHARE")?;
                let data = b.call("file-transfer", "files.list", json!({}))?;
                let s = data["shares"]
                    .as_array()
                    .and_then(|v| v.iter().find(|s| s["alias"] == name))
                    .ok_or_else(|| Error::denied("Unknown or restricted share"))?;
                let path = s["guest_path"].as_str().ok_or_else(|| {
                    Error::unavailable(
                        "This share uses a native provider instead of a visible mount",
                    )
                })?;
                emit(out, "files.path", json!({"path":path}), o, |w| {
                    writeln!(w, "{path}")?;
                    Ok(())
                })
            }
            "cp" => {
                let mut paths = vec![];
                let mut c = copy::Options {
                    deadline: o.timeout.map(|t| Instant::now() + t),
                    ..Default::default()
                };
                let mut literal = false;
                for a in &args[2..] {
                    if literal {
                        paths.push(a);
                        continue;
                    }
                    match a.as_str() {
                        "--" => literal = true,
                        "-r" | "-R" | "--recursive" => c.recursive = true,
                        "-n" | "--no-clobber" => c.no_clobber = true,
                        "-i" | "--interactive" => c.interactive = true,
                        a if a.starts_with('-') => {
                            return Err(Error::usage(format!("Unknown copy option: {a}")))
                        }
                        _ => paths.push(a),
                    }
                }
                if paths.len() != 2 {
                    return Err(Error::usage("Usage: trames files cp [-r] SOURCE DEST"));
                }
                let data = b.copy(paths[0], paths[1], &c)?;
                emit(out, "files.cp", data, o, |_| Ok(()))
            }
            _ => Err(Error::usage(
                "Usage: trames files ls | path SHARE | cp SOURCE DEST",
            )),
        },
        "mount" => {
            let op = arg(
                args,
                1,
                "Usage: trames mount ls | add SHARE TARGET | rm TARGET",
            )?;
            let (method, params) = match op {
                "ls" => ("mounts.list", json!({})),
                "add" => (
                    "mounts.add",
                    json!({"share":arg(args,2,"Share alias required")?,"target":arg(args,3,"Guest target required")?,"readonly":flags(args,"--read-only")}),
                ),
                "rm" => (
                    "mounts.remove",
                    json!({"target":arg(args,2,"Guest target required")?}),
                ),
                _ => return Err(Error::usage("Unknown mount command")),
            };
            let data = b.call("mount-control", method, params)?;
            emit(out, &format!("mount.{op}"), data.clone(), o, |w| {
                if op == "ls" {
                    if let Some(targets) = data["targets"].as_array() {
                        for target in targets {
                            writeln!(w, "{}", target.as_str().unwrap_or("?"))?;
                        }
                    }
                } else if !o.quiet && io::stderr().is_terminal() {
                    writeln!(
                        err,
                        "{}",
                        o.text("Updated for this boot.", "已更新，仅本次运行生效。")
                    )?;
                }
                Ok(())
            })
        }
        "port" => {
            let op = arg(
                args,
                1,
                "Usage: trames port ls | publish HOST:GUEST | unpublish HOST",
            )?;
            let mut params = json!({});
            let method = match op {
                "ls" => "ports.list",
                "publish" | "unpublish" => {
                    let spec = arg(args, 2, "Port required")?;
                    let (first, second) = spec
                        .split_once(':')
                        .map_or((spec, None), |(a, b)| (a, Some(b)));
                    let address = value(args, "--listen")
                        .unwrap_or("127.0.0.1")
                        .parse::<std::net::IpAddr>()
                        .map_err(|_| Error::usage("Invalid listen IP"))?;
                    params = json!({"host":std::net::SocketAddr::new(address,port(first)?).to_string(),"protocol":value(args,"--protocol").unwrap_or("tcp")});
                    if op == "publish" {
                        params["guest"] = json!(port(
                            second.ok_or_else(|| Error::usage("Use HOST:GUEST ports"))?
                        )?);
                        "ports.add"
                    } else {
                        "ports.remove"
                    }
                }
                _ => return Err(Error::usage("Unknown port command")),
            };
            let data = b.call("port-forward", method, params)?;
            emit(out, &format!("port.{op}"), data.clone(), o, |w| {
                if op == "ls" {
                    if let Some(rows) = data["publish"].as_array() {
                        for row in rows {
                            writeln!(
                                w,
                                "{}  {} -> {}",
                                row["protocol"].as_str().unwrap_or("tcp"),
                                row["host"].as_str().unwrap_or("?"),
                                row["guest"]
                            )?;
                        }
                    }
                } else if !o.quiet && io::stderr().is_terminal() {
                    writeln!(
                        err,
                        "{}",
                        o.text("Updated for this boot.", "已更新，仅本次运行生效。")
                    )?;
                }
                Ok(())
            })
        }
        "host" => match arg(args, 1, "Usage: trames host cli | exec | open | gui")? {
            "cli" | "exec" => {
                let argv = args[2..].strip_prefix(&["--".into()]).unwrap_or(&args[2..]);
                if argv.is_empty() {
                    return Err(Error::usage("A host command is required after --"));
                }
                let cli = args[1] == "cli";
                b.stream(
                    if cli { "host-control" } else { "host-exec" },
                    if cli { "host.cli" } else { "host.exec" },
                    argv,
                    o,
                    out,
                    err,
                )
            }
            "open" => {
                let data = b.call(
                    "host-control",
                    "url.open",
                    json!({"url":arg(args,2,"HTTP(S) URL required")?}),
                )?;
                emit(out, "host.open", data, o, |_| Ok(()))
            }
            "gui" => {
                let data = b.call("host-control", "ui.manager", json!({}))?;
                emit(out, "host.gui", data, o, |_| Ok(()))
            }
            _ => Err(Error::usage("Usage: trames host cli | exec | open | gui")),
        },
        "completion" => {
            let shell = arg(args, 1, "Choose bash, zsh or fish")?;
            let words = "status doctor permissions clipboard files mount port host completion help";
            match shell {
                "bash" => writeln!(out, "complete -W '{words}' trames")?,
                "zsh" => writeln!(
                    out,
                    "#compdef trames\n_arguments '1:command:({words})' '*:path:_files'"
                )?,
                "fish" => writeln!(out, "complete -c trames -f -a '{words}'")?,
                _ => return Err(Error::usage("Choose bash, zsh or fish")),
            }
            Ok(0)
        }
        "debug" if args.get(1).is_some_and(|a| a == "rpc") => {
            if args.len() != 5 {
                return Err(Error::usage("Usage: trames debug rpc DEVICE METHOD JSON"));
            }
            if matches!(args[3].as_str(), "host.exec" | "host.cli") {
                return Err(Error::usage("Use host exec/cli for stream operations"));
            }
            let data = b.call(&args[2], &args[3], serde_json::from_str(&args[4])?)?;
            writeln!(out, "{data}")?;
            Ok(0)
        }
        unknown => Err(Error::usage(format!(
            "Unknown command '{unknown}'; run trames --help"
        ))),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_arguments_are_literal_and_global_flags_stop_at_separator() {
        let (o, args) = Options::parse(
            &[
                "--json",
                "host",
                "exec",
                "--",
                "/bin/echo",
                "--timeout",
                "space quote\"\n",
            ]
            .map(String::from),
        )
        .unwrap();
        assert!(o.json);
        assert_eq!(&args[3..], &["/bin/echo", "--timeout", "space quote\"\n"]);
    }
    #[test]
    fn timeout_rejects_zero_and_overflow() {
        for t in ["0", "-1", "200x", "18446744073709551615m"] {
            assert!(Options::parse(&["--timeout".into(), t.into()]).is_err());
        }
    }
}
