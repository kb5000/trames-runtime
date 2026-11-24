// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared cold environment declaration. Host grants are independent authority;
//! parsing config never starts a worker, mutates the guest or grants native access.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const GUEST_CONFIG: &[u8] = b"/etc/trames/env.toml";
pub const MAX_CONFIG: usize = 65536;
pub fn decode<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
    if text.len() > MAX_CONFIG {
        return Err("configuration exceeds 64 KiB".into());
    }
    Ok(toml::from_str(text)?)
}
pub fn encode<T: Serialize>(value: &T) -> Result<String> {
    Ok(toml::to_string_pretty(value)?)
}
pub fn uuid() -> Result<String> {
    let mut bytes = [0; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let s = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..]
    ))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CpuCount {
    Count(usize),
    All(String),
}
impl Default for CpuCount {
    fn default() -> Self {
        Self::All("all".into())
    }
}
impl CpuCount {
    pub fn resolve(&self, available: usize) -> Result<usize> {
        match self {
            Self::Count(n) if *n > 0 && *n <= available => Ok(*n),
            Self::All(s) if s == "all" => Ok(available),
            _ => Err("resources.cpus must be all or a supported positive count".into()),
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    #[default]
    Host,
    Bridge,
    None,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Switch {
    Enabled(bool),
    Auto(String),
}
impl Default for Switch {
    fn default() -> Self {
        Self::Auto("auto".into())
    }
}
impl Switch {
    pub fn resolve(&self, supported: bool) -> Result<bool> {
        match self {
            Self::Enabled(true) if !supported => {
                Err("required native component is unavailable on this platform".into())
            }
            Self::Enabled(v) => Ok(*v),
            Self::Auto(v) if v == "auto" => Ok(supported),
            _ => Err("component switch must be true, false or auto".into()),
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Identity {
    pub name: String,
    pub uuid: String,
    #[serde(rename = "type")]
    pub kind: crate::boot::Target,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Resources {
    pub cpus: CpuCount,
    pub memory: String,
    pub memory_limit: Option<String>,
}
impl Default for Resources {
    fn default() -> Self {
        Self {
            cpus: Default::default(),
            memory: "auto".into(),
            memory_limit: None,
        }
    }
}
pub fn memory_mib(value: &str) -> Result<Option<u64>> {
    if value == "auto" {
        return Ok(None);
    }
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let n: u64 = value[..split].parse()?;
    let factor = match &value[split..] {
        "GiB" => 1 << 30,
        "MiB" | "" => 1 << 20,
        "KiB" => 1 << 10,
        "B" => 1,
        _ => return Err("memory size must use GiB, MiB, KiB or B".into()),
    };
    let bytes = n
        .checked_mul(factor)
        .filter(|v| *v > 0 && *v <= usize::MAX as u64)
        .ok_or("invalid memory size")?;
    Ok(Some(bytes.div_ceil(1 << 20)))
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    pub mode: NetworkMode,
    pub bridge: Option<String>,
    pub publish: Vec<Publish>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publish {
    pub protocol: String,
    pub host: std::net::SocketAddr,
    pub guest: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Components {
    pub vulkan: Switch,
    pub vaapi: Switch,
    pub thunking: Switch,
    pub audio: bool,
    pub audio_input: bool,
}
impl Default for Components {
    fn default() -> Self {
        Self {
            vulkan: Switch::Enabled(true),
            vaapi: Switch::Enabled(false),
            thunking: Default::default(),
            audio: false,
            audio_input: false,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Init {
    #[default]
    Shell,
    Systemd,
    Android,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Boot {
    pub mode: Init,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Session {
    pub shell: Vec<String>,
    pub cwd: String,
}
impl Default for Session {
    fn default() -> Self {
        Self {
            shell: vec!["/bin/sh".into(), "-l".into()],
            cwd: "/".into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Display {
    pub windows: bool,
}
impl Default for Display {
    fn default() -> Self {
        Self { windows: true }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub target: String,
    pub share: Option<String>,
    pub host: Option<String>,
    #[serde(default)]
    pub readonly: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Capability {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shares: Option<Vec<String>>,
}
impl Default for Capability {
    fn default() -> Self {
        Self {
            enabled: true,
            shares: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Interop {
    pub host_ui: Capability,
    pub host_cli: Capability,
    pub clipboard: Capability,
    pub host_exec: Capability,
    pub files: Capability,
    pub ports: Capability,
    pub mounts: Capability,
}
impl Default for Interop {
    fn default() -> Self {
        Self {
            clipboard: Capability {
                enabled: true,
                shares: None,
            },
            host_ui: Default::default(),
            host_cli: Default::default(),
            host_exec: Default::default(),
            files: Default::default(),
            ports: Default::default(),
            mounts: Default::default(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Image {
    pub distribution: String,
    pub source: Option<String>,
    pub sha256: String,
}
impl Default for Image {
    fn default() -> Self {
        Self {
            distribution: "alpine".into(),
            source: None,
            sha256: String::new(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub environment: Identity,
    pub image: Image,
    pub resources: Resources,
    pub kernel: Kernel,
    pub network: Network,
    pub components: Components,
    pub boot: Boot,
    pub session: Session,
    pub display: Display,
    pub mounts: Vec<Mount>,
    pub interop: Interop,
}
impl Default for Manifest {
    fn default() -> Self {
        Self {
            version: 1,
            environment: Default::default(),
            image: Default::default(),
            resources: Default::default(),
            kernel: Default::default(),
            network: Default::default(),
            components: Default::default(),
            boot: Default::default(),
            session: Default::default(),
            display: Default::default(),
            mounts: vec![],
            interop: Default::default(),
        }
    }
}
impl Manifest {
    pub fn with_defaults(text: &str, defaults: &Self) -> Result<Self> {
        fn merge(base: &mut serde_json::Value, value: serde_json::Value) {
            match (base, value) {
                (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
                    for (k, v) in b {
                        merge(a.entry(k).or_insert(serde_json::Value::Null), v);
                    }
                }
                (base, value) => *base = value,
            }
        }
        let input: toml::Value = decode(text)?;
        let mut value = serde_json::to_value(defaults)?;
        merge(&mut value, serde_json::to_value(input)?);
        let result: Self = serde_json::from_value(value)?;
        result.validate()?;
        Ok(result)
    }
    pub fn new(distribution: &str) -> Self {
        let mut value = Self::default();
        value.image.distribution = distribution.into();
        if distribution == "android" {
            value.environment.kind = crate::boot::Target::Android;
            value.boot.mode = Init::Android;
            value.session.shell = vec!["/system/bin/sh".into(), "-i".into()];
            value.session.cwd = "/".into();
        }
        value
    }
    pub fn using_image(&self, distribution: &str) -> Self {
        let mut value = self.clone();
        let image = Self::new(distribution);
        value.image = image.image;
        value.environment.kind = image.environment.kind;
        if distribution == "android" {
            value.boot = image.boot;
            value.session = image.session;
        } else if value.boot.mode == Init::Android {
            value.boot.mode = Init::Shell;
            value.session = Session::default();
        }
        value
    }
    pub fn command(&self) -> Vec<String> {
        if self.environment.kind == crate::boot::Target::Android {
            crate::android::command()
        } else {
            self.session.shell.clone()
        }
    }
    pub fn parse(text: &str) -> Result<Self> {
        let value: Self = decode(text)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        self.kernel.validate()?;
        if self.version != 1 {
            return Err("unsupported environment TOML version".into());
        }
        let id = &self.environment;
        if id.name == "." || id.name == ".." || id.name.contains(['/', '\0']) || id.name.len() > 255
        {
            return Err("invalid environment name".into());
        }
        if !id.uuid.is_empty()
            && (id.uuid.len() != 36
                || !id.uuid.bytes().enumerate().all(|(i, c)| {
                    if [8, 13, 18, 23].contains(&i) {
                        c == b'-'
                    } else {
                        c.is_ascii_hexdigit()
                    }
                }))
        {
            return Err("invalid environment UUID".into());
        }
        self.resources.cpus.resolve(usize::MAX)?;
        memory_mib(&self.resources.memory)?;
        if let Some(limit) = &self.resources.memory_limit {
            if memory_mib(limit)?.is_none() {
                return Err("memory_limit must be a concrete size".into());
            }
        }
        for flag in [
            &self.components.vulkan,
            &self.components.vaapi,
            &self.components.thunking,
        ] {
            flag.resolve(true)?;
        }
        if (self.network.mode == NetworkMode::Bridge) != self.network.bridge.is_some() {
            return Err("bridge mode requires exactly one Trames network name".into());
        }
        if self.network.mode != NetworkMode::Bridge && !self.network.publish.is_empty() {
            return Err("port publishing is only needed in bridge mode".into());
        }
        for p in &self.network.publish {
            if !["tcp", "udp"].contains(&p.protocol.as_str()) || p.guest == 0 {
                return Err("invalid published port".into());
            }
        }
        if self.environment.kind == crate::boot::Target::Android && self.boot.mode != Init::Android
        {
            return Err("Android requires boot.mode = android".into());
        }
        if self.environment.kind == crate::boot::Target::Linux && self.boot.mode == Init::Android {
            return Err("Linux cannot use Android init".into());
        }
        if self.session.shell.is_empty()
            || !self.session.shell[0].starts_with('/')
            || self.session.shell.iter().any(|v| v.contains('\0'))
        {
            return Err("session.shell must be an absolute argv array".into());
        }
        if !self.session.cwd.starts_with('/') || self.session.cwd.contains('\0') {
            return Err("session needs an absolute cwd".into());
        }
        for m in &self.mounts {
            if !m.target.starts_with('/')
                || m.target.split('/').any(|v| matches!(v, "." | ".."))
                || m.share.is_some() == m.host.is_some()
            {
                return Err(
                    "mount needs an absolute target and exactly one share or host source".into(),
                );
            }
        }
        Ok(())
    }
}
/// Guest kernel policy initialized before task admission. These are the same
/// resources exposed by proc sysctl; declaring them grants no native authority.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Kernel {
    pub sysctl: BTreeMap<String, u32>,
}
impl Kernel {
    pub fn validate(&self) -> Result<()> {
        for (name, &value) in &self.sysctl {
            if name != "kernel.threads-max" {
                return Err(format!("unsupported kernel.sysctl key: {name}").into());
            }
            if !(1..=trames_vfs::TaskLimit::MAX).contains(&value) {
                return Err("kernel.threads-max must be 1..=1073741823".into());
            }
        }
        Ok(())
    }
    pub fn apply(&self, vfs: &trames_vfs::Vfs) -> Result<()> {
        self.validate()?;
        if let Some(&value) = self.sysctl.get("kernel.threads-max") {
            vfs.task_limit_control().set(value)?;
        }
        Ok(())
    }
    pub fn argument(&mut self, text: &str) -> Result<()> {
        let (name, value) = text.split_once('=').ok_or("--sysctl requires NAME=VALUE")?;
        let value = value.parse::<u32>()?;
        let declaration = Self {
            sysctl: [(name.to_owned(), value)].into(),
        };
        declaration.validate()?;
        self.sysctl.insert(name.to_owned(), value);
        Ok(())
    }
}
pub fn install_cli(vfs: &mut trames_vfs::Vfs) -> Result<()> {
    install_cli_for(vfs, crate::boot::Target::Linux)
}
pub fn install_cli_for(vfs: &mut trames_vfs::Vfs, target: crate::boot::Target) -> Result<()> {
    let path = if target == crate::boot::Target::Android {
        b"/system/bin/trames".as_slice()
    } else {
        b"/usr/local/bin/trames".as_slice()
    };
    use sha2::{Digest, Sha256};
    fn existing(vfs: &mut trames_vfs::Vfs, path: &[u8]) -> Result<Option<Vec<u8>>> {
        let fd = match vfs.open_at(trames_vfs::AT_FDCWD, path, 0, 0) {
            Ok(fd) => fd,
            Err(trames_vfs::Errno(2)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let result: Result<Option<Vec<u8>>> = (|| {
            let mut bytes = Vec::new();
            loop {
                let chunk = vfs.read(fd, 65536)?;
                if chunk.is_empty() {
                    break;
                }
                bytes.extend(chunk);
                if bytes.len() > 8 * 1024 * 1024 {
                    return Err("existing trames command exceeds managed artifact size".into());
                }
            }
            Ok(Some(bytes))
        })();
        let closed = vfs.close(fd);
        let bytes = result?;
        closed?;
        Ok(bytes)
    }
    let bytes = include_bytes!(env!("TRAMES_GUEST_CLI"));
    let record = b"/var/lib/trames/guest-cli.sha256";
    if let Some(old) = existing(vfs, path)? {
        let hash = format!("{:x}", Sha256::digest(&old));
        let owned = old == bytes
            || old == include_bytes!("../../../resources/guest/trames")
            || existing(vfs, record)?.is_some_and(|r| r == hash.as_bytes());
        if !owned {
            return Err(format!("{} already contains an unrelated command; rename it before enabling Trames CLI injection",String::from_utf8_lossy(path)).into());
        }
    }
    if target == crate::boot::Target::Linux {
        match vfs.mkdir_at(trames_vfs::AT_FDCWD, b"/usr", 0o755) {
            Ok(()) | Err(trames_vfs::Errno(17)) => (),
            Err(e) => return Err(e.into()),
        }
        match vfs.mkdir_at(trames_vfs::AT_FDCWD, b"/usr/bin", 0o755) {
            Ok(()) | Err(trames_vfs::Errno(17)) => (),
            Err(e) => return Err(e.into()),
        }
        match vfs.readlink_at(trames_vfs::AT_FDCWD, b"/usr/bin/trames") {
            Ok(link) if link == path => (),
            Err(trames_vfs::Errno(2)) => {
                vfs.symlink_at(path, trames_vfs::AT_FDCWD, b"/usr/bin/trames")?;
            }
            _ => return Err("/usr/bin/trames already contains an unrelated command".into()),
        }
    }
    vfs.import_reader_replace(path, &mut std::io::Cursor::new(bytes))?;
    vfs.chmod_at(trames_vfs::AT_FDCWD, path, 0o755)?;
    let hash = format!("{:x}", Sha256::digest(bytes));
    vfs.import_reader_replace(record, &mut std::io::Cursor::new(hash.as_bytes()))?;
    Ok(())
}
pub fn guest(vfs: &mut trames_vfs::Vfs, defaults: &Manifest) -> Result<Option<Manifest>> {
    let fd = match vfs.open_at(trames_vfs::AT_FDCWD, GUEST_CONFIG, 0, 0) {
        Ok(fd) => fd,
        Err(trames_vfs::Errno(2)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let result = (|| {
        let mut bytes = Vec::new();
        loop {
            let b = vfs.read(fd, MAX_CONFIG + 1 - bytes.len())?;
            if b.is_empty() {
                break;
            }
            bytes.extend(b);
            if bytes.len() > MAX_CONFIG {
                return Err("guest environment configuration exceeds 64 KiB".into());
            }
        }
        Manifest::with_defaults(std::str::from_utf8(&bytes)?, defaults).map(Some)
    })();
    vfs.close(fd)?;
    result
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Grant {
    pub host_ui: bool,
    pub host_cli: bool,
    pub clipboard: bool,
    pub host_exec: bool,
    pub files: bool,
    pub ports: bool,
    pub mounts: bool,
    pub shares: BTreeMap<String, Share>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub host: String,
    pub readonly: bool,
}
impl Grant {
    /// Owner-chosen defaults, used only when creating a new authorization record.
    /// Missing/invalid records never call this implicitly.
    pub fn allowed() -> Self {
        Self {
            host_ui: true,
            host_cli: true,
            clipboard: true,
            host_exec: true,
            files: true,
            ports: true,
            mounts: true,
            shares: BTreeMap::new(),
        }
    }
    pub fn permission(&self, key: &str) -> Option<bool> {
        Some(match key {
            "host-ui" => self.host_ui,
            "host-cli" => self.host_cli,
            "host-exec" => self.host_exec,
            "files" => self.files,
            "mounts" => self.mounts,
            "ports" => self.ports,
            "clipboard" => self.clipboard,
            _ => return None,
        })
    }
    pub fn set_permission(&mut self, key: &str, allowed: bool) -> Result<()> {
        *match key {
            "host-ui" => &mut self.host_ui,
            "host-cli" => &mut self.host_cli,
            "host-exec" => &mut self.host_exec,
            "files" => &mut self.files,
            "mounts" => &mut self.mounts,
            "ports" => &mut self.ports,
            "clipboard" => &mut self.clipboard,
            _ => return Err("unknown interoperability permission".into()),
        } = allowed;
        Ok(())
    }
    pub fn effective(&self, requested: &Interop) -> Interop {
        let cap = |r: &Capability, enabled: bool| Capability {
            enabled: r.enabled && enabled,
            shares: Some(match &r.shares {
                Some(shares) => shares
                    .iter()
                    .filter(|s| self.shares.contains_key(*s))
                    .cloned()
                    .collect(),
                None => self.shares.keys().cloned().collect(),
            }),
        };
        Interop {
            host_ui: cap(&requested.host_ui, self.host_ui),
            host_cli: cap(&requested.host_cli, self.host_cli),
            clipboard: cap(&requested.clipboard, self.clipboard),
            host_exec: cap(&requested.host_exec, self.host_exec),
            files: cap(&requested.files, self.files),
            ports: cap(&requested.ports, self.ports),
            mounts: cap(&requested.mounts, self.mounts),
        }
    }
}
/// Host-owned authorization record. Never load this from the guest filesystem.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub environment_uuid: String,
    pub grant: Grant,
}
impl Authorization {
    pub fn for_environment<'a>(&'a self, uuid: &str) -> Result<&'a Grant> {
        if uuid.is_empty() || uuid != self.environment_uuid {
            return Err("host grants belong to another environment".into());
        }
        Ok(&self.grant)
    }
}
impl Grant {
    /// Resolve once at environment start. The ordinary hostfs data path is unchanged.
    pub fn mounts(&self, manifest: &Manifest) -> Result<Vec<Mount>> {
        manifest
            .mounts
            .iter()
            .map(|mount| {
                let source = if let Some(alias) = &mount.share {
                    self.shares
                        .get(alias)
                        .ok_or("shared folder has no host grant")?
                } else {
                    let host =
                        std::path::Path::new(mount.host.as_deref().ok_or("missing mount source")?);
                    self.shares
                        .values()
                        .filter(|share| host.starts_with(&share.host))
                        .max_by_key(|share| share.host.len())
                        .ok_or("host mount has no host grant")?
                };
                let host = mount.host.as_deref().unwrap_or(&source.host);
                if !std::path::Path::new(host).is_absolute()
                    || std::path::Path::new(host).components().any(|c| {
                        matches!(
                            c,
                            std::path::Component::ParentDir | std::path::Component::CurDir
                        )
                    })
                {
                    return Err("host mount must be an absolute canonical path".into());
                }
                Ok(Mount {
                    target: mount.target.clone(),
                    host: Some(host.into()),
                    share: None,
                    readonly: mount.readonly || source.readonly,
                })
            })
            .collect()
    }
}
/// A stable private view of the existing authorized hostfs resource. It needs no
/// dynamic mount permission and adds nothing to ordinary byte I/O admission.
pub fn share_path(alias: &str) -> String {
    format!(
        "/run/trames/shares/{}",
        alias
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
pub fn control_info(c: &Manifest, g: &Grant, platform: &str) -> serde_json::Value {
    use serde_json::json;
    let e = g.effective(&c.interop);
    let mac = platform == "macos";
    let mut capabilities = serde_json::Map::new();
    for (key, enabled, supported) in [
        ("clipboard", e.clipboard.enabled, true),
        ("files", e.files.enabled, true),
        ("host-ui", e.host_ui.enabled, true),
        ("host-cli", e.host_cli.enabled, mac),
        ("host-exec", e.host_exec.enabled, mac),
        ("mounts", e.mounts.enabled, mac),
        ("ports", e.ports.enabled, mac),
    ] {
        capabilities.insert(
            key.into(),
            json!({"allowed":enabled&&supported,"supported":supported}),
        );
    }
    let shares: Vec<_> = e
        .files
        .shares
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|alias| {
            g.shares.get(alias).map(
                |s| json!({"alias":alias,"guest_path":share_path(alias),"readonly":s.readonly}),
            )
        })
        .collect();
    json!({"schema_version":1,"environment":c.environment,"platform":platform,"network":c.network.mode,"capabilities":capabilities,"features":{"exec_bytes":mac,"exec_stdin":mac},"shares":shares,"file_scope":c.interop.files.shares})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_defaults_allow_but_imported_config_cannot_authorize_itself() {
        let c = Manifest::default();
        let denied = Grant::default();
        let mut allowed = Grant::allowed();
        assert!(!denied.effective(&c.interop).host_exec.enabled);
        assert!(allowed.effective(&c.interop).host_exec.enabled);
        allowed.shares.insert(
            "work".into(),
            Share {
                host: "/work".into(),
                readonly: true,
            },
        );
        assert_eq!(
            allowed
                .effective(&c.interop)
                .files
                .shares
                .as_deref()
                .unwrap(),
            ["work"]
        );
        let mut restricted = c.clone();
        restricted.interop.files.shares = Some(vec![]);
        assert!(allowed
            .effective(&restricted.interop)
            .files
            .shares
            .as_ref()
            .unwrap()
            .is_empty());
        restricted.interop.host_exec.enabled = false;
        assert!(!allowed.effective(&restricted.interop).host_exec.enabled);
        assert_eq!(
            control_info(&c, &allowed, "ipados")["capabilities"]["host-exec"]["supported"],
            false
        );
        let mut v = trames_vfs::Vfs::default();
        v.import_file(b"/usr/local/bin/trames", b"custom program".to_vec())
            .unwrap();
        assert!(install_cli(&mut v).is_err());
        assert_eq!(v.executable(b"/usr/local/bin/trames").unwrap_err().0, 13);
    }
    #[test]
    fn defaults_roundtrip_and_errors() {
        let m = Manifest::parse("").unwrap();
        assert_eq!(m.network.mode, NetworkMode::Host);
        assert_eq!(m.resources.cpus.resolve(12).unwrap(), 12);
        assert!(Manifest::parse("unknown = 1").is_err());
        assert!(Manifest::parse("[resources]\ncpus=0").is_err());
        assert!(Manifest::parse("[network]\nmode='bridge'").is_err());
        assert!(Manifest::parse("[environment]\ntype='android'").is_err());
        assert!(Manifest::parse(&encode(&m).unwrap()).is_ok());
    }
    #[test]
    fn task_capacity_manifest_and_cli_share_the_live_resource_and_reject_unknown_configuration() {
        let m = Manifest::parse("[kernel.sysctl]\n'kernel.threads-max'=12345").unwrap();
        let v = trames_vfs::Vfs::default();
        m.kernel.apply(&v).unwrap();
        v.task_limit_control().bind_initial(65536);
        assert_eq!(v.task_limit_control().get(), 12345);
        let encoded = encode(&m).unwrap();
        assert_eq!(
            Manifest::parse(&encoded).unwrap().kernel.sysctl,
            m.kernel.sysctl
        );
        for declaration in [
            "'kernel.threads-max'=0",
            "'kernel.threads-max'=1073741824",
            "'kernel.unknown'=2",
        ] {
            assert!(Manifest::parse(&format!("[kernel.sysctl]\n{declaration}")).is_err());
        }
        let mut kernel = Kernel::default();
        kernel.argument("kernel.threads-max=1").unwrap();
        kernel.argument("kernel.threads-max=7").unwrap();
        kernel.apply(&v).unwrap();
        assert_eq!(v.task_limit_control().get(), 7);
        assert!(kernel.argument("kernel.unknown=3").is_err());
        assert_eq!(v.task_limit_control().get(), 7);
    }
    #[test]
    fn guest_requests_never_grant_host_access() {
        let mut m = Manifest::default();
        m.interop.host_exec.enabled = true;
        m.interop.files.enabled = true;
        m.interop.files.shares = Some(vec!["project".into(), "private".into()]);
        let mut grant = Grant {
            files: true,
            ..Default::default()
        };
        grant.shares.insert(
            "project".into(),
            Share {
                host: "/work".into(),
                readonly: true,
            },
        );
        let e = grant.effective(&m.interop);
        assert!(!e.host_exec.enabled);
        assert!(e.files.enabled);
        assert_eq!(e.files.shares.as_deref().unwrap(), ["project"]);
    }
    #[test]
    fn memory_and_identity() {
        assert_eq!(memory_mib("4GiB").unwrap(), Some(4096));
        assert_eq!(memory_mib("auto").unwrap(), None);
        assert!(memory_mib("18446744073709551615GiB").is_err());
        let mut m = Manifest::default();
        m.environment.uuid = uuid().unwrap();
        m.validate().unwrap();
        assert_ne!(m.environment.uuid, uuid().unwrap());
    }
    #[test]
    fn embedded_profile_overrides_defaults_without_authority() {
        let mut defaults = Manifest::new("android");
        defaults.environment.uuid = uuid().unwrap();
        let value =
            Manifest::with_defaults("[resources]\ncpus=2\n[network]\nmode='none'", &defaults)
                .unwrap();
        assert_eq!(value.boot.mode, Init::Android);
        assert_eq!(value.environment.uuid, defaults.environment.uuid);
        assert_eq!(value.resources.cpus.resolve(12).unwrap(), 2);
        assert!(Manifest::with_defaults("[resources]\ntypo=2", &defaults).is_err());
        let mut vfs = trames_vfs::Vfs::default();
        assert!(guest(&mut vfs, &defaults).unwrap().is_none());
        vfs.import_reader(
            GUEST_CONFIG,
            &mut std::io::Cursor::new(b"[resources]\ncpus=3"),
            true,
        )
        .unwrap();
        assert_eq!(
            guest(&mut vfs, &defaults)
                .unwrap()
                .unwrap()
                .resources
                .cpus
                .resolve(12)
                .unwrap(),
            3
        );
    }
    #[test]
    fn grants_bind_identity_and_mount_authority() {
        let uuid = uuid().unwrap();
        let mut auth = Authorization {
            environment_uuid: uuid.clone(),
            grant: Grant::default(),
        };
        auth.grant.shares.insert(
            "work".into(),
            Share {
                host: "/work".into(),
                readonly: true,
            },
        );
        assert!(auth.for_environment("another").is_err());
        let mut m = Manifest::default();
        m.mounts.push(Mount {
            target: "/mnt/work".into(),
            share: Some("work".into()),
            host: None,
            readonly: false,
        });
        assert!(auth.for_environment(&uuid).unwrap().mounts(&m).unwrap()[0].readonly);
        m.mounts[0].share = None;
        m.mounts[0].host = Some("/work/../private".into());
        assert!(auth.grant.mounts(&m).is_err());
        m.mounts[0].host = Some("/workspace".into());
        assert!(auth.grant.mounts(&m).is_err());
    }
    #[test]
    fn cli_installation_replaces_an_older_script_and_remains_executable() {
        let mut v = trames_vfs::Vfs::default();
        install_cli(&mut v).unwrap();
        install_cli(&mut v).unwrap();
        assert!(v
            .executable(b"/usr/local/bin/trames")
            .unwrap()
            .starts_with(b"\x7fELF"));
    }
}
