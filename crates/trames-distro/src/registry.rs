// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold, UUID-addressed host registry. No CPU/device initialization or guest I/O.
use crate::environment::{self as model, Manifest, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    pub name: String,
    pub uuid: String,
    pub distribution: String,
    pub sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CliConfig {
    pub version: u32,
    pub default_environment: String,
    pub defaults: Manifest,
    pub permission_defaults: model::Grant,
}
impl Default for CliConfig {
    fn default() -> Self {
        Self {
            version: 1,
            default_environment: "default".into(),
            defaults: Manifest::default(),
            permission_defaults: model::Grant::allowed(),
        }
    }
}
pub fn name(n: &str) -> Result<()> {
    if n.is_empty()
        || n.len() > 40
        || !n
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err("name must contain 1–40 letters, digits, '-' or '_'".into());
    }
    Ok(())
}
pub fn private_dir(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Ok(m) if !m.file_type().is_dir() => Err("management path must be a real directory".into()),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(p)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}
pub fn atomic_write(p: &Path, data: &[u8]) -> Result<()> {
    let temp = p.with_extension(format!("tmp-{}", model::uuid()?));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&temp, p)?;
        File::open(p.parent().ok_or("missing metadata parent")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
fn lock_file(p: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?)
}
#[derive(Clone)]
pub struct Registry {
    pub root: PathBuf,
}
impl Registry {
    pub fn at(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
        }
    }
    pub fn open(root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            return Err("TRAMES_HOME must be absolute".into());
        }
        private_dir(root)?;
        for d in ["environments", "locks", "logs", "cache"] {
            private_dir(&root.join(d))?;
        }
        Ok(Self::at(&root.canonicalize()?))
    }
    pub fn config(&self) -> Result<CliConfig> {
        let p = self.root.join("config.toml");
        if !p.exists() {
            return Ok(CliConfig::default());
        }
        let c: CliConfig = model::decode(&fs::read_to_string(p)?)?;
        if c.version != 1 {
            return Err("unsupported CLI config version".into());
        }
        name(&c.default_environment)?;
        c.defaults.validate()?;
        Ok(c)
    }
    pub fn metadata_lock(&self) -> Result<File> {
        let f = lock_file(&self.root.join("locks/.metadata"))?;
        f.lock()?;
        Ok(f)
    }
    pub fn directory(&self, n: &str) -> Result<PathBuf> {
        name(n)?;
        for entry in fs::read_dir(self.root.join("environments"))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() || entry.file_name().to_string_lossy().starts_with('.')
            {
                continue;
            }
            let p = entry.path();
            let file = p.join("instance.toml");
            if file.is_file() {
                let i = instance(&p)?;
                if i.name == n || i.uuid == n {
                    return Ok(p);
                }
            }
        }
        Ok(self.root.join("environments").join(format!(".missing-{n}")))
    }
    pub fn require(&self, n: &str) -> Result<PathBuf> {
        let p = self.directory(n)?;
        if !p.join("instance.toml").is_file() {
            return Err(format!(
                "environment '{n}' does not exist; create it with `trames env create {n}`"
            )
            .into());
        }
        Ok(p)
    }
    pub fn instances(&self) -> Result<Vec<(PathBuf, Instance)>> {
        let mut result = vec![];
        for e in fs::read_dir(self.root.join("environments"))? {
            let e = e?;
            if e.file_type()?.is_dir()
                && !e.file_name().to_string_lossy().starts_with('.')
                && e.path().join("instance.toml").is_file()
            {
                result.push((e.path(), instance(&e.path())?));
            }
        }
        result.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        Ok(result)
    }
    pub fn owner_lock(&self, n: &str) -> Result<File> {
        let p = self.require(n)?;
        let f = lock_file(
            &self
                .root
                .join("locks")
                .join(p.file_name().ok_or("invalid environment directory")?),
        )?;
        f.try_lock()
            .map_err(|e| format!("environment is running or busy: {e}"))?;
        Ok(f)
    }
    pub fn running(&self, n: &str) -> Result<bool> {
        let p = self.require(n)?;
        let f = lock_file(
            &self
                .root
                .join("locks")
                .join(p.file_name().ok_or("invalid environment directory")?),
        )?;
        match f.try_lock() {
            Ok(()) => Ok(false),
            Err(fs::TryLockError::WouldBlock) => Ok(true),
            Err(fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }
    pub fn lifecycle_lock(&self, n: &str) -> Result<File> {
        let i = instance(&self.require(n)?)?;
        let f = lock_file(
            &self
                .root
                .join("locks")
                .join(format!(".lifecycle-{}", i.uuid)),
        )?;
        f.lock()?;
        Ok(f)
    }
    pub fn socket(&self, n: &str) -> Result<PathBuf> {
        let directory = self.require(n)?;
        let tmp = PathBuf::from(format!("/tmp/trames-{}", unsafe { libc::geteuid() }));
        private_dir(&tmp)?;
        let m = fs::symlink_metadata(&tmp)?;
        if m.uid() != unsafe { libc::geteuid() } || m.permissions().mode() & 0o077 != 0 {
            return Err("unsafe control socket directory permissions".into());
        }
        let hash = format!(
            "{:x}",
            Sha256::digest(directory.as_os_str().as_encoded_bytes())
        );
        Ok(tmp.join(format!("{}.sock", &hash[..32])))
    }
    pub fn stage(&self) -> Result<Stage> {
        let p = self
            .root
            .join("environments")
            .join(format!(".staging-{}", model::uuid()?));
        fs::DirBuilder::new().mode(0o700).create(&p)?;
        Ok(Stage(p))
    }
    pub fn publish(&self, stage: &Path, c: &Manifest) -> Result<PathBuf> {
        let _metadata = self.metadata_lock()?;
        name(&c.environment.name)?;
        if self.directory(&c.environment.name)?.exists() {
            return Err("environment name already exists".into());
        }
        let destination = self.root.join("environments").join(&c.environment.uuid);
        if destination.exists() {
            return Err("environment UUID already exists".into());
        }
        fs::rename(stage, &destination)?;
        File::open(destination.parent().unwrap())?.sync_all()?;
        Ok(destination)
    }
    pub fn register(&self, dir: &Path, c: &Manifest, explicit: bool) -> Result<()> {
        c.validate()?;
        name(&c.environment.name)?;
        if c.environment.uuid.is_empty() {
            return Err("registered environment requires a UUID".into());
        }
        let new = if dir.join("instance.toml").exists() {
            instance(dir)?.uuid != c.environment.uuid
        } else {
            true
        };
        if new {
            let auth = model::Authorization {
                environment_uuid: c.environment.uuid.clone(),
                grant: self.config()?.permission_defaults,
            };
            atomic_write(&dir.join("grants.toml"), model::encode(&auth)?.as_bytes())?;
        }
        let i = Instance {
            name: c.environment.name.clone(),
            uuid: c.environment.uuid.clone(),
            distribution: c.image.distribution.clone(),
            sha256: c.image.sha256.clone(),
        };
        atomic_write(&dir.join("instance.toml"), model::encode(&i)?.as_bytes())?;
        atomic_write(
            &dir.join(if explicit {
                "env.toml"
            } else {
                "effective.toml"
            }),
            model::encode(c)?.as_bytes(),
        )
    }
    pub fn save(&self, dir: &Path, c: &Manifest) -> Result<()> {
        let i = instance(dir)?;
        if i.uuid != c.environment.uuid || i.name != c.environment.name {
            return Err("use env rename/clone to change registered identity".into());
        }
        if i.distribution != c.image.distribution || i.sha256 != c.image.sha256 {
            return Err(
                "registered image provenance is immutable; create a new environment".into(),
            );
        }
        self.register(dir, c, true)
    }
}
pub struct Stage(pub PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub fn instance(dir: &Path) -> Result<Instance> {
    let i: Instance = model::decode(&fs::read_to_string(dir.join("instance.toml"))?)?;
    name(&i.name)?;
    let mut c = Manifest::default();
    c.environment.name = i.name.clone();
    c.environment.uuid = i.uuid.clone();
    c.validate()?;
    if i.uuid.is_empty() {
        return Err("missing environment UUID".into());
    }
    Ok(i)
}
pub fn load(dir: &Path) -> Result<Manifest> {
    let i = instance(dir)?;
    let p = if dir.join("env.toml").is_file() {
        dir.join("env.toml")
    } else {
        dir.join("effective.toml")
    };
    let mut c = if p.is_file() {
        Manifest::parse(&fs::read_to_string(p)?)?
    } else {
        Manifest::new(&i.distribution)
    };
    if !c.environment.uuid.is_empty() && c.environment.uuid != i.uuid {
        return Err("configuration UUID differs from registered environment".into());
    }
    c.environment.name = i.name;
    c.environment.uuid = i.uuid;
    c.image.distribution = i.distribution;
    c.image.sha256 = i.sha256;
    c.validate()?;
    Ok(c)
}
pub fn effective(dir: &Path, defaults: &Manifest, vfs: &mut trames_vfs::Vfs) -> Result<Manifest> {
    if dir.join("env.toml").is_file() {
        return load(dir);
    }
    let stored = load(dir)?;
    let mut base = defaults.using_image(&stored.image.distribution);
    base.environment = stored.environment;
    base.image = stored.image;
    let mut c = model::guest(vfs, &base)?.unwrap_or(base.clone());
    c.environment = base.environment;
    c.image = base.image;
    atomic_write(&dir.join("effective.toml"), model::encode(&c)?.as_bytes())?;
    Ok(c)
}
pub fn set(c: &mut Manifest, key: &str, value: &str) -> Result<()> {
    if key == "environment"
        || key == "image"
        || key == "environment.name"
        || key == "environment.uuid"
        || key.starts_with("image.")
    {
        return Err(
            "registered identity and image provenance are immutable; use env rename/create/clone"
                .into(),
        );
    }
    set_default(c, key, value)
}
/// Update a future-environment template; registered identity remains protected by set/save.
pub fn set_default(c: &mut Manifest, key: &str, value: &str) -> Result<()> {
    let mut json = serde_json::to_value(&*c)?;
    let parts = key.split('.').collect::<Vec<_>>();
    let mut p = &mut json;
    for k in &parts[..parts.len() - 1] {
        p = p.get_mut(*k).ok_or("unknown configuration table")?;
    }
    let f = p
        .get_mut(parts[parts.len() - 1])
        .ok_or("unknown configuration field")?;
    *f = serde_json::from_str(value).unwrap_or_else(|_| serde_json::Value::String(value.into()));
    *c = serde_json::from_value(json)?;
    Ok(())
}
pub fn digest(p: &Path) -> Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = f.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        h.update(&bytes[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_identity_locks_and_profiles_are_independent() {
        let temp = std::env::temp_dir().join(format!("trames-registry-{}", model::uuid().unwrap()));
        let r = Registry::open(&temp).unwrap();
        let stage = r.stage().unwrap();
        let mut c = Manifest::new("custom");
        c.environment.name = "work".into();
        c.environment.uuid = model::uuid().unwrap();
        r.register(&stage.0, &c, true).unwrap();
        let dir = r.publish(&stage.0, &c).unwrap();
        assert_eq!(
            r.directory("work").unwrap(),
            r.directory(&c.environment.uuid).unwrap()
        );
        let lock = r.owner_lock("work").unwrap();
        assert!(r.running("work").unwrap());
        assert!(r.owner_lock("work").is_err());
        drop(lock);
        assert!(!r.running("work").unwrap());
        let socket = r.socket("work").unwrap();
        let _metadata = r.metadata_lock().unwrap();
        c.environment.name = "renamed".into();
        r.register(&dir, &c, true).unwrap();
        assert_eq!(socket, r.socket("renamed").unwrap());
        assert!(r
            .save(&dir, &{
                let mut c = c.clone();
                c.environment.uuid = model::uuid().unwrap();
                c
            })
            .is_err());
        let before = fs::read(dir.join("instance.toml")).unwrap();
        let mut replaced = c.clone();
        replaced.image.distribution = "debian".into();
        assert!(r.save(&dir, &replaced).is_err());
        assert_eq!(fs::read(dir.join("instance.toml")).unwrap(), before);
        assert!(!r.directory("work").unwrap().exists());
        drop(_metadata);
        fs::remove_dir_all(temp).unwrap();
    }
    #[test]
    fn dotted_batch_rejects_unknown_and_preserves_original_config() {
        let c = Manifest::default();
        let mut next = c.clone();
        set(&mut next, "resources.cpus", "0").unwrap();
        assert!(next.validate().is_err());
        assert_eq!(
            model::encode(&c).unwrap(),
            model::encode(&Manifest::default()).unwrap()
        );
        assert!(set(&mut next, "resources.typo", "2").is_err());
        assert!(set(&mut next, "environment.uuid", "other").is_err());
    }
}
