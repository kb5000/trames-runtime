// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold host-owned network registry shared by Linux and Mac.
//! Packet transport and native sockets remain in the existing Runtime fabric.
use crate::{
    environment::{self as model, Grant, Manifest, Result},
    registry::{self, Registry},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bridge {
    version: u32,
    pub name: String,
    pub uuid: String,
    pub nat: bool,
    pub members: BTreeMap<String, u8>,
}
pub struct Networks {
    registry: Registry,
}
impl Networks {
    pub fn at(root: &Path) -> Self {
        Self {
            registry: Registry::at(root),
        }
    }
    fn path(&self, name: &str) -> Result<PathBuf> {
        registry::name(name)?;
        Ok(self
            .registry
            .root
            .join("networks")
            .join(format!("{name}.toml")))
    }
    fn lock(&self) -> Result<File> {
        registry::private_dir(&self.registry.root.join("networks"))?;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.registry.root.join("locks/networks"))?;
        f.lock()?;
        Ok(f)
    }
    fn load(&self, name: &str) -> Result<Bridge> {
        let p = self.path(name)?;
        if !fs::symlink_metadata(&p)?.is_file() {
            return Err("network profile must be a regular file".into());
        }
        let b: Bridge = model::decode(&fs::read_to_string(p)?)?;
        registry::name(&b.name)?;
        let mut identity = Manifest::default();
        identity.environment.uuid = b.uuid.clone();
        identity.validate()?;
        if b.version != 1
            || b.name != name
            || b.uuid.is_empty()
            || b.members.values().any(|id| !(2..=254).contains(id))
            || b.members.values().collect::<BTreeSet<_>>().len() != b.members.len()
        {
            return Err("invalid Trames network profile".into());
        }
        for uuid in b.members.keys() {
            registry::name(uuid)?;
        }
        Ok(b)
    }
    fn transport(&self, b: &Bridge) -> Result<PathBuf> {
        let key = format!(
            "{:x}",
            Sha256::digest(format!("{}:{}", self.registry.root.display(), b.uuid))
        );
        #[cfg(target_vendor = "apple")]
        const TMP: &str = "/private/tmp";
        #[cfg(not(target_vendor = "apple"))]
        const TMP: &str = "/tmp";
        let p = Path::new(TMP).join(format!(
            "trames-net-{}-{}",
            unsafe { libc::geteuid() },
            &key[..24]
        ));
        registry::private_dir(&p)?;
        let m = fs::symlink_metadata(&p)?;
        if m.uid() != unsafe { libc::geteuid() } || m.permissions().mode() & 0o077 != 0 {
            return Err("unsafe Trames network directory".into());
        }
        Ok(p)
    }
    /// Caller retains the original environment owner lock through fabric teardown.
    pub fn arguments(&self, c: &Manifest, g: &Grant) -> Result<Vec<String>> {
        c.validate()?;
        if !c.network.publish.is_empty() && !g.effective(&c.interop).ports.enabled {
            return Err(
                "host port publication requires both the ports request and host grant".into(),
            );
        }
        let name = c
            .network
            .bridge
            .as_deref()
            .ok_or("bridge network is missing")?;
        let _lock = self.lock()?;
        let mut b = self.load(name)?;
        let registered = self
            .registry
            .instances()?
            .into_iter()
            .map(|(_, i)| i.uuid)
            .collect::<BTreeSet<_>>();
        if !registered.contains(&c.environment.uuid) {
            return Err("network member must be a registered environment".into());
        }
        let previous_members = b.members.len();
        b.members.retain(|uuid, _| registered.contains(uuid));
        let mut changed = b.members.len() != previous_members;
        let id = if let Some(id) = b.members.get(&c.environment.uuid) {
            *id
        } else {
            let id = (2..=254)
                .find(|id| !b.members.values().any(|v| v == id))
                .ok_or("bridge addresses exhausted")?;
            b.members.insert(c.environment.uuid.clone(), id);
            changed = true;
            id
        };
        if changed {
            registry::atomic_write(&self.path(name)?, model::encode(&b)?.as_bytes())?;
        }
        let dir = self.transport(&b)?;
        let endpoint = dir.join(format!("p{id}"));
        match fs::symlink_metadata(&endpoint) {
            Ok(m) if m.file_type().is_socket() => fs::remove_file(&endpoint)?,
            Ok(_) => return Err("network endpoint is not a socket".into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        let mut args = vec![
            "--network-link".into(),
            dir.to_string_lossy().into_owned(),
            "--network-id".into(),
            id.to_string(),
            "--network-nat".into(),
            b.nat.to_string(),
        ];
        for p in &c.network.publish {
            args.extend([
                "--publish".into(),
                format!("{},{},{}", p.protocol, p.host, p.guest),
            ]);
        }
        Ok(args)
    }
    pub fn listing(&self) -> Result<Vec<Bridge>> {
        let _lock = self.lock()?;
        self.list_locked()
    }
    fn list_locked(&self) -> Result<Vec<Bridge>> {
        let mut rows = vec![];
        for entry in fs::read_dir(self.registry.root.join("networks"))? {
            let p = entry?.path();
            if p.extension().is_some_and(|s| s == "toml") {
                rows.push(
                    self.load(
                        p.file_stem()
                            .and_then(|s| s.to_str())
                            .ok_or("invalid network filename")?,
                    )?,
                );
            }
        }
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(rows)
    }
    pub fn dispatch(&self, args: &[String]) -> Result<u8> {
        let _lock = self.lock()?;
        match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
            []|["ls"]|["ls","--json"]=>{
                let rows=self.list_locked()?;
                if args.iter().any(|s|s=="--json") {println!("{}",serde_json::to_string_pretty(&rows)?);}
                else {println!("NAME                 NAT    MEMBERS");for b in rows {println!("{:<20} {:<6} {}",b.name,b.nat,b.members.len());}}
            }
            ["create",name]|["create",name,"--internal"]=>{
                let p=self.path(name)?;if p.exists(){return Err("network exists".into());}
                registry::atomic_write(&p,model::encode(&Bridge{version:1,name:(*name).into(),uuid:model::uuid()?,nat:args.len()==2,members:BTreeMap::new()})?.as_bytes())?;
                println!("Created Trames network {name}");
            }
            ["inspect",name]=>print!("{}",model::encode(&self.load(name)?)?),
            ["remove",name]=>{
                let b=self.load(name)?;
                // Include first-time starts that hold an owner before allocation,
                // and running members whose next-boot profile was changed.
                for (dir,i) in self.registry.instances()? {
                    let attached=b.members.contains_key(&i.uuid) || registry::load(&dir).is_ok_and(|c|c.network.bridge.as_deref()==Some(name));
                    if attached && self.registry.running(&i.uuid)? {return Err("stop attached environments before removing network".into());}
                }
                let dir=self.transport(&b)?;
                fs::remove_file(self.path(name)?)?;
                fs::File::open(self.registry.root.join("networks"))?.sync_all()?;
                fs::remove_dir_all(dir)?;
            }
            _=>return Err("usage: network ls [--json] | create NAME [--internal] | inspect NAME | remove NAME".into()),
        }
        Ok(0)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stable_membership_authority_and_first_start_remove_race() {
        let root = std::env::temp_dir().join(format!(
            "trames-network-registry-{}",
            model::uuid().unwrap()
        ));
        let r = Registry::open(&root).unwrap();
        let nets = Networks::at(&root);
        let args = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        nets.dispatch(&args(&["create", "lan", "--internal"]))
            .unwrap();
        let stage = r.stage().unwrap();
        let mut c = Manifest::new("custom");
        c.environment.name = "work".into();
        c.environment.uuid = model::uuid().unwrap();
        c.network.mode = model::NetworkMode::Bridge;
        c.network.bridge = Some("lan".into());
        r.register(&stage.0, &c, true).unwrap();
        let dir = r.publish(&stage.0, &c).unwrap();
        let owner = r.owner_lock("work").unwrap();
        assert!(nets.dispatch(&args(&["remove", "lan"])).is_err());
        let first = nets.arguments(&c, &Grant::allowed()).unwrap();
        assert_eq!(first[3], "2");
        assert_eq!(first[5], "false");
        c.environment.name = "renamed".into();
        r.register(&dir, &c, true).unwrap();
        assert_eq!(nets.arguments(&c, &Grant::allowed()).unwrap(), first);
        c.network.publish.push(model::Publish {
            protocol: "tcp".into(),
            host: "127.0.0.1:38080".parse().unwrap(),
            guest: 80,
        });
        assert!(nets.arguments(&c, &Grant::default()).is_err());
        c.interop.ports.enabled = false;
        assert!(nets.arguments(&c, &Grant::allowed()).is_err());
        c.interop.ports.enabled = true;
        let endpoint = Path::new(&first[1]).join("p2");
        fs::write(&endpoint, b"keep").unwrap();
        assert!(nets.arguments(&c, &Grant::allowed()).is_err());
        assert_eq!(fs::read(&endpoint).unwrap(), b"keep");
        fs::remove_file(endpoint).unwrap();
        drop(owner);
        nets.dispatch(&args(&["remove", "lan"])).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
