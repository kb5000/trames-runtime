// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{Error, Result};
use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    path::{Component, Path},
    time::Instant,
};
#[derive(Clone, Default)]
pub struct Options {
    pub recursive: bool,
    pub no_clobber: bool,
    pub interactive: bool,
    pub deadline: Option<Instant>,
}
pub fn checked_relative(path: &str) -> Result<&Path> {
    let p = Path::new(path);
    if p.is_absolute()
        || p.components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(Error::usage(
            "Share paths must stay inside their configured root",
        ));
    }
    Ok(p)
}
pub fn run(source: &Path, dest: &Path, options: &Options) -> Result<u64> {
    let meta = fs::symlink_metadata(source)?;
    if meta.is_dir() {
        let from = fs::canonicalize(source)?;
        let to = if dest.exists() {
            fs::canonicalize(dest)?
        } else {
            fs::canonicalize(
                dest.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .join(
                dest.file_name()
                    .ok_or_else(|| Error::usage("Destination needs a name"))?,
            )
        };
        if to.starts_with(&from) {
            return Err(Error::usage("Cannot copy a directory into itself"));
        }
    }
    let target = if dest.is_dir() {
        dest.join(
            source
                .file_name()
                .ok_or_else(|| Error::usage("Source needs a filename"))?,
        )
    } else {
        dest.to_owned()
    };
    copy_node(source, &target, options)
}
fn copy_node(source: &Path, dest: &Path, o: &Options) -> Result<u64> {
    if o.deadline.is_some_and(|d| Instant::now() >= d) {
        return Err(Error::new("timeout", "Copy timed out", 124));
    }
    let meta = fs::symlink_metadata(source)?;
    if meta.is_dir() {
        if !o.recursive {
            return Err(Error::usage("Directory copy requires -r"));
        }
        fs::create_dir_all(dest)?;
        let mut total = 0;
        for e in fs::read_dir(source)? {
            let e = e?;
            total += copy_node(&e.path(), &dest.join(e.file_name()), o)?;
        }
        return Ok(total);
    }
    if fs::symlink_metadata(dest).is_ok() {
        if o.no_clobber {
            return Ok(0);
        }
        if o.interactive {
            if !io::stdin().is_terminal() {
                return Err(Error::usage("--interactive needs a terminal"));
            }
            eprint!("Overwrite {}? [y/N] ", dest.display());
            io::stderr().flush()?;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            if !matches!(line.trim(), "y" | "Y" | "yes") {
                return Ok(0);
            }
        }
    }
    if meta.file_type().is_symlink() {
        let link = fs::read_link(source)?;
        if fs::symlink_metadata(dest).is_ok() {
            fs::remove_file(dest)?;
        }
        std::os::unix::fs::symlink(link, dest)?;
        return Ok(0);
    }
    use std::os::unix::fs::MetadataExt;
    if meta.is_file()
        && fs::metadata(dest)
            .is_ok_and(|other| other.dev() == meta.dev() && other.ino() == meta.ino())
    {
        return Err(Error::usage("Source and destination are the same file"));
    }
    if !meta.is_file() {
        return Err(Error::usage(
            "Only files, directories and symlinks can be copied",
        ));
    }
    // Ordinary std copy retains the platform's existing file data path. Explicit
    // deadlines need chunk boundaries; the normal path gains no clock reads.
    if o.deadline.is_none() {
        return Ok(fs::copy(source, dest)?);
    }
    let mut input = fs::File::open(source)?;
    let mut output = fs::File::create(dest)?;
    let mut buf = vec![0; 256 * 1024];
    let mut count = 0;
    loop {
        if o.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Error::new("timeout", "Copy timed out", 124));
        }
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
        count += n as u64;
    }
    fs::set_permissions(dest, meta.permissions())?;
    Ok(count)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn copies_binary_trees_links_and_preserves_self_and_no_clobber() {
        let root = std::env::temp_dir().join(format!("trames-copy-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        let bytes: Vec<_> = (0..=255).collect();
        fs::write(source.join("binary"), &bytes).unwrap();
        std::os::unix::fs::symlink("missing", source.join("dangling")).unwrap();
        assert!(run(&source, &root.join("target"), &Options::default()).is_err());
        let options = Options {
            recursive: true,
            ..Default::default()
        };
        run(&source, &root.join("target"), &options).unwrap();
        assert_eq!(fs::read(root.join("target/binary")).unwrap(), bytes);
        assert_eq!(
            fs::read_link(root.join("target/dangling")).unwrap(),
            Path::new("missing")
        );
        assert!(run(&source, &source.join("nested"), &options).is_err());
        assert!(run(&source.join("binary"), &source.join("binary"), &options).is_err());
        fs::write(root.join("existing"), b"keep").unwrap();
        run(
            &source.join("binary"),
            &root.join("existing"),
            &Options {
                no_clobber: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(fs::read(root.join("existing")).unwrap(), b"keep");
        assert!(checked_relative("../escape").is_err());
        assert!(checked_relative("/escape").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
