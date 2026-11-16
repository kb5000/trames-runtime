// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded tar streams over the existing exec pipes; never control JSON payloads.
use crate::{copy, Error, Result};
use std::{
    fs,
    io::{Read, Write},
    path::{Component, Path},
};
pub fn send(path: &Path, output: impl Write) -> Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::usage("Copy source needs a basename"))?;
    let mut tar = tar::Builder::new(output);
    tar.follow_symlinks(false);
    if fs::symlink_metadata(path)?.is_dir() {
        tar.append_dir_all(name, path)?;
    } else {
        tar.append_path_with_name(path, name)?;
    }
    tar.finish()?;
    Ok(())
}
pub fn receive(input: impl Read, dest: &Path, options: &copy::Options) -> Result<()> {
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = parent.join(format!(
        ".trames-copy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::new("io", "Clock unavailable", 1))?
            .as_nanos()
    ));
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&staging)?;
    let result = (|| {
        let mut tar = tar::Archive::new(input);
        let mut root = None;
        for item in tar.entries()? {
            let mut item = item?;
            let kind = item.header().entry_type();
            if !kind.is_file() && !kind.is_dir() && !kind.is_symlink() {
                return Err(Error::usage("Unsupported copy archive entry type"));
            }
            let path = item.path()?.into_owned();
            if path
                .components()
                .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
            {
                return Err(Error::usage("Unsafe copy archive path"));
            }
            let name = path
                .components()
                .find_map(|c| {
                    if let Component::Normal(n) = c {
                        Some(n.to_owned())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| Error::usage("Empty archive path"))?;
            if root.as_ref().is_some_and(|r| r != &name) {
                return Err(Error::usage("Copy archive contains multiple roots"));
            }
            root = Some(name);
            if !item.unpack_in(&staging)? {
                return Err(Error::usage("Copy archive escapes its destination"));
            }
        }
        // tar entries stop at the first end marker. Drain the original pipe
        // before closing it, otherwise a split trailing marker can turn a
        // successful copy into a broken pipe at the peer.
        std::io::copy(&mut tar.into_inner(), &mut std::io::sink())?;
        let source = staging.join(root.ok_or_else(|| Error::usage("Empty copy archive"))?);
        let meta = fs::symlink_metadata(&source)?;
        if meta.is_dir() && !options.recursive {
            return Err(Error::usage("Directory copy requires -r"));
        }
        let target = if dest.is_dir() {
            dest.join(source.file_name().unwrap())
        } else {
            dest.to_owned()
        };
        if options.no_clobber && fs::symlink_metadata(&target).is_ok() {
            return Ok(());
        }
        // Rename the completed staging object within the destination filesystem:
        // ordinary single-file/tree transfers incur no second data copy.
        if !target.exists() || !meta.is_dir() && !options.interactive {
            fs::rename(&source, &target)?;
        } else {
            copy::run(&source, dest, options)?;
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_roundtrip_uses_copy_semantics_and_rejects_directory_without_r() {
        let root = std::env::temp_dir().join(format!("trames-archive-test-{}", std::process::id()));
        fs::create_dir_all(root.join("tree")).unwrap();
        fs::write(root.join("tree/file"), b"hello\0world").unwrap();
        let mut bytes = Vec::new();
        send(&root.join("tree"), &mut bytes).unwrap();
        assert!(receive(&bytes[..], &root.join("denied"), &Default::default()).is_err());
        let mut input = std::io::Cursor::new(&bytes);
        receive(
            &mut input,
            &root.join("received"),
            &copy::Options {
                recursive: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            input.position(),
            bytes.len() as u64,
            "the pipe must be drained through its trailing markers"
        );
        assert_eq!(
            fs::read(root.join("received/file")).unwrap(),
            b"hello\0world"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
