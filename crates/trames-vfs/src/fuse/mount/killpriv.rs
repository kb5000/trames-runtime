// SPDX-License-Identifier: GPL-3.0-or-later
//! Privilege removal stays in the accepted inode's data-write transaction.
use super::*;

pub(super) fn capabilities_present(fs: &Mounted, result: Result<Vec<u8>>) -> bool {
    match result {
        Ok(bytes) if bytes.len() == 8 => u32::from_le_bytes(bytes[..4].try_into().unwrap()) > 0,
        Err(Errno(38)) => {
            fs.xattr_unsupported.fetch_or(2, Ordering::Relaxed);
            false
        }
        _ => false,
    }
}
pub(super) fn removed_capabilities(fs: &Mounted, result: Result<Vec<u8>>) -> Result<()> {
    match result {
        Ok(bytes) if bytes.is_empty() => Ok(()),
        Ok(_) => Err(Errno(5)),
        Err(Errno(38)) => {
            fs.xattr_unsupported.fetch_or(8, Ordering::Relaxed);
            Ok(())
        }
        Err(Errno(95)) => Ok(()),
        Err(error) => Err(error),
    }
}
fn mode_mask(mode: u32, credentials: &Credentials) -> u32 {
    if credentials.has_cap(capabilities::FSETID) {
        return 0;
    }
    (mode & 0o4000) | if mode & 0o2010 == 0o2010 { 0o2000 } else { 0 }
}
#[derive(Clone, Copy)]
enum Phase {
    Capabilities,
    Remove,
    Refresh,
    Mode,
}
pub(super) struct Preparation {
    file: Arc<File>,
    node: NodeRef,
    caller: Caller,
    credentials: Credentials,
    phase: Phase,
    opcode: u32,
    body: Vec<u8>,
    result: Option<FileResult>,
}
impl Preparation {
    fn next_mode(&self) -> Option<Phase> {
        (mode_mask(self.node.borrow().mode, &self.credentials) != 0).then_some(Phase::Refresh)
    }
    fn request(&self) -> Result<Arc<Request>> {
        let fs = &self.file.reference.fs;
        fs.check_inode(&self.node)?;
        let (opcode, body) = match self.phase {
            Phase::Capabilities => {
                let mut body = vec![0; 8];
                body.extend(file_caps::NAME);
                body.push(0);
                (22, body)
            }
            Phase::Remove => {
                let mut body = file_caps::NAME.to_vec();
                body.push(0);
                (24, body)
            }
            Phase::Refresh => {
                fs.invalidate_acl(&self.node);
                (3, vec![0; 16])
            }
            Phase::Mode => {
                let mode = self.node.borrow().mode;
                let mut body = vec![0; 88];
                body[..4].copy_from_slice(&1u32.to_le_bytes());
                body[68..72]
                    .copy_from_slice(&(mode & !mode_mask(mode, &self.credentials)).to_le_bytes());
                (4, body)
            }
        };
        Ok(Arc::new(fs.connection.request(
            opcode,
            self.file.reference.node,
            self.caller,
            &body,
        )?))
    }
}
impl File {
    pub(super) fn prepare_data_write(
        self: &Arc<Self>,
        v: &Vfs,
        opcode: u32,
        body: Vec<u8>,
        result: FileResult,
    ) -> Result<Metadata> {
        let node = self.inode().ok_or(Errno(5))?;
        let fs = &self.reference.fs;
        let phase = if fs.xattr_unsupported.load(Ordering::Relaxed) & 2 == 0 {
            Some(Phase::Capabilities)
        } else {
            (mode_mask(node.borrow().mode, &v.credentials) != 0).then_some(Phase::Refresh)
        };
        let Some(phase) = phase else {
            return self.request(v, opcode, &body, ResultKind::File(result));
        };
        let preparation = Preparation {
            file: self.clone(),
            node,
            caller: fs.caller(v),
            credentials: v.credentials.clone(),
            phase,
            opcode,
            body,
            result: Some(result),
        };
        // A zero-length envelope sends no data request. It retains the exact
        // offset, writer and inode guard until the preparation completes.
        let mut metadata = self.request(
            v,
            16,
            &[0; 40],
            ResultKind::Preparing(Box::new(preparation)),
        )?;
        let ResultKind::Preparing(preparation) = &metadata.kind else {
            unreachable!()
        };
        metadata.request = Some(preparation.request()?);
        Ok(metadata)
    }
}
impl Metadata {
    pub(super) fn advance_preparation(
        &mut self,
        result: Result<Vec<u8>>,
    ) -> Result<Option<FileValue>> {
        let version = self
            .request
            .as_ref()
            .map_or(0, |request| request.attr_version);
        let ResultKind::Preparing(preparation) = &mut self.kind else {
            unreachable!()
        };
        let fs = &preparation.file.reference.fs;
        let next = match preparation.phase {
            Phase::Capabilities => {
                if capabilities_present(fs, result)
                    && fs.xattr_unsupported.load(Ordering::Relaxed) & 8 == 0
                {
                    Some(Phase::Remove)
                } else {
                    preparation.next_mode()
                }
            }
            Phase::Remove => {
                removed_capabilities(fs, result)?;
                fs.invalidate_permission_attr(&preparation.node);
                inotify::notify(&preparation.node, inotify::ATTRIB, None);
                preparation.next_mode()
            }
            Phase::Refresh => {
                fs.refresh_permission_attr(&preparation.node, &mut result?, version, false)?;
                (mode_mask(preparation.node.borrow().mode, &preparation.credentials) != 0)
                    .then_some(Phase::Mode)
            }
            Phase::Mode => {
                fs.refresh_permission_attr(&preparation.node, &mut result?, version, true)?;
                fs.invalidate_acl(&preparation.node);
                inotify::notify(&preparation.node, inotify::ATTRIB, None);
                None
            }
        };
        if let Some(phase) = next {
            preparation.phase = phase;
            self.request = Some(preparation.request()?);
            return Ok(None);
        }
        fs.check_inode(&preparation.node)?;
        self.request = Some(Arc::new(fs.connection.request(
            preparation.opcode,
            preparation.file.reference.node,
            preparation.caller,
            &preparation.body,
        )?));
        self.kind = ResultKind::File(preparation.result.take().expect("original write result"));
        Ok(None)
    }
}
