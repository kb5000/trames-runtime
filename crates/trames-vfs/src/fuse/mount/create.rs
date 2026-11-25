// SPDX-License-Identifier: GPL-3.0-or-later
//! Atomic create/open with the connection's Linux MKNOD+OPEN fallback.
use super::*;

impl Metadata {
    pub(super) fn create_missing(&mut self) -> Result<bool> {
        let ResultKind::Lookup(walk) = &mut self.kind else {
            return Ok(false);
        };
        let PathOperation::Open(flags) = walk.operation else {
            return Ok(false);
        };
        if flags & O_CREAT == 0
            || walk
                .continuation
                .as_ref()
                .is_some_and(|walk| !walk.parts.is_empty())
            || walk.directory
        {
            return Ok(false);
        }
        let plan = self.open.as_mut().unwrap();
        if plan.mount.readonly() {
            return Err(Errno(30));
        }
        let access = landlock::MAKE_REG
            | if fd_can_read(flags) {
                landlock::READ_FILE
            } else {
                0
            }
            | if fd_can_write(flags) {
                landlock::WRITE_FILE
            } else {
                0
            };
        if plan.denied & access != 0 {
            return Err(Errno(13));
        }
        let create = Create {
            _parent_directory: walk.parent_directory.clone(),
            _parent_access: walk.parent_access.take(),
            fs: walk.fs.clone(),
            caller: walk.caller,
            parent: walk.parent,
            name: walk.name.clone(),
        };
        let credentials = walk
            .continuation
            .as_ref()
            .and_then(|w| w.credentials.as_deref())
            .expect("accepted create credentials")
            .clone();
        let mut check = posix::Check::new(walk.parent_directory.clone(), credentials, 3);
        let request = check.next(&walk.fs, walk.caller)?;
        plan.writer = Some(mapped::MountWrite::new(&plan.mount.identity)?);
        if let Some(request) = request {
            self.request = Some(request);
            self.kind = ResultKind::CreatePermission(Box::new((create, check)));
        } else {
            let fallback = walk.fs.create_unsupported.load(Ordering::Relaxed);
            self.start_create(create, fallback)?;
        }
        Ok(true)
    }
    pub(super) fn advance_create_permission(&mut self, result: Result<Vec<u8>>) -> Result<()> {
        let ResultKind::CreatePermission(mut pending) =
            std::mem::replace(&mut self.kind, ResultKind::Readlink)
        else {
            unreachable!()
        };
        let (create, check) = &mut *pending;
        check.accept(&create.fs, result)?;
        if let Some(request) = check.next(&create.fs, create.caller)? {
            self.request = Some(request);
            self.kind = ResultKind::CreatePermission(pending);
        } else {
            let (create, _) = *pending;
            let fallback = create.fs.create_unsupported.load(Ordering::Relaxed);
            self.start_create(create, fallback)?;
        }
        Ok(())
    }
    fn start_create(&mut self, create: Create, fallback: bool) -> Result<()> {
        let plan = self.open.as_ref().unwrap();
        let mut body = Vec::new();
        // FUSE marks its superblock POSIXACL to defer VFS umask stripping.
        // Mask raw mode in the callback and report a second live read. ENOSYS
        // enters the MKNOD callback anew with the original unmasked mode.
        let mask = plan.umask.as_ref().unwrap();
        let mode = if create.fs.dont_mask() {
            plan.mode
        } else {
            plan.mode & !mask.get()
        };
        let umask = mask.get();
        if fallback {
            body.extend(mode.to_le_bytes());
            body.extend([0; 4]);
            body.extend(umask.to_le_bytes());
            body.extend([0; 4]);
        } else {
            // Linux CREATE retains O_CREAT/O_EXCL/O_TRUNC. O_NOCTTY belongs to
            // the VFS open side, and CLOEXEC is descriptor membership only.
            body.extend((plan.flags & !(O_CLOEXEC | 0x100) | O_LARGEFILE).to_le_bytes());
            body.extend(mode.to_le_bytes());
            body.extend(umask.to_le_bytes());
            body.extend([0; 4]);
        }
        body.extend(&create.name);
        body.push(0);
        self.request = Some(Arc::new(create.fs.connection.request(
            if fallback { 8 } else { 35 },
            create.parent,
            create.caller,
            &body,
        )?));
        self.kind = if fallback {
            ResultKind::MknodOpen(create)
        } else {
            ResultKind::Create(create)
        };
        Ok(())
    }
    pub(super) fn finish_create(&mut self, result: Result<Vec<u8>>) -> Option<Result<FileValue>> {
        if matches!(self.kind, ResultKind::Create(_)) && matches!(result, Err(Errno(38))) {
            let ResultKind::Create(create) =
                std::mem::replace(&mut self.kind, ResultKind::Readlink)
            else {
                unreachable!()
            };
            create.fs.create_unsupported.store(true, Ordering::Relaxed);
            return self.start_create(create, true).err().map(Err);
        }
        let has_open = matches!(self.kind, ResultKind::Create(_));
        let result = result.and_then(|bytes| {
            let create = match &self.kind {
                ResultKind::Create(create) | ResultKind::MknodOpen(create) => create,
                _ => unreachable!(),
            };
            if bytes.len() != if has_open { 144 } else { 128 } {
                return Err(Errno(5));
            }
            let node = transport::entry_id(&bytes[..128], Some(0o100000)).ok_or(Errno(5))?;
            let mut reference = LookupRef::new(&create.fs, create.caller, node);
            let fh = has_open
                .then(|| {
                    bytes
                        .get(128..136)
                        .map(|raw| u64::from_le_bytes(raw.try_into().unwrap()))
                })
                .flatten();
            let flags =
                self.open.as_ref().unwrap().flags & !(O_CLOEXEC | OPEN_ONLY_FLAGS) | O_LARGEFILE;
            let mut attr: [u8; 88] = bytes[40..128].try_into().unwrap();
            let inode = create.fs.leaf_inode(
                &reference,
                u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                &create._parent_directory,
                &mut attr,
                0,
                (
                    u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
                    u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
                ),
            );
            reference.leaf = Some(match inode {
                Ok(inode) => inode,
                Err(error) => {
                    if let Some(fh) = fh {
                        create
                            .fs
                            .connection
                            .release(node, create.caller, fh, flags, false);
                    }
                    return Err(error);
                }
            });
            reference.entry = Some(create.fs.entries.bind(
                reference.leaf.as_ref().unwrap(),
                &create._parent_directory,
                &create.name,
            ));
            create.fs.inode_changed(&create._parent_directory);
            self.reference = Some(reference);
            self.open.as_mut().unwrap().created = true;
            if has_open {
                self.publish_open(
                    fh,
                    attr,
                    u32::from_le_bytes(bytes[136..140].try_into().unwrap()),
                )
                .map(Some)
            } else {
                let reference = self.reference.as_ref().unwrap();
                let mut body = [0; 8];
                body[..4].copy_from_slice(&flags.to_le_bytes());
                self.request = Some(Arc::new(reference.fs.connection.request(
                    14,
                    node,
                    reference.caller,
                    &body,
                )?));
                self.kind = ResultKind::Open(attr);
                Ok(None)
            }
        });
        result.transpose()
    }
}
