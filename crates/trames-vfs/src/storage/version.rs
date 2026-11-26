// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold compare-and-save snapshots reuse existing mapping publication tokens.
use super::*;

pub(crate) struct Validation {
    pub(crate) lease: Option<trames_shared::FileTransactionLease>,
    pub(crate) version: DataVersion,
}
pub(crate) enum DataVersion {
    Plain(Arc<crate::file_data::PlainFile>, u64),
    Shared(trames_shared::SharedFile, u64),
    Mapped((u64, u64), Box<DataVersion>),
    Layer(Arc<overlay::LayerFile>, Box<DataVersion>),
    Lower(NodeRef, Box<DataVersion>),
}
impl FileData {
    /// Acquire the original leaf transaction and observe its provider under
    /// the same short node/data custody. Read-only layer projections still
    /// have mutable providers, so validation follows them without copy-up.
    pub(crate) fn begin_validation(
        &self,
    ) -> Result<std::result::Result<Validation, Arc<dyn trames_shared::ResourceWait>>> {
        let (lease, version) = match self {
            Self::Plain(file) => {
                let lease = match file.begin_transaction() {
                    Ok(lease) => lease,
                    Err(wait) => return Ok(Err(wait)),
                };
                (lease, DataVersion::Plain(file.clone(), file.len()))
            }
            Self::Shared(file) => {
                let lease = match file.begin_transaction() {
                    Ok(lease) => lease,
                    Err(wait) => return Ok(Err(wait)),
                };
                (
                    lease,
                    DataVersion::Shared(file.clone(), file.logical_size().revision()),
                )
            }
            Self::Mapped(file) => return file.begin_validation(),
            Self::Layer(file) => {
                let validation = match file.read(Self::begin_validation)? {
                    Ok(validation) => validation,
                    Err(wait) => return Ok(Err(wait)),
                };
                (
                    validation.lease,
                    DataVersion::Layer(file.clone(), Box::new(validation.version)),
                )
            }
            Self::Lower(node) => {
                let provider = node.borrow();
                let Content::File(data) = &provider.content else {
                    return Err(Errno(5));
                };
                let validation = match data.begin_validation()? {
                    Ok(validation) => validation,
                    Err(wait) => return Ok(Err(wait)),
                };
                (
                    validation.lease,
                    DataVersion::Lower(node.clone(), Box::new(validation.version)),
                )
            }
        };
        Ok(Ok(Validation { lease, version }))
    }
}
impl DataVersion {
    /// No backend reads and no physical byte pins. Ordinary writes are held
    /// by the retained object transaction; mapped CPU/native writes keep their
    /// original publication protocol and invalidate this existing generation.
    pub(crate) fn matches(&self, data: &FileData) -> Result<bool> {
        match (self, data) {
            (Self::Plain(original, length), FileData::Plain(file)) => {
                Ok(Arc::ptr_eq(original, file) && *length == file.len())
            }
            (Self::Shared(original, revision), FileData::Shared(file)) => {
                Ok(original.key() == file.key() && *revision == file.logical_size().revision())
            }
            (Self::Mapped(token, source), FileData::Mapped(file)) => {
                file.matches_validation(*token, source)
            }
            (Self::Layer(original, source), FileData::Layer(file)) => {
                if !Arc::ptr_eq(original, file) {
                    return Ok(false);
                }
                file.read(|data| source.matches(data))
            }
            (Self::Lower(original, source), FileData::Lower(node)) => {
                if !Arc::ptr_eq(original, node) {
                    return Ok(false);
                }
                let provider = node.borrow();
                let Content::File(data) = &provider.content else {
                    return Err(Errno(5));
                };
                source.matches(data)
            }
            _ => Ok(false),
        }
    }
}
