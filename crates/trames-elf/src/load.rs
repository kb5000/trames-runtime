// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted main/interpreter bytes and anonymous page progress survive pressure.
use super::*;
use std::sync::Arc;

pub struct Loader {
    bytes: Vec<u8>,
    file: Option<MappingFileInfo>,
    interpreter: Option<(Vec<u8>, Option<MappingFileInfo>)>,
    memory: Option<Memory>,
    work: Option<ImageWork>,
    main: Option<Image>,
    wait: Option<Arc<trames_memory::PageWait>>,
    resources: trames_memory::CgroupMemoryContext,
}
impl Loader {
    pub fn new(
        bytes: Vec<u8>,
        memory_limit: usize,
        file: Option<MappingFileInfo>,
        interpreter: Option<(Vec<u8>, Option<MappingFileInfo>)>,
    ) -> Result<Self, ElfError> {
        let header = Header::parse(&bytes, 0x4000_0000)?;
        if header.interpreter.is_some() != interpreter.is_some() {
            return Err(ElfError::Interpreter(2));
        }
        // Resolve and validate PT_INTERP before the first main segment effect.
        if let Some((bytes, _)) = &interpreter {
            loader_header(bytes)?;
        }
        let memory = Memory::new(memory_limit);
        let work = Some(ImageWork::new(&bytes, &memory, header)?);
        Ok(Self {
            bytes,
            file,
            interpreter,
            memory: Some(memory),
            work,
            main: None,
            wait: None,
            resources: trames_memory::CgroupMemoryContext::capture(),
        })
    }
    pub fn wait(&self) -> Option<&Arc<trames_memory::PageWait>> {
        self.wait.as_ref()
    }
    pub fn run(&mut self) -> Result<Option<LoadedElf>, ElfError> {
        assert!(self.memory.is_some(), "completed ELF load");
        if self.wait.as_ref().is_some_and(|wait| !wait.ready()) {
            return Ok(None);
        }
        let _resumed = self.wait.take();
        let _resources = self.resources.enter();
        if self.main.is_none() {
            let result = self.work.as_mut().unwrap().run(
                &self.bytes,
                self.memory.as_mut().unwrap(),
                self.file.as_ref(),
            );
            match result {
                Err(ElfError::Memory(MemoryError::Pending(fault))) => {
                    self.wait = Some(fault.wait);
                    return Ok(None);
                }
                result => self.main = Some(result?),
            }
            self.work = None;
        }
        let (start_entry, interpreter_base) = if let Some((bytes, file)) = &self.interpreter {
            let memory = self.memory.as_mut().unwrap();
            if self.work.is_none() {
                self.work = Some(ImageWork::new(bytes, memory, loader_header(bytes)?)?);
            }
            match self
                .work
                .as_mut()
                .unwrap()
                .run(bytes, memory, file.as_ref())
            {
                Err(ElfError::Memory(MemoryError::Pending(fault))) => {
                    self.wait = Some(fault.wait);
                    return Ok(None);
                }
                result => {
                    let loader = result?;
                    (loader.entry, loader.bias)
                }
            }
        } else {
            (self.main.as_ref().unwrap().entry, 0)
        };
        let main = self.main.take().unwrap();
        Ok(Some(LoadedElf {
            memory: self.memory.take().unwrap(),
            entry: main.entry,
            phdr: main.phdr,
            phnum: main.phnum,
            start_entry,
            interpreter_base,
            code: main.executable.code,
            data: main.executable.data,
            brk_base: main.executable.start_brk,
        }))
    }
}
fn loader_header(bytes: &[u8]) -> Result<Header<'_>, ElfError> {
    let header = Header::parse(bytes, INTERPRETER_BASE).map_err(|error| match error {
        ElfError::Invalid(_) | ElfError::Unsupported(_) => ElfError::Interpreter(80),
        error => error,
    })?;
    if header.interpreter.is_some() {
        return Err(ElfError::Invalid("nested PT_INTERP"));
    }
    Ok(header)
}
