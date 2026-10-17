// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned nonblocking pipe FDs used by clipboard/SCM_RIGHTS adapters.
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::fs::FileTypeExt,
    },
};
pub struct NativePipe(File);
impl NativePipe {
    pub fn is_pipe(fd: &OwnedFd) -> io::Result<bool> {
        Ok(File::from(fd.try_clone()?)
            .metadata()?
            .file_type()
            .is_fifo())
    }
    pub fn import(fd: OwnedFd) -> io::Result<Self> {
        let file = File::from(fd);
        if !file.metadata()?.file_type().is_fifo() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let flags = rustix::fs::fcntl_getfl(&file)?;
        rustix::fs::fcntl_setfl(&file, flags | rustix::fs::OFlags::NONBLOCK)?;
        #[cfg(target_vendor = "apple")]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: a live pipe descriptor. Darwin's per-FD flag prevents a
            // closed clipboard reader from delivering SIGPIPE to the iPad app.
            if unsafe {
                libc::fcntl(
                    file.as_raw_fd(),
                    73, /* F_SETNOSIGPIPE: public Darwin <sys/fcntl.h> */
                    1,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self(file))
    }
    pub fn pair() -> io::Result<(Self, Self)> {
        let (read, write) = std::io::pipe()?;
        Ok((Self::import(read.into())?, Self::import(write.into())?))
    }
    pub fn writable(&self) -> io::Result<bool> {
        Ok(rustix::fs::fcntl_getfl(&self.0)?.contains(rustix::fs::OFlags::WRONLY))
    }
    pub fn into_fd(self) -> OwnedFd {
        self.0.into()
    }
}
impl AsFd for NativePipe {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl Read for NativePipe {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.read(bytes)
    }
}
impl Write for NativePipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
