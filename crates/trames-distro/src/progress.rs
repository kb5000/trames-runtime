// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold installation diagnostics, delivered synchronously by the importing
//! worker. No progress thread, polling loop, or runtime data-path dependency.
use serde::Serialize;
use std::{
    io::{self, Read},
    time::{Duration, Instant},
};

#[derive(Debug, Serialize)]
pub struct InstallProgress {
    pub stage: &'static str,
    pub item: String,
    pub path: String,
    pub completed: u64,
    /// Zero means unknown; do not turn it into a fabricated percentage.
    pub total: u64,
    pub files: u64,
}
pub type Callback<'a> = dyn FnMut(&InstallProgress) -> io::Result<()> + 'a;

pub struct Reporter<'a> {
    callback: Option<&'a mut Callback<'a>>,
    last: Instant,
}
impl<'a> Reporter<'a> {
    pub fn new(callback: Option<&'a mut Callback<'a>>) -> Self {
        Self {
            callback,
            last: Instant::now(),
        }
    }
    pub fn event(
        &mut self,
        stage: &'static str,
        item: &str,
        completed: u64,
        total: u64,
        files: u64,
    ) -> io::Result<()> {
        self.emit(stage, item, "", completed, total, files)
    }
    pub fn update(
        &mut self,
        stage: &'static str,
        item: &str,
        path: &str,
        completed: u64,
        total: u64,
        files: u64,
    ) -> io::Result<()> {
        if self.callback.is_none() || self.last.elapsed() < Duration::from_millis(500) {
            return Ok(());
        }
        self.emit(stage, item, path, completed, total, files)
    }
    fn emit(
        &mut self,
        stage: &'static str,
        item: &str,
        path: &str,
        completed: u64,
        total: u64,
        files: u64,
    ) -> io::Result<()> {
        if let Some(callback) = &mut self.callback {
            callback(&InstallProgress {
                stage,
                item: item.into(),
                path: path.into(),
                completed,
                total,
                files,
            })?;
            self.last = Instant::now();
        }
        Ok(())
    }
}

/// Accounts for actual bytes read, including inside a single large file.
pub struct ProgressReader<'a, 'b, R> {
    pub inner: R,
    pub reporter: &'a mut Reporter<'b>,
    pub stage: &'static str,
    pub item: &'a str,
    pub path: &'a str,
    pub completed: u64,
    pub total: u64,
    pub files: u64,
}
impl<R: Read> Read for ProgressReader<'_, '_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(bytes)?;
        self.completed += count as u64;
        self.reporter.update(
            self.stage,
            self.item,
            self.path,
            self.completed,
            self.total,
            self.files,
        )?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_real_bytes_and_callback_can_stop_the_import() {
        let mut events = Vec::new();
        let mut callback = |p: &InstallProgress| {
            events.push((p.stage, p.completed));
            Ok(())
        };
        {
            let mut reporter = Reporter::new(Some(&mut callback));
            reporter.event("unpack", "system", 0, 6, 0).unwrap();
            reporter.last = Instant::now() - Duration::from_secs(1);
            let mut reader = ProgressReader {
                inner: io::Cursor::new(b"abcdef"),
                reporter: &mut reporter,
                stage: "unpack",
                item: "system",
                path: "",
                completed: 0,
                total: 6,
                files: 0,
            };
            let mut output = [0; 3];
            assert_eq!(reader.read(&mut output).unwrap(), 3);
            assert_eq!(&output, b"abc");
        }
        assert_eq!(events, vec![("unpack", 0), ("unpack", 3)]);
        let mut callback =
            |_: &InstallProgress| Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        let mut reporter = Reporter::new(Some(&mut callback));
        assert_eq!(
            reporter.event("store", "", 0, 0, 0).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }
}
