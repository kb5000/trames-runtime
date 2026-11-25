// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn original(v: &Vfs, fd: u32) -> SharedFd {
    v.shared_files().lookup(fd).unwrap().unwrap()
}
fn splice(v: &Vfs, input: u32, output: u32, count: u64, flags: u32) -> FileWork {
    let (target, command) = splice_command(v, input, output, count, flags);
    FileWork::from_vfs(v, target, command)
}
fn splice_command(
    v: &Vfs,
    input: u32,
    output: u32,
    count: u64,
    flags: u32,
) -> (FileTarget, FileCommand) {
    let input = original(v, input);
    let output = original(v, output);
    assert!(StreamTransfer::admitted(&input, &output));
    let target = output.filesystem_target();
    (
        target,
        FileCommand::Transfer(Arc::new(std::sync::Mutex::new(StreamTransfer::new(
            input,
            output,
            Ok(None),
            Ok(None),
            count,
            true,
            flags,
        )))),
    )
}
fn device_fd(v: &Vfs) -> u32 {
    (0..32)
        .find(|&fd| v.fuse_device(fd).ok().flatten().is_some())
        .unwrap()
}
fn attributes(size: u64) -> [u8; 104] {
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&entry(10, 210, 0o100600)[40..]);
    attr[24..32].copy_from_slice(&size.to_le_bytes());
    attr
}
fn copy(v: &Vfs, input: u32, output: u32, range: bool) -> FileWork {
    FileWork::from_vfs(
        v,
        original(v, output).filesystem_target(),
        FileCommand::Copy {
            input: original(v, input).filesystem_target(),
            transfer: Arc::new(std::sync::Mutex::new(FileCopy::new(
                Ok(range.then_some(0)),
                Ok(range.then_some(8)),
                if range { 4 } else { 6 },
                range,
            ))),
        },
    )
}
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}

#[test]
fn device_splice_waits_on_original_connection_and_supports_pipe_replies() {
    let (mut v, dev) = mounted();
    let fd = device_fd(&v);
    let [reader, writer] = v.pipe(0).unwrap();
    let work = waiting(splice(&v, fd, writer, 8192, 0));
    assert!(!work.ready());
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(19, Arc::downgrade(&wake));
    let subscriptions = work.wait_sources(&signal).unwrap();
    assert!(!subscriptions.subscriptions.is_empty());
    let request = dev
        .daemon
        .get()
        .unwrap()
        .connection
        .request(3, 70, Caller::default(), &[0; 16])
        .unwrap();
    assert!(signal.ready() && work.ready());
    assert!(matches!(
        finish(work),
        Ok(FileValue::Transfer { count: 56, .. })
    ));
    let packet = v.read(reader, 8192).unwrap();
    assert_eq!(op(&packet), 3);
    let reply = reply(id(&packet), 0, &[0; 104]);
    v.write(writer, &reply).unwrap();
    assert!(
        matches!(finish(splice(&v, reader, fd, reply.len() as u64, 0)),
        Ok(FileValue::Transfer { count, .. }) if count == reply.len() as u64)
    );
    assert_eq!(request.take(), Some(Ok(vec![0; 104])));
    v.set_status_flags(fd, O_NONBLOCK).unwrap();
    assert!(matches!(
        finish(splice(&v, fd, writer, 8192, 0)),
        Err(Errno(11))
    ));
}

#[test]
fn device_splice_backpressure_cancellation_and_abort_leave_requests_unconsumed() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let fd = device_fd(&v);
    let [reader, writer] = v.pipe(0).unwrap();
    v.write(writer, &vec![1; PIPE_CAPACITY]).unwrap();
    let request = dev
        .daemon
        .get()
        .unwrap()
        .connection
        .request(3, 70, Caller::default(), &[0; 16])
        .unwrap();
    let work = waiting(splice(&v, fd, writer, 8192, 0));
    assert!(!work.ready());
    drop(work);
    let packet = receive(c, 3, 70);
    answer(c, &packet, &[0; 104]);
    assert_eq!(request.take(), Some(Ok(vec![0; 104])));
    v.read(reader, PIPE_CAPACITY).unwrap();
    let work = waiting(splice(&v, fd, writer, 8192, 0));
    c.abort();
    assert!(work.ready());
    assert!(matches!(finish(work), Err(Errno(19))));
    assert_eq!(v.read(reader, 1), Err(Errno(11)));
}

#[test]
fn sendfile_keeps_metadata_internal_and_never_rewrites_an_accepted_output() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, source) = open_file(&v, c, 2);
    let output = v.open_at(AT_FDCWD, b"/output", O_CREAT | 2, 0o600).unwrap();
    let accepted = original(&v, source);
    let work = waiting(copy(&v, source, output, false));
    answer(c, &receive(c, 3, 10), &attributes(6));
    let work = waiting(work);
    let read = receive(c, 15, 10);
    let competing = waiting(FileWork::from_vfs(
        &v,
        accepted.filesystem_target(),
        FileCommand::Read {
            count: 1,
            offset: None,
        },
    ));
    answer(c, &receive(c, 15, 10), b"a");
    let FileValue::Read(competing) = finish(competing).unwrap() else {
        panic!()
    };
    let (_, mut position) = competing.into_parts();
    answer(c, &read, b"abcdef");
    let work = waiting(work);
    assert_eq!(v.pread(output, 6, 0).unwrap(), b"abcdef");
    assert_eq!(v.seek(output, 0, 1).unwrap(), 6);
    assert!(!work.ready());
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(20, Arc::downgrade(&wake));
    let _subscriptions = work.wait_sources(&signal).unwrap();
    position.record(1);
    drop(position);
    assert!(signal.ready() && work.ready());
    assert!(matches!(
        finish(work),
        Ok(FileValue::Transfer {
            count: 6,
            from: 6,
            to: None
        })
    ));
    assert_eq!(
        v.seek(output, 0, 1).unwrap(),
        6,
        "the output was written once"
    );
    assert_eq!(accepted.open.file_position.snapshot(), 6);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "GETATTR and READ were not replayed"
    );
}

#[test]
fn copy_to_fuse_retains_accepted_bytes_and_original_source_after_fd_reuse() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, output) = open_file(&v, c, 2);
    v.import_file(b"/source", b"abcdef".to_vec()).unwrap();
    let source = v.open_at(AT_FDCWD, b"/source", 2, 0).unwrap();
    let accepted = original(&v, source);
    let work = waiting(copy(&v, source, output, false));
    let work = no_capabilities(c, work);
    let write = receive(c, 16, 10);
    assert_eq!(&write[80..], b"abcdef");
    v.pwrite(source, b"newnew", 0).unwrap();
    v.shared_files().close_range(source, source, 0, 1).unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        source
    );
    answer(c, &write, &3u64.to_le_bytes());
    assert!(matches!(
        finish(work),
        Ok(FileValue::Transfer {
            count: 3,
            from: 3,
            to: None
        })
    ));
    assert_eq!(accepted.open.file_position.snapshot(), 3);
    assert_eq!(v.seek(source, 0, 1).unwrap(), 0);
    assert_eq!(original(&v, output).open.file_position.snapshot(), 3);
}

#[test]
fn copy_range_between_fuse_ofds_awaits_both_stats_and_preserves_explicit_offsets() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, source) = open_file(&v, c, 2);
    let (_, output) = open_file(&v, c, 2);
    let work = waiting(copy(&v, source, output, true));
    answer(c, &receive(c, 3, 10), &attributes(16));
    let work = waiting(work);
    answer(c, &receive(c, 3, 10), &attributes(16));
    let work = waiting(work);
    answer(c, &receive(c, 15, 10), b"abcd");
    let work = no_capabilities(c, waiting(work));
    let write = receive(c, 16, 10);
    assert_eq!(&write[48..56], &8u64.to_le_bytes());
    assert_eq!(&write[80..], b"abcd");
    answer(c, &write, &4u64.to_le_bytes());
    assert!(matches!(
        finish(work),
        Ok(FileValue::Transfer {
            count: 4,
            from: 4,
            to: Some(12)
        })
    ));
    assert_eq!(original(&v, source).open.file_position.snapshot(), 0);
    assert_eq!(original(&v, output).open.file_position.snapshot(), 0);
}

#[test]
fn cancelling_copy_read_never_writes_output_or_advances_source() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, source) = open_file(&v, c, 2);
    let output = v.open_at(AT_FDCWD, b"/output", O_CREAT | 2, 0o600).unwrap();
    let work = waiting(copy(&v, source, output, false));
    answer(c, &receive(c, 3, 10), &attributes(6));
    let work = waiting(work);
    let read = receive(c, 15, 10);
    drop(work);
    let interrupt = receive(c, 36, 0);
    assert_eq!(&interrupt[40..48], &read[8..16]);
    answer(c, &read, b"abcdef");
    assert_eq!(v.pread(output, 6, 0).unwrap(), b"");
    assert_eq!(original(&v, source).open.file_position.snapshot(), 0);
}

#[test]
fn splice_from_fuse_retains_read_reply_until_the_original_pipe_has_capacity() {
    for mode in 0..3 {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let (paths, source) = open_file(&v, c, 2);
        let stat = waiting(
            paths
                .fuse_file_work(source, FileCommand::Stat)
                .unwrap()
                .unwrap(),
        );
        answer(c, &receive(c, 3, 10), &attributes(64));
        assert!(matches!(finish(stat), Ok(FileValue::FuseStat(..))));
        let [reader, writer] = v.pipe(0).unwrap();
        let (target, command) = splice_command(&v, source, writer, 64, 0);
        let outcome = match mode {
            0 => FileWork::from_vfs(&v, target, command).run(),
            1 => FileWork::run_inline(&paths, target, command),
            _ => FileWork::run_owned(&mut v, target, command),
        };
        let FileOutcome::Waiting(work) = outcome else {
            panic!("original source daemon must retain its transfer")
        };
        let read = receive(c, 15, 10);
        answer(c, &read, &[7; 64]);
        v.write(writer, &vec![1; PIPE_CAPACITY]).unwrap();
        let work = waiting(work);
        assert!(!work.ready());
        v.read(reader, PIPE_CAPACITY).unwrap();
        assert!(work.ready());
        let result = finish(work);
        assert!(
            matches!(
                result,
                Ok(FileValue::Transfer {
                    count: 64,
                    from: 64,
                    ..
                })
            ),
            "{}",
            result.err().map_or(0, |e| e.0)
        );
        assert_eq!(v.read(reader, 64).unwrap(), [7; 64]);
        assert_eq!(original(&v, source).open.file_position.snapshot(), 64);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn splice_waits_for_original_regular_position_before_consuming_or_writing() {
    let mut v = Vfs::default();
    v.import_file(b"/source", b"abcdef".to_vec()).unwrap();
    let source = v.open_at(AT_FDCWD, b"/source", 0, 0).unwrap();
    let FileValue::Read(read) = finish(FileWork::from_vfs(
        &v,
        original(&v, source).filesystem_target(),
        FileCommand::Read {
            count: 1,
            offset: None,
        },
    ))
    .unwrap() else {
        panic!()
    };
    let (_, mut position) = read.into_parts();
    let [reader, writer] = v.pipe(0).unwrap();
    let (target, command) = splice_command(&v, source, writer, 1, 0);
    let FileOutcome::Waiting(work) = FileWork::run_inline(&v.path_queries(), target, command)
    else {
        panic!("original offset wait")
    };
    assert!(!work.ready());
    assert_eq!(v.read(reader, 1), Err(Errno(11)));
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(21, Arc::downgrade(&wake));
    let _subscriptions = work.wait_sources(&signal).unwrap();
    position.record(1);
    drop(position);
    assert!(signal.ready() && work.ready());
    assert!(matches!(
        finish(work),
        Ok(FileValue::Transfer {
            count: 1,
            from: 2,
            ..
        })
    ));
    assert_eq!(v.read(reader, 1).unwrap(), b"b");
}

#[test]
fn copy_waits_for_original_output_position_and_keeps_its_staged_input() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, source) = open_file(&v, c, 2);
    v.import_file(b"/output", b"X".to_vec()).unwrap();
    let output = v.open_at(AT_FDCWD, b"/output", 2, 0).unwrap();
    let work = waiting(copy(&v, source, output, false));
    answer(c, &receive(c, 3, 10), &attributes(6));
    let work = waiting(work);
    let input = receive(c, 15, 10);
    let FileValue::Read(read) = finish(FileWork::from_vfs(
        &v,
        original(&v, output).filesystem_target(),
        FileCommand::Read {
            count: 1,
            offset: None,
        },
    ))
    .unwrap() else {
        panic!()
    };
    let (_, mut position) = read.into_parts();
    answer(c, &input, b"abcdef");
    let work = waiting(work);
    assert!(!work.ready());
    position.record(1);
    drop(position);
    assert!(work.ready());
    assert!(matches!(
        finish(work),
        Ok(FileValue::Transfer { count: 6, .. })
    ));
    assert_eq!(v.pread(output, 7, 0).unwrap(), b"Xabcdef");
    assert_eq!(v.seek(output, 0, 1).unwrap(), 7);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "the accepted input was not reread"
    );
}

#[test]
fn canonical_splice_query_retains_the_entire_transfer_across_device_wait() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let fd = device_fd(&v);
    let [reader, writer] = v.pipe(0).unwrap();
    let paths = v.path_queries();
    let (result, _) = paths.uring_original(None, |view| view.splice(fd, writer, 8192, None, None));
    assert!(result.is_none());
    let work = paths.take_fuse_stat().unwrap();
    let request = dev
        .daemon
        .get()
        .unwrap()
        .connection
        .request(3, 70, Caller::default(), &[0; 16])
        .unwrap();
    assert!(matches!(
        finish(work),
        Ok(FileValue::Transfer { count: 56, .. })
    ));
    let packet = v.read(reader, 8192).unwrap();
    answer(c, &packet, &[0; 104]);
    assert_eq!(request.take(), Some(Ok(vec![0; 104])));
}
