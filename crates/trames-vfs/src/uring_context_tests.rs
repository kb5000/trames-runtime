// SPDX-License-Identifier: GPL-3.0-or-later
//! Full original-resource admission is private to accepted asynchronous work.
use super::*;

struct Unavailable;
impl ProcSource for Unavailable {
    fn available(&self, _: ProcRefresh) -> bool {
        false
    }
    fn observe(&self, _: ProcQuery<'_>) -> RuntimeInfo {
        panic!("an absent live observer must not be called")
    }
}

#[test]
fn original_uring_context_keeps_files_credentials_namespace_and_private_admission() {
    let mut owner = Vfs::default();
    owner.set_runtime_info(1, RuntimeInfo::default());
    owner.set_proc_source(Arc::new(Unavailable));
    owner.mkdir_at(AT_FDCWD, b"/other", 0o755).unwrap();
    owner.import_file(b"/secret", b"secret".to_vec()).unwrap();
    owner.chmod_at(AT_FDCWD, b"/secret", 0o600).unwrap();
    let raw = owner.open_at(AT_FDCWD, b"/proc/version", 0, 0).unwrap();
    let retained = owner.retain_uring_fd(raw).unwrap();
    owner.credentials = Credentials::user(1000, 1000);
    let paths = owner.path_queries().retain_context();
    let publication = Arc::downgrade(&owner.pseudo);
    let original_files = owner.clone_with_files(true);
    // The current task subsequently has a different Files/fs_struct and root
    // credentials. Neither this task nor a CQ observer may donate them.
    let mut replacement = owner.clone_with_resources(false, false);
    replacement.credentials = Credentials::default();
    replacement.chroot(b"/other").unwrap();
    drop(owner);
    let result = std::thread::spawn(move || {
        assert_eq!(paths.stat_at(AT_FDCWD, b"/proc/version", false), None);
        let (result, signal) = paths.uring_original(None, |view| {
            assert_eq!(view.credentials.euid, 1000);
            assert_eq!(view.open_at(AT_FDCWD, b"/secret", 0, 0), Err(Errno(13)));
            let fd = view.open_at(AT_FDCWD, b"/proc/version", 0, 0)?;
            let bytes = view.with_uring_fd(&retained, |v, alias| v.read(alias, 8))?;
            Ok((fd, bytes))
        });
        assert!(!signal);
        let (fd, bytes) = result.unwrap().unwrap();
        assert_eq!(bytes, b"Linux ve");
        // Cold full admission must never persist in the ordinary resolver.
        assert_eq!(paths.stat_at(AT_FDCWD, b"/proc/version", false), None);
        assert!(!paths.view.borrow().query.as_ref().unwrap().original);
        // Live guest-mm content is not supplied by global publication.
        assert_eq!(
            paths
                .uring_original(None, |v| v.open_at(AT_FDCWD, b"/proc/1/environ", 0, 0))
                .0,
            None
        );
        fd
    })
    .join()
    .unwrap();
    assert!(original_files.stat_fd(result).is_ok());
    assert_eq!(replacement.stat_fd(result), Err(Errno(9)));
    drop(original_files);
    drop(replacement);
    assert!(
        publication.upgrade().is_none(),
        "no retained context or Files cycle"
    );
}

#[test]
fn original_uring_context_unwind_restores_policy_files_reader_and_signal_state() {
    struct Reader;
    impl SignalReader for Reader {
        fn poll(&self, _: u64) -> (u16, [u64; 2]) {
            (0, [0, 0])
        }
        fn take(&self, _: u64) -> Option<[u8; 128]> {
            None
        }
        fn subscribe(&self, _: &Arc<IoSignal>) -> Vec<IoSubscription> {
            Vec::new()
        }
    }
    let mut owner = Vfs::default();
    owner.set_runtime_info(1, RuntimeInfo::default());
    let paths = owner.path_queries();
    let original_pseudo = paths.view.borrow().pseudo.clone();
    let reader: Arc<dyn SignalReader> = Arc::new(Reader);
    let descriptors = DirectFds::default().with_signal_reader(Some(reader.clone()));
    paths.view.borrow().file_size_signal.set(true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        paths.uring_original(Some(&descriptors), |view| -> Result<()> {
            assert!(view.query.as_ref().unwrap().original);
            assert!(Arc::ptr_eq(
                view.signal_reader.borrow().as_ref().unwrap(),
                &reader
            ));
            view.file_size_signal.set(false);
            panic!("interrupt the private alias scope");
        });
    }));
    assert!(result.is_err());
    let view = paths.view.borrow();
    assert!(!view.query.as_ref().unwrap().original);
    assert!(Arc::ptr_eq(&view.pseudo, &original_pseudo));
    assert!(view.signal_reader.borrow().is_none());
    assert!(view.take_file_size_signal());
    assert_eq!(view.fds.entries().iter().count(), 0);
    drop(view);
    let (result, signal) = paths.uring_original(None, |view| -> Result<()> {
        view.file_size_signal.set(true);
        Err(Errno(27))
    });
    assert_eq!(result, Some(Err(Errno(27))));
    assert!(signal);
    assert!(!paths.view.borrow().take_file_size_signal());
}
