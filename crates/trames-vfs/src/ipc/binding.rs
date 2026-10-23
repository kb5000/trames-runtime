// SPDX-License-Identifier: GPL-3.0-or-later
//! Inodes retain a shared weak identity, never a local socket control object.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

struct Identity(AtomicBool);

#[derive(Clone, Default)]
pub(crate) struct PathBinding(std::sync::Weak<Identity>);
impl PathBinding {
    pub(super) fn is_live(&self) -> bool {
        self.0
            .upgrade()
            .is_some_and(|id| id.0.load(Ordering::Relaxed))
    }
    fn key(&self) -> usize {
        // Opaque routing key only; never dereferenced or exposed to the guest.
        // A retained Weak keeps this allocation's address from being reused.
        self.0.as_ptr() as usize
    }
}

/// Owner-side resolution until socket controls themselves are shared. All VFS
/// task clones share this domain, including after unshare/setns(CLONE_NEWNET):
/// pathname sockets belong to the filesystem, unlike abstract socket names.
#[derive(Clone, Default)]
pub(crate) struct PathBindings(Rc<RefCell<BTreeMap<usize, Weak<LocalSocket>>>>);
impl PathBindings {
    pub(super) fn bind(&self, socket: &Rc<LocalSocket>) -> OwnedBinding {
        let identity = Arc::new(Identity(AtomicBool::new(true)));
        let binding = OwnedBinding {
            identity,
            routes: self.clone(),
        };
        self.0
            .borrow_mut()
            .insert(binding.path().key(), Rc::downgrade(socket));
        binding
    }
    pub(super) fn resolve(&self, path: &PathBinding) -> Option<Rc<LocalSocket>> {
        if !path.is_live() {
            return None;
        }
        self.0.borrow().get(&path.key()).and_then(Weak::upgrade)
    }
}

pub(super) struct OwnedBinding {
    identity: Arc<Identity>,
    routes: PathBindings,
}
impl OwnedBinding {
    pub(super) fn path(&self) -> PathBinding {
        PathBinding(Arc::downgrade(&self.identity))
    }
}
impl Drop for OwnedBinding {
    fn drop(&mut self) {
        // A concurrent liveness reader may temporarily retain the identity.
        // Its Arc must not keep a closed binding alive. This flag is not a
        // byte-publication barrier; controls remain in the owner domain.
        self.identity.0.store(false, Ordering::Relaxed);
        self.routes.0.borrow_mut().remove(&self.path().key());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(path: &[u8]) -> Vec<u8> {
        [b"\x01\0".as_slice(), path, b"\0"].concat()
    }
    fn path(v: &Vfs, name: &[u8]) -> PathBinding {
        let resolved = v.resolve_final(AT_FDCWD, name, true).unwrap();
        let node = v.node(&resolved).unwrap();
        let Content::Socket(binding) = &node.borrow().content else {
            panic!("socket inode")
        };
        binding.clone()
    }
    fn listener(v: &mut Vfs, name: &[u8]) -> Rc<LocalSocket> {
        let socket = v.new_local(1).unwrap();
        v.local_bind(&socket, &address(name)).unwrap();
        socket.listen(2).unwrap();
        socket
    }

    #[test]
    fn shared_identity_readers_do_not_extend_closed_socket_lifetime() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<PathBinding>();
        let mut v = Vfs::default();
        let socket = listener(&mut v, b"/socket");
        let binding = path(&v, b"/socket");
        let weak = Rc::downgrade(&socket);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let reader = binding.clone();
        let thread = std::thread::spawn(move || {
            let retained_identity = reader.0.upgrade().unwrap();
            assert!(reader.is_live());
            ready_tx.send(()).unwrap();
            closed_rx.recv().unwrap();
            assert!(!reader.is_live());
            assert!(!retained_identity.0.load(Ordering::Relaxed));
        });
        ready_rx.recv().unwrap();
        assert!(Rc::ptr_eq(
            &v.path_bindings.resolve(&binding).unwrap(),
            &socket
        ));
        drop(socket);
        assert!(weak.upgrade().is_none());
        assert!(!binding.is_live());
        assert!(v.path_bindings.resolve(&binding).is_none());
        assert!(v.path_bindings.0.borrow().is_empty());
        closed_tx.send(()).unwrap();
        thread.join().unwrap();
        // The stale inode still exists; the pathname is not implicitly unlinked.
        let client = v.new_local(1).unwrap();
        assert_eq!(
            v.local_connect(&client, &address(b"/socket")),
            Err(Errno(111))
        );
        assert_eq!(v.local_bind(&client, &address(b"/socket")), Err(Errno(98)));
    }

    #[test]
    fn failed_inode_insert_releases_route_and_allows_retry() {
        let mut v = Vfs::default();
        let socket = v.new_local(1).unwrap();
        let limits = v.fs.borrow().limits;
        v.fs.borrow_mut().limits.nodes = 0;
        assert_eq!(v.local_bind(&socket, &address(b"/socket")), Err(Errno(28)));
        assert!(v.path_bindings.0.borrow().is_empty());
        assert!(socket.pathname_binding.get().is_none());
        assert_eq!(*socket.name.borrow(), [1, 0]);
        v.fs.borrow_mut().limits = limits;
        v.local_bind(&socket, &address(b"/socket")).unwrap();
        assert!(path(&v, b"/socket").is_live());
        assert_eq!(v.path_bindings.0.borrow().len(), 1);
    }

    #[test]
    fn restored_socket_inode_has_no_route_to_previous_live_instance() {
        let dir = std::env::temp_dir().join(format!("trames-unix-binding-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut v = Vfs::open_disk(&dir, DiskOptions::default()).unwrap();
        let server = listener(&mut v, b"/socket");
        let original = path(&v, b"/socket");
        v.checkpoint().unwrap();
        // Release the exclusive disk lock, keeping the actual socket alive.
        drop(v);
        // Even while the old socket is live, a separately restored guest must
        // not recover its host identity or its socket control reference.
        let restored = Vfs::open_disk(&dir, DiskOptions::default()).unwrap();
        assert!(!path(&restored, b"/socket").is_live());
        assert!(original.is_live());
        let client = restored.new_local(1).unwrap();
        assert_eq!(
            restored.local_connect(&client, &address(b"/socket")),
            Err(Errno(111))
        );
        drop((client, restored, server));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pathname_routes_cross_network_namespaces_but_abstract_names_do_not() {
        let mut v = Vfs::default();
        let server = listener(&mut v, b"/socket");
        let abstract_name = b"\x01\0\0private";
        let abstract_server = v.new_local(1).unwrap();
        v.local_bind(&abstract_server, abstract_name).unwrap();
        abstract_server.listen(1).unwrap();
        let mut child = v.clone();
        child.unshare_net().unwrap();
        let client = child.new_local(1).unwrap();
        assert_eq!(child.local_connect(&client, abstract_name), Err(Errno(111)));
        child.local_bind(&client, abstract_name).unwrap();
        child.local_connect(&client, &address(b"/socket")).unwrap();
        let accepted = server
            .listener
            .borrow_mut()
            .as_mut()
            .unwrap()
            .pending
            .pop_front()
            .unwrap();
        assert!(Rc::ptr_eq(&accepted.network, &v.root_network));
        assert!(!Rc::ptr_eq(&client.network, &v.root_network));
        let unrelated = Vfs::default();
        assert!(unrelated
            .path_bindings
            .resolve(&path(&v, b"/socket"))
            .is_none());
        assert_eq!(abstract_server.poll(1) & 1, 0);
    }

    #[test]
    fn hardlinks_and_replaced_paths_keep_distinct_binding_identities() {
        let mut v = Vfs::default();
        let old = listener(&mut v, b"/socket");
        let old_binding = path(&v, b"/socket");
        v.link_at(AT_FDCWD, b"/socket", AT_FDCWD, b"/alias")
            .unwrap();
        v.unlink_at(AT_FDCWD, b"/socket", false).unwrap();
        let new = listener(&mut v, b"/socket");
        let new_binding = path(&v, b"/socket");
        assert_ne!(old_binding.key(), new_binding.key());
        let c1 = v.new_local(1).unwrap();
        let c2 = v.new_local(1).unwrap();
        v.local_connect(&c1, &address(b"/alias")).unwrap();
        v.local_connect(&c2, &address(b"/socket")).unwrap();
        assert_eq!(old.listener.borrow().as_ref().unwrap().pending.len(), 1);
        assert_eq!(new.listener.borrow().as_ref().unwrap().pending.len(), 1);
        drop(old);
        assert!(v.path_bindings.resolve(&old_binding).is_none());
        assert!(Rc::ptr_eq(
            &v.path_bindings.resolve(&new_binding).unwrap(),
            &new
        ));
        let c3 = v.new_local(1).unwrap();
        assert_eq!(v.local_connect(&c3, &address(b"/alias")), Err(Errno(111)));
        v.local_connect(&c3, &address(b"/socket")).unwrap();
    }

    #[test]
    fn overlay_and_bind_aliases_resolve_original_socket_after_mount_unshare() {
        let mut v = Vfs::default();
        for dir in [
            b"/lower".as_slice(),
            b"/merged",
            b"/alias",
            b"/upper",
            b"/work",
        ] {
            v.mkdir_at(AT_FDCWD, dir, 0o755).unwrap();
        }
        let server = listener(&mut v, b"/lower/socket");
        v.mount(
            None,
            b"/merged",
            Some(b"overlay"),
            0,
            Some(b"lowerdir=/lower,upperdir=/upper,workdir=/work"),
        )
        .unwrap();
        v.mount(Some(b"/merged"), b"/alias", None, 4096, None)
            .unwrap();
        let mut child = v.clone();
        child.unshare_mounts().unwrap();
        child.unshare_net().unwrap();
        for name in [
            b"/lower/socket".as_slice(),
            b"/merged/socket",
            b"/alias/socket",
        ] {
            let client = child.new_local(1).unwrap();
            child.local_connect(&client, &address(name)).unwrap();
        }
        assert_eq!(server.listener.borrow().as_ref().unwrap().pending.len(), 3);
        drop(server);
        let client = child.new_local(1).unwrap();
        assert_eq!(
            child.local_connect(&client, &address(b"/alias/socket")),
            Err(Errno(111))
        );
    }
}
