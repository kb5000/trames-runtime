// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual shared OFDs for admitted resources, with explicit owner-only control.
use super::*;

#[derive(Clone)]
pub(super) enum OpenHandle {
    Shared(Arc<SharedOpenDescription>),
    Owner(Rc<RefCell<OpenDescription>>),
}
#[derive(Clone)]
pub(super) enum OpenWeak {
    Shared(std::sync::Weak<SharedOpenDescription>),
    Owner(Weak<RefCell<OpenDescription>>),
}
pub(super) enum OpenRead<'a> {
    Shared(OpenDescription),
    Owner(std::cell::Ref<'a, OpenDescription>),
}
pub(super) enum OpenWrite<'a> {
    Shared(OpenDescription),
    Owner(std::cell::RefMut<'a, OpenDescription>),
}
impl OpenDescription {
    pub(super) fn shared_projection(shared: Arc<SharedOpenDescription>) -> Self {
        Self {
            shared,
            position: 0,
            socket: None,
            anonymous: None,
            local: None,
            pty: None,
            namespace: None,
            oom: None,
            network_control: None,
            mount: None,
        }
    }
    fn shareable(&self) -> bool {
        if self.socket.is_some()
            || self.anonymous.is_some()
            || self.local.is_some()
            || self.pty.is_some()
            || self.namespace.is_some()
            || self.oom.is_some()
            || self.network_control.is_some()
            || self.mount.is_some()
            || self.bridge.is_some()
            || self.kernel_log.is_some()
        {
            return false;
        }
        self.pipe.is_some()
            || self.node.as_ref().is_some_and(|node| {
                let node = node.borrow();
                !node.volatile && node.seals.is_none() && matches!(node.content, Content::File(_))
            })
    }
}
impl OpenHandle {
    pub(super) fn new(open: OpenDescription) -> Self {
        if open.shareable() {
            Self::Shared(open.shared.clone())
        } else {
            Self::Owner(Rc::new(RefCell::new(open)))
        }
    }
    pub(super) fn borrow(&self) -> OpenRead<'_> {
        match self {
            Self::Shared(open) => {
                OpenRead::Shared(OpenDescription::shared_projection(open.clone()))
            }
            Self::Owner(open) => OpenRead::Owner(open.borrow()),
        }
    }
    pub(super) fn borrow_mut(&self) -> OpenWrite<'_> {
        match self {
            Self::Shared(open) => {
                OpenWrite::Shared(OpenDescription::shared_projection(open.clone()))
            }
            Self::Owner(open) => OpenWrite::Owner(open.borrow_mut()),
        }
    }
    pub(super) fn downgrade(&self) -> OpenWeak {
        match self {
            Self::Shared(open) => OpenWeak::Shared(Arc::downgrade(open)),
            Self::Owner(open) => OpenWeak::Owner(Rc::downgrade(open)),
        }
    }
    pub(super) fn ptr_eq(a: &Self, b: &Self) -> bool {
        match (a, b) {
            (Self::Shared(a), Self::Shared(b)) => Arc::ptr_eq(a, b),
            (Self::Owner(a), Self::Owner(b)) => Rc::ptr_eq(a, b),
            _ => false,
        }
    }
    pub(super) fn identity(&self) -> usize {
        match self {
            Self::Shared(open) => Arc::as_ptr(open) as usize,
            Self::Owner(open) => Rc::as_ptr(open) as usize,
        }
    }
    #[cfg(test)]
    pub(super) fn strong_count(&self) -> usize {
        match self {
            Self::Shared(open) => Arc::strong_count(open),
            Self::Owner(open) => Rc::strong_count(open),
        }
    }
}
impl OpenWeak {
    pub(super) fn strong_count(&self) -> usize {
        match self {
            Self::Shared(open) => open.strong_count(),
            Self::Owner(open) => open.strong_count(),
        }
    }
    pub(super) fn upgrade(&self) -> Option<OpenHandle> {
        match self {
            Self::Shared(open) => open.upgrade().map(OpenHandle::Shared),
            Self::Owner(open) => open.upgrade().map(OpenHandle::Owner),
        }
    }
}
impl std::ops::Deref for OpenRead<'_> {
    type Target = OpenDescription;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Shared(open) => open,
            Self::Owner(open) => open,
        }
    }
}
impl std::ops::Deref for OpenWrite<'_> {
    type Target = OpenDescription;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Shared(open) => open,
            Self::Owner(open) => open,
        }
    }
}
impl std::ops::DerefMut for OpenWrite<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Shared(open) => open,
            Self::Owner(open) => open,
        }
    }
}
