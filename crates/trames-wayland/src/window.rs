// SPDX-License-Identifier: GPL-3.0-or-later
//! Native window state is separate from the legacy three-mode embedding API.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowState {
    pub maximized: bool,
    pub fullscreen: bool,
    pub minimized: bool,
    pub resizing: bool,
}
/// Ordered requests for independent state fields; native replies may describe
/// an earlier operation without cancelling a later, undispatched one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowRequest {
    pub serial: u64,
    pub maximized: u64,
    pub fullscreen: u64,
    pub minimized: u64,
}
impl WindowRequest {
    pub fn changes(self, old: Self) -> impl Iterator<Item = u8> {
        let mut fields = [
            (1, self.maximized, old.maximized),
            (2, self.fullscreen, old.fullscreen),
            (4, self.minimized, old.minimized),
        ];
        fields.sort_unstable_by_key(|f| (f.1, f.0));
        fields.into_iter().filter(|f| f.1 != f.2).map(|f| f.0)
    }
}
impl WindowState {
    pub(crate) fn mode(self) -> WindowMode {
        if self.minimized {
            WindowMode::Minimized
        } else if self.maximized || self.fullscreen {
            WindowMode::Maximized
        } else {
            WindowMode::Floating
        }
    }
}
impl State {
    pub(crate) fn request_window_state(&mut self, id: u64, next: WindowState, fields: u8) {
        let Some(s) = self.surfaces.get_mut(&id) else {
            return;
        };
        if s.window_state == next && !self.native_windows {
            return;
        }
        let floating = if self.native_windows {
            s.confirmed_window_state.mode() == WindowMode::Floating
        } else {
            s.mode == WindowMode::Floating
        };
        if floating && s.mode == WindowMode::Floating && next.mode() != WindowMode::Floating {
            s.restore_size = s.size;
        }
        s.window_state = next;
        let serial = s.window_request.serial.wrapping_add(1).max(1);
        s.window_request.serial = serial;
        if fields & 1 != 0 {
            s.window_request.maximized = serial;
        }
        if fields & 2 != 0 {
            s.window_request.fullscreen = serial;
        }
        if fields & 4 != 0 {
            s.window_request.minimized = serial;
        }
        s.mode = next.mode();
        if !self.native_windows {
            s.confirmed_window_state = next;
            s.requested_size = if next.maximized || next.fullscreen {
                self.viewport
            } else {
                s.restore_size
            };
            self.xcommand(id, |xid| crate::xwm::Command::State(xid, next));
            self.configure(id);
        }
        self.changed();
        if next.minimized && self.focus_toplevel(self.seat.focus) == Some(id) {
            self.input(InputEvent::Focus { window: None });
        }
    }
    pub(crate) fn window_parent(&mut self, id: u64, parent: Option<u64>) -> bool {
        let mut next = parent;
        for _ in 0..=self.surfaces.len() {
            let Some(p) = next else {
                if let Some(s) = self.surfaces.get_mut(&id) {
                    s.top_parent = parent;
                }
                self.changed();
                return true;
            };
            if p == id {
                return false;
            }
            let Some(s) = self.surfaces.get(&p) else {
                return false;
            };
            if !s.is_toplevel() {
                return false;
            }
            next = s.top_parent;
        }
        false
    }
}
impl Compositor {
    /// A native presenter owns geometry/state confirmation. Legacy embeddings
    /// retain the original viewport-based behavior until they opt in.
    pub fn manage_windows(&mut self) {
        self.state.native_windows = true;
    }
    pub fn window_states(&self) -> std::collections::BTreeMap<u64, WindowState> {
        self.state
            .surfaces
            .iter()
            .filter(|(_, s)| s.is_toplevel())
            .map(|(&id, s)| (id, s.window_state))
            .collect()
    }
    pub fn window_requests(&self) -> std::collections::BTreeMap<u64, WindowRequest> {
        self.state
            .surfaces
            .iter()
            .filter(|(_, s)| s.is_toplevel())
            .map(|(&id, s)| (id, s.window_request))
            .collect()
    }
    pub fn configure_window(
        &mut self,
        id: u64,
        width: u32,
        height: u32,
        next: WindowState,
        request: u64,
    ) {
        let Some(s) = self.state.surfaces.get_mut(&id) else {
            return;
        };
        let restoring = s.confirmed_window_state.mode() != WindowMode::Floating
            && next.mode() == WindowMode::Floating;
        if request == s.window_request.serial {
            s.window_state = next;
            s.mode = next.mode();
        }
        s.confirmed_window_state = next;
        let (width, height) = if restoring {
            (
                if width == 0 { s.restore_size.0 } else { width },
                if height == 0 {
                    s.restore_size.1
                } else {
                    height
                },
            )
        } else {
            (width, height)
        };
        if width > 0 && height > 0 && width <= 4096 && height <= 4096 {
            s.requested_size = (width, height);
            if next.mode() == WindowMode::Floating {
                s.restore_size = (width, height);
            }
        }
        self.state
            .xcommand(id, |xid| crate::xwm::Command::State(xid, next));
        self.state.configure(id);
        self.state.changed();
        if next.minimized && self.state.focus_toplevel(self.state.seat.focus) == Some(id) {
            self.state.input(InputEvent::Focus { window: None });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scene::{Surface, SurfaceKey};
    fn windows() -> Compositor {
        let mut c = Compositor::new().unwrap();
        let (_peer, socket) = std::os::unix::net::UnixStream::pair().unwrap();
        c.connect(
            socket,
            ClientIdentity {
                connection: 1,
                pid: 1,
                uid: 0,
                gid: 0,
            },
        )
        .unwrap();
        let client = &c.clients[&1];
        let handle = c.display.handle();
        for id in 1..=3 {
            let resource = client
                .create_resource::<wayland_server::protocol::wl_surface::WlSurface, _, State>(
                    &handle,
                    4,
                    SurfaceKey(id),
                )
                .unwrap();
            let mut s = Surface::new(resource, 1);
            s.top=Some(client.create_resource::<wayland_protocols::xdg::shell::server::xdg_toplevel::XdgToplevel,_,State>(&handle,3,SurfaceKey(id)).unwrap());
            s.size = (240, 160);
            s.requested_size = s.size;
            c.state.surfaces.insert(id, s);
        }
        c
    }
    fn confirm(c: &mut Compositor, id: u64, width: u32, height: u32, next: WindowState) {
        let request = c.state.surfaces[&id].window_request.serial;
        c.configure_window(id, width, height, next, request);
    }
    #[test]
    fn coalesced_field_requests_preserve_order_and_do_not_invent_other_actions() {
        let mut c = windows();
        c.manage_windows();
        let max = WindowState {
            maximized: true,
            ..Default::default()
        };
        c.state.request_window_state(1, max, 1);
        let old = c.window_requests()[&1];
        assert_eq!(
            old.changes(WindowRequest::default()).collect::<Vec<_>>(),
            [1]
        );
        c.state.request_window_state(
            1,
            WindowState {
                fullscreen: true,
                ..max
            },
            2,
        );
        c.state.request_window_state(
            1,
            WindowState {
                fullscreen: true,
                ..Default::default()
            },
            1,
        );
        assert_eq!(
            c.window_requests()[&1].changes(old).collect::<Vec<_>>(),
            [2, 1]
        );
    }
    #[test]
    fn late_native_confirmation_cannot_erase_an_undispatched_request() {
        let mut c = windows();
        c.manage_windows();
        let maximum = WindowState {
            maximized: true,
            ..Default::default()
        };
        c.state.request_window_state(1, maximum, 1);
        let first = c.state.surfaces[&1].window_request.serial;
        c.state.request_window_state(1, WindowState::default(), 3);
        let before = c.state.surfaces[&1].window_request.serial;
        c.state.request_window_state(1, WindowState::default(), 3);
        let second = c.state.surfaces[&1].window_request.serial;
        assert!(second > before);
        c.configure_window(1, 900, 700, maximum, first);
        assert_eq!(c.window_states()[&1], WindowState::default());
        assert_eq!(c.state.surfaces[&1].confirmed_window_state, maximum);
        assert_eq!(c.window_requests()[&1].serial, second);
        c.configure_window(1, 0, 0, WindowState::default(), second);
        assert_eq!(c.state.surfaces[&1].requested_size, (240, 160));
    }
    #[test]
    fn native_state_waits_for_host_confirmation_and_preserves_restore_size() {
        let mut c = windows();
        c.manage_windows();
        let serial = c.state.serial;
        let maximized = WindowState {
            maximized: true,
            ..Default::default()
        };
        c.state.request_window_state(1, maximized, 1);
        assert_eq!(c.state.serial, serial);
        assert_eq!(c.state.surfaces[&1].requested_size, (240, 160));
        confirm(&mut c, 1, 900, 700, maximized);
        let fullscreen = WindowState {
            fullscreen: true,
            ..maximized
        };
        c.state.request_window_state(1, fullscreen, 2);
        confirm(&mut c, 1, 1024, 768, fullscreen);
        assert_eq!(c.window_states()[&1], fullscreen);
        assert_eq!(c.state.surfaces[&1].restore_size, (240, 160));
        c.state.request_window_state(1, maximized, 1);
        confirm(&mut c, 1, 900, 700, maximized);
        c.state.request_window_state(1, WindowState::default(), 3);
        confirm(&mut c, 1, 0, 0, WindowState::default());
        assert_eq!(c.state.surfaces[&1].requested_size, (240, 160));
    }
    #[test]
    fn parent_cycles_are_rejected_without_replacing_the_existing_tree() {
        let mut c = windows();
        assert!(c.state.window_parent(2, Some(1)));
        assert!(c.state.window_parent(3, Some(2)));
        assert!(!c.state.window_parent(1, Some(3)));
        assert_eq!(c.state.surfaces[&1].top_parent, None);
        assert!(!c.state.window_parent(2, Some(2)));
        assert_eq!(c.state.surfaces[&2].top_parent, Some(1));
        assert!(c.state.window_parent(2, None));
    }
}
