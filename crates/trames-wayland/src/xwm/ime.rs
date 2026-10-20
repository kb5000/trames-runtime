// SPDX-License-Identifier: GPL-3.0-or-later
//! Original xim-rs XIM server on the XWM's existing x11rb connection. UIKit
//! owns composition/candidates; only confirmed text crosses XIM_COMMIT.
use super::*;
use xim::{
    x11rb::{HasConnection, X11rbServer},
    InputContext, InputStyle, Server, ServerError, ServerHandler, UserInputContext, XimConnections,
};

#[derive(Clone, Debug)]
pub(crate) struct Text {
    pub token: u64,
    pub window: u32,
    pub caret: [i32; 4],
    pub generation: u64,
}
type Im<'a> = X11rbServer<&'a RustConnection>;
struct Context {
    ic: InputContext,
    text: Text,
}
struct Handler {
    contexts: BTreeMap<u64, Context>,
    next: u64,
    live: std::collections::BTreeSet<u64>,
    focused: Option<u64>,
    generation: u64,
    updates: mpsc::SyncSender<Update>,
}
impl Handler {
    fn publish(&self) {
        let text = self.focused.and_then(|id| self.contexts.get(&id)).map(|c| {
            let mut text = c.text.clone();
            text.generation = self.generation;
            text
        });
        let _ = self.updates.try_send(Update::Text(text));
    }
    fn refresh(&mut self, server: &Im<'_>, u: &UserInputContext<u64>) {
        let ic = &u.ic;
        let Some(mut window) = ic.app_win().or(ic.app_focus_win()).map(|w| w.get()) else {
            return;
        };
        let root = server.conn().setup().roots[0].root;
        for _ in 0..32 {
            let Ok(cookie) = server.conn().query_tree(window) else {
                return;
            };
            let Ok(tree) = cookie.reply() else { return };
            if tree.parent == root {
                break;
            }
            if tree.parent == NONE {
                return;
            }
            window = tree.parent;
        }
        let spot = ic.preedit_spot();
        let caret = ic
            .app_focus_win()
            .or(ic.app_win())
            .and_then(|source| {
                server
                    .conn()
                    .translate_coordinates(source.get(), window, spot.x, spot.y)
                    .ok()?
                    .reply()
                    .ok()
            })
            .map(|p| [i32::from(p.dst_x), i32::from(p.dst_y), 1, 20])
            .unwrap_or([i32::from(spot.x), i32::from(spot.y), 1, 20]);
        let text = Text {
            token: u.user_data,
            window,
            caret,
            generation: self.generation,
        };
        self.contexts.insert(
            u.user_data,
            Context {
                ic: InputContext::new(
                    ic.client_win(),
                    ic.input_method_id(),
                    ic.input_context_id(),
                    ic.locale().into(),
                ),
                text,
            },
        );
        if self.focused == Some(u.user_data) {
            self.publish()
        }
    }
}
impl ServerHandler<Im<'_>> for Handler {
    type InputContextData = u64;
    type InputStyleArray = [InputStyle; 2];
    fn new_ic_data(
        &mut self,
        _: &mut Im<'_>,
        _: InputStyle,
    ) -> std::result::Result<u64, ServerError> {
        if self.live.len() >= 256 {
            return Err(ServerError::Internal("XIM context limit".into()));
        }
        self.next = self.next.wrapping_add(1).max(1);
        self.live.insert(self.next);
        Ok(self.next)
    }
    fn input_styles(&self) -> Self::InputStyleArray {
        [
            InputStyle::PREEDIT_NOTHING | InputStyle::STATUS_NOTHING,
            InputStyle::PREEDIT_NONE | InputStyle::STATUS_NONE,
        ]
    }
    fn filter_events(&self) -> u32 {
        0
    }
    fn handle_connect(&mut self, _: &mut Im<'_>) -> std::result::Result<(), ServerError> {
        Ok(())
    }
    fn handle_create_ic(
        &mut self,
        s: &mut Im<'_>,
        u: &mut UserInputContext<u64>,
    ) -> std::result::Result<(), ServerError> {
        self.refresh(s, u);
        s.set_event_mask(&u.ic, 0, 0)
    }
    fn handle_destroy_ic(
        &mut self,
        _: &mut Im<'_>,
        u: UserInputContext<u64>,
    ) -> std::result::Result<(), ServerError> {
        self.contexts.remove(&u.user_data);
        self.live.remove(&u.user_data);
        if self.focused == Some(u.user_data) {
            self.focused = None;
            self.publish()
        }
        Ok(())
    }
    fn handle_reset_ic(
        &mut self,
        _: &mut Im<'_>,
        u: &mut UserInputContext<u64>,
    ) -> std::result::Result<String, ServerError> {
        if self.focused == Some(u.user_data) {
            self.generation = self.generation.wrapping_add(1);
            self.publish();
        }
        Ok(String::new())
    }
    fn handle_set_ic_values(
        &mut self,
        s: &mut Im<'_>,
        u: &mut UserInputContext<u64>,
    ) -> std::result::Result<(), ServerError> {
        self.refresh(s, u);
        Ok(())
    }
    fn handle_set_focus(
        &mut self,
        s: &mut Im<'_>,
        u: &mut UserInputContext<u64>,
    ) -> std::result::Result<(), ServerError> {
        self.refresh(s, u);
        self.generation = self.generation.wrapping_add(1);
        self.focused = Some(u.user_data);
        self.publish();
        Ok(())
    }
    fn handle_unset_focus(
        &mut self,
        _: &mut Im<'_>,
        u: &mut UserInputContext<u64>,
    ) -> std::result::Result<(), ServerError> {
        if self.focused == Some(u.user_data) {
            self.focused = None;
            self.publish()
        }
        Ok(())
    }
    fn handle_forward_event(
        &mut self,
        _: &mut Im<'_>,
        _: &mut UserInputContext<u64>,
        _: &KeyPressEvent,
    ) -> std::result::Result<bool, ServerError> {
        Ok(false)
    }
}
pub(super) struct Ime<'a> {
    connection: &'a RustConnection,
    server: Im<'a>,
    connections: XimConnections<u64>,
    handler: Handler,
    protocol: u32,
    connect: u32,
    owner: u32,
    clients: BTreeMap<u32, u32>,
}
impl<'a> Ime<'a> {
    pub fn new(c: &'a RustConnection, updates: mpsc::SyncSender<Update>) -> Result<Self> {
        let server = X11rbServer::init(c, 0, "trames", xim::ALL_LOCALES)?;
        let atom = |name: &[u8]| -> Result<u32> { Ok(c.intern_atom(false, name)?.reply()?.atom) };
        let owner = c
            .get_selection_owner(atom(b"@server=trames")?)?
            .reply()?
            .owner;
        Ok(Self {
            connection: c,
            server,
            connections: XimConnections::new(),
            handler: Handler {
                contexts: BTreeMap::new(),
                next: 0,
                live: Default::default(),
                focused: None,
                generation: 0,
                updates,
            },
            protocol: atom(b"_XIM_PROTOCOL")?,
            connect: atom(b"_XIM_XCONNECT")?,
            owner,
            clients: BTreeMap::new(),
        })
    }
    pub fn filter(&mut self, e: &Event) -> Result<bool> {
        let c = self.connection;
        if let Event::DestroyNotify(e) = e {
            if let Some(transport) = self.clients.remove(&e.window) {
                if let Some(mut conn) = self.connections.remove_connection(transport) {
                    conn.disconnect(&mut self.server, &mut self.handler)?;
                }
                c.destroy_window(transport)?;
            }
            return Ok(false);
        }
        match e {
            Event::ClientMessage(m) if m.type_ == self.connect => {
                if self.clients.len() >= 64 || m.format != 32 {
                    return Ok(true);
                }
                let client = m.data.as_data32()[0];
                if let Some(old) = self.clients.remove(&client) {
                    if let Some(mut conn) = self.connections.remove_connection(old) {
                        conn.disconnect(&mut self.server, &mut self.handler)?;
                    }
                    c.destroy_window(old)?;
                }
                let old = c.query_tree(self.owner)?.reply()?.children;
                self.server
                    .filter_event(e, &mut self.connections, &mut self.handler)?;
                if let Some(window) = c
                    .query_tree(self.owner)?
                    .reply()?
                    .children
                    .into_iter()
                    .find(|id| !old.contains(id))
                {
                    let client = m.data.as_data32()[0];
                    c.change_window_attributes(
                        client,
                        &ChangeWindowAttributesAux::new().event_mask(EventMask::STRUCTURE_NOTIFY),
                    )?;
                    self.clients.insert(client, window);
                }
                Ok(true)
            }
            Event::ClientMessage(m) if m.type_ == self.protocol => {
                if m.format == 32 && m.data.as_data32()[0] > 16384 {
                    return Ok(true);
                }
                if m.format != 8 && m.format != 32 {
                    return Ok(true);
                }
                // Malformed/closed individual input methods cannot take down
                // other X11 windows or the native compositor.
                if let Err(error) =
                    self.server
                        .filter_event(e, &mut self.connections, &mut self.handler)
                {
                    eprintln!("trames-xim: {error}");
                }

                Ok(true)
            }
            Event::SelectionRequest(r) if r.owner == self.owner => {
                self.server
                    .filter_event(e, &mut self.connections, &mut self.handler)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    pub fn commit(&mut self, token: u64, text: &str) -> Result<()> {
        if text.len() <= 4096 && !text.contains('\0') && self.handler.focused == Some(token) {
            if let Some(c) = self.handler.contexts.get(&token) {
                self.server.commit(&c.ic, text)?
            }
        }
        Ok(())
    }
}
