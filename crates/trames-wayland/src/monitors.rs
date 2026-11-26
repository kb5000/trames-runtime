// SPDX-License-Identifier: GPL-3.0-or-later
//! Host monitor identities and logical geometry, independent of CPU/page geometry.
use crate::*;
use std::collections::{BTreeMap, BTreeSet};
use wayland_protocols::{
    wp::fractional_scale::v1::server::{
        wp_fractional_scale_manager_v1 as fm, wp_fractional_scale_v1 as fs,
    },
    xdg::xdg_output::zv1::server::{zxdg_output_manager_v1 as xm, zxdg_output_v1 as xo},
};
use wayland_server::{
    backend::GlobalId, protocol::wl_output, Client, DataInit, Dispatch, DisplayHandle,
    GlobalDispatch, New,
};
/// Native output identity and geometry. IDs and connector names remain stable
/// while an output is present; coordinates and sizes are logical unless named pixels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopOutput {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub position: (i32, i32),
    pub logical_size: (u32, u32),
    pub pixel_size: (u32, u32),
    pub physical_mm: (i32, i32),
    /// Preferred density in 1/120 units (120 = 1x), independent of page geometry.
    pub scale_120: u32,
    pub refresh_millihz: i32,
    pub transform: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MonitorKey(pub u64, u64);
struct Monitor {
    data: DesktopOutput,
    global: GlobalId,
    generation: u64,
    resources: Vec<wl_output::WlOutput>,
    xdg: Vec<(wl_output::WlOutput, xo::ZxdgOutputV1)>,
}
#[derive(Default)]
pub(crate) struct Monitors {
    pub active: bool,
    generation: u64,
    entries: BTreeMap<u64, Monitor>,
    pub members: BTreeMap<u64, BTreeSet<u64>>,
    pub scales: BTreeMap<u64, u32>,
    fractional: BTreeMap<u64, fs::WpFractionalScaleV1>,
    pub fullscreen: BTreeMap<u64, u64>,
}
impl Monitors {
    pub(crate) fn forget(&mut self, id: u64) {
        self.members.remove(&id);
        self.scales.remove(&id);
        self.fullscreen.remove(&id);
        self.fractional.remove(&id);
    }
}
fn client_id(r: &impl Resource) -> u64 {
    r.client()
        .and_then(|c| c.get_data::<ClientIdentity>().map(|i| i.connection))
        .unwrap_or(0)
}
fn integer_scale(s: u32) -> i32 {
    s.div_ceil(120).clamp(1, 4) as i32
}
fn output_events(o: &wl_output::WlOutput, d: &DesktopOutput, initial: bool) {
    o.geometry(
        d.position.0,
        d.position.1,
        d.physical_mm.0,
        d.physical_mm.1,
        wl_output::Subpixel::Unknown,
        "Trames".into(),
        d.description.clone(),
        wl_output::Transform::try_from(d.transform).unwrap_or(wl_output::Transform::Normal),
    );
    o.mode(
        wl_output::Mode::Current | wl_output::Mode::Preferred,
        d.pixel_size.0 as i32,
        d.pixel_size.1 as i32,
        d.refresh_millihz,
    );
    if o.version() >= 2 {
        o.scale(integer_scale(d.scale_120));
    }
    if initial && o.version() >= 4 {
        o.name(d.name.clone());
        o.description(d.description.clone());
    }
}
fn xdg_events(x: &xo::ZxdgOutputV1, d: &DesktopOutput, initial: bool) {
    x.logical_position(d.position.0, d.position.1);
    x.logical_size(d.logical_size.0 as i32, d.logical_size.1 as i32);
    if initial && x.version() >= 2 {
        x.name(d.name.clone());
        x.description(d.description.clone());
    }
    if x.version() < 3 {
        x.done();
    }
}
impl State {
    pub(crate) fn monitor_output_id(&self, output: &wl_output::WlOutput) -> Option<u64> {
        let key = output.data::<MonitorKey>()?;
        let monitor = self.monitors.entries.get(&key.0)?;
        (monitor.generation == key.1 && monitor.resources.contains(output)).then_some(key.0)
    }
    pub(crate) fn monitor_members(&mut self, id: u64, outputs: Vec<u64>, scale: u32) {
        if !self.monitors.active || !self.surfaces.contains_key(&id) {
            return;
        }
        let next = outputs
            .into_iter()
            .filter(|o| self.monitors.entries.contains_key(o))
            .collect::<BTreeSet<_>>();
        let old = self.monitors.members.get(&id).cloned().unwrap_or_default();
        let s = &self.surfaces[&id];
        for (&key, m) in &self.monitors.entries {
            if old.contains(&key) == next.contains(&key) {
                continue;
            }
            for o in m
                .resources
                .iter()
                .filter(|o| o.is_alive() && client_id(*o) == s.connection)
            {
                if next.contains(&key) {
                    s.resource.enter(o);
                } else {
                    s.resource.leave(o);
                }
            }
        }
        self.monitors.members.insert(id, next);
        let scale = scale.clamp(120, 480);
        if self.monitors.scales.insert(id, scale) != Some(scale) {
            let s = self.surfaces.get_mut(&id).unwrap();
            s.preferred_scale = integer_scale(scale);
            if s.resource.version() >= 6 {
                s.resource.preferred_buffer_scale(integer_scale(scale));
            }
            if let Some(f) = self.monitors.fractional.get(&id).filter(|f| f.is_alive()) {
                f.preferred_scale(scale);
            }
        }
    }
    pub(crate) fn inherit_monitor(&mut self, id: u64) {
        if let Some(parent) = self.surfaces.get(&id).and_then(|s| s.parent.map(|p| p.0)) {
            let members = self
                .monitors
                .members
                .get(&parent)
                .cloned()
                .unwrap_or_default();
            let scale = self.monitors.scales.get(&parent).copied().unwrap_or(120);
            self.monitor_members(id, members.into_iter().collect(), scale);
        }
    }
}
impl Compositor {
    /// Opt in to actual host outputs. Existing Apple density-group callers retain their API.
    pub fn desktop_outputs(&mut self, outputs: Vec<DesktopOutput>) {
        let handle = self.display.handle();
        if !self.state.monitors.active {
            for s in self.state.surfaces.values() {
                for (&density, resources) in &self.state.outputs.resources {
                    if density != s.preferred_scale {
                        continue;
                    }
                    for o in resources
                        .iter()
                        .filter(|o| o.is_alive() && client_id(*o) == s.connection)
                    {
                        s.resource.leave(o);
                    }
                }
            }
            for global in self.state.outputs.global_ids.drain(..) {
                handle.disable_global::<State>(global);
            }
            self.state.monitors.active = true;
            handle.create_global::<State, fm::WpFractionalScaleManagerV1, _>(1, ());
            handle.create_global::<State, xm::ZxdgOutputManagerV1, _>(3, ());
        }
        let next = outputs
            .into_iter()
            .filter(|o| {
                o.id != 0
                    && (120..=480).contains(&o.scale_120)
                    && o.logical_size.0 > 0
                    && o.logical_size.1 > 0
                    && o.pixel_size.0 > 0
                    && o.pixel_size.1 > 0
                    && o.pixel_size.0 <= i32::MAX as u32
                    && o.pixel_size.1 <= i32::MAX as u32
                    && o.logical_size.0 <= i32::MAX as u32
                    && o.logical_size.1 <= i32::MAX as u32
                    && o.transform <= 7
            })
            .map(|o| (o.id, o))
            .collect::<BTreeMap<_, _>>();
        let removed = self
            .state
            .monitors
            .entries
            .keys()
            .filter(|id| !next.contains_key(id))
            .copied()
            .collect::<Vec<_>>();
        for id in removed {
            let affected = self
                .state
                .monitors
                .members
                .iter()
                .filter(|(_, v)| v.contains(&id))
                .map(|(&s, _)| s)
                .collect::<Vec<_>>();
            for s in affected {
                let members = self.state.monitors.members[&s]
                    .iter()
                    .copied()
                    .filter(|v| *v != id)
                    .collect();
                let scale = self.state.monitors.scales.get(&s).copied().unwrap_or(120);
                self.state.monitor_members(s, members, scale);
            }
            if let Some(m) = self.state.monitors.entries.remove(&id) {
                handle.disable_global::<State>(m.global);
            }
        }
        for (id, data) in next {
            if let Some(m) = self.state.monitors.entries.get_mut(&id) {
                if m.data != data {
                    m.data = data;
                    m.resources.retain(Resource::is_alive);
                    m.xdg.retain(|(_, x)| x.is_alive());
                    for o in &m.resources {
                        output_events(o, &m.data, false);
                    }
                    for (_, x) in &m.xdg {
                        xdg_events(x, &m.data, false);
                    }
                    for o in &m.resources {
                        if o.version() >= 2 {
                            o.done();
                        }
                    }
                }
            } else {
                self.state.monitors.generation = self.state.monitors.generation.wrapping_add(1);
                let generation = self.state.monitors.generation;
                let global = handle
                    .create_global::<State, wl_output::WlOutput, _>(4, MonitorKey(id, generation));
                self.state.monitors.entries.insert(
                    id,
                    Monitor {
                        data,
                        global,
                        generation,
                        resources: vec![],
                        xdg: vec![],
                    },
                );
            }
        }
        self.state.changed();
    }
    pub fn window_outputs(&mut self, window: u64, outputs: Vec<u64>, scale_120: u32) {
        let ids = self
            .state
            .surfaces
            .keys()
            .copied()
            .filter(|&id| self.state.is_descendant(id, window))
            .collect::<Vec<_>>();
        for id in ids {
            self.state.monitor_members(id, outputs.clone(), scale_120);
        }
    }
    pub fn fullscreen_outputs(&self) -> BTreeMap<u64, u64> {
        self.state.monitors.fullscreen.clone()
    }
}
impl GlobalDispatch<wl_output::WlOutput, MonitorKey> for State {
    fn bind(
        state: &mut Self,
        _: &DisplayHandle,
        client: &Client,
        id: New<wl_output::WlOutput>,
        key: &MonitorKey,
        init: &mut DataInit<'_, Self>,
    ) {
        let o = init.init(id, *key);
        let Some(m) = state
            .monitors
            .entries
            .get_mut(&key.0)
            .filter(|m| m.generation == key.1)
        else {
            return;
        };
        output_events(&o, &m.data, true);
        if o.version() >= 2 {
            o.done();
        }
        m.resources.retain(Resource::is_alive);
        m.resources.push(o.clone());
        let conn = client
            .get_data::<ClientIdentity>()
            .map_or(0, |i| i.connection);
        for (&id, s) in &state.surfaces {
            if s.connection == conn
                && state
                    .monitors
                    .members
                    .get(&id)
                    .is_some_and(|m| m.contains(&key.0))
            {
                s.resource.enter(&o);
            }
        }
    }
}
impl Dispatch<wl_output::WlOutput, MonitorKey> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        o: &wl_output::WlOutput,
        _: wl_output::Request,
        key: &MonitorKey,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        if let Some(m) = state.monitors.entries.get_mut(&key.0) {
            m.resources.retain(|v| v != o);
        }
    }
}
impl GlobalDispatch<xm::ZxdgOutputManagerV1, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        id: New<xm::ZxdgOutputManagerV1>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        init.init(id, ());
    }
}
impl Dispatch<xm::ZxdgOutputManagerV1, ()> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        _: &xm::ZxdgOutputManagerV1,
        req: xm::Request,
        _: &(),
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        if let xm::Request::GetXdgOutput { id, output } = req {
            let key = output
                .data::<MonitorKey>()
                .copied()
                .unwrap_or(MonitorKey(0, 0));
            let x = init.init(id, key);
            if let Some(m) = state
                .monitors
                .entries
                .get_mut(&key.0)
                .filter(|m| m.generation == key.1 && m.resources.contains(&output))
            {
                xdg_events(&x, &m.data, true);
                if x.version() >= 3 && output.version() >= 2 {
                    output.done();
                }
                m.xdg.retain(|(_, x)| x.is_alive());
                m.xdg.push((output, x));
            }
        }
    }
}
impl Dispatch<xo::ZxdgOutputV1, MonitorKey> for State {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &xo::ZxdgOutputV1,
        _: xo::Request,
        _: &MonitorKey,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
    }
}
impl GlobalDispatch<fm::WpFractionalScaleManagerV1, ()> for State {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        id: New<fm::WpFractionalScaleManagerV1>,
        _: &(),
        init: &mut DataInit<'_, Self>,
    ) {
        init.init(id, ());
    }
}
impl Dispatch<fm::WpFractionalScaleManagerV1, ()> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &fm::WpFractionalScaleManagerV1,
        req: fm::Request,
        _: &(),
        _: &DisplayHandle,
        init: &mut DataInit<'_, Self>,
    ) {
        if let fm::Request::GetFractionalScale { id, surface } = req {
            let key = *surface.data::<crate::scene::SurfaceKey>().unwrap();
            if state
                .monitors
                .fractional
                .get(&key.0)
                .is_some_and(Resource::is_alive)
            {
                r.post_error(
                    fm::Error::FractionalScaleExists as u32,
                    "fractional scale exists",
                );
                return;
            }
            let f = init.init(id, key);
            f.preferred_scale(state.monitors.scales.get(&key.0).copied().unwrap_or(120));
            state.monitors.fractional.insert(key.0, f);
        }
    }
}
impl Dispatch<fs::WpFractionalScaleV1, crate::scene::SurfaceKey> for State {
    fn request(
        state: &mut Self,
        _: &Client,
        r: &fs::WpFractionalScaleV1,
        _: fs::Request,
        key: &crate::scene::SurfaceKey,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        if state.monitors.fractional.get(&key.0) == Some(r) {
            state.monitors.fractional.remove(&key.0);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    fn output(id: u64, scale: u32) -> DesktopOutput {
        DesktopOutput {
            id,
            name: format!("DP-{id}"),
            description: format!("Monitor {id}"),
            position: if id == 1 { (0, 0) } else { (-800, 0) },
            logical_size: (800, 600),
            pixel_size: (1000, 750),
            physical_mm: (300, 225),
            scale_120: scale,
            refresh_millihz: 60000,
            transform: 0,
        }
    }
    fn string(s: &str) -> Vec<u32> {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        let len = b.len();
        b.resize(len.next_multiple_of(4), 0);
        std::iter::once(len as u32)
            .chain(
                b.chunks_exact(4)
                    .map(|b| u32::from_ne_bytes(b.try_into().unwrap())),
            )
            .collect()
    }
    type Event = (u32, u32, Vec<u32>);
    struct Peer {
        c: Compositor,
        socket: std::os::unix::net::UnixStream,
        globals: BTreeMap<String, Vec<u32>>,
        highest: u32,
    }
    impl Peer {
        fn new() -> Self {
            let mut c = Compositor::new().unwrap();
            c.desktop_outputs(vec![output(1, 150), output(2, 150)]);
            let (socket, server) = std::os::unix::net::UnixStream::pair().unwrap();
            socket.set_nonblocking(true).unwrap();
            c.connect(
                server,
                ClientIdentity {
                    connection: 42,
                    pid: 7,
                    uid: 0,
                    gid: 0,
                },
            )
            .unwrap();
            let mut p = Self {
                c,
                socket,
                globals: BTreeMap::new(),
                highest: 2,
            };
            p.send(1, 1, &[2]);
            for (id, op, a) in p.events() {
                if id == 2 && op == 0 {
                    let b = a[2..]
                        .iter()
                        .flat_map(|v| v.to_ne_bytes())
                        .collect::<Vec<_>>();
                    let s = String::from_utf8(b[..a[1] as usize - 1].to_vec()).unwrap();
                    p.globals.entry(s).or_default().push(a[0]);
                }
            }
            p
        }
        fn send(&mut self, id: u32, op: u32, a: &[u32]) {
            let b = [id, ((a.len() + 2) as u32 * 4) << 16 | op]
                .into_iter()
                .chain(a.iter().copied())
                .flat_map(u32::to_ne_bytes)
                .collect::<Vec<_>>();
            self.socket.write_all(&b).unwrap();
            self.c.dispatch().unwrap();
        }
        fn events(&mut self) -> Vec<Event> {
            self.c.dispatch().unwrap();
            let mut b = vec![];
            loop {
                let mut v = [0; 8192];
                match self.socket.read(&mut v) {
                    Ok(0) => break,
                    Ok(n) => b.extend_from_slice(&v[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("{e}"),
                }
            }
            let w = b
                .chunks_exact(4)
                .map(|v| u32::from_ne_bytes(v.try_into().unwrap()))
                .collect::<Vec<_>>();
            let mut at = 0;
            let mut e = vec![];
            while at < w.len() {
                let n = (w[at + 1] >> 16) as usize / 4;
                e.push((w[at], w[at + 1] & 65535, w[at + 2..at + n].to_vec()));
                at += n;
            }
            e
        }
        fn reserve(&mut self, id: u32) {
            // Wayland object IDs must grow sequentially. Temporary callbacks fill
            // gaps, and are destroyed by their done event before IDs are reused.
            for next in self.highest + 1..id {
                self.send(1, 0, &[next]);
            }
            self.highest = self.highest.max(id);
        }
        fn create(&mut self, id: u32, op: u32, args: &[u32]) {
            self.reserve(args[0]);
            self.send(id, op, args);
        }
        fn bind(&mut self, name: &str, index: usize, version: u32, id: u32) {
            self.reserve(id);
            let mut a = vec![self.globals[name][index]];
            a.extend(string(name));
            a.extend([version, id]);
            self.send(2, 0, &a);
        }
        fn surface(&mut self) -> u64 {
            self.bind("wl_compositor", 0, 6, 3);
            self.create(3, 0, &[4]);
            *self.c.state.surfaces.keys().next().unwrap()
        }
    }
    #[test]
    fn same_density_outputs_keep_identity_and_logical_metadata() {
        let mut p = Peer::new();
        assert_eq!(p.globals["wl_output"].len(), 2);
        p.bind("wl_output", 0, 4, 10);
        p.bind("wl_output", 1, 4, 11);
        let e = p.events();
        for id in [10, 11] {
            assert!(e
                .iter()
                .any(|v| v.0 == id && v.1 == 1 && v.2[1..3] == [1000, 750]));
            assert!(e.iter().any(|v| v.0 == id && v.1 == 3 && v.2 == [2]));
        }
        p.bind("zxdg_output_manager_v1", 0, 3, 12);
        p.create(12, 1, &[13, 11]);
        let e = p.events();
        assert!(e.contains(&(13, 0, vec![(-800i32) as u32, 0])));
        assert!(e.contains(&(13, 1, vec![800, 600])));
        assert_eq!(e.last(), Some(&(11, 2, vec![])));
        let mut updated = output(2, 180);
        updated.position = (-600, -200);
        updated.logical_size = (500, 667);
        updated.transform = 1;
        p.c.desktop_outputs(vec![output(1, 150), updated]);
        let e = p.events();
        assert!(e.contains(&(13, 0, vec![(-600i32) as u32, (-200i32) as u32])));
        assert!(e.contains(&(13, 1, vec![500, 667])));
        assert!(!e.iter().any(|e| e.0 == 11 && e.1 == 4));
        assert_eq!(e.last(), Some(&(11, 2, vec![])));
    }
    #[test]
    fn surface_fractional_scale_subsurface_inheritance_and_hot_unplug() {
        let mut p = Peer::new();
        p.bind("wl_output", 0, 4, 10);
        p.bind("wl_output", 1, 4, 11);
        let root = p.surface();
        p.bind("wp_fractional_scale_manager_v1", 0, 1, 20);
        p.create(20, 1, &[21, 4]);
        p.events();
        p.c.window_outputs(root, vec![2], 150);
        let e = p.events();
        assert!(e.contains(&(4, 0, vec![11])));
        assert!(e.contains(&(4, 2, vec![2])));
        assert!(e.contains(&(21, 0, vec![150])));
        p.create(3, 0, &[5]);
        p.bind("wl_subcompositor", 0, 1, 22);
        p.create(22, 1, &[23, 5, 4]);
        p.send(5, 6, &[]);
        p.send(4, 6, &[]);
        let e = p.events();
        assert!(e.contains(&(5, 0, vec![11])));
        let child = *p.c.state.surfaces.keys().find(|&&id| id != root).unwrap();
        assert_eq!(p.c.state.monitors.scales[&child], 150);
        p.c.window_outputs(root, vec![1, 2], 180);
        let e = p.events();
        assert!(e.contains(&(4, 0, vec![10])));
        assert!(e.contains(&(5, 0, vec![10])));
        assert!(e.contains(&(21, 0, vec![180])));
        p.c.desktop_outputs(vec![output(1, 150)]);
        let e = p.events();
        let leave = e.iter().position(|e| *e == (4, 1, vec![11])).unwrap();
        let remove = e.iter().position(|e| e.0 == 2 && e.1 == 1).unwrap();
        assert!(leave < remove);
        assert_eq!(p.c.state.monitors.members[&root], BTreeSet::from([1]));
        p.c.desktop_outputs(vec![output(1, 150), output(2, 150)]);
        let e = p.events();
        assert!(e.iter().any(|e| e.0 == 2 && e.1 == 0));
    }
    #[test]
    fn duplicate_fractional_addon_uses_standard_error() {
        let mut p = Peer::new();
        p.surface();
        p.bind("wp_fractional_scale_manager_v1", 0, 1, 20);
        p.create(20, 1, &[21, 4]);
        p.events();
        p.create(20, 1, &[22, 4]);
        let e = p.events();
        assert!(e.iter().any(|e| e.0 == 1
            && e.1 == 0
            && e.2[0] == 20
            && e.2[1] == fm::Error::FractionalScaleExists as u32));
    }
    #[test]
    fn fullscreen_keeps_requested_monitor_and_unset_clears_it() {
        let mut p = Peer::new();
        p.bind("wl_output", 1, 4, 11);
        let root = p.surface();
        p.bind("xdg_wm_base", 0, 3, 30);
        p.create(30, 2, &[31, 4]);
        p.create(31, 1, &[32]);
        p.send(32, 11, &[11]);
        assert_eq!(p.c.fullscreen_outputs().get(&root), Some(&2));
        p.send(32, 12, &[]);
        assert!(p.c.fullscreen_outputs().is_empty());
        p.c.desktop_outputs(vec![output(1, 150)]);
        p.c.desktop_outputs(vec![output(1, 150), output(2, 150)]);
        p.send(32, 11, &[11]);
        assert!(
            p.c.fullscreen_outputs().is_empty(),
            "retired output must not target its replacement"
        );
    }
}
