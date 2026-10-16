// SPDX-License-Identifier: GPL-3.0-or-later
//! xdg-positioner anchor/gravity and ordered flip, slide, resize constraints.
#[derive(Clone, Copy, Default)]
pub(crate) struct Positioner {
    pub size: (i32, i32),
    pub rect: (i32, i32, i32, i32),
    pub anchor: u32,
    pub gravity: u32,
    pub offset: (i32, i32),
    pub constraints: u32,
}
fn edges(value: u32) -> (i64, i64) {
    match value {
        1 => (0, -1),
        2 => (0, 1),
        3 => (-1, 0),
        4 => (1, 0),
        5 => (-1, -1),
        6 => (-1, 1),
        7 => (1, -1),
        8 => (1, 1),
        _ => (0, 0),
    }
}
fn axis(start: i64, extent: i64, length: i64, anchor: i64, gravity: i64, offset: i64) -> i64 {
    start + (anchor + 1) * extent / 2 - (1 - gravity) * length / 2 + offset
}
fn constrain(
    mut position: i64,
    mut length: i64,
    limit: i64,
    flipped: i64,
    flags: (bool, bool, bool),
) -> (i32, u32) {
    let fits = |p: i64, n: i64| p >= 0 && p + n <= limit;
    if !fits(position, length) && flags.0 && fits(flipped, length) {
        position = flipped;
    }
    if !fits(position, length) && flags.1 {
        position = position.clamp((limit - length).min(0), (limit - length).max(0));
    }
    if !fits(position, length) && flags.2 {
        let end = (position + length).clamp(1, limit);
        position = position.clamp(0, end - 1);
        length = end - position;
    }
    (
        position.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
        length as u32,
    )
}
impl Positioner {
    pub fn complete(self) -> bool {
        self.size.0 > 0 && self.size.1 > 0 && self.rect.2 > 0 && self.rect.3 > 0
    }
    pub fn geometry(self, viewport: (u32, u32)) -> (i32, i32, u32, u32) {
        let (ax, ay) = edges(self.anchor);
        let (gx, gy) = edges(self.gravity);
        let (rx, ry, rw, rh) = self.rect;
        let (w, h) = self.size;
        let (ox, oy) = self.offset;
        let x = axis(rx as i64, rw as i64, w as i64, ax, gx, ox as i64);
        let y = axis(ry as i64, rh as i64, h as i64, ay, gy, oy as i64);
        let fx = axis(rx as i64, rw as i64, w as i64, -ax, -gx, ox as i64);
        let fy = axis(ry as i64, rh as i64, h as i64, -ay, -gy, oy as i64);
        let c = self.constraints;
        let (x, w) = constrain(
            x,
            w as i64,
            viewport.0 as i64,
            fx,
            (c & 4 != 0, c & 1 != 0, c & 16 != 0),
        );
        let (y, h) = constrain(
            y,
            h as i64,
            viewport.1 as i64,
            fy,
            (c & 8 != 0, c & 2 != 0, c & 32 != 0),
        );
        (x, y, w, h)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn menu_anchor_gravity_and_flip_precede_slide_or_resize() {
        let p = Positioner {
            size: (80, 40),
            rect: (220, 150, 10, 10),
            anchor: 8,
            gravity: 8,
            ..Default::default()
        };
        assert_eq!(p.geometry((240, 180)), (230, 160, 80, 40));
        assert_eq!(
            Positioner {
                constraints: 4 | 8 | 1 | 2 | 16 | 32,
                ..p
            }
            .geometry((240, 180)),
            (140, 110, 80, 40)
        );
        assert_eq!(
            Positioner {
                constraints: 1 | 2,
                ..p
            }
            .geometry((240, 180)),
            (160, 140, 80, 40)
        );
        assert_eq!(
            Positioner {
                constraints: 16 | 32,
                ..p
            }
            .geometry((240, 180)),
            (230, 160, 10, 20)
        );
        assert_eq!(
            Positioner {
                size: (20, 10),
                rect: (10, 10, 40, 20),
                ..Default::default()
            }
            .geometry((240, 180)),
            (20, 15, 20, 10)
        );
    }
}
