// SPDX-License-Identifier: GPL-3.0-or-later
//! Signed-in, pure accelerators. Disabled calls have no effect and can fall back.
pub mod allocator;
pub mod callbacks;
pub mod integer;
pub mod native;
pub mod numeric;
mod strings;
pub use trames_bridge::hash::{Registry, ABI_VERSION, MAX_INPUT};
