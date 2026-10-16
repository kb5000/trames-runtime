# Trames Apple platform patch

Original crate: wayland-backend 0.3.17, MIT.
Upstream revision: 72f7fe0d9e99cb720ed57ade0c3077aec533b6ab.
All original source and license files are retained.

The Rust backend already implements kqueue and Darwin socket flags for macOS.
Three source files extend those existing conditions to target_vendor=apple,
covering iOS device/simulator with the same public Unix APIs. No protocol or
wire encoding is changed. Guest credentials are supplied separately by Trames;
the upstream non-Linux fallback credentials are not used as guest identity.
