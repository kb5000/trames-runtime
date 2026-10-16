The `us.xkb` keymap is the default evdev/pc105/us keymap emitted by the
original libxkbcommon 1.5.0 `xkb_keymap_get_as_string(..., XKB_KEYMAP_FORMAT_TEXT_V1)`
with xkeyboard-config 2.35.1. It is a protocol data artifact, not translated code.
The keyboard sends Linux evdev codes; native UIKit HID codes are converted once
at the frontend boundary. Layout-sensitive text uses native text-input instead.

Upstream: https://gitlab.freedesktop.org/xkeyboard-config/xkeyboard-config
License: MIT/X11. See `COPYING.xkeyboard-config` for the original notices.
