#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original GTK3 paste and client-side repeat while host permission is pending."""
import ctypes as C
import os
from pathlib import Path
import time

gtk = C.CDLL('libgtk-3.so.0')
gobject = C.CDLL('libgobject-2.0.so.0')
glib = C.CDLL('libglib-2.0.so.0')
pointer = C.c_void_p

def function(lib, name, result, args):
    f = getattr(lib, name)
    f.restype, f.argtypes = result, args
    return f

assert function(gtk, 'gtk_init_check', C.c_int, [pointer, pointer])(None, None)
window = function(gtk, 'gtk_window_new', pointer, [C.c_int])(0)
function(gtk, 'gtk_window_set_default_size', None, [pointer, C.c_int, C.c_int])(window, 400, 240)
view = function(gtk, 'gtk_text_view_new', pointer, [])()
function(gtk, 'gtk_container_add', None, [pointer, pointer])(window, view)
buffer = function(gtk, 'gtk_text_view_get_buffer', pointer, [pointer])(view)
bounds = function(gtk, 'gtk_text_buffer_get_bounds', None, [pointer, pointer, pointer])
get_text = function(gtk, 'gtk_text_buffer_get_text', pointer, [pointer, pointer, pointer, C.c_int])
free = function(glib, 'g_free', None, [pointer])
marker = Path(os.environ['TRAMES_GTK_PASTE_MARKER'])
callback_type = C.CFUNCTYPE(None, pointer, pointer)
@callback_type
def changed(buf, data):
    start, end = C.create_string_buffer(128), C.create_string_buffer(128)
    bounds(buf, start, end)
    text = get_text(buf, start, end, 1)
    marker.write_bytes(C.string_at(text))
    free(text)
function(gobject, 'g_signal_connect_data', C.c_ulong,
         [pointer, C.c_char_p, callback_type, pointer, pointer, C.c_int])(
             buffer, b'changed', changed, None, None, 0)
function(gtk, 'gtk_widget_show_all', None, [pointer])(window)
function(gtk, 'gtk_widget_grab_focus', None, [pointer])(view)
iterate = function(gtk, 'gtk_main_iteration_do', C.c_int, [C.c_int])
for _ in range(2000):
    iterate(0)
    time.sleep(.005)
