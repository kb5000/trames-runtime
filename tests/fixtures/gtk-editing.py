#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original GTK3 text view and its real context menu; no toolkit patches."""
import ctypes as C
import os
import pathlib
import time

gtk = C.CDLL('libgtk-3.so.0')
gdk = C.CDLL('libgdk-3.so.0')
gobject = C.CDLL('libgobject-2.0.so.0')
pointer = C.c_void_p

def function(lib, name, result, args):
    f = getattr(lib, name)
    f.restype, f.argtypes = result, args
    return f

assert function(gtk, 'gtk_init_check', C.c_int, [pointer, pointer])(None, None)
window = function(gtk, 'gtk_window_new', pointer, [C.c_int])(0)
function(gtk, 'gtk_window_set_title', None, [pointer, C.c_char_p])(window, b'GTK editing regression')
function(gtk, 'gtk_window_set_default_size', None, [pointer, C.c_int, C.c_int])(window, 400, 240)
view = function(gtk, 'gtk_text_view_new', pointer, [])()
function(gtk, 'gtk_container_add', None, [pointer, pointer])(window, view)
buffer = function(gtk, 'gtk_text_view_get_buffer', pointer, [pointer])(view)
text = 'menu clipboard 中文 🧪'.encode()
function(gtk, 'gtk_text_buffer_set_text', None, [pointer, C.c_char_p, C.c_int])(buffer, text, len(text))
# GtkTextIter is opaque at this boundary; reserve more than the public ABI size.
start, end = C.create_string_buffer(128), C.create_string_buffer(128)
function(gtk, 'gtk_text_buffer_get_bounds', None, [pointer, pointer, pointer])(buffer, start, end)
function(gtk, 'gtk_text_buffer_select_range', None, [pointer, pointer, pointer])(buffer, start, end)
marker = pathlib.Path(os.environ['TRAMES_GTK_EDITING_MARKER'])
callback_type = C.CFUNCTYPE(None, pointer, pointer, pointer)
@callback_type
def populated(widget, menu, data):
    marker.write_text('menu')
function(gobject, 'g_signal_connect_data', C.c_ulong,
         [pointer, C.c_char_p, callback_type, pointer, pointer, C.c_int])(
             view, b'populate-popup', populated, None, None, 0)
function(gtk, 'gtk_widget_show_all', None, [pointer])(window)
function(gtk, 'gtk_widget_grab_focus', None, [pointer])(view)
iterate = function(gtk, 'gtk_main_iteration_do', C.c_int, [C.c_int])
for _ in range(1500):
    iterate(0)
    time.sleep(.01)
function(gtk, 'gtk_widget_destroy', None, [pointer])(window)
print('GTK editing finished', flush=True)
