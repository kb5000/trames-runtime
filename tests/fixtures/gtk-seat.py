#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unmodified host GTK3 ABI; no GTK seat or keyboard is mocked."""
import ctypes as C
import time
import os

gtk=C.CDLL('libgtk-3.so.0')
gdk=C.CDLL('libgdk-3.so.0')
def function(lib,name,result,args):
 f=getattr(lib,name);f.restype=result;f.argtypes=args;return f
pointer=C.c_void_p
assert function(gtk,'gtk_init_check',C.c_int,[pointer,pointer])(None,None)
display=function(gdk,'gdk_display_get_default',pointer,[])()
seat=function(gdk,'gdk_display_get_default_seat',pointer,[pointer])(display)
assert seat,'GTK did not create a default seat'
assert function(gdk,'gdk_seat_get_keyboard',pointer,[pointer])(seat),'GTK keyboard missing'
assert function(gdk,'gdk_seat_get_pointer',pointer,[pointer])(seat),'GTK pointer missing'
window=function(gtk,'gtk_window_new',pointer,[C.c_int])(0)
function(gtk,'gtk_window_set_title',None,[pointer,C.c_char_p])(window,b'Original GTK3 seat acceptance')
function(gtk,'gtk_window_set_default_size',None,[pointer,C.c_int,C.c_int])(window,320,200)
function(gtk,'gtk_widget_show_all',None,[pointer])(window)
iterate=function(gtk,'gtk_main_iteration_do',C.c_int,[C.c_int])
for _ in range(300):
 iterate(0);time.sleep(.01)
if os.environ.get('TRAMES_GTK_CLIPBOARD')=='1':
 atom=function(gdk,'gdk_atom_intern_static_string',pointer,[C.c_char_p])(b'CLIPBOARD')
 clipboard=function(gtk,'gtk_clipboard_get',pointer,[pointer])(atom)
 text=function(gtk,'gtk_clipboard_wait_for_text',C.c_char_p,[pointer])(clipboard)
 assert text=='host 中文 🧪'.encode(),text
 payload='guest 剪贴板 ✅'.encode()
 function(gtk,'gtk_clipboard_set_text',None,[pointer,C.c_char_p,C.c_int])(clipboard,payload,len(payload))
 for _ in range(100):iterate(0);time.sleep(.01)
function(gtk,'gtk_widget_destroy',None,[pointer])(window)
print('Original GTK3: default seat, keyboard, pointer and window passed',flush=True)
