#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run under `unshare -n` on native Linux; never reconfigure a host namespace.
Produces bounded netlink request/ACK reference lines for shared runtime replay.
"""
import os
import socket
import struct
import subprocess

assert os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino
subprocess.run(['ip', 'link', 'add', 'eth0', 'type', 'dummy'], check=True)
subprocess.run(['ip', 'link', 'set', 'eth0', 'up'], check=True)
assert socket.if_nametoindex('eth0') == 2
nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
nl.bind((0, 0))
seq = 0

def attr(kind, data):
    n = len(data) + 4
    return struct.pack('<HH', n, kind) + data + bytes((-n) % 4)

def u32(n):
    return struct.pack('<I', n)

def request(label, kind, flags, data):
    global seq
    seq += 1
    wire = struct.pack('<IHHII', len(data) + 16, kind, flags | 5, seq, 0) + data
    nl.send(wire)
    response = nl.recv(65536)
    assert struct.unpack_from('<H', response, 4)[0] == 2
    status = struct.unpack_from('<i', response, 16)[0]
    print(label, wire.hex(), status, flush=True)

request('netd-zero-address', 20, 0, bytes([2, 0, 0, 0]) + u32(2) + attr(2, bytes(4)) + attr(4, bytes(4)))
request('assign', 20, 0x600, bytes([2, 24, 0, 0]) + u32(2) + attr(2, socket.inet_aton('10.0.0.2')))
route = bytes([2, 0, 0, 0, 0, 3, 0, 1]) + bytes(4)
request('table-1002-default', 24, 0x600, route + attr(4, u32(2)) + attr(5, socket.inet_aton('10.0.0.1')) + attr(15, u32(1002)))
rule = bytes([2, 0, 0, 0, 0, 0, 0, 1]) + bytes(4)
request('marked-rule', 32, 0x600, rule + attr(6, u32(10000)) + attr(10, u32(0x10064)) + attr(16, u32(0x1ffff)) + attr(15, u32(1002)))
request('uid-prohibit', 32, 0x600, bytes([2, 0, 0, 0, 0, 0, 0, 8]) + bytes(4) + attr(6, u32(9000)) + attr(20, u32(10005) + u32(10005)))
request('default-rule', 32, 0x600, rule + attr(6, u32(29000)) + attr(10, u32(0)) + attr(16, u32(0xffff)) + attr(15, u32(1002)))
request('unreachable', 32, 0x600, bytes([2, 0, 0, 0, 0, 0, 0, 7]) + bytes(4) + attr(6, u32(32000)))
for mark in [0x10064, 0, 77]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    status = 0
    try:
        s.connect(('198.51.100.17', 0))
        assert s.getsockname()[0] == '10.0.0.2'
    except OSError as e:
        status = e.errno
    print('route-probe', mark, status, flush=True)
    s.close()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
os.fchown(s.fileno(), 10005, -1)
try:
    s.connect(('198.51.100.17', 0))
    status = 0
except OSError as e:
    status = e.errno
print('chown-route-probe', status, flush=True)
s.close()
child = os.fork()
if child == 0:
    os.setuid(10005)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('198.51.100.17', 0))
        status = 0
    except OSError as e:
        status = e.errno
    print('uid-probe', status, flush=True)
    os._exit(0)
os.waitpid(child, 0)
