#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Invoked inside the native harness's fresh network namespace for each case.
set -eu
ip link set lo multicast on
ip link set lo up
ip link add eth0 type dummy
ip link set eth0 multicast on
ip link set eth0 up
ip -4 addr add 10.0.0.2/24 brd + dev eth0
ip -6 addr add fd00::2/64 dev eth0 nodad
ip -4 route add default dev eth0
ip -6 route add default dev eth0
ip -6 route add ff00::/8 dev lo metric 16
exec "$@"
