# Trames smoltcp patch

Source: crates.io smoltcp 0.12.0, 0BSD license retained in LICENSE-0BSD.txt.
Crate checksum: `dad095989c1533c1c266d9b1e8d70a1329dd3723c3edac6d03bbd67e7bf6f4bb`.
Upstream Git revision from the published crate: `d2d647090d544b1e7c142571da9d55f7280f664b`.

`src/storage/packet_buffer.rs` and `src/socket/udp.rs` contain local API
changes. The packet ring can resize owned metadata/data storage while retaining
queued packets in order. A smaller logical capacity blocks new enqueue until
the retained queue drains; it does not discard existing packets. UDP exposes
separate receive/send resizing methods. `src/iface/interface/mod.rs` also prevents a new fragmented IPv4 packet from
replacing the interface's still-active fragmenter. It returns device exhaustion
so socket dispatch retains the datagram for retry, instead of treating it as
missing-neighbor failure. Short packets can still transmit; unsolicited replies
that need the occupied fragmenter can be dropped without corrupting its owner.
The patch uses safe owned allocations; it neither accesses private layout via
casts nor adds locks or worker threads.

Application sockets derive metadata capacity from their configured byte budget
and apply SO_RCVBUF/SO_SNDBUF both before bind and to live sockets. Keep this
patch small and replace it with upstream equivalent APIs when available.
The runtime, iPad/Mac workspace roots and benchmark wrapper must select this
same patched package; changing a patch in only one root leaves another product
using the registry version.

Regression coverage lives in trames-net: wrapped ring preservation, queued
transmit preservation, shrinking below occupied data, zero-size datagram budget,
64-packet bursts, live receive-buffer changes, and multiple 60 KB datagrams
queued across bounded fabric slices. The latter fails on the unpatched interface
and passes with this ownership fix.

`src/iface/interface/mod.rs` also preserves the single IPv4 fragmentation
buffer until its final fragment is emitted. Starting another fragmented
socket datagram returns transient device exhaustion, keeping that datagram
queued for retry rather than overwriting its predecessor. This is distinct
from neighbor-discovery backoff. Short packets can still be emitted while
fragmentation is active. Large immediate ingress replies are dropped on
exhaustion, preserving the already queued datagram.

The queued-large-UDP IPv4/IPv6 regression in `tests/virtual.rs` covers this
ownership fix. Replace this local change when an upstream equivalent is used.
