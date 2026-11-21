# Trames smoltcp patch

Source: crates.io smoltcp 0.12.0, 0BSD license retained in LICENSE-0BSD.txt.
Crate checksum: `dad095989c1533c1c266d9b1e8d70a1329dd3723c3edac6d03bbd67e7bf6f4bb`.
Upstream Git revision from the published crate: `d2d647090d544b1e7c142571da9d55f7280f664b`.

`src/storage/packet_buffer.rs` and `src/socket/udp.rs` contain local API
changes. The packet ring can resize owned metadata/data storage while retaining
queued packets in order. A smaller logical capacity blocks new enqueue until
the retained queue drains; it does not discard existing packets. UDP exposes
separate receive/send resizing methods.

`src/iface/interface/mod.rs` also prevents a new fragmented IPv4 packet from
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
queued across bounded fabric slices. The private-link full-writer regression additionally checks that EAGAIN
advances the original pending fragment resource instead of stranding it.

`src/socket/tcp.rs` exposes a read-only transport diagnostic snapshot for Linux
TCP_INFO: the original RTO/RTT estimates, negotiated peer MSS, congestion window
and available receive-buffer space. It does not copy the TCP control block,
advance protocol work or introduce a lock. Unimplemented Linux counters remain
zero; the existing transport state supplies tcpi_state.

Guest TCP sockets can select CUBIC or Reno, including after the handshake.
Both readiness and packet construction limit total data in flight by the
smaller of the congestion and advertised windows. The initial flight uses
the negotiated MSS. CUBIC tracks its growth curve in segments and resumes
ACK-driven slow start after a timeout. The transport arms retransmission on
the first outstanding segment and tracks timeout backoff separately from
measured RTT. The guest connection-establishment deadline clears when the
handshake completes, including a transition directly to CLOSE-WAIT.

The TCP unit tests cover the full-flight bound, reopening the window on ACK,
and retransmission before and after the backed-off deadline. The trames-net
integration tests exercise both controllers under packet loss and corruption.
