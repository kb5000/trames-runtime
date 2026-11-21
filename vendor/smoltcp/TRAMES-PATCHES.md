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

The Linux TCP options for corking, the MSS limit and a temporary quick ACK
act on the original transport. Scheduling and packet construction both apply
the cork limit. A full segment, uncork, explicit TCP_NODELAY push, close or
200 ms deadline can release data. Retransmission can send outstanding bytes
without flushing a newly appended short tail. An ACK owed to the other peer
can travel independently. MSG_TRUNC advances the receive ring and sequence
space through the ordinary receive path without copying payload bytes.

A connected stream with an I/O subscriber records its original socket handle
when an incoming segment makes the queue readable, crosses an armed byte
threshold for poll or a blocking peek, frees a full
transmit queue, or changes the connection state. The interface drains those
handles after polling. Trames notifies the socket waiters after releasing the
fabric lock. Protocol timers still drive delayed ACKs and loss recovery.

Linux listeners use protocol sockets as accept-queue slots. Only slots
explicitly reserved by a listener participate. A SYN consumed by such a
slot can request another one from its owner after the interface poll.
An unmatched SYN for a full queue is dropped so the client may retry.
Acceptance releases the queue association. An incoming RST before accept
returns the transport to the same listener.

The TCP socket accepts live changes to its owned receive and transmit rings.
Ring growth preserves wrapped and out-of-order bytes. Shrinking an established
receive queue limits future advertisements while honoring credit already sent
to the peer. The larger allocation stays with the connection through close.
Shrinking a transmit queue below its occupancy keeps the outstanding bytes
and blocks new writes until the queue falls below the new limit. Applications
that only set buffers before connect or listen allocate the requested sizes
when the protocol sockets are created.

Guest TCP_USER_TIMEOUT uses ACK progress, a blocked zero-window send and
transmitted keepalive probes to track delivery stalls. The existing transport
timer expires the connection and wakes its socket subscribers. An ordinary
idle connection has no delivery deadline. TCP_SYNCNT counts SYNs emitted by
an active opener and checks the retry budget on retransmission expiry.

TCP_WINDOW_CLAMP limits newly advertised credit, including the unscaled
SYN window. The transport remembers whether the last advertisement used
scaling so a live change can honor credit already granted. Window growth
can trigger a standalone update after establishment. SYN retransmission
continues to use the handshake timer.

TCP_DEFER_ACCEPT holds an established socket in its listener slot until
contiguous data, peer FIN or its deadline makes it acceptable. The guest
poll and accept paths consult the same readiness condition. This models
application-visible readiness using the existing transport timers. It does
not reproduce Linux's wire-level treatment of bare ACKs during deferred
accept.

Final TCP close marks the socket as having no remaining reader. New,
in-window payload arriving afterward elicits a reset. A write-half shutdown
keeps the reader. The transport records an accepted RST on its original
socket along with the connection state at receipt. Linux I/O and SO_ERROR
can then consume the reason once. Packet ingress no longer scans the
environment's socket registry to attribute reset packets.

TCP_INQ reads the current receive queue and FIN sequence point. On std
builds, a socket with software receive timestamps enabled records timestamp
boundaries along its receive ring. Reads look up the final byte copied and
discard consumed boundaries. Reordered segments can carry different arrival
times. Disabling timestamps releases the index. A stream using the defaults
does not allocate this index or read the wall clock for incoming TCP data.

Under the std build, UDP sockets can observe incoming ICMP destination
unreachable messages. The interface matches the original UDP endpoints
from the quoted IP packet to a local binding. A connected or specifically
bound socket takes precedence. Reuse-port groups apply their usual reply-flow
selection. The observer receives the reporter address, code and quoted UDP
payload and can notify the existing readable waiter. IPv4 quotations may end
before the original packet's declared total length.

Guest-owned TCP and UDP queues can accept a privileged Linux socket buffer
budget above the ordinary limit. The socket retains the logical ceiling while
its rings grow on demand. TCP receive growth preserves sequence offsets for
out-of-order segments and the scale negotiated at connection setup. UDP
growth repacks whole datagrams, including empty records, in arrival order.
Borrowed rings used by other callers retain their fixed capacity.

TCP backlog slots can carry their logical listener's stable reuse-port key
and original bind specificity. A new SYN selects among eligible shared
listeners by endpoint specificity, ingress device and a hash of the TCP
four-tuple. Established connections retain their tuple match. TCP and UDP
can both restrict delivery to a guest ingress interface. The existing UDP
flow hash is shared with TCP listener selection.
