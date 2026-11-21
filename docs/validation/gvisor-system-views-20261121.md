# Network namespace socket tables and virtual CPU topology

Reading an Internet socket table now samples the sockets belonging to the
target network namespace. Fresh and accepted socket descriptions publish a
weak entry at creation. Final drop removes it. The reader retains a snapshot
and releases the namespace lock before querying individual endpoints. The
packet data path does not update the table. Duplicate descriptors have the
same inode. Rows use the socket's inode owner, including a later chown.
TCP and UDP tables have their Linux IPv4 and IPv6 header layouts.

The Unix table uses the existing namespace endpoint list. It reports abstract
and filesystem names, listening flags, type, connection state and file inode.
Pending accepts have inode zero until a file description exists. The pointer
column is masked. The reference count reflects runtime endpoint references.
Network table reads now require task metadata only. A regression exercises
independent file tables, socket ownership, namespace changes and final close.

CPU topology describes one virtual package and cluster with one thread per
core. The online CPU count determines the IDs, list aliases and bit masks.
A test covers masks extending past 32 CPUs.

## Original gVisor results

Seven complete suites were added to the running inventory. Both builds ran
the same 66 cases on the Mac hardware backend with two guest CPUs.

| Suite | Previous passes | Candidate passes | Cases |
| --- | ---: | ---: | ---: |
| proc_net_tcp | 0 | 10 | 10 |
| proc_net_udp | 0 | 7 | 7 |
| proc_net_unix | 1 | 9 | 9 |
| sysfs_cpu_topology | 1 | 4 | 4 |
| proc_net | 8 | 8 | 26 |
| processes | 7 | 7 | 8 |
| syslog | 2 | 2 | 2 |

All 47 candidate passes have original passing XML. One upstream platform
skip remained. The 18 failures include seven SNMP/netstat cases, ten IPv4 or
IPv6 configuration cases, and one stopped-member orphan-group signal case.
The Mac-hosted iPad interpreter passed all 32 cases in the four repaired
suites and syslog. The iOS arm64 FFI check passed. All eight steps of the
local macOS shared runtime workflow passed after updating the old observation
dependency assertion and the test for socket quota lifetime.

Across the expanded inventory of 3,353 cases, the previous build had 3,150
passes and 93 failures. The candidate has 3,178 passes and 65 failures. Both
have 89 skips, 20 timeouts and one fixture failure. Prior evidence was reused
for the 3,287 cases outside this batch.

## Timing comparison

The previous and candidate hardware runners alternated on the same Mac.
Each build had two warmups and sixteen timed samples per workload. Socket
create/close loops used 2,000 iterations per sample, the Unix datagram pair
used 5,000 send/receive exchanges, and the UDP table test performed 200 reads
with 64 unrelated files open. Times are median milliseconds.

| Workload | Previous | Candidate | Change |
| --- | ---: | ---: | ---: |
| TCP create/close | 14.97 | 14.97 | +0.02% |
| UDP create/close | 14.26 | 14.05 | -1.49% |
| Unix stream create/close | 4.91 | 4.86 | -0.89% |
| Unix datagram send/receive | 13.07 | 13.14 | +0.50% |
| Read /proc/net/udp | 33.83 | 8.03 | -76.26% |
| Memory loop | 175.92 | 177.07 | +0.65% |
| Map, fault and unmap | 133.70 | 134.26 | +0.42% |
| File pread/pwrite | 96.66 | 96.09 | -0.59% |
| Fork and wait | 19.30 | 19.40 | +0.52% |

Raw XML, runner and benchmark hashes, per-run samples and both same-scope inventories are under `target/gvisor-system-view-20261121` in the iPad checkout.
