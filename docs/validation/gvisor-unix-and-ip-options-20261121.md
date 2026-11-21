# Unix socket coverage and IP option widths

The Mac hardware executor ran 3,608 distinct upstream cases on two guest CPUs.
Every case used the same original ARM64 test binary and root filesystem on
the old and new builds. The old runtime passed 3,480, failed six and skipped
122. The new runtime passed 3,486 and skipped the same 122. Every pass has
its original GoogleTest XML. All cases in this batch are new to the cumulative
inventory.

| Scope | Cases | Passed | Skipped |
| --- | ---: | ---: | ---: |
| Unix socket addresses, nonblocking operations, queued messages and socket options | 3,500 | 3,382 | 118 |
| IPv4 and IPv6 traffic class, TTL, hop limit and receive options | 108 | 104 | 4 |

The Unix selection includes the complete socket_abstract and socket_filesystem
binaries (1,464 cases each). The other Unix coverage includes datagram and
sequenced-packet shutdown, readiness, zero-length records, abstract names and
pathname binding. The native Linux reference passed 3,467 of the 3,486 cases,
with no result for 19. It skipped the same 122 as Trames. The Mac-hosted iPad
interpreter independently passed 104 of the 108 IP cases and skipped four.
The iOS device FFI target compiled.

Linux IPv4 scalar header options accept an empty value as zero and one byte
when supplied a short buffer. With a full integer they use only its first four
bytes. A short getsockopt result uses a single byte and reports that actual
length. Regression coverage places the byte at the end of a mapped page.
An IPv6 option query on an IPv4 UDP socket reports EOPNOTSUPP.

## Continuation evidence

Batch reuse now selects cases by suite, binary hash and case name across worker
partitions. The cache checks the execution environment, suite fixtures,
process exit status and original XML for completed passes and skips. A missing
or mismatched positive record is run again. Suppressed XML cases cannot pass.
A 576-case replay changed from two workers to one and then to three. All 576
retained the original log paths, including 552 verified passes. Fully reused
guest partitions complete without creating a guest store.

The cumulative inventory now contains 7,080 cases, with 6,793 passes,
53 failures, 213 skips, 20 timeouts and one fixture failure. The six repairs
were discovered in the newly added IP cases. The earlier 53 failures retain
their prior outcomes.

## Ordinary socket cost

The same Mac alternated release runners with identical guest code on the
internal network. The table shows median milliseconds over 16 samples per
build after two warmups.

| Operation | Iterations | Previous | Current | Change |
| --- | ---: | ---: | ---: | ---: |
| UDP bind and close | 2,000 | 98.543 | 95.747 | -2.84% |
| Connected UDP send and receive | 5,000 | 153.544 | 152.787 | -0.49% |
| TCP connect, accept and transfer two bytes | 100 | 21.851 | 21.701 | -0.69% |
