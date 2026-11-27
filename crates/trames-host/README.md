# Shared host execution transports

This crate contains the Runtime side of the existing `TRMEXEC1`, `TRAMES02` and
`TRMLIST1` Unix socket protocols. Linux and Mac products retain their own process
lifecycle, UI and CPU backends. The independently versioned `trames-cli-common`
crate retains clients, terminal/signal ownership and literal argument parsing.
Neither crate depends on the other's repository.

Servers borrow the product's existing foreground `HostWait`/`HostWake`, original
VFS resources and Runtime task admission. They introduce no executor, coordinator
or service thread. Each exec detaches its descriptor table from PID1 before
allocating pipes/PTYs, preserving PID1's unrelated locks. Private terminal
channels use the common distro launcher and original guest binaries.

Products compare protocol constants at compile time; wire interoperability is
exercised by real exec/console acceptance. Registry/schema, host authority and
portable cold-store operations live in `trames-distro`.
