# Security Policy

## Security Model

`trames-runtime` is a userspace Linux compatibility kernel, not a hardware virtualization boundary. Guest binaries, syscalls, paths, and network packets are treated as untrusted inputs, but memory-safety or parser bugs in the runtime can affect the host embedding process.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via:
1. **GitHub Private Vulnerability Reporting** *(preferred)*: [Report a vulnerability](https://github.com/project-trames/trames-runtime/security/advisories/new)
2. **Email**: `a123edcrfv@gmail.com` with `[SECURITY]` in the subject line

Include the affected crate/commit, reproduction steps or PoC, and potential impact.

## Handling of Private Reports

Private security reports are excluded from the public-channel AI processing default and are never published without coordination with the reporter. Please remove personal credentials or keys from any voluntarily shared diagnostic logs.
