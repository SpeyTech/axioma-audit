# BUILD-MANIFEST.md
# axioma-audit Verified Build Configurations
#
# DVEC: v1.3 | SRS-001: v0.3 | Class: D1
#
# Copyright (c) 2026 The Murray Family Innovation Trust
# SPDX-License-Identifier: GPL-3.0-or-later
# Patent: UK GB2521625.0

## Purpose

This manifest documents the exact toolchain configurations that have been
empirically verified to produce bit-identical outputs for the axioma-audit
cryptographic audit ledger.

**Determinism Claim**: For identical canonical inputs, axioma-audit produces
identical cryptographic outputs across all verified configurations listed below.

---

## Golden References

These hashes **MUST** be identical across all verified platforms:

| Reference | SHA-256 |
|-----------|---------|
| E0 (genesis evidence) | `0976582f90120f7c10263221aef8f0666156f465fc46cd48ef9aa2d6a1ed390c` |
| L0 (genesis chain) | `7bb0d791697306ce2f1cc5df0bcdf66d810d6af9425aa380b352a62453a5ec7b` |
| L3 (chain +3 appends) | `0a6b796ca38fe030c7108e15551a05ee1628392e9a88af94ccf840b8d4605d3e` |

---

## Verified Configurations

### Platform 1: Debian 12 x86_64

| Property | Value |
|----------|-------|
| OS | Debian GNU/Linux 12 (bookworm) |
| Kernel | Linux 6.1.x |
| Architecture | x86_64 (Intel/AMD) |
| Compiler | GCC 12.2.0 |
| libc | glibc 2.36 |
| Verification Date | 2026-03-26 |
| Status | ✓ VERIFIED |

### Platform 2: macOS Big Sur x86_64

| Property | Value |
|----------|-------|
| OS | macOS 11.7.10 (Big Sur) |
| Kernel | Darwin 20.6.0 |
| Architecture | x86_64 (Intel Haswell) |
| Compiler | AppleClang 12.0.5.12050022 |
| libc | libSystem (macOS) |
| Verification Date | 2026-03-26 |
| Status | ✓ VERIFIED |

### Platform 3: Debian 12 ARM64 (GCP Tau T2A)

| Property | Value |
|----------|-------|
| OS | Debian GNU/Linux 12 (bookworm) |
| Kernel | Linux 6.1.x |
| Architecture | aarch64 (ARM64) |
| Compiler | GCC 12.2.0 |
| libc | glibc 2.36 |
| Cloud Provider | Google Cloud Platform |
| Instance Type | t2a-standard-1 |
| Verification Date | 2026-03-26 |
| Status | ✓ VERIFIED |

---

## Pending Verification

| Platform | Architecture | Status |
|----------|--------------|--------|
| RISC-V (Scaleway EM-RV1) | rv64gc | Pending |
| Apple Silicon (M1/M2) | aarch64 | Pending |
| FreeBSD | x86_64 | Pending |

---

## Required Compiler Flags

All builds **MUST** include the following determinism closure flags:

```
-std=c99
-Wall -Wextra -Werror -pedantic
-fno-strict-aliasing
-fwrapv
-fno-tree-vectorize
-fno-builtin
-fno-omit-frame-pointer
-fno-common
-ffp-contract=off
-fno-fast-math
-fstack-protector-strong
```

These flags are enforced in `CMakeLists.txt` and remove optimisation-induced
variance across compilers.

---

## Verification Procedure

To verify a new platform:

```bash
# Clone repositories
git clone https://github.com/SpeyTech/axioma-spec.git ~/axilog/axioma-spec
git clone https://github.com/SpeyTech/axioma-audit.git ~/axilog/axioma-audit

# Run Phase 1 audit
cd ~/axilog/axioma-audit
./ax-phase1-audit.sh

# Expected output (must match exactly):
#   E0: 0976582f90120f7c10263221aef8f0666156f465fc46cd48ef9aa2d6a1ed390c
#   L0: 7bb0d791697306ce2f1cc5df0bcdf66d810d6af9425aa380b352a62453a5ec7b
#   L3: 0a6b796ca38fe030c7108e15551a05ee1628392e9a88af94ccf840b8d4605d3e
```

If hashes do not match, the platform is **NOT** verified and must be investigated.

---

## Certification Status

| Claim | Status |
|-------|--------|
| D1 — Strict Deterministic | EMPIRICALLY VERIFIED (CONFORMANT) |
| Toolchain Qualification | Pending |
| UB Absence Proof | Pending |
| Full State Space Coverage | Pending |

**Note**: "EMPIRICALLY VERIFIED" means determinism has been demonstrated through
testing on multiple platforms. Full certification (DO-178C / IEC 62304 / ISO 26262)
requires additional evidence including formal toolchain qualification, static
analysis for UB absence, and comprehensive state space coverage.

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-26 | William Murray | Initial verified configurations |
