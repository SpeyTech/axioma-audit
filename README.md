# axioma-audit
## Axioma Framework — Layer 6 — Cryptographic Audit Ledger with Typed Evidence

**DVEC:** v1.3
**Determinism Class:** D1
**Layer:** Layer 6 — Cryptographic Audit Ledger with Typed Evidence
**License:** AGPL-3.0
**Part of:** [axilog.io](https://axilog.io) · SpeyTech

> *"Turing completeness is a vulnerability. Totality is a feature."*

### Overview

A C99 library that maintains a SHA-256 hash-chain accumulator over typed evidence commitments. It is the Layer 6 component linked by `axioma-agent`. Fixed-size, caller-owned context; no heap allocation.

#### What it implements

- **Evidence commitment.** `ax_commit_evidence(ev, out, faults)` accepts a payload only if its tag is one of the ten registered tags (`AX:STATE:v1`, `AX:TRANS:v1`, `AX:OBS:v1`, `AX:POLICY:v1`, `AX:PROOF:v1`, `AX:FCC:C:v1`, `AX:FCC:TS:v1`, `AX:FCC:DEV:v1`, `AX:FCC:REG:v1`, `AX:FCC:VERDICT:v1`, defined in axioma-spec `include/axilog/dvec.h`) and the payload is non-empty. It computes `SHA-256(tag || LE64(len) || payload)` via `axilog_commit()` from the axioma-spec SHA-256 substrate.
- **Chain.** `ax_ledger_genesis()` sets `L0 = SHA-256("AX:LEDGER:v1" || commit("AX:STATE:v1", genesis_payload))`. `ax_ledger_append(ctx, commit)` sets `Ln = SHA-256("AX:LEDGER:v1" || Ln-1 || commit)` and increments `sequence`. Append is refused, and the context latches `failed`, when the context is failed, uninitialised, or at `sequence == UINT64_MAX`.
- **`ax_verify_chain()`** is an internal-consistency check of the context only: the `failed` and `initialised` flags and zero padding. It does not recompute or compare any hash, and it does not detect reordered, truncated, inserted or substituted entries.

#### Reference values

Reproducible with any SHA-256 implementation (see `BUILD-MANIFEST.md`): E0 `0976582f...ed390c`, L0 `7bb0d791...53a5ec7b`, L3 (three fixed test commits) `0a6b796c...d4605d3e`.

#### Build and test

Requires `../axioma-spec` alongside this checkout and the axioma-spec SHA-256 archive installed as `libaxilog.a` with the axioma-spec `axilog/*.h` headers under `AXILOG_SDK_ROOT` (default `$HOME/axilog/sdk-root`).

```
cmake -S . -B /path/to/build -DCMAKE_BUILD_TYPE=Release -DAXILOG_SDK_ROOT=/path/to/sdk-root
cmake --build /path/to/build
ctest --test-dir /path/to/build --output-on-failure
```

`ax-rtm-verify.py` currently reports NON-CONFORMANT because `axilog_commit` now lives in axioma-spec while the script still expects it here; `ax-phase1-audit.sh` builds into `./build` and stops at that step.

#### Limits at this revision

- In memory only. Evidence payloads and individual commitments are not retained; only the 32-byte head and sequence survive. There is no file format, fsync, crash recovery or export.
- No record-list verifier, no signatures or keys, no external anchoring. Integrity holds only relative to a head value obtained and trusted independently.
- No writer authentication: any code holding the context can append, or clear `failed`.
- `ax_ledger_append` accepts any 32 bytes; the tag registry is enforced only when callers go through `ax_commit_evidence`.
- A hash chain shows that recorded bytes are unchanged relative to a trusted head. It does not show that the recorded events were true, complete or authorised.
- `BUILD-MANIFEST.md` records cross-platform identity for a revision before 2026-04-13. No logs for other platforms are held in this repository.

### Governing Documents

- [Axioma Framework v0.4](https://github.com/SpeyTech/axioma-spec/blob/main/docs/AXIOMA-FRAMEWORK-v0.4.md)
- DVEC-001: this README declares v1.3; the only DVEC text in axioma-spec is [DVEC-001 v1.4](https://github.com/SpeyTech/axioma-spec/blob/main/docs/DVEC-001-v1.4-Final.md), which introduced the AX:FCC tags above
- [DVM-SPEC-001](https://github.com/SpeyTech/certifiable)

### SRS Documents

[SRS-001 v0.3](https://github.com/SpeyTech/axioma-spec/blob/main/docs/requirements/SRS-001-v0.3.md) in axioma-spec. The `SRS-006-SHALL-*` identifiers cited in the source are defined inside that document; there is no separate SRS-006 file.

### License

AGPL-3.0 — see LICENSE

---

Copyright © 2026 Spey Systems LTD. All rights reserved.
Patent GB2521625.0
