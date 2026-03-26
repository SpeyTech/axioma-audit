#!/bin/bash
# ax-phase1-audit.sh
# Verification script for axioma-audit Phase 1
#
# DVEC: v1.3 | SRS: v0.3
# STATUS: Production-grade CI/CD harness
#
# Copyright (c) 2026 The Murray Family Innovation Trust
# SPDX-License-Identifier: GPL-3.0-or-later
# Patent: UK GB2521625.0

set -euo pipefail

REPO_ROOT=$(pwd)
BUILD_DIR="${REPO_ROOT}/build"

# Golden references — MUST match on x86_64, ARM64, RISC-V
EXPECTED_E0="0976582f90120f7c10263221aef8f0666156f465fc46cd48ef9aa2d6a1ed390c"
EXPECTED_L0="7bb0d791697306ce2f1cc5df0bcdf66d810d6af9425aa380b352a62453a5ec7b"
EXPECTED_L3="0a6b796ca38fe030c7108e15551a05ee1628392e9a88af94ccf840b8d4605d3e"

echo "==============================================================="
echo "  axioma-audit Phase 1 Verification"
echo "  DVEC: v1.3 | SRS-001: v0.3 | Class: D1"
echo "==============================================================="
echo ""

# =============================================================================
# [1/4] BUILD VERIFICATION
# =============================================================================
echo "=== [1/4] Build Verification ==="

# Portable job count (Linux nproc, macOS sysctl, fallback 1)
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)

cmake -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${BUILD_DIR}" -- -j"${JOBS}"

echo "    ✓ Build complete"
echo ""

# =============================================================================
# [2/4] TEST SUITE EXECUTION
# =============================================================================
echo "=== [2/4] Test Suite Execution ==="

ctest --test-dir "${BUILD_DIR}" --output-on-failure

echo "    ✓ All tests passed"
echo ""

# =============================================================================
# [3/4] RTM TRACEABILITY AUDIT
# =============================================================================
echo "=== [3/4] RTM Traceability Audit ==="

if ! python3 "${REPO_ROOT}/ax-rtm-verify.py" --root "${REPO_ROOT}"; then
    echo "    ✗ RTM verification failed"
    exit 1
fi

echo "    ✓ RTM conformant"
echo ""

# =============================================================================
# [4/4] CROSS-PLATFORM BIT-IDENTITY CHECK
# =============================================================================
echo "=== [4/4] Cross-Platform Bit-Identity Check ==="

# Capture test output
COMMITMENT_OUTPUT=$("${BUILD_DIR}/test_commitment" 2>&1)
LEDGER_OUTPUT=$("${BUILD_DIR}/test_ledger" 2>&1)

# Extract machine-readable hashes (format: KEY:hash)
ACTUAL_E0=$(echo "${COMMITMENT_OUTPUT}" | grep "^E0:" | cut -d':' -f2 || true)
ACTUAL_L0=$(echo "${LEDGER_OUTPUT}" | grep "^L0:" | cut -d':' -f2 || true)
ACTUAL_L3=$(echo "${LEDGER_OUTPUT}" | grep "^L3:" | cut -d':' -f2 || true)

# Validate extraction succeeded
if [ -z "${ACTUAL_E0}" ]; then
    echo "    ✗ FAILED: Could not extract E0 (genesis evidence)"
    echo "      Ensure test_commitment outputs: E0:<hex>"
    exit 1
fi

if [ -z "${ACTUAL_L0}" ]; then
    echo "    ✗ FAILED: Could not extract L0 (genesis chain)"
    echo "      Ensure test_ledger outputs: L0:<hex>"
    exit 1
fi

if [ -z "${ACTUAL_L3}" ]; then
    echo "    ✗ FAILED: Could not extract L3 (chain after 3 appends)"
    echo "      Ensure test_ledger outputs: L3:<hex>"
    exit 1
fi

# Verify E0
if [ "${ACTUAL_E0}" = "${EXPECTED_E0}" ]; then
    echo "    ✓ E0 (genesis evidence): MATCH"
else
    echo "    ✗ E0 MISMATCH"
    echo "      Expected: ${EXPECTED_E0}"
    echo "      Actual:   ${ACTUAL_E0}"
    exit 1
fi

# Verify L0
if [ "${ACTUAL_L0}" = "${EXPECTED_L0}" ]; then
    echo "    ✓ L0 (genesis chain):    MATCH"
else
    echo "    ✗ L0 MISMATCH"
    echo "      Expected: ${EXPECTED_L0}"
    echo "      Actual:   ${ACTUAL_L0}"
    exit 1
fi

# Verify L3
if [ "${ACTUAL_L3}" = "${EXPECTED_L3}" ]; then
    echo "    ✓ L3 (chain +3 appends): MATCH"
else
    echo "    ✗ L3 MISMATCH"
    echo "      Expected: ${EXPECTED_L3}"
    echo "      Actual:   ${ACTUAL_L3}"
    exit 1
fi

echo ""
echo "==============================================================="
echo "  PHASE 1 AUDIT: CONFORMANT"
echo ""
echo "  Golden References (D1 — cross-platform identical):"
echo "    E0: ${ACTUAL_E0}"
echo "    L0: ${ACTUAL_L0}"
echo "    L3: ${ACTUAL_L3}"
echo "==============================================================="
