/**
 * @file audit.h
 * @brief Axilog Layer 6 Cryptographic Audit Ledger
 *
 * DVEC: v1.3
 * DETERMINISM: D1 — Strict Deterministic
 * MEMORY: Zero Dynamic Allocation
 *
 * This module implements the append-only cryptographic audit ledger
 * for the Axioma framework. All state transitions are committed to
 * a hash chain that provides tamper-evident, verifiable audit trails.
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Patent: UK GB2521625.0
 *
 * @traceability SRS-001-SHALL-006, SRS-001-SHALL-007, SRS-005-SHALL-001,
 *               SRS-005-SHALL-002, SRS-005-SHALL-003, SRS-005-SHALL-005,
 *               SRS-005-SHALL-006, SRS-005-SHALL-007, SRS-006-SHALL-001,
 *               SRS-006-SHALL-002, SRS-006-SHALL-003, SRS-006-SHALL-004,
 *               SRS-006-SHALL-005, SRS-006-SHALL-006, SRS-006-SHALL-007,
 *               SRS-007-SHALL-006, SRS-007-SHALL-007, SRS-007-SHALL-008
 */

#ifndef AXILOG_AUDIT_H
#define AXILOG_AUDIT_H

#include <axilog/types.h>
#include <axilog/commitment.h>
#include <axilog/dvec.h>
#include <stdint.h>

/**
 * @brief Ledger context structure
 *
 * Represents the complete state of a cryptographic audit ledger.
 *
 * Memory layout: Fixed size, no pointers, no heap ownership.
 * _pad MUST be zeroed via memset (SRS-001-SHALL-006).
 *
 * Rules:
 * - failed == 1 → no further mutation permitted (SRS-005-SHALL-005)
 * - initialised != 1 → context invalid for append operations
 * - sequence overflow → terminal failure (SRS-006-SHALL-005)
 *
 * @traceability SRS-001-SHALL-006, SRS-005-SHALL-005, SRS-006-SHALL-005
 */
typedef struct {
    uint8_t  current_hash[32];  /**< Current chain head hash (Ln) */
    uint8_t  genesis_hash[32];  /**< Genesis hash (L0) — immutable after init */
    uint64_t sequence;          /**< Event sequence number (0 at genesis) */
    uint8_t  failed;            /**< Terminal failure flag */
    uint8_t  initialised;       /**< Initialization complete flag */
    uint8_t  _pad[6];           /**< Padding — MUST be zeroed */
} ax_ledger_ctx_t;

/**
 * @brief Evidence record for commitment
 *
 * Transport/view structure for evidence records to be committed.
 *
 * Rules:
 * - MUST NOT be hashed directly (only payload bytes)
 * - Null terminator NOT included in payload_len
 * - tag must be valid AX_TAG_* from domain registry
 *
 * @traceability SRS-006-SHALL-003, SRS-007-SHALL-006
 */
typedef struct {
    const char    *tag;         /**< Evidence type tag (AX_TAG_*) */
    const uint8_t *payload;     /**< RFC 8785 canonicalised payload */
    uint64_t       payload_len; /**< Byte count (no null terminator) */
} ax_evidence_t;

/**
 * @defgroup GenesisConstants Genesis Constants
 *
 * Immutable genesis payload for deterministic initialization.
 * Length is exact byte count, no null terminator included.
 *
 * @{
 */

/** @brief Genesis payload (RFC 8785 JCS canonical JSON) */
static const char AX_GENESIS_PAYLOAD[] =
    "{\"component\":\"axilog-core\","
    "\"evidence_type\":\"AX:STATE:v1\","
    "\"is_terminal\":false,"
    "\"platform\":\"universal\","
    "\"state_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\"}";

/** @brief Genesis payload length (no null terminator) */
#define AX_GENESIS_PAYLOAD_LEN ((uint64_t)(sizeof(AX_GENESIS_PAYLOAD) - 1U))

/** @brief Ledger chain tag (protocol prefix, NOT evidence type) */
static const char AX_LEDGER_CHAIN_TAG[] = "AX:LEDGER:v1";

/** @} */

/**
 * @brief Initialize ledger with deterministic genesis
 *
 * Creates a new ledger context with deterministic genesis state.
 * Two independent calls with identical inputs MUST produce identical
 * genesis_hash values across all platforms (x86_64, ARM64, RISC-V).
 *
 * GENESIS SEQUENCE (MANDATORY — SRS-001-SHALL-006):
 * 1. memset(ctx, 0, sizeof(ax_ledger_ctx_t))
 * 2. Compute e0 = SHA-256(AX_TAG_STATE || LE64(len) || genesis_payload)
 * 3. Compute L0 = SHA-256("AX:LEDGER:v1" || e0)
 * 4. ctx->genesis_hash = L0
 * 5. ctx->current_hash = L0
 * 6. ctx->sequence = 0
 * 7. ctx->initialised = 1
 * 8. ctx->failed = 0
 *
 * @param ctx    Ledger context to initialize (caller-owned)
 * @param faults Fault context for error propagation
 *
 * @pre ctx != NULL
 * @pre faults != NULL
 *
 * @post On success: ctx fully initialized, genesis_hash set
 * @post On failure: faults->domain == 1, ctx zeroed
 *
 * @traceability SRS-001-SHALL-006, SRS-001-SHALL-007, SRS-006-SHALL-002
 */
void ax_ledger_genesis(
    ax_ledger_ctx_t  *ctx,
    ct_fault_flags_t *faults
);

/**
 * @brief Append commitment to ledger chain
 *
 * Extends the hash chain with a new commitment:
 *   Ln = SHA-256("AX:LEDGER:v1" || Ln-1 || commit)
 *
 * ENTRY GUARDS (STRICT ORDER — must be checked in this sequence):
 * 1. ctx->failed == 1 → set ledger_fail, return
 * 2. ctx->initialised != 1 → set ledger_fail, set failed, return
 * 3. ctx->sequence == UINT64_MAX → set ledger_fail, set failed, return
 *
 * @param ctx    Ledger context
 * @param commit 32-byte commitment to append
 * @param faults Fault context for error propagation
 *
 * @pre ctx != NULL
 * @pre commit != NULL
 * @pre faults != NULL
 * @pre ctx->initialised == 1
 * @pre ctx->failed == 0
 *
 * @post On success: ctx->current_hash updated, ctx->sequence incremented
 * @post On failure: ctx->failed == 1, faults->ledger_fail == 1
 *
 * @traceability SRS-005-SHALL-005, SRS-006-SHALL-002, SRS-006-SHALL-004,
 *               SRS-006-SHALL-005
 */
void ax_ledger_append(
    ax_ledger_ctx_t  *ctx,
    const uint8_t     commit[32],
    ct_fault_flags_t *faults
);

/**
 * @brief Verify internal ledger consistency
 *
 * Phase 1 verification: checks internal state consistency.
 * Sets failed flag on any inconsistency (fail-closed).
 *
 * Checks performed:
 * - initialised == 1
 * - padding bytes are zero
 * - sequence is within valid range
 *
 * @param ctx    Ledger context to verify
 * @param faults Fault context for error propagation
 *
 * @pre ctx != NULL
 * @pre faults != NULL
 *
 * @post On inconsistency: ctx->failed == 1, faults->ledger_fail == 1
 *
 * @traceability SRS-005-SHALL-005, SRS-006-SHALL-007
 */
void ax_verify_chain(
    ax_ledger_ctx_t  *ctx,
    ct_fault_flags_t *faults
);

/**
 * @brief Commit evidence record to hash
 *
 * Validates evidence record and computes domain-separated commitment.
 *
 * VALIDATION (ALL REQUIRED — SRS-007-SHALL-008):
 * - ev != NULL
 * - ev->tag != NULL
 * - ev->payload != NULL
 * - ev->payload_len > 0
 * - tag is valid AX_TAG_* from domain registry
 *
 * On validation failure: faults->domain = 1, return without output.
 *
 * @param ev         Evidence record to commit
 * @param out_commit Output buffer for 32-byte commitment
 * @param faults     Fault context for error propagation
 *
 * @pre ev != NULL
 * @pre out_commit != NULL
 * @pre faults != NULL
 *
 * @post On success: out_commit contains valid SHA-256 commitment
 * @post On failure: faults->domain == 1, out_commit zeroed
 *
 * @traceability SRS-006-SHALL-003, SRS-007-SHALL-006, SRS-007-SHALL-008
 */
void ax_commit_evidence(
    const ax_evidence_t  *ev,
    uint8_t               out_commit[32],
    ct_fault_flags_t     *faults
);

#endif /* AXILOG_AUDIT_H */
