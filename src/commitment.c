/**
 * @file commitment.c
 * @brief Domain-separated cryptographic commitment implementation
 *
 * DVEC: v1.3
 * DETERMINISM: D1 — Strict Deterministic
 * MEMORY: Zero Dynamic Allocation
 *
 * Implements the commitment function per DVM-SPEC-001 §7.1:
 *   commit(e) = SHA-256(tag || LE64(|payload|) || payload)
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Patent: UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-001, SRS-007-SHALL-002, SRS-007-SHALL-003,
 *               SRS-007-SHALL-004, SRS-007-SHALL-005, SRS-007-SHALL-008
 */

#include <axilog/commitment.h>
#include <axilog/dvm_compat.h>
#include "sha256_internal.h"
#include <string.h>

/**
 * @brief Compute domain-separated cryptographic commitment
 *
 * SRS-007-SHALL-001: Evidence commitment SHALL use SHA-256.
 * SRS-007-SHALL-002: Commitment function SHALL use domain separation.
 * SRS-007-SHALL-003: Domain separation SHALL use format:
 *                    SHA-256(tag || LE64(len) || payload)
 * SRS-007-SHALL-004: Tag SHALL be ASCII, null-terminated, NOT included
 *                    in payload_len.
 * SRS-007-SHALL-005: Length encoding SHALL be little-endian 64-bit.
 * SRS-007-SHALL-008: Input domain validation SHALL reject invalid inputs.
 *
 * SHA-256 INPUT RULE (MANDATORY):
 *   sha256_update(&ctx, tag, tag_len);
 *   sha256_update(&ctx, le64, 8);
 *   sha256_update(&ctx, payload, payload_len);
 *   sha256_final(&ctx, out);
 * No concatenated buffer allowed.
 */
void axilog_commit(
    const char    *tag,
    const uint8_t *payload,
    uint64_t       payload_len,
    uint8_t        out_commit[32],
    ct_fault_flags_t *faults
)
{
    ax_sha256_ctx_t sha_ctx;
    uint8_t le64_buf[8];
    size_t tag_len;

    /* Input domain validation (SRS-007-SHALL-008) */
    if (tag == NULL || out_commit == NULL || faults == NULL) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        if (out_commit != NULL) {
            memset(out_commit, 0, 32);
        }
        return;
    }

    /* Payload validation: NULL payload only valid if payload_len == 0 */
    if (payload == NULL && payload_len != 0U) {
        faults->domain = 1;
        memset(out_commit, 0, 32);
        return;
    }

    /* Compute tag length (not including null terminator) */
    tag_len = strlen(tag);
    if (tag_len == 0U) {
        faults->domain = 1;
        memset(out_commit, 0, 32);
        return;
    }

    /* Encode payload length as little-endian 64-bit */
    axilog_le64_encode(payload_len, le64_buf);

    /* Initialize SHA-256 context */
    ax_sha256_init(&sha_ctx);

    /*
     * SHA-256 INPUT SEQUENCE (MANDATORY ORDER):
     * 1. tag bytes (not including null terminator)
     * 2. LE64(payload_len)
     * 3. payload bytes
     */
    ax_sha256_update(&sha_ctx, (const uint8_t *)tag, tag_len);
    ax_sha256_update(&sha_ctx, le64_buf, 8U);
    if (payload_len > 0U) {
        ax_sha256_update(&sha_ctx, payload, (size_t)payload_len);
    }

    /* Finalize and output */
    ax_sha256_final(&sha_ctx, out_commit);
}
