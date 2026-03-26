/**
 * @file sha256_internal.h
 * @brief Internal SHA-256 implementation (FIPS 180-4 compliant)
 *
 * DVEC: v1.3
 * DETERMINISM: D1 — Strict Deterministic
 * MEMORY: Zero Dynamic Allocation
 *
 * This implementation is:
 * - FIPS 180-4 compliant
 * - Big-endian explicit (no platform dependencies)
 * - Zero dynamic allocation
 * - No global mutable state
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Patent: UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-001, SRS-011-SHALL-001
 */

#ifndef AXILOG_SHA256_INTERNAL_H
#define AXILOG_SHA256_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief SHA-256 context structure
 *
 * Memory layout: Fixed size, no pointers, caller-owned.
 * Total size: 8*4 + 64 + 8 + 1 + 7 = 112 bytes
 */
typedef struct {
    uint32_t state[8];       /**< Current hash state (H0-H7) */
    uint8_t  buffer[64];     /**< Partial block buffer */
    uint64_t total_len;      /**< Total bytes processed */
    uint8_t  buffer_len;     /**< Bytes in partial buffer (0-63) */
    uint8_t  _pad[7];        /**< Padding for alignment */
} ax_sha256_ctx_t;

/**
 * @brief Initialize SHA-256 context
 *
 * Sets initial hash values per FIPS 180-4 §5.3.3.
 *
 * @param ctx SHA-256 context to initialize
 *
 * @pre ctx != NULL
 * @post ctx is ready for sha256_update calls
 */
void ax_sha256_init(ax_sha256_ctx_t *ctx);

/**
 * @brief Update SHA-256 hash with data
 *
 * Processes input data in 64-byte blocks. Partial blocks are
 * buffered until complete.
 *
 * @param ctx  SHA-256 context
 * @param data Input data bytes
 * @param len  Number of bytes to process
 *
 * @pre ctx != NULL
 * @pre data != NULL || len == 0
 */
void ax_sha256_update(ax_sha256_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalize SHA-256 hash
 *
 * Applies padding and outputs final hash per FIPS 180-4.
 *
 * @param ctx  SHA-256 context
 * @param hash Output buffer for 32-byte hash
 *
 * @pre ctx != NULL
 * @pre hash != NULL
 * @post hash contains the final SHA-256 digest
 * @post ctx is invalidated (must re-init before reuse)
 */
void ax_sha256_final(ax_sha256_ctx_t *ctx, uint8_t hash[32]);

#endif /* AXILOG_SHA256_INTERNAL_H */
