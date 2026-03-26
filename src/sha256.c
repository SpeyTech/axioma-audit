/**
 * @file sha256.c
 * @brief SHA-256 implementation (FIPS 180-4 compliant)
 *
 * DVEC: v1.3
 * DETERMINISM: D1 — Strict Deterministic
 * MEMORY: Zero Dynamic Allocation
 *
 * This implementation follows FIPS 180-4 exactly:
 * - §4.1.2: SHA-256 Functions
 * - §4.2.2: SHA-256 Constants
 * - §5.3.3: Initial Hash Values
 * - §6.2.2: SHA-256 Hash Computation
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Patent: UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-001, SRS-011-SHALL-001
 */

#include "sha256_internal.h"
#include <string.h>

/**
 * @brief SHA-256 round constants K (FIPS 180-4 §4.2.2)
 *
 * These are the first 32 bits of the fractional parts of the
 * cube roots of the first 64 prime numbers.
 */
static const uint32_t K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

/**
 * @brief Initial hash values H (FIPS 180-4 §5.3.3)
 *
 * These are the first 32 bits of the fractional parts of the
 * square roots of the first 8 prime numbers.
 */
static const uint32_t H_INIT[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

/**
 * @brief Right rotate (FIPS 180-4 §3.2)
 */
static inline uint32_t rotr(uint32_t x, unsigned int n)
{
    return (x >> n) | (x << (32U - n));
}

/**
 * @brief Ch function (FIPS 180-4 §4.1.2)
 * Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
 */
static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

/**
 * @brief Maj function (FIPS 180-4 §4.1.2)
 * Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
 */
static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/**
 * @brief Σ0 function (FIPS 180-4 §4.1.2)
 * Σ0(x) = ROTR²(x) XOR ROTR¹³(x) XOR ROTR²²(x)
 */
static inline uint32_t sigma0_upper(uint32_t x)
{
    return rotr(x, 2U) ^ rotr(x, 13U) ^ rotr(x, 22U);
}

/**
 * @brief Σ1 function (FIPS 180-4 §4.1.2)
 * Σ1(x) = ROTR⁶(x) XOR ROTR¹¹(x) XOR ROTR²⁵(x)
 */
static inline uint32_t sigma1_upper(uint32_t x)
{
    return rotr(x, 6U) ^ rotr(x, 11U) ^ rotr(x, 25U);
}

/**
 * @brief σ0 function (FIPS 180-4 §4.1.2)
 * σ0(x) = ROTR⁷(x) XOR ROTR¹⁸(x) XOR SHR³(x)
 */
static inline uint32_t sigma0_lower(uint32_t x)
{
    return rotr(x, 7U) ^ rotr(x, 18U) ^ (x >> 3U);
}

/**
 * @brief σ1 function (FIPS 180-4 §4.1.2)
 * σ1(x) = ROTR¹⁷(x) XOR ROTR¹⁹(x) XOR SHR¹⁰(x)
 */
static inline uint32_t sigma1_lower(uint32_t x)
{
    return rotr(x, 17U) ^ rotr(x, 19U) ^ (x >> 10U);
}

/**
 * @brief Decode big-endian 32-bit word from bytes
 *
 * SHA-256 processes data as big-endian words (FIPS 180-4 §3.1).
 */
static inline uint32_t be32_decode(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}

/**
 * @brief Encode 32-bit word as big-endian bytes
 */
static inline void be32_encode(uint32_t v, uint8_t *p)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

/**
 * @brief Process a single 512-bit (64-byte) block
 *
 * Implements FIPS 180-4 §6.2.2 hash computation.
 */
static void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;
    unsigned int t;

    /* Step 1: Prepare message schedule W (FIPS 180-4 §6.2.2 step 1) */
    for (t = 0U; t < 16U; t++) {
        W[t] = be32_decode(&block[t * 4U]);
    }
    for (t = 16U; t < 64U; t++) {
        W[t] = sigma1_lower(W[t - 2U]) + W[t - 7U] +
               sigma0_lower(W[t - 15U]) + W[t - 16U];
    }

    /* Step 2: Initialize working variables (FIPS 180-4 §6.2.2 step 2) */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    /* Step 3: Main loop (FIPS 180-4 §6.2.2 step 3) */
    for (t = 0U; t < 64U; t++) {
        T1 = h + sigma1_upper(e) + ch(e, f, g) + K[t] + W[t];
        T2 = sigma0_upper(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    /* Step 4: Compute intermediate hash (FIPS 180-4 §6.2.2 step 4) */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/**
 * @brief Initialize SHA-256 context
 *
 * SRS-007-SHALL-001: Evidence commitment SHALL use SHA-256.
 */
void ax_sha256_init(ax_sha256_ctx_t *ctx)
{
    unsigned int i;

    for (i = 0U; i < 8U; i++) {
        ctx->state[i] = H_INIT[i];
    }
    ctx->total_len = 0U;
    ctx->buffer_len = 0U;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    memset(ctx->_pad, 0, sizeof(ctx->_pad));
}

/**
 * @brief Update SHA-256 hash with data
 *
 * SRS-011-SHALL-001: Cross-platform identity SHALL be verified.
 */
void ax_sha256_update(ax_sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t fill;
    size_t left;

    if (len == 0U) {
        return;
    }

    left = (size_t)ctx->buffer_len;
    fill = 64U - left;

    ctx->total_len += (uint64_t)len;

    /* Fill partial buffer if we have one and incoming data completes it */
    if (left > 0U && len >= fill) {
        memcpy(&ctx->buffer[left], data, fill);
        sha256_transform(ctx->state, ctx->buffer);
        data += fill;
        len -= fill;
        left = 0U;
    }

    /* Process complete blocks directly */
    while (len >= 64U) {
        sha256_transform(ctx->state, data);
        data += 64U;
        len -= 64U;
    }

    /* Buffer remaining partial block */
    if (len > 0U) {
        memcpy(&ctx->buffer[left], data, len);
    }
    ctx->buffer_len = (uint8_t)(left + len);
}

/**
 * @brief Finalize SHA-256 hash
 *
 * Applies FIPS 180-4 §5.1.1 padding:
 * - Append bit '1' (0x80 byte)
 * - Append zeros until 448 bits mod 512
 * - Append 64-bit big-endian message length in bits
 */
void ax_sha256_final(ax_sha256_ctx_t *ctx, uint8_t hash[32])
{
    uint8_t finalblock[64];
    uint64_t bit_len;
    size_t pad_start;
    unsigned int i;

    /* Calculate message length in bits */
    bit_len = ctx->total_len * 8U;

    /* Prepare final block(s) */
    memset(finalblock, 0, sizeof(finalblock));
    memcpy(finalblock, ctx->buffer, ctx->buffer_len);

    /* Append padding bit */
    pad_start = ctx->buffer_len;
    finalblock[pad_start] = 0x80U;

    /* If not enough room for length, process this block and start another */
    if (pad_start >= 56U) {
        sha256_transform(ctx->state, finalblock);
        memset(finalblock, 0, sizeof(finalblock));
    }

    /* Append bit length as big-endian 64-bit value */
    finalblock[56] = (uint8_t)(bit_len >> 56);
    finalblock[57] = (uint8_t)(bit_len >> 48);
    finalblock[58] = (uint8_t)(bit_len >> 40);
    finalblock[59] = (uint8_t)(bit_len >> 32);
    finalblock[60] = (uint8_t)(bit_len >> 24);
    finalblock[61] = (uint8_t)(bit_len >> 16);
    finalblock[62] = (uint8_t)(bit_len >> 8);
    finalblock[63] = (uint8_t)(bit_len);

    sha256_transform(ctx->state, finalblock);

    /* Output hash as big-endian */
    for (i = 0U; i < 8U; i++) {
        be32_encode(ctx->state[i], &hash[i * 4U]);
    }
}
