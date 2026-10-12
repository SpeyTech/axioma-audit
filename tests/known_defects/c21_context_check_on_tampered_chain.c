/**
 * @file c21_context_check_on_tampered_chain.c
 * @brief Known-defect reproducer (C-21), built against PINNED MAIN only
 *
 * Uses only the API present on 5c7b05f. Asserts the behaviour a chain
 * verifier must have: ax_verify_chain() should fault on a context whose
 * head was altered or that was fabricated. On 5c7b05f it does not, so this
 * program exits 1 there. CI runs it against the pinned main commit and
 * requires exit 1, so the defect stays explicitly tracked until the fix
 * is merged; it is not part of the normal test suite.
 *
 * Copyright (c) 2026 Spey Systems LTD
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <axilog/audit.h>
#include <axilog/types.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    ax_ledger_ctx_t ctx, fake;
    ct_fault_flags_t f;
    uint8_t c[32];
    int detected = 0;

    memset(c, 0xAB, sizeof c);
    ct_fault_init(&f);
    ax_ledger_genesis(&ctx, &f);
    ax_ledger_append(&ctx, c, &f);

    ctx.current_hash[0] ^= 0x01;          /* altered head */
    ct_fault_init(&f);
    ax_verify_chain(&ctx, &f);
    detected += ct_fault_any(&f) ? 1 : 0;

    memset(&fake, 0, sizeof fake);        /* fabricated, never through genesis */
    fake.initialised = 1;
    ct_fault_init(&f);
    ax_verify_chain(&fake, &f);
    detected += ct_fault_any(&f) ? 1 : 0;

    printf("tamper cases detected by ax_verify_chain: %d of 2\n", detected);
    return detected == 2 ? 0 : 1;
}
