/*
 * ZeroFIDO
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#include "pbkdf2.h"

#include <string.h>

#include "hmac_sha256.h"

#define ZF_PBKDF2_MAX_SALT_LEN 64U

/*
 * Volatile-store zero, mirroring the local helper in hmac_sha256.c. This file
 * stays inside crypto/ and does not pull in zerofido_crypto.h, so it keeps
 * its own copy rather than reaching into the app-level crypto wrapper.
 */
static void zf_pbkdf2_secure_zero(void *data, size_t size) {
    volatile uint8_t *ptr = data;

    if (!ptr) {
        return;
    }

    while (size-- > 0U) {
        *ptr++ = 0;
    }
}

/*
 * dkLen is fixed at 32 bytes, so only the first PBKDF2 block (i = 1) is ever
 * produced. Uses the scratch-based HMAC entry point so no HMAC context or key
 * block is duplicated across iterations, keeping the frame small relative to
 * the 4KB app stack_size.
 */
bool zf_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt,
                           size_t salt_len, uint32_t iterations, uint8_t out[32]) {
    ZfHmacSha256Scratch scratch;
    uint8_t salt_block[ZF_PBKDF2_MAX_SALT_LEN + 4U];
    uint8_t u[32];
    uint8_t t[32];
    bool ok = false;

    if (!password || !salt || !out || iterations == 0U || salt_len > ZF_PBKDF2_MAX_SALT_LEN) {
        return false;
    }

    memcpy(salt_block, salt, salt_len);
    salt_block[salt_len + 0U] = 0x00U;
    salt_block[salt_len + 1U] = 0x00U;
    salt_block[salt_len + 2U] = 0x00U;
    salt_block[salt_len + 3U] = 0x01U;

    if (!zf_hmac_sha256_parts_with_scratch(&scratch, password, password_len, salt_block,
                                           salt_len + 4U, NULL, 0U, u)) {
        goto cleanup;
    }
    memcpy(t, u, sizeof(t));

    for (uint32_t i = 1; i < iterations; ++i) {
        if (!zf_hmac_sha256_parts_with_scratch(&scratch, password, password_len, u, sizeof(u), NULL,
                                               0U, u)) {
            goto cleanup;
        }
        for (size_t b = 0; b < sizeof(t); ++b) {
            t[b] ^= u[b];
        }
    }

    memcpy(out, t, sizeof(t));
    ok = true;

cleanup:
    zf_pbkdf2_secure_zero(salt_block, sizeof(salt_block));
    zf_pbkdf2_secure_zero(u, sizeof(u));
    zf_pbkdf2_secure_zero(t, sizeof(t));
    return ok;
}
