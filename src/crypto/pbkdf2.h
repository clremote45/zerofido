/*
 * ZeroFIDO
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Single-block PBKDF2-HMAC-SHA256 (dkLen fixed at 32 bytes, one AES-256 key).
 * salt_len must be <= 64 bytes; the vault KDF always uses a 16-byte random
 * salt, but the limit is generous enough for the test-vector salts used to
 * validate this implementation.
 */
bool zf_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt,
                           size_t salt_len, uint32_t iterations, uint8_t out[32]);
