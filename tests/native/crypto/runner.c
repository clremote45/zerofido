/*
 * ZeroFIDO native AES adapter tests.
 *
 * The fake HAL below models Flipper's raw AES-CBC byte ordering: callers must
 * present key, IV, input, and output in swapped 32-bit register order. It does
 * not implement AES itself; it verifies the adapter's register-order contract
 * against the NIST SP 800-38A AES-256-CBC test vector.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aes256.h"
#include "pbkdf2.h"

static const uint8_t k_key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
    0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
    0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};
static const uint8_t k_iv[16] = {
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x0e,
    0x0f,
};
static const uint8_t k_plain[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
    0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
    0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
    0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
    0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
    0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};
static const uint8_t k_cipher[64] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab,
    0xfb, 0x5f, 0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb,
    0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d, 0x39,
    0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63,
    0x04, 0x23, 0x14, 0x61, 0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9,
    0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b,
};

static uint8_t g_loaded_key[32];
static uint8_t g_loaded_iv[16];
static bool g_loaded;

static void bswap_words(uint8_t *out, const uint8_t *in, size_t size) {
    for (size_t offset = 0; offset < size; offset += 4U) {
        out[offset + 0U] = in[offset + 3U];
        out[offset + 1U] = in[offset + 2U];
        out[offset + 2U] = in[offset + 1U];
        out[offset + 3U] = in[offset + 0U];
    }
}

static bool hal_state_matches(void) {
    uint8_t expected_key[32];
    uint8_t expected_iv[16];

    bswap_words(expected_key, k_key, sizeof(expected_key));
    bswap_words(expected_iv, k_iv, sizeof(expected_iv));
    return g_loaded && memcmp(g_loaded_key, expected_key, sizeof(expected_key)) == 0 &&
           memcmp(g_loaded_iv, expected_iv, sizeof(expected_iv)) == 0;
}

bool furi_hal_crypto_load_key(const uint8_t *key, const uint8_t *iv) {
    memcpy(g_loaded_key, key, sizeof(g_loaded_key));
    memcpy(g_loaded_iv, iv, sizeof(g_loaded_iv));
    g_loaded = true;
    return true;
}

bool furi_hal_crypto_unload_key(void) {
    g_loaded = false;
    return true;
}

bool furi_hal_crypto_encrypt(const uint8_t *input, uint8_t *output, size_t size) {
    uint8_t expected_input[64];
    uint8_t expected_output[64];

    bswap_words(expected_input, k_plain, sizeof(expected_input));
    bswap_words(expected_output, k_cipher, sizeof(expected_output));
    if (size != sizeof(expected_input) || !hal_state_matches() ||
        memcmp(input, expected_input, sizeof(expected_input)) != 0) {
        return false;
    }
    memcpy(output, expected_output, sizeof(expected_output));
    return true;
}

bool furi_hal_crypto_decrypt(const uint8_t *input, uint8_t *output, size_t size) {
    uint8_t expected_input[64];
    uint8_t expected_output[64];

    bswap_words(expected_input, k_cipher, sizeof(expected_input));
    bswap_words(expected_output, k_plain, sizeof(expected_output));
    if (size != sizeof(expected_input) || !hal_state_matches() ||
        memcmp(input, expected_input, sizeof(expected_input)) != 0) {
        return false;
    }
    memcpy(output, expected_output, sizeof(expected_output));
    return true;
}

static int expect_bytes(const char *label, const uint8_t *actual, const uint8_t *expected,
                        size_t size) {
    if (memcmp(actual, expected, size) == 0) {
        return 0;
    }
    fprintf(stderr, "%s mismatch\n", label);
    return 1;
}

/*
 * PBKDF2-HMAC-SHA256 vectors generated with Python's hashlib.pbkdf2_hmac and
 * cross-checked independently; no published PBKDF2-HMAC-SHA256 RFC exists
 * (RFC 6070 covers SHA-1 only), so these are the reference values instead.
 */
static const uint8_t k_pbkdf2_pw1[] = {
    0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
};
static const uint8_t k_pbkdf2_salt1[] = {
    0x73, 0x61, 0x6c, 0x74,
};
static const uint8_t k_pbkdf2_dk1_c1[32] = {
    0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52,
    0x56, 0xc4, 0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
    0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
};
static const uint8_t k_pbkdf2_dk1_c2[32] = {
    0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9,
    0x28, 0xf0, 0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
    0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43,
};
static const uint8_t k_pbkdf2_dk1_c4096[32] = {
    0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6,
    0x84, 0x5c, 0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
    0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a,
};
static const uint8_t k_pbkdf2_pw2[] = {
    0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x50, 0x41, 0x53, 0x53,
    0x57, 0x4f, 0x52, 0x44, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
};
static const uint8_t k_pbkdf2_salt2[] = {
    0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74,
    0x53, 0x41, 0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54,
    0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74,
};
static const uint8_t k_pbkdf2_dk2_c4096[32] = {
    0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f, 0x32, 0xd8, 0x14, 0xb8,
    0x11, 0x6e, 0x84, 0xcf, 0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
    0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1,
};

static int check_pbkdf2(void) {
    uint8_t out[32];
    int failures = 0;

    memset(out, 0, sizeof(out));
    if (!zf_pbkdf2_hmac_sha256(k_pbkdf2_pw1, sizeof(k_pbkdf2_pw1), k_pbkdf2_salt1,
                               sizeof(k_pbkdf2_salt1), 1U, out)) {
        fprintf(stderr, "pbkdf2 c=1 call failed\n");
        failures++;
    } else {
        failures += expect_bytes("pbkdf2 c=1", out, k_pbkdf2_dk1_c1, sizeof(out));
    }

    memset(out, 0, sizeof(out));
    if (!zf_pbkdf2_hmac_sha256(k_pbkdf2_pw1, sizeof(k_pbkdf2_pw1), k_pbkdf2_salt1,
                               sizeof(k_pbkdf2_salt1), 2U, out)) {
        fprintf(stderr, "pbkdf2 c=2 call failed\n");
        failures++;
    } else {
        failures += expect_bytes("pbkdf2 c=2", out, k_pbkdf2_dk1_c2, sizeof(out));
    }

    memset(out, 0, sizeof(out));
    if (!zf_pbkdf2_hmac_sha256(k_pbkdf2_pw1, sizeof(k_pbkdf2_pw1), k_pbkdf2_salt1,
                               sizeof(k_pbkdf2_salt1), 4096U, out)) {
        fprintf(stderr, "pbkdf2 c=4096 call failed\n");
        failures++;
    } else {
        failures += expect_bytes("pbkdf2 c=4096 short", out, k_pbkdf2_dk1_c4096, sizeof(out));
    }

    /* Longer password/salt exercises the >1-block HMAC key path and a 36-byte salt. */
    memset(out, 0, sizeof(out));
    if (!zf_pbkdf2_hmac_sha256(k_pbkdf2_pw2, sizeof(k_pbkdf2_pw2), k_pbkdf2_salt2,
                               sizeof(k_pbkdf2_salt2), 4096U, out)) {
        fprintf(stderr, "pbkdf2 c=4096 long call failed\n");
        failures++;
    } else {
        failures += expect_bytes("pbkdf2 c=4096 long", out, k_pbkdf2_dk2_c4096, sizeof(out));
    }

    /* Rejected inputs must fail rather than silently returning garbage. */
    if (zf_pbkdf2_hmac_sha256(k_pbkdf2_pw1, sizeof(k_pbkdf2_pw1), k_pbkdf2_salt1,
                              sizeof(k_pbkdf2_salt1), 0U, out)) {
        fprintf(stderr, "pbkdf2 zero iterations should be rejected\n");
        failures++;
    }

    return failures;
}

int main(void) {
    uint8_t output[64];
    int failures = 0;

    memset(output, 0, sizeof(output));
    if (!zf_aes256_cbc_encrypt(k_key, k_iv, k_plain, output, sizeof(output))) {
        fprintf(stderr, "encrypt failed\n");
        failures++;
    } else {
        failures += expect_bytes("ciphertext", output, k_cipher, sizeof(output));
    }

    memset(output, 0, sizeof(output));
    if (!zf_aes256_cbc_decrypt(k_key, k_iv, k_cipher, output, sizeof(output))) {
        fprintf(stderr, "decrypt failed\n");
        failures++;
    } else {
        failures += expect_bytes("plaintext", output, k_plain, sizeof(output));
    }

    failures += check_pbkdf2();

    if (failures != 0) {
        return 1;
    }
    printf("native crypto AES adapter and PBKDF2 regressions passed\n");
    return 0;
}
