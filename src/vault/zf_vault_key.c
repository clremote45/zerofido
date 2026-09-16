#include "zf_vault_key.h"

#include <furi_hal.h>
#include <furi_hal_random.h>
#include <string.h>

#include "../crypto/aes256.h"
#include "../crypto/pbkdf2.h"
#include "../zerofido_crypto.h"
#include "../zerofido_storage.h"
#include "../zerofido_types.h"

#define ZF_VAULT_KEY_FILE_PATH ZF_APP_DATA_DIR "/vault_key.bin"
#define ZF_VAULT_KEY_FILE_TEMP_PATH ZF_APP_DATA_DIR "/vault_key.tmp"
#define ZF_VAULT_KEY_FILE_MAGIC 0x5A464B31UL
#define ZF_VAULT_KEY_FILE_VERSION 1U
#define ZF_VAULT_KEY_SEAL_MAGIC 0x564D4B31UL
#define ZF_VAULT_KEY_ENCLAVE_SLOT FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t reserved[3];
    uint8_t vmk[ZF_VAULT_KEY_LEN];
    uint8_t digest[24];
} ZfVaultKeySeal;

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t reserved[3];
    uint8_t kdf_salt[ZF_VAULT_KDF_SALT_LEN];
    uint32_t kdf_iterations;
    uint8_t kek_iv[16];
    uint8_t enclave_iv[16];
    uint8_t sealed_vmk[sizeof(ZfVaultKeySeal)];
} ZfVaultKeyFileRecord;

static void zf_vault_key_compute_digest(uint32_t magic, uint8_t version, const uint8_t reserved[3],
                                        const uint8_t vmk[ZF_VAULT_KEY_LEN], uint8_t digest[32]) {
    uint8_t material[4 + 1 + 3 + ZF_VAULT_KEY_LEN];

    material[0] = (uint8_t)(magic & 0xFFU);
    material[1] = (uint8_t)((magic >> 8) & 0xFFU);
    material[2] = (uint8_t)((magic >> 16) & 0xFFU);
    material[3] = (uint8_t)((magic >> 24) & 0xFFU);
    material[4] = version;
    memcpy(material + 5, reserved, 3);
    memcpy(material + 8, vmk, ZF_VAULT_KEY_LEN);
    zf_crypto_sha256(material, sizeof(material), digest);
    zf_crypto_secure_zero(material, sizeof(material));
}

static bool zf_vault_key_seal_vmk(const uint8_t kek[32], const uint8_t kek_iv[16],
                                  const uint8_t vmk[ZF_VAULT_KEY_LEN],
                                  uint8_t sealed[sizeof(ZfVaultKeySeal)]) {
    ZfVaultKeySeal plain = {
        .magic = ZF_VAULT_KEY_SEAL_MAGIC,
        .version = ZF_VAULT_KEY_FILE_VERSION,
    };
    uint8_t digest[32];
    bool ok;

    memcpy(plain.vmk, vmk, sizeof(plain.vmk));
    zf_vault_key_compute_digest(plain.magic, plain.version, plain.reserved, plain.vmk, digest);
    memcpy(plain.digest, digest, sizeof(plain.digest));

    ok = zf_crypto_aes256_cbc_encrypt(kek, kek_iv, (const uint8_t *)&plain, sealed, sizeof(plain));

    zf_crypto_secure_zero(&plain, sizeof(plain));
    zf_crypto_secure_zero(digest, sizeof(digest));
    return ok;
}

static bool zf_vault_key_unseal_vmk(const uint8_t kek[32], const uint8_t kek_iv[16],
                                    const uint8_t sealed[sizeof(ZfVaultKeySeal)],
                                    uint8_t out_vmk[ZF_VAULT_KEY_LEN]) {
    ZfVaultKeySeal plain = {0};
    uint8_t digest[32];
    bool ok = false;

    if (!zf_crypto_aes256_cbc_decrypt(kek, kek_iv, sealed, (uint8_t *)&plain, sizeof(plain))) {
        goto cleanup;
    }
    if (plain.magic != ZF_VAULT_KEY_SEAL_MAGIC || plain.version != ZF_VAULT_KEY_FILE_VERSION) {
        goto cleanup;
    }
    zf_vault_key_compute_digest(plain.magic, plain.version, plain.reserved, plain.vmk, digest);
    if (!zf_crypto_constant_time_equal(plain.digest, digest, sizeof(plain.digest))) {
        goto cleanup;
    }
    memcpy(out_vmk, plain.vmk, ZF_VAULT_KEY_LEN);
    ok = true;

cleanup:
    zf_crypto_secure_zero(&plain, sizeof(plain));
    zf_crypto_secure_zero(digest, sizeof(digest));
    return ok;
}

static bool zf_vault_key_enclave_wrap(const uint8_t iv[16], const uint8_t *plain, uint8_t *sealed,
                                      size_t size) {
    bool ok;

    if (!furi_hal_crypto_enclave_load_key(ZF_VAULT_KEY_ENCLAVE_SLOT, iv)) {
        return false;
    }
    ok = furi_hal_crypto_encrypt(plain, sealed, size);
    furi_hal_crypto_enclave_unload_key(ZF_VAULT_KEY_ENCLAVE_SLOT);
    return ok;
}

static bool zf_vault_key_enclave_unwrap(const uint8_t iv[16], const uint8_t *sealed, uint8_t *plain,
                                        size_t size) {
    bool ok;

    if (!furi_hal_crypto_enclave_load_key(ZF_VAULT_KEY_ENCLAVE_SLOT, iv)) {
        return false;
    }
    ok = furi_hal_crypto_decrypt(sealed, plain, size);
    furi_hal_crypto_enclave_unload_key(ZF_VAULT_KEY_ENCLAVE_SLOT);
    return ok;
}

bool zf_vault_key_is_configured(Storage *storage) {
    return storage_file_exists(storage, ZF_VAULT_KEY_FILE_PATH);
}

bool zf_vault_key_create(Storage *storage, const char *pin, size_t pin_len,
                         uint32_t pbkdf2_iterations, uint8_t out_vmk[ZF_VAULT_KEY_LEN]) {
    ZfVaultKeyFileRecord record = {
        .magic = ZF_VAULT_KEY_FILE_MAGIC,
        .version = ZF_VAULT_KEY_FILE_VERSION,
        .kdf_iterations = pbkdf2_iterations,
    };
    uint8_t vmk[ZF_VAULT_KEY_LEN];
    uint8_t kek[32];
    uint8_t sealed_kek_layer[sizeof(ZfVaultKeySeal)];
    bool ok = false;

    if (!storage || !pin || pbkdf2_iterations == 0U || !out_vmk) {
        return false;
    }
    if (!zf_storage_ensure_app_data_dir(storage)) {
        return false;
    }

    furi_hal_random_fill_buf(vmk, sizeof(vmk));
    furi_hal_random_fill_buf(record.kdf_salt, sizeof(record.kdf_salt));
    furi_hal_random_fill_buf(record.kek_iv, sizeof(record.kek_iv));
    furi_hal_random_fill_buf(record.enclave_iv, sizeof(record.enclave_iv));

    if (!zf_pbkdf2_hmac_sha256((const uint8_t *)pin, pin_len, record.kdf_salt,
                               sizeof(record.kdf_salt), pbkdf2_iterations, kek)) {
        goto cleanup;
    }
    if (!zf_vault_key_seal_vmk(kek, record.kek_iv, vmk, sealed_kek_layer)) {
        goto cleanup;
    }
    if (!zf_vault_key_enclave_wrap(record.enclave_iv, sealed_kek_layer, record.sealed_vmk,
                                   sizeof(record.sealed_vmk))) {
        goto cleanup;
    }
    if (!zf_storage_write_file_atomic(storage, ZF_VAULT_KEY_FILE_PATH, ZF_VAULT_KEY_FILE_TEMP_PATH,
                                      (const uint8_t *)&record, sizeof(record))) {
        goto cleanup;
    }

    memcpy(out_vmk, vmk, sizeof(vmk));
    ok = true;

cleanup:
    zf_crypto_secure_zero(vmk, sizeof(vmk));
    zf_crypto_secure_zero(kek, sizeof(kek));
    zf_crypto_secure_zero(sealed_kek_layer, sizeof(sealed_kek_layer));
    zf_crypto_secure_zero(&record, sizeof(record));
    return ok;
}

ZfVaultKeyLoadStatus zf_vault_key_unlock(Storage *storage, const char *pin, size_t pin_len,
                                         uint8_t out_vmk[ZF_VAULT_KEY_LEN]) {
    ZfVaultKeyFileRecord record;
    uint8_t sealed_kek_layer[sizeof(ZfVaultKeySeal)];
    uint8_t kek[32];
    size_t read_size = 0;
    ZfVaultKeyLoadStatus status = ZfVaultKeyLoadInvalid;

    if (!storage || !pin || !out_vmk) {
        return ZfVaultKeyLoadInvalid;
    }
    if (!zf_storage_read_file(storage, ZF_VAULT_KEY_FILE_PATH, (uint8_t *)&record, sizeof(record),
                              &read_size)) {
        return storage_file_exists(storage, ZF_VAULT_KEY_FILE_PATH) ? ZfVaultKeyLoadInvalid
                                                                     : ZfVaultKeyLoadMissing;
    }
    if (read_size != sizeof(record) || record.magic != ZF_VAULT_KEY_FILE_MAGIC ||
        record.version != ZF_VAULT_KEY_FILE_VERSION || record.kdf_iterations == 0U) {
        /* Only wrapped material, but keep the single-exit zeroing discipline. */
        zf_crypto_secure_zero(&record, sizeof(record));
        return ZfVaultKeyLoadInvalid;
    }

    if (!zf_vault_key_enclave_unwrap(record.enclave_iv, record.sealed_vmk, sealed_kek_layer,
                                     sizeof(sealed_kek_layer))) {
        goto cleanup;
    }
    if (!zf_pbkdf2_hmac_sha256((const uint8_t *)pin, pin_len, record.kdf_salt,
                               sizeof(record.kdf_salt), record.kdf_iterations, kek)) {
        goto cleanup;
    }
    if (!zf_vault_key_unseal_vmk(kek, record.kek_iv, sealed_kek_layer, out_vmk)) {
        goto cleanup;
    }
    status = ZfVaultKeyLoadOk;

cleanup:
    zf_crypto_secure_zero(sealed_kek_layer, sizeof(sealed_kek_layer));
    zf_crypto_secure_zero(kek, sizeof(kek));
    zf_crypto_secure_zero(&record, sizeof(record));
    return status;
}

bool zf_vault_key_rewrap(Storage *storage, const char *old_pin, size_t old_pin_len,
                         const char *new_pin, size_t new_pin_len, uint32_t pbkdf2_iterations) {
    uint8_t vmk[ZF_VAULT_KEY_LEN];
    ZfVaultKeyFileRecord record = {
        .magic = ZF_VAULT_KEY_FILE_MAGIC,
        .version = ZF_VAULT_KEY_FILE_VERSION,
        .kdf_iterations = pbkdf2_iterations,
    };
    uint8_t kek[32];
    uint8_t sealed_kek_layer[sizeof(ZfVaultKeySeal)];
    bool ok = false;

    if (!storage || !old_pin || !new_pin || pbkdf2_iterations == 0U) {
        return false;
    }
    if (zf_vault_key_unlock(storage, old_pin, old_pin_len, vmk) != ZfVaultKeyLoadOk) {
        return false;
    }

    furi_hal_random_fill_buf(record.kdf_salt, sizeof(record.kdf_salt));
    furi_hal_random_fill_buf(record.kek_iv, sizeof(record.kek_iv));
    furi_hal_random_fill_buf(record.enclave_iv, sizeof(record.enclave_iv));

    if (!zf_pbkdf2_hmac_sha256((const uint8_t *)new_pin, new_pin_len, record.kdf_salt,
                               sizeof(record.kdf_salt), pbkdf2_iterations, kek)) {
        goto cleanup;
    }
    if (!zf_vault_key_seal_vmk(kek, record.kek_iv, vmk, sealed_kek_layer)) {
        goto cleanup;
    }
    if (!zf_vault_key_enclave_wrap(record.enclave_iv, sealed_kek_layer, record.sealed_vmk,
                                   sizeof(record.sealed_vmk))) {
        goto cleanup;
    }
    ok = zf_storage_write_file_atomic(storage, ZF_VAULT_KEY_FILE_PATH, ZF_VAULT_KEY_FILE_TEMP_PATH,
                                      (const uint8_t *)&record, sizeof(record));

cleanup:
    zf_crypto_secure_zero(vmk, sizeof(vmk));
    zf_crypto_secure_zero(kek, sizeof(kek));
    zf_crypto_secure_zero(sealed_kek_layer, sizeof(sealed_kek_layer));
    zf_crypto_secure_zero(&record, sizeof(record));
    return ok;
}

bool zf_vault_key_destroy(Storage *storage) {
    if (!storage) {
        return false;
    }
    return zf_storage_remove_atomic_file(storage, ZF_VAULT_KEY_FILE_PATH, ZF_VAULT_KEY_FILE_TEMP_PATH);
}
