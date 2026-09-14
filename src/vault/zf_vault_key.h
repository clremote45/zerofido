#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <storage/storage.h>

#define ZF_VAULT_KEY_LEN 32U
#define ZF_VAULT_KDF_SALT_LEN 16U

typedef enum {
    ZfVaultKeyLoadMissing = 0,
    ZfVaultKeyLoadOk,
    ZfVaultKeyLoadInvalid,
} ZfVaultKeyLoadStatus;

bool zf_vault_key_is_configured(Storage *storage);
bool zf_vault_key_create(Storage *storage, const char *pin, size_t pin_len,
                         uint32_t pbkdf2_iterations, uint8_t out_vmk[ZF_VAULT_KEY_LEN]);
ZfVaultKeyLoadStatus zf_vault_key_unlock(Storage *storage, const char *pin, size_t pin_len,
                                         uint8_t out_vmk[ZF_VAULT_KEY_LEN]);
bool zf_vault_key_rewrap(Storage *storage, const char *old_pin, size_t old_pin_len,
                         const char *new_pin, size_t new_pin_len, uint32_t pbkdf2_iterations);
bool zf_vault_key_destroy(Storage *storage);
