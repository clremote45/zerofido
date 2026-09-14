#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <storage/storage.h>

#include "zf_vault_key.h"

bool zf_vault_session_is_configured(Storage *storage);
bool zf_vault_session_is_unlocked(void);
ZfVaultKeyLoadStatus zf_vault_session_unlock(Storage *storage, const char *pin, size_t pin_len);
void zf_vault_session_lock(void);
bool zf_vault_session_copy_key(uint8_t out_vmk[ZF_VAULT_KEY_LEN]);
void zf_vault_session_shutdown(void);
