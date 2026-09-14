#include "zf_vault_session.h"

#include <string.h>

#include "../zerofido_crypto.h"

static uint8_t g_vmk[ZF_VAULT_KEY_LEN];
static bool g_unlocked;

bool zf_vault_session_is_configured(Storage *storage) {
    return zf_vault_key_is_configured(storage);
}

bool zf_vault_session_is_unlocked(void) {
    return g_unlocked;
}

ZfVaultKeyLoadStatus zf_vault_session_unlock(Storage *storage, const char *pin, size_t pin_len) {
    uint8_t vmk[ZF_VAULT_KEY_LEN];
    ZfVaultKeyLoadStatus status = zf_vault_key_unlock(storage, pin, pin_len, vmk);

    if (status == ZfVaultKeyLoadOk) {
        memcpy(g_vmk, vmk, sizeof(g_vmk));
        g_unlocked = true;
    }
    zf_crypto_secure_zero(vmk, sizeof(vmk));
    return status;
}

void zf_vault_session_lock(void) {
    zf_crypto_secure_zero(g_vmk, sizeof(g_vmk));
    g_unlocked = false;
}

bool zf_vault_session_copy_key(uint8_t out_vmk[ZF_VAULT_KEY_LEN]) {
    if (!g_unlocked || !out_vmk) {
        return false;
    }
    memcpy(out_vmk, g_vmk, sizeof(g_vmk));
    return true;
}

void zf_vault_session_shutdown(void) {
    zf_vault_session_lock();
}
