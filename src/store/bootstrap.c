/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "bootstrap.h"

#include <string.h>

#include "../zerofido_crypto.h"
#include "../zerofido_storage.h"
#include "../zerofido_store.h"
#include "internal.h"
#include "record_format.h"
#include "recovery.h"
#if ZF_VAULT_PIN_KEK
#include "../vault/zf_vault_key.h"
#endif

/* Creates the shared application data directories used by store, PIN, and U2F. */
bool zf_store_bootstrap_ensure_app_data_dir(Storage *storage) {
    return zf_storage_ensure_app_data_dir(storage);
}

typedef struct {
    Storage *storage;
    ZfCredentialStore *store;
    uint8_t *buffer;
    size_t buffer_size;
} ZfStoreBootstrapIndexContext;

static bool zf_store_bootstrap_index_visitor(const char *name, const FileInfo *info,
                                             void *context) {
    ZfStoreBootstrapIndexContext *index_context = context;

    if (!name || !info || !index_context || !index_context->store) {
        return false;
    }
    if (file_info_is_dir(info) || !zf_store_record_format_is_record_name(name)) {
        return true;
    }
    if (index_context->store->count >= ZF_MAX_CREDENTIALS) {
        return true;
    }
    if (!zf_store_ensure_capacity(index_context->store, index_context->store->count + 1U)) {
        return false;
    }
    if (zf_store_record_format_load_index_with_buffer(
            index_context->storage, name,
            &index_context->store->records[index_context->store->count], index_context->buffer,
            index_context->buffer_size)) {
        index_context->store->count++;
    }
    return true;
}

/*
 * Rebuilds the volatile credential index from record files. Broken or
 * non-record files are skipped so one corrupt entry does not hide all others.
 */
bool zf_store_bootstrap_init_with_buffer(Storage *storage, ZfCredentialStore *store,
                                         uint8_t *buffer, size_t buffer_size) {
    char name[96];
    bool ok = false;
    ZfStoreBootstrapIndexContext context = {
        .storage = storage,
        .store = store,
        .buffer = buffer,
        .buffer_size = buffer_size,
    };

    if (!storage || !store || !buffer || buffer_size < ZF_STORE_RECORD_MAX_SIZE) {
        return false;
    }

    zf_store_clear(store);
    if (!zf_store_bootstrap_ensure_app_data_dir(storage)) {
        goto cleanup;
    }

    zf_store_recovery_cleanup_temp_files_with_buffer(storage, buffer, buffer_size);
    if (!zf_storage_for_each_dir_entry(storage, ZF_APP_DATA_DIR, name, sizeof(name),
                                       zf_store_bootstrap_index_visitor, &context)) {
        goto cleanup;
    }

    ok = true;

cleanup:
    zf_crypto_secure_zero(buffer, ZF_STORE_RECORD_MAX_SIZE);
    return ok;
}

typedef struct {
    Storage *storage;
} ZfStoreBootstrapWipeContext;

static bool zf_store_bootstrap_wipe_visitor(const char *name, const FileInfo *info, void *context) {
    ZfStoreBootstrapWipeContext *wipe_context = context;
    char path[128];

    if (!name || !info || !wipe_context) {
        return false;
    }
    if (file_info_is_dir(info)) {
        return true;
    }
    if (!zf_storage_build_child_path(ZF_APP_DATA_DIR, name, path, sizeof(path))) {
        return false;
    }
    return zf_storage_remove_optional(wipe_context->storage, path);
}

/*
 * Startup reset removes every credential-like file plus PIN state. U2F files
 * live under their own subtree and are managed by the U2F persistence layer.
 */
bool zf_store_bootstrap_wipe_app_data(Storage *storage) {
    char name[96];
    const char *const pin_paths[] = {
        ZF_APP_DATA_DIR "/client_pin.bin",
        ZF_APP_DATA_DIR "/client_pin.tmp",
        ZF_APP_DATA_DIR "/client_pin_v2.bin",
        ZF_APP_DATA_DIR "/client_pin_v2.tmp",
    };
    ZfStoreBootstrapWipeContext context = {.storage = storage};

    if (!zf_store_bootstrap_ensure_app_data_dir(storage)) {
        return false;
    }

    if (!zf_storage_remove_optional_paths(storage, pin_paths,
                                          sizeof(pin_paths) / sizeof(pin_paths[0]))) {
        return false;
    }

    return zf_storage_for_each_dir_entry(storage, ZF_APP_DATA_DIR, name, sizeof(name),
                                         zf_store_bootstrap_wipe_visitor, &context);
}


#if ZF_VAULT_PIN_KEK

typedef struct {
    Storage *storage;
    ZfCredentialStore *store;
    const uint8_t *vmk;
    uint8_t *buffer;
    size_t buffer_size;
} ZfStoreBootstrapAppendVaultContext;

/* File names are the lowercase-hex credential ID; decode back to bytes to
 * check identity against the store, independent of which pass (v1 or a
 * previous vault append) already indexed it. */
static bool zf_store_bootstrap_hex_nibble(char c, uint8_t *out) {
    if (c >= '0' && c <= '9') {
        *out = (uint8_t)(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        *out = (uint8_t)(c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        *out = (uint8_t)(c - 'A' + 10);
        return true;
    }
    return false;
}

static bool zf_store_bootstrap_hex_decode_credential_id(const char *name, uint8_t *out,
                                                         size_t out_len) {
    uint8_t hi = 0;
    uint8_t lo = 0;

    if (strlen(name) < out_len * 2U) {
        return false;
    }
    for (size_t i = 0; i < out_len; ++i) {
        if (!zf_store_bootstrap_hex_nibble(name[i * 2U], &hi) ||
            !zf_store_bootstrap_hex_nibble(name[i * 2U + 1U], &lo)) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool zf_store_bootstrap_append_vault_visitor(const char *name, const FileInfo *info,
                                                     void *context) {
    ZfStoreBootstrapAppendVaultContext *ctx = context;
    uint8_t credential_id[ZF_CREDENTIAL_ID_LEN];

    if (!name || !info || !ctx || !ctx->store) {
        return false;
    }
    if (file_info_is_dir(info) || !zf_store_record_format_is_record_name(name)) {
        return true;
    }
    if (ctx->store->count >= ZF_MAX_CREDENTIALS) {
        return true;
    }
    /*
     * Already indexed -- by the v1 pass, or by an earlier call to this same
     * function -- skip. Identity is checked by credential ID rather than by
     * re-attempting a v1 load, so repeated calls stay idempotent.
     */
    if (zf_store_bootstrap_hex_decode_credential_id(name, credential_id, sizeof(credential_id)) &&
        zf_store_find_index_by_id(ctx->store, credential_id, sizeof(credential_id), NULL)) {
        return true;
    }
    if (!zf_store_ensure_capacity(ctx->store, ctx->store->count + 1U)) {
        return false;
    }
    if (zf_store_record_format_load_index_with_buffer_vault(
            ctx->storage, name, &ctx->store->records[ctx->store->count], ctx->vmk, ctx->buffer,
            ctx->buffer_size)) {
        ctx->store->count++;
    }
    return true;
}

bool zf_store_bootstrap_append_vault_records_with_buffer(Storage *storage, ZfCredentialStore *store,
                                                         const uint8_t vmk[ZF_VAULT_KEY_LEN],
                                                         uint8_t *buffer, size_t buffer_size) {
    char name[96];
    ZfStoreBootstrapAppendVaultContext context = {
        .storage = storage,
        .store = store,
        .vmk = vmk,
        .buffer = buffer,
        .buffer_size = buffer_size,
    };
    bool ok;

    if (!storage || !store || !vmk || !buffer || buffer_size < ZF_STORE_RECORD_MAX_SIZE) {
        return false;
    }

    ok = zf_storage_for_each_dir_entry(storage, ZF_APP_DATA_DIR, name, sizeof(name),
                                       zf_store_bootstrap_append_vault_visitor, &context);
    zf_crypto_secure_zero(buffer, buffer_size);
    return ok;
}

#endif
