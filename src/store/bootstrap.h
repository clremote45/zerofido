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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <storage/storage.h>

#include "../zerofido_types.h"

/*
 * Store bootstrap owns directory creation, startup index rebuild, temp cleanup,
 * and app-data wipe. Record encoding/decoding stays in record_format.
 */
bool zf_store_bootstrap_ensure_app_data_dir(Storage *storage);
bool zf_store_bootstrap_init_with_buffer(Storage *storage, ZfCredentialStore *store,
                                         uint8_t *buffer, size_t buffer_size);
bool zf_store_bootstrap_wipe_app_data(Storage *storage);

#if ZF_VAULT_PIN_KEK
#include "../vault/zf_vault_key.h"

/*
 * Appends index entries for v2 (vault-wrapped) records the v1-only initial
 * scan can't see -- read-only, never rewrites a file. A file already
 * indexed by the v1 pass is skipped (its v1 index-load succeeds, which is
 * exactly the signal used to avoid a duplicate entry), so this is safe to
 * call after zf_store_bootstrap_init_with_buffer regardless of how many v2
 * records exist.
 */
bool zf_store_bootstrap_append_vault_records_with_buffer(Storage *storage, ZfCredentialStore *store,
                                                         const uint8_t vmk[ZF_VAULT_KEY_LEN],
                                                         uint8_t *buffer, size_t buffer_size);
#endif
