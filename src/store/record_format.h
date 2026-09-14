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

#include <storage/storage.h>

#include "../zerofido_types.h"

/*
 * Record-format helpers own the serialized credential file contract. They
 * expose index-only loads for boot, display-only loads that avoid private key
 * material, and full loads for signing paths.
 */
void zf_store_record_format_hex_encode(const uint8_t *data, size_t size, char *out);
bool zf_store_record_format_is_record_name(const char *name);
bool zf_store_record_format_load_index_with_buffer(Storage *storage, const char *file_name,
                                                   ZfCredentialIndexEntry *entry, uint8_t *buffer,
                                                   size_t buffer_size);
bool zf_store_record_format_load_record_with_buffer(Storage *storage, const char *file_name,
                                                    ZfCredentialRecord *record, uint8_t *buffer,
                                                    size_t buffer_size);
bool zf_store_record_format_load_record_for_display_with_buffer(Storage *storage,
                                                                const char *file_name,
                                                                ZfCredentialRecord *record,
                                                                uint8_t *buffer,
                                                                size_t buffer_size);
/*
 * Counter reservation updates only the small counter floor/high-water file.
 * It is intentionally narrower than a full record rewrite so response
 * publication can be fail-closed around monotonic counters.
 */
bool zf_store_record_format_reserve_counter_with_buffer(Storage *storage,
                                                        const ZfCredentialRecord *record,
                                                        uint8_t *buffer, size_t buffer_size,
                                                        uint32_t *out_high_water);
bool zf_store_record_format_reserve_counter(Storage *storage, const ZfCredentialRecord *record,
                                            uint32_t *out_high_water);
bool zf_store_record_format_write_record_with_buffer(Storage *storage,
                                                     const ZfCredentialRecord *record,
                                                     uint8_t *buffer, size_t buffer_size);

#if ZF_VAULT_PIN_KEK
#include "../vault/zf_vault_key.h"

/*
 * Vault-aware record I/O (format version 2): the enclave-wrapped private key
 * gets a second AES-256-CBC layer keyed by the unlocked vault's VMK, so an
 * offline reader of the SD card needs the vault PIN (not just this device)
 * to recover a usable private key. RP ID, user ID, username, and display
 * name stay plaintext exactly as in v1 -- only the private key gains the
 * extra layer. A v2 record cannot be decoded without the VMK; there is no
 * display-only path that skips it. Nothing calls these yet.
 */
bool zf_store_record_format_encode_vault(const ZfCredentialRecord *record,
                                         const uint8_t vmk[ZF_VAULT_KEY_LEN], uint8_t *out,
                                         size_t *out_size);
bool zf_store_record_format_write_record_with_buffer_vault(Storage *storage,
                                                            const ZfCredentialRecord *record,
                                                            const uint8_t vmk[ZF_VAULT_KEY_LEN],
                                                            uint8_t *buffer, size_t buffer_size);
bool zf_store_record_format_load_record_with_buffer_vault(Storage *storage, const char *file_name,
                                                           ZfCredentialRecord *record,
                                                           const uint8_t vmk[ZF_VAULT_KEY_LEN],
                                                           uint8_t *buffer, size_t buffer_size);
#endif
