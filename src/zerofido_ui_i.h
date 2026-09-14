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

typedef struct ZerofidoApp ZerofidoApp;

/*
 * Private UI helpers used across view/status/approval modules. They assume the
 * caller already respects the UI mutex rules documented on public UI functions.
 */
void zerofido_ui_dispatch_custom_event(ZerofidoApp *app, ZfCustomEvent event);
void zerofido_ui_switch_to_view(ZerofidoApp *app, ZfViewId view_id);
void zerofido_ui_show_interaction(ZerofidoApp *app);
void zerofido_ui_hide_interaction(ZerofidoApp *app);
bool zerofido_ui_ensure_view(ZerofidoApp *app, ZfViewId view_id);
#if ZF_VAULT_PIN_KEK
/* Opens the PIN-input view in vault-unlock mode. Safe to call whether or not
 * a vault is configured -- if the pin_buffers allocation fails, falls back
 * to ZfViewStatus like any other UI-unavailable case. */
void zerofido_ui_open_vault_unlock_prompt(ZerofidoApp *app);
#endif
