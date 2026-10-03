/* HTTP server public API.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <esp_http_server.h>

#ifdef __cplusplus
extern "C" {
#endif

httpd_handle_t start_webserver(uint16_t port);

void web_server_start_captive_dns(void);

/** Get current web UI interface access bitmask (RC_BIND_AP, RC_BIND_STA, RC_BIND_VPN). */
uint8_t web_ui_get_bind(void);

/** Set web UI interface access bitmask. Saves to NVS and takes effect immediately. */
void web_ui_set_bind(uint8_t bind);

/** True while a firmware upload (/api/ota-upload) is being written. */
bool http_server_ota_busy(void);

#ifdef __cplusplus
}
#endif
