#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Remote reboot over UDP (port REMOTE_CMD_PORT), sent by the VPN enrollment
 * server dashboard. Independent of the web server: one UDP socket opened at
 * boot, so it still works when httpd has run out of sessions. Only datagrams
 * that come from the WireGuard tunnel subnet get a reply; others are dropped.
 *
 * Challenge-response, signed with the device's WireGuard preshared key:
 *   server -> "CHAL"
 *   device -> "NONCE <32 hex>"            (valid 10 s, single use)
 *   server -> "REBOOT <nonce> <hmac hex>"  HMAC-SHA256(key = PSK base64 text,
 *                                                     msg = "REBOOT|<nonce>")
 *   device -> "OK" and reboots ~1 s later, or "ERR auth" / "ERR busy" / "ERR off"
 */
#define REMOTE_CMD_PORT 4210

esp_err_t remote_cmd_start(void);

#ifdef __cplusplus
}
#endif
