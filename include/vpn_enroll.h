/* WireGuard Auto-Enrollment (Oracle wg-enroll server integration)
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_ENROLL_URL "https://168.110.106.47:8443"

// Check if auto-enrollment is possible (enabled, URL and token set)
bool vpn_enroll_is_enabled(void);

// Ensure the local WireGuard device key pair exists in NVS (generates Curve25519 if not set)
esp_err_t vpn_enroll_ensure_device_key(void);

// Derive base64 public key from base64 private key (out must be at least 45 bytes)
esp_err_t vpn_enroll_public_key_from_private(const char *private_b64, char *out);

// Perform a single enrollment HTTPS POST request to the server, parses response,
// and saves received tunnel settings to NVS and runtime variables.
// Returns ESP_OK on success, or appropriate error code.
esp_err_t vpn_enroll_request(void);

// Returns current user-facing status string (Korean)
const char* vpn_enroll_get_status(void);

#ifdef __cplusplus
}
#endif
