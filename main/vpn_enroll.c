/* WireGuard Auto-Enrollment Client for Oracle wg-enroll server
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "cJSON.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_http_client.h"
#include "mbedtls/base64.h"
#include "mbedtls/ecp.h"

#include "vpn_config.h"
#include "vpn_enroll.h"
#include "wifi_config.h"
#include "router_config.h"

static const char *TAG = "vpn_enroll";

#define MAX_RESPONSE_BUF 1024

// Embedded certificate: main/certs/enroll_server.pem
extern const char enroll_server_pem_start[] asm("_binary_enroll_server_pem_start");
extern const char enroll_server_pem_end[]   asm("_binary_enroll_server_pem_end");

static char s_enroll_status[64] = "대기";

const char* vpn_enroll_get_status(void)
{
    return s_enroll_status;
}

bool vpn_enroll_is_enabled(void)
{
    return (vpn_auto_enroll == 1) &&
           (vpn_enroll_url != NULL && vpn_enroll_url[0] != '\0') &&
           (vpn_enroll_token != NULL && vpn_enroll_token[0] != '\0');
}

/* ---- Device Key Pair (Curve25519) Generation & Derivation ---- */

static int rng_callback(void *ctx, unsigned char *buf, size_t len)
{
    esp_fill_random(buf, len);
    return 0;
}

/* Curve25519 public key = scalar * basepoint (Curve25519) */
static esp_err_t x25519_public(const uint8_t priv[32], uint8_t pub[32])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    size_t olen = 0;
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary_le(&d, priv, 32);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_mul(&grp, &q, &d, &grp.G, rng_callback, NULL);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 32);
    }

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    if (ret != 0 || olen != 32) {
        ESP_LOGE(TAG, "x25519 scalar multiplication failed: -0x%04x", (unsigned)-ret);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t b64_encode_key(const uint8_t key[32], char out[45])
{
    size_t olen = 0;
    if (mbedtls_base64_encode((unsigned char *)out, 45, &olen, key, 32) != 0 || olen != 44) {
        return ESP_FAIL;
    }
    out[44] = '\0';
    return ESP_OK;
}

esp_err_t vpn_enroll_public_key_from_private(const char *private_b64, char *out)
{
    uint8_t priv[32], pub[32];
    size_t olen = 0;
    if (mbedtls_base64_decode(priv, sizeof(priv), &olen, (const unsigned char *)private_b64,
                              strlen(private_b64)) != 0 || olen != 32) {
        return ESP_ERR_INVALID_ARG;
    }
    /* WireGuard scalar clamping */
    priv[0] &= 248;
    priv[31] = (priv[31] & 127) | 64;
    esp_err_t err = x25519_public(priv, pub);
    if (err == ESP_OK) {
        err = b64_encode_key(pub, out);
    }
    memset(priv, 0, sizeof(priv));
    return err;
}

esp_err_t vpn_enroll_ensure_device_key(void)
{
    // If a private key is already stored and we have the matching public key, keep it
    if (vpn_private_key != NULL && strlen(vpn_private_key) == 44) {
        if (vpn_device_pubkey != NULL && strlen(vpn_device_pubkey) == 44) {
            return ESP_OK;
        }
        // Derive public key from the existing private key
        char pub_b64[45];
        esp_err_t err = vpn_enroll_public_key_from_private(vpn_private_key, pub_b64);
        if (err == ESP_OK) {
            set_config_param_str("vpn_dev_pubkey", pub_b64);
            if (vpn_device_pubkey) free(vpn_device_pubkey);
            vpn_device_pubkey = strdup(pub_b64);
            ESP_LOGI(TAG, "Derived device public key: %s", vpn_device_pubkey);
            return ESP_OK;
        }
    }

    // Generate a fresh random Curve25519 private key using hardware TRNG
    uint8_t priv[32];
    esp_fill_random(priv, sizeof(priv));
    priv[0] &= 248;
    priv[31] = (priv[31] & 127) | 64;

    char priv_b64[45], pub_b64[45];
    esp_err_t err = b64_encode_key(priv, priv_b64);
    memset(priv, 0, sizeof(priv));
    if (err == ESP_OK) {
        err = vpn_enroll_public_key_from_private(priv_b64, pub_b64);
    }

    if (err == ESP_OK) {
        // Persist to NVS
        set_config_param_str("vpn_privkey", priv_b64);
        set_config_param_str("vpn_dev_pubkey", pub_b64);

        if (vpn_private_key) free(vpn_private_key);
        vpn_private_key = strdup(priv_b64);

        if (vpn_device_pubkey) free(vpn_device_pubkey);
        vpn_device_pubkey = strdup(pub_b64);

        ESP_LOGI(TAG, "Generated new device key pair. Public key: %s", vpn_device_pubkey);
    } else {
        ESP_LOGE(TAG, "Failed to generate device key pair: %s", esp_err_to_name(err));
    }
    memset(priv_b64, 0, sizeof(priv_b64));
    return err;
}

/* ---- Enrollment HTTPS Client ---- */

static void get_sta_mac_str(char out[18])
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool copy_json_str(const cJSON *obj, const char *key, char *out, size_t size)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(item) || strlen(item->valuestring) >= size) {
        return false;
    }
    strlcpy(out, item->valuestring, size);
    return true;
}

static bool parse_enroll_response(const char *body)
{
    cJSON *root = cJSON_Parse(body);
    if (!root) {
        ESP_LOGE(TAG, "Failed to parse JSON response");
        return false;
    }

    char ip_buf[32] = {0};
    char mask_buf[32] = {0};
    char pubkey_buf[64] = {0};
    char psk_buf[64] = {0};
    char endpoint_buf[64] = {0};

    const cJSON *port = cJSON_GetObjectItemCaseSensitive(root, "port");
    const cJSON *ka = cJSON_GetObjectItemCaseSensitive(root, "keepalive");

    bool ok = copy_json_str(root, "ip", ip_buf, sizeof(ip_buf)) &&
              copy_json_str(root, "netmask", mask_buf, sizeof(mask_buf)) &&
              copy_json_str(root, "server_public_key", pubkey_buf, sizeof(pubkey_buf)) &&
              copy_json_str(root, "preshared_key", psk_buf, sizeof(psk_buf)) &&
              copy_json_str(root, "endpoint", endpoint_buf, sizeof(endpoint_buf)) &&
              cJSON_IsNumber(port) && port->valueint > 0 && port->valueint <= 65535 &&
              cJSON_IsNumber(ka) && ka->valueint >= 0 && ka->valueint <= 65535;

    if (ok) {
        // Save to NVS
        set_config_param_str("vpn_ip", ip_buf);
        set_config_param_str("vpn_mask", mask_buf);
        set_config_param_str("vpn_pubkey", pubkey_buf);
        set_config_param_str("vpn_psk", psk_buf);
        set_config_param_str("vpn_endpoint", endpoint_buf);
        set_config_param_int("vpn_port", port->valueint);
        set_config_param_int("vpn_ka", ka->valueint);
        set_config_param_int("vpn_enabled", 1);

        // Update runtime variables
        if (vpn_address) free(vpn_address);
        vpn_address = strdup(ip_buf);

        if (vpn_netmask) free(vpn_netmask);
        vpn_netmask = strdup(mask_buf);

        if (vpn_public_key) free(vpn_public_key);
        vpn_public_key = strdup(pubkey_buf);

        if (vpn_preshared_key) free(vpn_preshared_key);
        vpn_preshared_key = strdup(psk_buf);

        if (vpn_endpoint) free(vpn_endpoint);
        vpn_endpoint = strdup(endpoint_buf);

        vpn_port = (int32_t)port->valueint;
        vpn_keepalive = (int32_t)ka->valueint;
        vpn_enabled = 1;

        ESP_LOGI(TAG, "Enrollment successful! Assigned VPN IP: %s, Endpoint: %s:%d",
                 vpn_address, vpn_endpoint, (int)vpn_port);
    } else {
        ESP_LOGE(TAG, "Missing or invalid fields in enrollment response");
    }

    cJSON_Delete(root);
    return ok;
}

static void update_status_by_http_code(int status)
{
    switch (status) {
    case 200:
        strlcpy(s_enroll_status, "등록됨 (연결 준비 완료)", sizeof(s_enroll_status));
        break;
    case 401:
        strlcpy(s_enroll_status, "실패: 등록 토큰 불일치 (401)", sizeof(s_enroll_status));
        ESP_LOGE(TAG, "Enrollment token rejected (401)");
        break;
    case 403:
        strlcpy(s_enroll_status, "실패: 서버에서 차단된 장비 (403)", sizeof(s_enroll_status));
        ESP_LOGE(TAG, "Device revoked on server (403)");
        break;
    case 409:
        strlcpy(s_enroll_status, "실패: 다른 키로 이미 등록됨 (409)", sizeof(s_enroll_status));
        ESP_LOGE(TAG, "MAC already registered with another key (409)");
        break;
    case 429:
        strlcpy(s_enroll_status, "대기: 요청 제한 (429)", sizeof(s_enroll_status));
        ESP_LOGW(TAG, "Rate limited by server (429)");
        break;
    case 503:
        strlcpy(s_enroll_status, "실패: 서버 IP 풀 부족 (503)", sizeof(s_enroll_status));
        ESP_LOGE(TAG, "Server IP pool exhausted (503)");
        break;
    default:
        snprintf(s_enroll_status, sizeof(s_enroll_status), "실패: 서버 연결 오류 (%d)", status);
        ESP_LOGW(TAG, "Enrollment request failed with status %d", status);
        break;
    }
}

esp_err_t vpn_enroll_request(void)
{
    if (!vpn_enroll_is_enabled()) {
        strlcpy(s_enroll_status, "비활성화됨 (토큰 또는 URL 미설정)", sizeof(s_enroll_status));
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = vpn_enroll_ensure_device_key();
    if (err != ESP_OK) {
        strlcpy(s_enroll_status, "키 생성 실패", sizeof(s_enroll_status));
        return err;
    }

    char mac_str[18];
    get_sta_mac_str(mac_str);

    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "mac", mac_str);
    cJSON_AddStringToObject(req, "public_key", vpn_device_pubkey);
    cJSON_AddStringToObject(req, "name", (hostname && hostname[0]) ? hostname : "esp32-nat-router");
    cJSON_AddStringToObject(req, "firmware", "2.4.17+auto_enroll");
    char *body = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!body) {
        strlcpy(s_enroll_status, "메모리 부족 (JSON)", sizeof(s_enroll_status));
        return ESP_ERR_NO_MEM;
    }

    char url[160], auth_header[160];
    snprintf(url, sizeof(url), "%s/api/enroll", vpn_enroll_url);
    snprintf(auth_header, sizeof(auth_header), "Bearer %s", vpn_enroll_token);

    strlcpy(s_enroll_status, "서버 요청 중...", sizeof(s_enroll_status));
    ESP_LOGI(TAG, "Sending enrollment request to %s (MAC: %s)", url, mac_str);

    esp_http_client_config_t hc = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .cert_pem = enroll_server_pem_start,
        .skip_cert_common_name_check = true,
        .timeout_ms = 15000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&hc);
    int status = -1;
    char *resp = calloc(1, MAX_RESPONSE_BUF + 1);
    bool parsed_ok = false;

    if (client && resp) {
        esp_http_client_set_header(client, "Content-Type", "application/json");
        esp_http_client_set_header(client, "Authorization", auth_header);
        int len = strlen(body);
        err = esp_http_client_open(client, len);
        if (err == ESP_OK && esp_http_client_write(client, body, len) == len) {
            esp_http_client_fetch_headers(client);
            status = esp_http_client_get_status_code(client);
            int n = esp_http_client_read_response(client, resp, MAX_RESPONSE_BUF);
            resp[n > 0 ? n : 0] = '\0';
            if (status == 200) {
                parsed_ok = parse_enroll_response(resp);
            }
        } else {
            ESP_LOGW(TAG, "Connection failed to %s: %s", url, esp_err_to_name(err));
        }
    }

    if (client) esp_http_client_cleanup(client);
    free(resp);
    free(body);

    update_status_by_http_code(status);

    if (status == 200 && parsed_ok) {
        return ESP_OK;
    }
    return ESP_FAIL;
}
