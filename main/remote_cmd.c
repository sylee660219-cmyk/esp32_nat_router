#include "remote_cmd.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_random.h"
#include "mbedtls/md.h"
#include "vpn_config.h"
#include "http_server.h"

static const char *TAG = "remote";

#define NONCE_BYTES     16
#define NONCE_VALID_US  (10 * 1000 * 1000)
#define REBOOT_DELAY_US (1000 * 1000)   /* let the "OK" reply go out */

static char     s_nonce[NONCE_BYTES * 2 + 1];   /* "" = none outstanding */
static int64_t  s_nonce_us;
static uint32_t s_nonce_from;                   /* source IP the nonce was given to */
static bool     s_reboot_pending;

static void to_hex(const uint8_t *in, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = hx[in[i] >> 4];
        out[i * 2 + 1] = hx[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

/* Constant-time compare of two equal-length strings. */
static bool same(const char *a, const char *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static void reboot_cb(void *arg)
{
    esp_restart();
}

/* True if src (network byte order) is a peer inside the connected WireGuard
 * tunnel subnet. The subnet is worked out per packet from the live tunnel IP,
 * because the vpn_in_subnet() cache is only filled at boot. */
static bool from_tunnel(uint32_t src)
{
    uint32_t tun = vpn_tunnel_ip;
    if (!vpn_connected || tun == 0 || src == tun) {
        return false;
    }
    struct in_addr m;
    uint32_t mask = (vpn_netmask && vpn_netmask[0] && inet_aton(vpn_netmask, &m))
                    ? m.s_addr : htonl(0xffffff00);
    return (src & mask) == (tun & mask);
}

static bool check_sig(const char *psk, const char *nonce, const char *sig)
{
    char msg[8 + sizeof(s_nonce)];
    snprintf(msg, sizeof(msg), "REBOOT|%s", nonce);
    uint8_t mac[32];
    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                        (const uint8_t *)psk, strlen(psk),
                        (const uint8_t *)msg, strlen(msg), mac) != 0) {
        return false;
    }
    char want[sizeof(mac) * 2 + 1];
    to_hex(mac, sizeof(mac), want);
    return strlen(sig) == sizeof(mac) * 2 && same(sig, want, sizeof(mac) * 2);
}

/* Handle one datagram, write the reply into out. Returns false to send nothing. */
static bool handle(const char *rx, uint32_t from_ip, const char *from, char *out, size_t out_len)
{
    if (!from_tunnel(from_ip)) {
        return false;
    }

    const char *psk = vpn_preshared_key ? vpn_preshared_key : "";
    if (!vpn_enabled || psk[0] == '\0') {
        snprintf(out, out_len, "ERR off");
        return true;
    }

    if (strcmp(rx, "CHAL") == 0) {
        uint8_t rnd[NONCE_BYTES];
        esp_fill_random(rnd, sizeof(rnd));
        to_hex(rnd, sizeof(rnd), s_nonce);
        s_nonce_us = esp_timer_get_time();
        s_nonce_from = from_ip;
        snprintf(out, out_len, "NONCE %s", s_nonce);
        return true;
    }

    char nonce[sizeof(s_nonce)] = {0}, sig[65] = {0};
    if (sscanf(rx, "REBOOT %32s %64s", nonce, sig) == 2) {
        bool fresh = s_nonce[0] && from_ip == s_nonce_from &&
                     esp_timer_get_time() - s_nonce_us < NONCE_VALID_US &&
                     strcmp(nonce, s_nonce) == 0;
        s_nonce[0] = '\0';   /* single use, also after a failure */
        if (!fresh || !check_sig(psk, nonce, sig)) {
            ESP_LOGW(TAG, "rejected reboot command from %s", from);
            snprintf(out, out_len, "ERR auth");
            return true;
        }
        if (http_server_ota_busy()) {
            snprintf(out, out_len, "ERR busy");
            return true;
        }
        snprintf(out, out_len, "OK");
        if (!s_reboot_pending) {
            ESP_LOGW(TAG, "remote reboot from %s", from);
            const esp_timer_create_args_t targs = { .callback = reboot_cb, .name = "remote_reboot" };
            esp_timer_handle_t t;
            if (esp_timer_create(&targs, &t) != ESP_OK ||
                esp_timer_start_once(t, REBOOT_DELAY_US) != ESP_OK) {
                esp_restart();
            }
            s_reboot_pending = true;
        }
        return true;
    }

    snprintf(out, out_len, "ERR cmd");
    return true;
}

static void remote_task(void *arg)
{
    int sock = (int)(intptr_t)arg;
    char rx[128], out[64];
    for (;;) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        int n = recvfrom(sock, rx, sizeof(rx) - 1, 0, (struct sockaddr *)&src, &slen);
        if (n <= 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        rx[n] = '\0';
        while (n > 0 && (rx[n - 1] == '\n' || rx[n - 1] == '\r')) rx[--n] = '\0';

        char from[16];
        inet_ntoa_r(src.sin_addr, from, sizeof(from));
        if (handle(rx, src.sin_addr.s_addr, from, out, sizeof(out))) {
            sendto(sock, out, strlen(out), 0, (struct sockaddr *)&src, slen);
        }
    }
}

esp_err_t remote_cmd_start(void)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket failed (errno %d)", errno);
        return ESP_FAIL;
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(REMOTE_CMD_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        ESP_LOGE(TAG, "bind udp/%d failed (errno %d)", REMOTE_CMD_PORT, errno);
        close(sock);
        return ESP_FAIL;
    }
    if (xTaskCreate(remote_task, "remote_cmd", 4096, (void *)(intptr_t)sock, 3, NULL) != pdPASS) {
        close(sock);
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "remote reboot listening on udp/%d", REMOTE_CMD_PORT);
    return ESP_OK;
}
