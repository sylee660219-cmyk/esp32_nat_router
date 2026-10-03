/* MicroSD Card Asynchronous Logger for ESP32 NAT Router
 *
 * Captures system logs via vprintf hook and writes them to MicroSD card
 * asynchronously using FreeRTOS RingBuffer.
 *
 * Guarantees zero blocking / zero latency impact on routing & WireGuard VPN.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/ringbuf.h"
#include "sd_logger.h"

static const char *TAG = "sd_logger";

#define LOG_RINGBUF_SIZE    (8 * 1024)   // 8 KB memory buffer for logs
#define LOG_FLUSH_INTERVAL  pdMS_TO_TICKS(1000) // Flush to SD every 1 second
#define LOG_MAX_LINE_LEN    256

static RingbufHandle_t s_log_ringbuf = NULL;
static TaskHandle_t s_log_task_handle = NULL;
static sdmmc_card_t *s_card = NULL;
static bool s_sd_active = false;
static vprintf_like_t s_prev_vprintf = NULL;

static void check_and_rotate_file(FILE **f, size_t *written_bytes)
{
    if (*f == NULL) return;

    if (*written_bytes >= SD_MAX_LOG_SIZE_BYTES) {
        fclose(*f);
        *f = NULL;

        // Rotate: remove old backup and rename current to old
        remove(SD_LOG_FILE_OLD);
        rename(SD_LOG_FILE_PATH, SD_LOG_FILE_OLD);

        *f = fopen(SD_LOG_FILE_PATH, "a");
        *written_bytes = 0;
        if (*f) {
            fprintf(*f, "--- Log rotated ---\n");
            fflush(*f);
        }
    }
}

static void sd_log_writer_task(void *pvParameters)
{
    FILE *f = fopen(SD_LOG_FILE_PATH, "a");
    size_t written_bytes = 0;

    if (f) {
        fseek(f, 0, SEEK_END);
        written_bytes = (size_t)ftell(f);
        fprintf(f, "\n=== Router Log Session Started ===\n");
        fflush(f);
    } else {
        ESP_LOGE(TAG, "Failed to open %s for appending", SD_LOG_FILE_PATH);
    }

    TickType_t last_flush = xTaskGetTickCount();

    while (s_sd_active) {
        size_t item_size = 0;
        char *item = (char *)xRingbufferReceiveUpTo(s_log_ringbuf, &item_size, pdMS_TO_TICKS(500), 512);

        if (item != NULL && item_size > 0) {
            if (f != NULL) {
                size_t wrote = fwrite(item, 1, item_size, f);
                written_bytes += wrote;
                check_and_rotate_file(&f, &written_bytes);
            }
            vRingbufferReturnItem(s_log_ringbuf, (void *)item);
        }

        // Periodic flush to prevent data loss on sudden power loss
        if (f != NULL && (xTaskGetTickCount() - last_flush) >= LOG_FLUSH_INTERVAL) {
            fflush(f);
            last_flush = xTaskGetTickCount();
        }
    }

    if (f) {
        fflush(f);
        fclose(f);
    }
    vTaskDelete(NULL);
}

static int sd_log_vprintf_hook(const char *fmt, va_list args)
{
    // First, pass through to default serial console output
    int ret = 0;
    if (s_prev_vprintf != NULL) {
        va_list args_copy;
        va_copy(args_copy, args);
        ret = s_prev_vprintf(fmt, args_copy);
        va_end(args_copy);
    }

    // Second, if SD logger active, buffer log into non-blocking ring buffer
    if (s_sd_active && s_log_ringbuf != NULL) {
        char line_buf[LOG_MAX_LINE_LEN];
        int len = vsnprintf(line_buf, sizeof(line_buf), fmt, args);
        if (len > 0) {
            size_t send_len = (size_t)len;
            if (send_len >= sizeof(line_buf)) {
                send_len = sizeof(line_buf) - 1;
            }
            // Non-blocking: timeout = 0. Drops log if buffer full, NEVER blocks network!
            xRingbufferSend(s_log_ringbuf, line_buf, send_len, 0);
        }
    }

    return ret;
}

esp_err_t sd_logger_init(void)
{
#if !CONFIG_SD_LOGGER_ENABLED
    ESP_LOGI(TAG, "SD Card logger is disabled in configuration.");
    return ESP_OK;
#endif

    ESP_LOGI(TAG, "Initializing MicroSD Card logger (SPI mode)...");
    ESP_LOGI(TAG, "Pins: MOSI=%d, MISO=%d, CLK=%d, CS=%d",
             SD_PIN_MOSI, SD_PIN_MISO, SD_PIN_CLK, SD_PIN_CS);

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false,
        .max_files = 5,
        .allocation_unit_size = 16 * 1024
    };

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = SD_PIN_MOSI,
        .miso_io_num = SD_PIN_MISO,
        .sclk_io_num = SD_PIN_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4000,
    };

    esp_err_t ret = spi_bus_initialize((spi_host_device_t)host.slot, &bus_cfg, SDSPI_DEFAULT_DMA);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SPI bus initialize failed: %s (SD logging disabled)", esp_err_to_name(ret));
        return ret;
    }

    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = SD_PIN_CS;
    slot_config.host_id = (spi_host_device_t)host.slot;

    ret = esp_vfs_fat_sdspi_mount(SD_MOUNT_POINT, &host, &slot_config, &mount_config, &s_card);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "MicroSD card not detected or mount failed: %s", esp_err_to_name(ret));
        ESP_LOGW(TAG, "Router and WireGuard will continue normally without SD logging.");
        return ret;
    }

    ESP_LOGI(TAG, "MicroSD card mounted successfully at %s", SD_MOUNT_POINT);
    sdmmc_card_print_info(stdout, s_card);

    // Create non-blocking ring buffer
    s_log_ringbuf = xRingbufferCreate(LOG_RINGBUF_SIZE, RINGBUF_TYPE_BYTEBUF);
    if (s_log_ringbuf == NULL) {
        ESP_LOGE(TAG, "Failed to create log ring buffer");
        return ESP_ERR_NO_MEM;
    }

    s_sd_active = true;

    // Start background writer task with low priority (1)
    if (xTaskCreate(sd_log_writer_task, "sd_logger", 3584, NULL, 1, &s_log_task_handle) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create SD log writer task");
        s_sd_active = false;
        return ESP_FAIL;
    }

    // Hook ESP-IDF vprintf so all ESP_LOG* calls are mirrored to SD card
    s_prev_vprintf = esp_log_set_vprintf(sd_log_vprintf_hook);

    ESP_LOGI(TAG, "Asynchronous MicroSD logging started -> %s", SD_LOG_FILE_PATH);
    return ESP_OK;
}

bool sd_logger_is_active(void)
{
    return s_sd_active;
}

void sd_logger_flush(void)
{
    if (s_sd_active && s_log_ringbuf != NULL) {
        // Sleep briefly to let the writer task flush remaining items
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void sd_log_write(const char *fmt, ...)
{
    if (!s_sd_active || s_log_ringbuf == NULL) return;

    va_list args;
    va_start(args, fmt);
    char buf[LOG_MAX_LINE_LEN];
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (len > 0) {
        xRingbufferSend(s_log_ringbuf, buf, (size_t)len, 0);
    }
}
