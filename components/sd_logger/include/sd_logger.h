/* MicroSD Card Asynchronous Logger for ESP32 NAT Router
 *
 * Provides non-blocking logging to a MicroSD card over SPI.
 * Does not block networking or WireGuard tasks.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * GPIO Pin Assignments (Modify here or via `idfc` / menuconfig)
 * ========================================================================= */
#ifdef CONFIG_SD_LOGGER_MOSI_PIN
#define SD_PIN_MOSI   CONFIG_SD_LOGGER_MOSI_PIN
#else
#define SD_PIN_MOSI   23
#endif

#ifdef CONFIG_SD_LOGGER_MISO_PIN
#define SD_PIN_MISO   CONFIG_SD_LOGGER_MISO_PIN
#else
#define SD_PIN_MISO   19
#endif

#ifdef CONFIG_SD_LOGGER_CLK_PIN
#define SD_PIN_CLK    CONFIG_SD_LOGGER_CLK_PIN
#else
#define SD_PIN_CLK    18
#endif

#ifdef CONFIG_SD_LOGGER_CS_PIN
#define SD_PIN_CS     CONFIG_SD_LOGGER_CS_PIN
#else
#define SD_PIN_CS     5
#endif

/* Mount point and file paths */
#define SD_MOUNT_POINT      "/sdcard"
#define SD_LOG_FILE_PATH    SD_MOUNT_POINT "/router.log"
#define SD_LOG_FILE_OLD     SD_MOUNT_POINT "/router.log.old"

#ifdef CONFIG_SD_LOGGER_MAX_FILE_SIZE_KB
#define SD_MAX_LOG_SIZE_BYTES  (CONFIG_SD_LOGGER_MAX_FILE_SIZE_KB * 1024)
#else
#define SD_MAX_LOG_SIZE_BYTES  (1024 * 1024)  // 1 MB
#endif

/**
 * Initialize SD card and start background asynchronous logging.
 *
 * If the SD card is not inserted or cannot be initialized, this function
 * will log a warning and return ESP_ERR_NOT_FOUND without halting or blocking
 * the router system.
 */
esp_err_t sd_logger_init(void);

/**
 * Returns true if the SD card is mounted and logging is active.
 */
bool sd_logger_is_active(void);

/**
 * Flush any buffered logs to the SD card immediately.
 */
void sd_logger_flush(void);

/**
 * Manually write a custom log entry to the SD card log file.
 */
void sd_log_write(const char *fmt, ...);

#ifdef __cplusplus
}
#endif
