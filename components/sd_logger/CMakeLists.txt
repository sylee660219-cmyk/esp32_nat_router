idf_component_register(SRCS "sd_logger.c"
                       INCLUDE_DIRS "include"
                       REQUIRES fatfs vfs esp_timer driver esp_ringbuf log)
