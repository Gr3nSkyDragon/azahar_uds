/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version. */
#include "display.h"

#include <string.h>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "screen.h"

/* The screen's pins and the BOOT button (low while pressed) on each chip. C3 and C6 use the XIAO boards' D4 (SDA) and D5 (SCL). */
#if CONFIG_IDF_TARGET_ESP32S3
#define SDA_GPIO 8
#define SCL_GPIO 9
#define BOOT_GPIO 0
#elif CONFIG_IDF_TARGET_ESP32
#define SDA_GPIO 21
#define SCL_GPIO 22
#define BOOT_GPIO 0
#elif CONFIG_IDF_TARGET_ESP32C3
#define SDA_GPIO 6
#define SCL_GPIO 7
#define BOOT_GPIO 9
#elif CONFIG_IDF_TARGET_ESP32C6
#define SDA_GPIO 22
#define SCL_GPIO 23
#define BOOT_GPIO 9
#endif
#define FRAME_MS 50
#define I2C_HZ 400000

/* SSD1306 commands, after a 0x00 control byte. The common 0.96" module maps segment 127 to column 0 and COM0 to row 63, hence
 * the segment remap (A1), the reversed COM scan (C8) and the alternative COM pin layout (DA 12). Horizontal addressing (20 00)
 * lets one 1024-byte write fill the whole panel. */
static const uint8_t kInit[] = {
    0x00,
    0xAE,       /* off while it is set up */
    0xD5, 0x80, /* clock divide / oscillator: the reset value */
    0xA8, 0x3F, /* multiplex: 64 rows */
    0xD3, 0x00, /* no vertical offset */
    0x40,       /* start line 0 */
    0x8D, 0x14, /* charge pump on: the module has no external VCC */
    0x20, 0x00, /* horizontal addressing */
    0xA1, 0xC8, 0xDA, 0x12,
    0x81, 0xCF, /* contrast */
    0xD9, 0xF1, /* pre-charge 15 + 1 clocks */
    0xDB, 0x40, /* VCOMH deselect level */
    0xA4,       /* show RAM */
    0xA6,       /* not inverted */
    0x2E,       /* no scrolling */
    0xAF,       /* on */
};
static const uint8_t kWindow[] = {0x00, 0x21, 0x00, 0x7F, 0x22, 0x00, 0x07}; /* columns 0-127, pages 0-7 */

/* By enum scene_power. Dimmed is contrast 1 with a 2 + 2 clock pre-charge: lower contrast still lights, a 1 + 1 pre-charge
 * flickers on this module. Off keeps the RAM, so the next frame goes before the panel lights. */
static const uint8_t kPower[][6] = {
    {0x00, 0x81, 0xCF, 0xD9, 0xF1, 0xAF},
    {0x00, 0x81, 0x01, 0xD9, 0x22, 0xAF},
    {0x00, 0xAE},
};
static const size_t kPowerLength[] = {6, 6, 2};

static i2c_master_dev_handle_t s_panel;
static display_status_t s_status;
static volatile uint32_t s_wakes;
static uint8_t s_frame[1 + SCREEN_BYTES] = {0x40}; /* control byte: data follows */
static uint8_t s_shown[SCREEN_BYTES];

static void display_task(void *arg)
{
    (void)arg;
    uint8_t power = SCENE_ON; /* kInit's */
    bool shown = false;
    int button = 1;
    TickType_t wake = xTaskGetTickCount();
    for (;;) {
        /* A press, not a hold: one wake per falling edge, sampled every frame (50 ms debounces it). */
        const int level = gpio_get_level(BOOT_GPIO);
        if (!level && button) ++s_wakes;
        button = level;

        scene_status_t status = {0};
        s_status(&status);
        status.wakes = s_wakes;
        const uint8_t want = scene_draw(s_frame + 1, &status, (uint32_t)(esp_timer_get_time() / 1000));

        if (want != SCENE_OFF && (!shown || memcmp(s_shown, s_frame + 1, SCREEN_BYTES))) {
            if (i2c_master_transmit(s_panel, kWindow, sizeof(kWindow), 50) == ESP_OK &&
                i2c_master_transmit(s_panel, s_frame, sizeof(s_frame), 100) == ESP_OK) {
                memcpy(s_shown, s_frame + 1, SCREEN_BYTES);
                shown = true;
            } else {
                shown = false; /* resend in full next frame */
            }
        }
        if (want != power && i2c_master_transmit(s_panel, kPower[want], kPowerLength[want], 50) == ESP_OK) power = want;
        vTaskDelayUntil(&wake, pdMS_TO_TICKS(FRAME_MS));
    }
}

bool display_start(display_status_t status)
{
#ifdef SDA_GPIO
    const i2c_master_bus_config_t bus_config = {
        .i2c_port = -1,
        .sda_io_num = SDA_GPIO,
        .scl_io_num = SCL_GPIO,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true, /* the module has its own 4.7k pull-ups; these only help a bare panel */
    };
    i2c_master_bus_handle_t bus;
    if (i2c_new_master_bus(&bus_config, &bus) != ESP_OK) return false;
    uint16_t address = 0x3C;
    if (i2c_master_probe(bus, address, 20) != ESP_OK && i2c_master_probe(bus, ++address, 20) != ESP_OK) {
        i2c_del_master_bus(bus); /* no screen: the pins go back to how they were */
        return false;
    }
    const i2c_device_config_t panel_config = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = address,
        .scl_speed_hz = I2C_HZ,
    };
    if (i2c_master_bus_add_device(bus, &panel_config, &s_panel) != ESP_OK ||
        i2c_master_transmit(s_panel, kInit, sizeof(kInit), 100) != ESP_OK) {
        i2c_del_master_bus(bus);
        return false;
    }

    const gpio_config_t boot = {
        .pin_bit_mask = 1ULL << BOOT_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&boot);

    s_status = status;
    xTaskCreatePinnedToCore(display_task, "display", 4096, NULL, 1, NULL, configNUMBER_OF_CORES - 1);
    return true;
#else
    (void)status;
    return false;
#endif
}

void display_wake(void)
{
    ++s_wakes;
}
