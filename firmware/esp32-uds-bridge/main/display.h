/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
 *
 * An optional SSD1306 128x64 OLED on I2C: SDA GPIO8, SCL GPIO9 on the ESP32-S3 (GPIO21/22 on a classic ESP32, GPIO6/7 on a
 * C3, GPIO22/23 on a C6), VCC 3V3. At boot
 * the board probes 0x3C, then 0x3D; with neither answering it frees the pins and runs without a screen. With one, a priority-1
 * task on the last core draws scene.h's frame every 50 ms and sends it only when it changed (1031 bytes at 400 kHz, ~23 ms).
 * BOOT (GPIO0; GPIO9 on C3 and C6) wakes a dimmed or dark screen.
 */
#ifndef UDS_DISPLAY_H
#define UDS_DISPLAY_H

#include <stdbool.h>

#include "scene.h"

/* Fills in everything but `wakes` before each frame. Runs on the display task. */
typedef void (*display_status_t)(scene_status_t *status);

/* True when a screen answered and its task runs. */
bool display_start(display_status_t status);
/* Something worth waking the screen for (a HELLO). Any task. */
void display_wake(void);

#endif
