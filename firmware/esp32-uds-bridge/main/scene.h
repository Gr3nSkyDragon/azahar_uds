/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
 *
 * What the optional screen shows: the board's own state, drawn from a snapshot the display task takes every frame. Drawing only
 * (screen.h): the panel itself is display.c's.
 *
 *  idle     neither mode running: the firmware name, version and "waiting for host" (or "host connected" after a HELLO).
 *  radio    the raw radio Azahar drives (UDS_CMD_START): the 3DS on the air (left) and the one Azahar runs (right) on a cable: a ball
 *           rolls in above it for frames received, out below it for frames sent, with the channel and the totals.
 *  wrapper  the Game Boy wrapper (gbwrap.h): the game (PKMN RED ...), the stage of the join, the session and the cable, and the
 *           wrapper's own frame counts on the same cable, the cartridge on our side.
 *
 * OLED pixels wear with the time they are lit, so the panel dims after a minute with nothing happening and goes dark after ten;
 * a running mode, a change of stage, a frame either way, a HELLO or a BOOT press counts as something happening. The idle scene
 * also moves a step each minute.
 */
#ifndef UDS_SCENE_H
#define UDS_SCENE_H

#include <stdbool.h>
#include <stdint.h>

enum scene_mode { SCENE_IDLE, SCENE_RADIO, SCENE_WRAPPER };

typedef struct {
    uint8_t mode;          /* enum scene_mode */
    uint8_t channel;
    uint32_t rx, tx;       /* frames towards the host / the board's own, and frames sent on the air */
    uint32_t wakes;        /* HELLOs and BOOT presses since boot: each one is activity */
    bool host_seen;        /* a HELLO since boot */
    uint8_t fw_major, fw_minor;
    /* The wrapper's, valid in SCENE_WRAPPER (gbwrap_status_t). */
    uint8_t gen;
    uint8_t stage;         /* enum gbwrap_stage */
    char title[16];
} scene_status_t;

/* The panel brightness scene_draw asks for. */
enum scene_power { SCENE_ON, SCENE_DIM, SCENE_OFF };

uint8_t scene_draw(uint8_t *fb, const scene_status_t *status, uint32_t now_ms);

#endif
