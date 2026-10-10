/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
 *
 * The board's screen on a PC: the firmware's own scene.c and screen.c, compiled for the host, draw each clip below frame by
 * frame, 50 ms apart as display.c does. tools/screen_preview.py builds this, runs it and turns the frames into PNG and GIF
 * files. To preview a new scene or state, add a clip to kClips.
 *
 * Output file: for each clip, its name (NUL-terminated), the frame count (u16 LE), then each frame's 1024 bytes in the
 * SSD1306 page order of screen.h.
 */
#include <stdio.h>
#include <string.h>

/* scene.c's state is file-static; including it lets each clip start from a fresh screen. */
#include "../../main/scene.c"

#define FRAME_MS 50
#define START_MS 1000000u /* well past boot, as on a board that has been running */

struct clip {
    const char *name;
    scene_status_t status; /* the first frame's */
    int frames;
    uint32_t rx_step, tx_step; /* frames added to the counters each frame, to animate the cable */
};

#define FW .fw_major = 1, .fw_minor = 5

static const struct clip kClips[] = {
    {"idle", {.mode = SCENE_IDLE, FW}, 1, 0, 0},
    {"idle_host", {.mode = SCENE_IDLE, .host_seen = true, FW}, 1, 0, 0},
    {"radio", {.mode = SCENE_RADIO, .channel = 6, .rx = 1200, .tx = 900, .host_seen = true, FW}, 40, 3, 2},
    {"radio_big_counts", {.mode = SCENE_RADIO, .channel = 11, .rx = 1234567, .tx = 98765432, .host_seen = true, FW}, 1, 0, 0},
    {"wrapper_scanning", {.mode = SCENE_WRAPPER, .gen = 1, .channel = 1, .stage = GBWRAP_SCANNING, .title = "PKMN RED", FW}, 1, 0, 0},
    {"wrapper_joining", {.mode = SCENE_WRAPPER, .gen = 1, .channel = 6, .stage = GBWRAP_JOINING, .title = "PKMN BLUE", FW}, 1, 0, 0},
    {"wrapper_setup", {.mode = SCENE_WRAPPER, .gen = 2, .channel = 6, .stage = GBWRAP_SETUP, .title = "PKMN GOLD", FW}, 1, 0, 0},
    {"wrapper_menu", {.mode = SCENE_WRAPPER, .gen = 2, .channel = 11, .stage = GBWRAP_MENU, .title = "PKMN CRYSTAL", FW}, 20, 1, 1},
    {"wrapper_data", {.mode = SCENE_WRAPPER, .gen = 1, .channel = 11, .stage = GBWRAP_DATA, .title = "PKMN YELLOW", FW}, 40, 2, 2},
    {"wrapper_closed", {.mode = SCENE_WRAPPER, .gen = 1, .channel = 11, .stage = GBWRAP_CLOSED, .title = "PKMN RED", FW}, 1, 0, 0},
};

static void put_u16(FILE *out, unsigned value)
{
    fputc(value & 0xFF, out);
    fputc(value >> 8 & 0xFF, out);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: preview <output file>\n");
        return 2;
    }
    FILE *out = fopen(argv[1], "wb");
    if (!out) {
        perror(argv[1]);
        return 1;
    }
    for (size_t i = 0; i < sizeof(kClips) / sizeof(kClips[0]); ++i) {
        const struct clip *clip = &kClips[i];
        memset(&s, 0, sizeof(s));
        memset(s_balls, 0, sizeof(s_balls));
        fputs(clip->name, out);
        fputc(0, out);
        put_u16(out, (unsigned)clip->frames);
        scene_status_t status = clip->status;
        for (int f = 0; f < clip->frames; ++f) {
            uint8_t fb[SCREEN_BYTES];
            scene_draw(fb, &status, START_MS + (uint32_t)f * FRAME_MS);
            fwrite(fb, 1, sizeof(fb), out);
            status.rx += clip->rx_step;
            status.tx += clip->tx_step;
        }
    }
    fclose(out);
    return 0;
}
