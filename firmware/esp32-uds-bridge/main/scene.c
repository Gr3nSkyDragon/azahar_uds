/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version. */
#include "scene.h"

#include <stdio.h>
#include <string.h>

#include "gbwrap.h"
#include "screen.h"

#define DIM_MS 60000      /* nothing happening for a minute: dim */
#define OFF_MS 600000     /* for ten: dark */
#define STEP_MS 60000     /* the idle scene moves one step of kOrbit a minute */
#define BALLS 16
#define BALL_R 3            /* 7 pixels across */
#define BALL_TRAVEL_MS 1200 /* a ball's roll from one end of the cable to the other */
#define BALL_GAP_MS 200     /* at most one ball per direction per gap, however many frames went by: they never overlap */

/* The cable, between the 3DS on the left and our side on the right (a second 3DS for Azahar, a cartridge for the wrapper).
 * Inbound frames roll towards us above it, outbound frames roll away below it. */
#define CABLE_Y 25
#define CABLE_X0 30
#define CABLE_X1 97
#define INBOUND_Y (CABLE_Y - BALL_R - 2)
#define OUTBOUND_Y (CABLE_Y + BALL_R + 2)

static const int8_t kOrbit[][2] = {{0, 0}, {1, 0}, {1, 1}, {0, 1}, {-1, 1}, {-1, 0}, {-1, -1}, {0, -1}, {1, -1}};

static struct {
    uint32_t start_ms;
    int8_t dir;           /* 1: inbound (left to right), -1: outbound (right to left), 0: free */
} s_balls[BALLS];

static struct {
    bool seen;
    scene_status_t last;
    uint32_t active_ms;   /* the last time something happened */
    uint32_t rx_ball_ms, tx_ball_ms;
} s;

static void ball_spawn(int8_t dir, uint32_t now)
{
    for (int i = 0; i < BALLS; ++i)
        if (!s_balls[i].dir) {
            s_balls[i].dir = dir;
            s_balls[i].start_ms = now;
            return;
        }
}

/* New frames since the last draw start balls, one per direction per BALL_GAP_MS at most. */
static void balls_step(const scene_status_t *status, uint32_t now)
{
    const bool reset = status->mode != s.last.mode;
    if (!reset && status->rx != s.last.rx && now - s.rx_ball_ms >= BALL_GAP_MS) {
        ball_spawn(1, now);
        s.rx_ball_ms = now;
    }
    if (!reset && status->tx != s.last.tx && now - s.tx_ball_ms >= BALL_GAP_MS) {
        ball_spawn(-1, now);
        s.tx_ball_ms = now;
    }
    for (int i = 0; i < BALLS; ++i)
        if (s_balls[i].dir && (reset || now - s_balls[i].start_ms >= BALL_TRAVEL_MS)) s_balls[i].dir = 0;
}

/* A small Poke Ball turned by `rolled` pixels of travel: the outline, the filled (red) half, the dark band across the middle
 * and the button lit at its centre. It takes eight positions, 45 degrees apart, per turn: one each 19 / 8 pixels of roll at
 * this size. `dir` is the way it rolls, so it turns clockwise going right and anticlockwise going left. */
static void draw_rolling_ball(uint8_t *fb, int cx, int cy, int rolled, int dir)
{
    /* The band's direction, clockwise in 45-degree steps from flat; the filled half is to its left (upwards when flat). */
    static const int8_t kBand[8][2] = {{1, 0}, {1, 1}, {0, 1}, {-1, 1}, {-1, 0}, {-1, -1}, {0, -1}, {1, -1}};
    int turn = rolled * 8 / 19 % 8;
    if (dir < 0) turn = (8 - turn) % 8;
    const int bx = kBand[turn][0], by = kBand[turn][1];
    const int inner = (BALL_R - 1) * (BALL_R - 1) + (BALL_R - 1);
    for (int dy = -BALL_R; dy <= BALL_R; ++dy)
        for (int dx = -BALL_R; dx <= BALL_R; ++dx) {
            if (dx * dx + dy * dy > inner) continue;
            const int side = dx * by - dy * bx; /* > 0: the filled half */
            fb_set(fb, cx + dx, cy + dy, side > 0 || (dx == 0 && dy == 0));
        }
    fb_ring(fb, cx, cy, BALL_R);
}

static void draw_balls(uint8_t *fb, uint32_t now)
{
    const int x0 = CABLE_X0 + BALL_R, x1 = CABLE_X1 - BALL_R - 1;
    for (int i = 0; i < BALLS; ++i) {
        if (!s_balls[i].dir) continue;
        const int rolled = (int)((now - s_balls[i].start_ms) * (uint32_t)(x1 - x0) / BALL_TRAVEL_MS);
        if (s_balls[i].dir > 0) draw_rolling_ball(fb, x0 + rolled, INBOUND_Y, rolled, 1);
        else draw_rolling_ball(fb, x1 - rolled, OUTBOUND_Y, rolled, -1);
    }
}

/* A 3DS, open: the top screen above the hinge, the touch screen below. 24x24 from (x, y). */
static void draw_3ds(uint8_t *fb, int x, int y)
{
    fb_frame(fb, x, y, 24, 11);
    fb_frame(fb, x + 3, y + 2, 18, 7);
    fb_hline(fb, x + 2, y + 11, 20);
    fb_frame(fb, x, y + 12, 24, 12);
    fb_frame(fb, x + 6, y + 14, 12, 8);
    fb_set(fb, x + 3, y + 17, true);
    fb_set(fb, x + 2, y + 18, true);
    fb_set(fb, x + 4, y + 18, true);
    fb_set(fb, x + 3, y + 19, true);
}

/* A Game Boy cartridge with its label and the notch at the top right. 20x24 from (x, y). */
static void draw_cartridge(uint8_t *fb, int x, int y)
{
    fb_hline(fb, x, y, 16);
    fb_vline(fb, x, y, 24);
    fb_hline(fb, x, y + 23, 20);
    fb_vline(fb, x + 19, y + 4, 20);
    for (int i = 0; i < 4; ++i) fb_set(fb, x + 16 + i, y + i, true);
    fb_frame(fb, x + 3, y + 4, 14, 11);
    for (int i = 0; i < 4; ++i) fb_vline(fb, x + 4 + 3 * i, y + 19, 4);
}

static void draw_ball(uint8_t *fb, int cx, int cy, int r)
{
    fb_ring(fb, cx, cy, r);
    fb_hline(fb, cx - r, cy, 2 * r + 1);
    fb_disc(fb, cx, cy, 2, false);
    fb_ring(fb, cx, cy, 2);
}

/* 99999, 123.4k, 123.4M, 4294M: at most six characters. */
static void count_text(char *out, size_t size, uint32_t value)
{
    if (value < 100000) snprintf(out, size, "%lu", (unsigned long)value);
    else if (value < 1000000) snprintf(out, size, "%lu.%luk", (unsigned long)(value / 1000), (unsigned long)(value / 100 % 10));
    else if (value < 1000000000) snprintf(out, size, "%lu.%luM", (unsigned long)(value / 1000000), (unsigned long)(value / 100000 % 10));
    else snprintf(out, size, "%luM", (unsigned long)(value / 1000000));
}

/* gen 0: the raw radio, a 3DS on each side; otherwise the wrapper's cartridge, its generation beside the channel. */
static void draw_link(uint8_t *fb, const char *title, uint8_t gen, uint8_t channel, const char *line, uint32_t rx, uint32_t tx,
                      uint32_t now)
{
    char text[24];
    fb_print(fb, 0, 0, title, 1);
    if (gen) snprintf(text, sizeof(text), "G%u ch%u", (unsigned)gen, (unsigned)channel);
    else snprintf(text, sizeof(text), "ch %u", (unsigned)channel);
    fb_print_right(fb, SCREEN_W, 0, text, 1);
    fb_hline(fb, 0, 9, SCREEN_W);

    draw_3ds(fb, 2, 13);
    if (gen) draw_cartridge(fb, 104, 13);
    else draw_3ds(fb, 102, 13);
    fb_hline(fb, CABLE_X0, CABLE_Y, CABLE_X1 - CABLE_X0);
    draw_balls(fb, now);

    fb_print_centered(fb, 0, 41, line, 1);
    char count[8];
    count_text(count, sizeof(count), rx);
    snprintf(text, sizeof(text), "in %s", count);
    fb_print(fb, 0, 56, text, 1);
    count_text(count, sizeof(count), tx);
    snprintf(text, sizeof(text), "out %s", count);
    fb_print_right(fb, SCREEN_W, 56, text, 1);
}

static const char *stage_text(uint8_t stage)
{
    switch (stage) {
    case GBWRAP_SCANNING: return "Looking for a 3DS";
    case GBWRAP_JOINING: return "Joining the 3DS";
    case GBWRAP_JOINED: return "Joined";
    case GBWRAP_SETUP: return "Starting session";
    case GBWRAP_CLOSED: return "3DS left";
    case GBWRAP_CABLE_DOWN: return "Session up";
    case GBWRAP_ROLES: return "Choosing roles";
    case GBWRAP_LINKED: return "Linked";
    case GBWRAP_SYNC: return "Syncing";
    case GBWRAP_MENU: return "Link menu";
    case GBWRAP_DATA: return "Exchanging data";
    }
    return "";
}

static void draw_idle(uint8_t *fb, const scene_status_t *status, uint32_t now)
{
    const int8_t *o = kOrbit[now / STEP_MS % (sizeof(kOrbit) / sizeof(kOrbit[0]))];
    char text[24];
    draw_ball(fb, SCREEN_W / 2 + o[0], 10 + o[1], 8);
    fb_print_centered(fb, o[0], 22 + o[1], "UDS Bridge", 2);
    snprintf(text, sizeof(text), "firmware %u.%u", (unsigned)status->fw_major, (unsigned)status->fw_minor);
    fb_print_centered(fb, o[0], 41 + o[1], text, 1);
    fb_print_centered(fb, o[0], 53 + o[1], status->host_seen ? "host connected" : "waiting for host", 1);
}

static bool changed(const scene_status_t *a, const scene_status_t *b)
{
    return a->mode != b->mode || a->stage != b->stage || a->channel != b->channel || a->rx != b->rx || a->tx != b->tx ||
           a->wakes != b->wakes || a->host_seen != b->host_seen;
}

uint8_t scene_draw(uint8_t *fb, const scene_status_t *status, uint32_t now)
{
    if (!s.seen || changed(status, &s.last) || status->mode == SCENE_WRAPPER) s.active_ms = now;
    if (!s.seen) s.last = *status;
    balls_step(status, now);
    s.last = *status;
    s.seen = true;

    fb_clear(fb);
    switch (status->mode) {
    case SCENE_RADIO:
        draw_link(fb, "Azahar radio", 0, status->channel, "Radio running", status->rx, status->tx, now);
        break;
    case SCENE_WRAPPER:
        draw_link(fb, status->title, status->gen ? status->gen : 1, status->channel, stage_text(status->stage), status->rx,
                  status->tx, now);
        break;
    default:
        draw_idle(fb, status, now);
        break;
    }

    const uint32_t quiet = now - s.active_ms;
    return quiet >= OFF_MS ? SCENE_OFF : quiet >= DIM_MS ? SCENE_DIM : SCENE_ON;
}
