/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
 *
 * A 128x64 one-bit framebuffer in the SSD1306's own memory order (eight pages of 128 columns; byte x + 128 * (y / 8) holds
 * rows y & ~7 .. y | 7, bit 0 at the top), so a frame goes to the panel as it is. Drawing only: no hardware here.
 */
#ifndef UDS_SCREEN_H
#define UDS_SCREEN_H

#include <stdbool.h>
#include <stdint.h>

#define SCREEN_W 128
#define SCREEN_H 64
#define SCREEN_BYTES (SCREEN_W * SCREEN_H / 8)

#define GLYPH_W 5
#define GLYPH_H 7
#define GLYPH_PITCH 6

void fb_clear(uint8_t *fb);
void fb_set(uint8_t *fb, int x, int y, bool on);
void fb_box(uint8_t *fb, int x, int y, int w, int h, bool on); /* filled */
void fb_frame(uint8_t *fb, int x, int y, int w, int h);        /* outline */
void fb_hline(uint8_t *fb, int x, int y, int w);
void fb_vline(uint8_t *fb, int x, int y, int h);
void fb_ring(uint8_t *fb, int cx, int cy, int r);
void fb_disc(uint8_t *fb, int cx, int cy, int r, bool on);
/* A one-bit image as tools/img2c.py writes it: rows top to bottom, each padded to whole bytes, most significant bit leftmost.
 * Set bits are drawn lit (or dark with `on` false); clear bits leave the frame as it was. */
void fb_image(uint8_t *fb, int x, int y, int w, int h, const uint8_t *bits, bool on);
/* Printable ASCII on a 6-pixel pitch (anything else draws as '?'); returns the x after the last glyph. */
int fb_print(uint8_t *fb, int x, int y, const char *text, int scale);
int fb_print_width(const char *text, int scale);
void fb_print_centered(uint8_t *fb, int x_offset, int y, const char *text, int scale);
void fb_print_right(uint8_t *fb, int right, int y, const char *text, int scale);

#endif
