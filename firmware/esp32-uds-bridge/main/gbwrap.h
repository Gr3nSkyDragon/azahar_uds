/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
 *
 * The Game Boy wrapper mode. Without it the board is the raw radio Azahar drives (main.c). In it, the board itself joins a 3DS
 * running the Virtual Console Pokemon games (Red, Blue, Yellow, Gold, Silver, Crystal) and stands in for that console's partner on a
 * link cable: the host only carries the cartridge's serial transfers. The cartridge is the master of the cable; for every transfer it
 * starts, the host sends the byte it clocked out (UDS_CMD_GB_XFER) and the board answers with the byte the slave shifts back
 * (UDS_EVT_GB_REPLY). The cartridge may be a real one behind an adapter or an emulator standing in for one (mGBA's Wireless Adapter >
 * ESP32 with "Virtual Console" unticked).
 *
 * Everything between is the wrapper mGBA ran on the PC (src/gb/sio in the mgba_LDN repository), copied unchanged into gbwrap/: the
 * permanent slave (uds-wire.c, uds-cable.c), the Pia session (uds-session.c, uds-pia.c), the join (uds-room.c) and CCMP (uds-ccmp.c).
 * gbwrap.c holds what took the PC's place: the join on this board's radio and the task that runs it all. The 3DS key it needs is the
 * one stored on the board (keys.h).
 *
 * Threads: the command task (main.c) posts requests, the Wi-Fi task posts received frames; one wrapper task owns all of the state.
 */
#ifndef UDS_GBWRAP_H
#define UDS_GBWRAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/* Sends one frame to the host (main.c's serialized writer). */
typedef void (*gbwrap_send_t)(uint8_t type, uint8_t seq, const uint8_t *payload, size_t length);

void gbwrap_init(gbwrap_send_t send);

/* The command task hands these over; the wrapper task answers them (STATUS, or GB_REPLY for a transfer). */
void gbwrap_request(uint8_t type, uint8_t seq, const uint8_t *payload, size_t length);

/* True from GB_START until GB_STOP (or STOP): the radio belongs to the wrapper and its frames do not go to the host. */
bool gbwrap_active(void);

/* From the Wi-Fi task: a received frame ({channel, rssi, flags, mpdu}, as UDS_EVT_RX). Only queues. */
bool gbwrap_sink_rx(const uint8_t *payload, size_t length);

/* Where the wrapper is, for the screen: the join (room), then the Pia session, then the cable (wire phase). */
enum gbwrap_stage {
    GBWRAP_SCANNING,    /* room SCAN: hopping 1/6/11 for a Virtual Console host's beacon */
    GBWRAP_JOINING,     /* room AUTH / EAPOL */
    GBWRAP_JOINED,      /* room JOINED, no session yet */
    GBWRAP_SETUP,       /* session IDLE / SETUP */
    GBWRAP_CLOSED,      /* session CLOSED: the host left */
    GBWRAP_CABLE_DOWN,  /* session JOINED, wire DOWN */
    GBWRAP_ROLES,       /* wire ROLE */
    GBWRAP_LINKED,      /* wire IDLE */
    GBWRAP_SYNC,        /* wire SYNC */
    GBWRAP_MENU,        /* wire MENU */
    GBWRAP_DATA,        /* wire PASS */
};

typedef struct {
    bool active;
    uint8_t gen;        /* 1 or 2 */
    uint8_t channel;
    uint8_t stage;      /* enum gbwrap_stage */
    uint32_t frames_sent, frames_received;
    char title[16];     /* the game's name for the screen: PKMN RED, PKMN CRYSTAL ... */
} gbwrap_status_t;

/* Any task: the snapshot the wrapper task last published (every pass while active). */
void gbwrap_get_status(gbwrap_status_t *status);

#endif
