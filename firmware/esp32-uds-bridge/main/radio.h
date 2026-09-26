/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
 *
 * The 802.11 side: a station interface that is never connected, started with the MAC of the
 * emulated 3DS so the hardware acknowledges unicast frames addressed to it, plus promiscuous
 * capture and raw injection. Everything above the MPDU (CCMP, the UDS handshake) is Azahar's job.
 */
#ifndef UDS_RADIO_H
#define UDS_RADIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct {
    uint32_t rx_seen;      /* frames the radio delivered to the capture callback */
    uint32_t rx_forwarded; /* frames queued for the host */
    uint32_t rx_dropped;   /* frames that passed the filter but did not fit the queue */
    uint32_t tx_ok;
    uint32_t tx_failed;
    uint32_t beacons_sent;
    uint32_t usb_dropped;
    uint32_t tx_unicast;   /* unicast frames sent (each expects a link-layer ACK) */
    uint32_t acks_rx;      /* link-layer ACKs heard that were addressed to our MAC */
} uds_stats_t;

/* Called from the Wi-Fi task with a device-to-host event (UDS_EVT_RX, UDS_EVT_TXDONE): it must
 * only queue. */
typedef bool (*uds_event_sink_t)(uint8_t type, const uint8_t *payload, size_t length);

esp_err_t radio_init(uds_event_sink_t sink);
/* `mac` is the emulated 3DS address. With `decoy_hw_mac` the radio hardware owns a different
 * address instead, so frames sent to `mac` are treated as sniffed traffic (experiment: the
 * hardware then does not acknowledge them). */
esp_err_t radio_start(uint8_t channel, const uint8_t mac[6], bool decoy_hw_mac);
esp_err_t radio_stop(void);
esp_err_t radio_set_channel(uint8_t channel);
/* rate500k: 0 = the default (1 Mbit/s), otherwise the rate in 500 kbit/s units (22 = 11 Mbit/s). */
esp_err_t radio_tx(const uint8_t *mpdu, size_t length, uint8_t rate500k);
/* Installs the periodic beacon template (an empty one clears it). */
esp_err_t radio_set_beacon(const uint8_t *mpdu, size_t length);
void radio_set_watch(const uint8_t mac[6]);
void radio_get_stats(uds_stats_t *stats);
void radio_note_usb_dropped(void);

#endif
