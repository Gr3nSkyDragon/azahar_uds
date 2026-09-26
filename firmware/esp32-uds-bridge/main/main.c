/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
 *
 * ESP32-S3 UDS radio bridge for Azahar on Android. The phone talks to this board over the chip's
 * native USB Serial/JTAG port with the framing in uds_wire.h; the board is a raw 802.11 radio for
 * Nintendo 3DS local wireless (UDS).
 */
#include <stdio.h>
#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "radio.h"
#include "uds_wire.h"

#define FW_MAJOR 1
#define FW_MINOR 3
#define PROTOCOL_VERSION UDS_WIRE_VERSION
#define RX_RING_BYTES (48 * 1024)
#define STATS_INTERVAL_US (5 * 1000 * 1000)

static RingbufHandle_t s_rx_ring;
static SemaphoreHandle_t s_write_lock;
static uint8_t s_encoded[UDS_WIRE_MAX_ENCODED];

/* Serialized writer: the command task and the RX forwarder both send frames. */
static void send_frame(uint8_t type, uint8_t seq, uint8_t flags, const uint8_t *payload,
                       size_t length)
{
    xSemaphoreTake(s_write_lock, portMAX_DELAY);
    size_t encoded = uds_wire_encode(type, seq, flags, payload, length, s_encoded, sizeof(s_encoded));
    size_t sent = 0;
    while (encoded && sent < encoded) {
        int written = usb_serial_jtag_write_bytes(s_encoded + sent, encoded - sent, pdMS_TO_TICKS(100));
        if (written <= 0) {
            /* The host is not reading (port closed). Drop the frame; the COBS delimiter that
             * starts the next one resynchronizes the receiver. */
            radio_note_usb_dropped();
            break;
        }
        sent += (size_t)written;
    }
    xSemaphoreGive(s_write_lock);
}

static void send_status(uint8_t request_type, uint8_t seq, int32_t result)
{
    uint8_t payload[5];
    payload[0] = request_type;
    for (int i = 0; i < 4; ++i) payload[1 + i] = (uint8_t)((uint32_t)result >> (8 * i));
    send_frame(UDS_EVT_STATUS, seq, 0, payload, sizeof(payload));
}

/* Called from the Wi-Fi task: queue only. Ring items are {event type, payload...}. */
static bool event_sink(uint8_t type, const uint8_t *payload, size_t length)
{
    static uint8_t item[1 + UDS_WIRE_MAX_PAYLOAD];
    if (length > UDS_WIRE_MAX_PAYLOAD) return false;
    item[0] = type;
    memcpy(item + 1, payload, length);
    return xRingbufferSend(s_rx_ring, item, 1 + length, 0) == pdTRUE;
}

static void rx_forward_task(void *arg)
{
    (void)arg;
    for (;;) {
        size_t length = 0;
        uint8_t *item = xRingbufferReceive(s_rx_ring, &length, pdMS_TO_TICKS(50));
        if (item) {
            send_frame(item[0], 0, 0, item + 1, length - 1);
            vRingbufferReturnItem(s_rx_ring, item);
        }
    }
}

static void stats_task(void *arg)
{
    (void)arg;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(STATS_INTERVAL_US / 1000));
        uds_stats_t stats;
        radio_get_stats(&stats);
        uint8_t payload[36];
        const uint32_t values[9] = {stats.rx_seen,  stats.rx_forwarded, stats.rx_dropped,
                                    stats.tx_ok,    stats.tx_failed,    stats.beacons_sent,
                                    stats.usb_dropped, stats.tx_unicast, stats.acks_rx};
        for (int i = 0; i < 9; ++i)
            for (int b = 0; b < 4; ++b) payload[i * 4 + b] = (uint8_t)(values[i] >> (8 * b));
        send_frame(UDS_EVT_STATS, 0, 0, payload, sizeof(payload));
    }
}

static void handle_command(const uds_wire_frame_t *frame)
{
    const uint8_t *p = frame->payload;
    const size_t n = frame->length;
    esp_err_t result = ESP_OK;

    switch (frame->type) {
    case UDS_CMD_HELLO: {
        uint8_t payload[9] = {PROTOCOL_VERSION, FW_MAJOR, FW_MINOR};
        esp_efuse_mac_get_default(payload + 3);
        send_frame(UDS_EVT_HELLO_ACK, frame->seq, 0, payload, sizeof(payload));
        return;
    }
    case UDS_CMD_START:
        /* {channel, mac[6]} plus an optional flags byte: bit 0 = decoy hardware MAC. */
        result = (n == 7 || n == 8) ? radio_start(p[0], p + 1, n == 8 && (p[7] & 1))
                                    : ESP_ERR_INVALID_SIZE;
        break;
    case UDS_CMD_STOP:
        result = radio_stop();
        break;
    case UDS_CMD_SET_CHANNEL:
        result = n == 1 ? radio_set_channel(p[0]) : ESP_ERR_INVALID_SIZE;
        break;
    case UDS_CMD_TX_FRAME:
        /* {tx_flags, rate500k, mpdu...}. Fire-and-forget: no Status, so the host can stream
         * frames; failures show up as tx_failed in the periodic stats. The driver decides from
         * the address whether a frame expects an ACK, so UDS_TX_NO_ACK is informational. */
        if (n >= 2 + 10) (void)radio_tx(p + 2, n - 2, p[1]);
        return;
    case UDS_CMD_SET_BEACON:
        result = radio_set_beacon(p, n);
        break;
    case UDS_CMD_SET_WATCH:
        if (n == 6) radio_set_watch(p); else result = ESP_ERR_INVALID_SIZE;
        break;
    case UDS_CMD_PING:
        send_frame(UDS_EVT_PONG, frame->seq, 0, p, n);
        return;
    default:
        result = ESP_ERR_NOT_SUPPORTED;
        break;
    }
    send_status(frame->type, frame->seq, (int32_t)result);
}

void app_main(void)
{
    s_write_lock = xSemaphoreCreateMutex();
    s_rx_ring = xRingbufferCreate(RX_RING_BYTES, RINGBUF_TYPE_NOSPLIT);

    usb_serial_jtag_driver_config_t usb_config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    usb_config.rx_buffer_size = 16384;
    usb_config.tx_buffer_size = 16384;
    usb_serial_jtag_driver_install(&usb_config);

    /* The ROM boot banner and anything else that reached the port ends at a newline; a bare
     * delimiter first makes the host discard it as an idle/garbage frame. */
    const uint8_t delimiter = 0;
    usb_serial_jtag_write_bytes(&delimiter, 1, pdMS_TO_TICKS(50));

    radio_init(event_sink);

    xTaskCreate(rx_forward_task, "rx_fwd", 4096, NULL, 6, NULL);
    xTaskCreate(stats_task, "stats", 3072, NULL, 2, NULL);

    static uds_wire_decoder_t decoder;
    uds_wire_decoder_init(&decoder);
    uint8_t chunk[256];
    for (;;) {
        int count = usb_serial_jtag_read_bytes(chunk, sizeof(chunk), pdMS_TO_TICKS(20));
        for (int i = 0; i < count; ++i) {
            uds_wire_frame_t frame;
            if (uds_wire_feed(&decoder, chunk[i], &frame)) handle_command(&frame);
        }
    }
}
