/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
 *
 * Serial framing between Azahar (Android) and this firmware. Mirrors
 * src/core/hle/service/nwm/uds_real/esp32_wire.{h,cpp} in the emulator - keep the two in step
 * (test/wire_test.c and src/tests/core/hle/service/nwm/esp32_wire.cpp share golden vectors).
 *
 *   raw frame = | version=1 | type | seq | flags | length:u16 LE | payload | crc32:u32 LE |
 *
 * CRC-32/ISO-HDLC (zlib) over everything before it; the raw frame is COBS encoded and terminated
 * by one 0x00 byte.
 */
#ifndef UDS_WIRE_H
#define UDS_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UDS_WIRE_VERSION 1
#define UDS_WIRE_HEADER 6
#define UDS_WIRE_MAX_PAYLOAD 2432
#define UDS_WIRE_MAX_RAW (UDS_WIRE_HEADER + UDS_WIRE_MAX_PAYLOAD + 4)
#define UDS_WIRE_MAX_ENCODED (UDS_WIRE_MAX_RAW + UDS_WIRE_MAX_RAW / 254 + 2)

/* Host -> device. */
#define UDS_CMD_HELLO 0x01
#define UDS_CMD_START 0x02      /* {channel:u8, mac[6]} */
#define UDS_CMD_STOP 0x03       /* {} */
#define UDS_CMD_SET_CHANNEL 0x04 /* {channel:u8} */
#define UDS_CMD_TX_FRAME 0x06   /* {tx_flags:u8, rate500k:u8, mpdu...} */
#define UDS_CMD_SET_BEACON 0x07 /* {mpdu...}, empty clears */
#define UDS_CMD_SET_WATCH 0x08  /* {mac[6]}, all zero clears */
#define UDS_CMD_PING 0x09       /* {token:u32} */

/* Device -> host. */
#define UDS_EVT_HELLO_ACK 0x81 /* {proto:u8, fw_major:u8, fw_minor:u8, factory_mac[6]} */
#define UDS_EVT_STATUS 0x82    /* {request_type:u8, result:s32 LE}, echoes the request seq */
#define UDS_EVT_RX 0x83        /* {channel:u8, rssi:s8, rx_flags:u8, mpdu...} */
#define UDS_EVT_LOG 0x84       /* {text...} */
#define UDS_EVT_STATS 0x85     /* 9 x u32 LE: see uds_stats_t in radio.h */
#define UDS_EVT_PONG 0x86      /* {token:u32} */
#define UDS_EVT_TXDONE 0x87    /* {acked:u8, length:u16 LE, first bytes of the frame sent} */

#define UDS_TX_NO_ACK 0x01
#define UDS_RX_TRUNCATED 0x01

uint32_t uds_crc32(const uint8_t *data, size_t length);

/* Encodes one frame including the trailing 0x00 delimiter. Returns the byte count, or 0 if the
 * payload or `capacity` is too small. */
size_t uds_wire_encode(uint8_t type, uint8_t seq, uint8_t flags, const uint8_t *payload,
                       size_t length, uint8_t *out, size_t capacity);

typedef struct {
    uint8_t type;
    uint8_t seq;
    uint8_t flags;
    uint16_t length;
    const uint8_t *payload; /* points into the decoder; valid until the next uds_wire_feed */
} uds_wire_frame_t;

typedef struct {
    uint8_t encoded[UDS_WIRE_MAX_ENCODED];
    uint8_t raw[UDS_WIRE_MAX_RAW];
    size_t length;
    bool overflowed;
    uint32_t bad_frames; /* corrupt frames dropped; decoding resynchronizes at the next 0x00 */
} uds_wire_decoder_t;

void uds_wire_decoder_init(uds_wire_decoder_t *decoder);
/* Feeds one received byte. Returns true when it completed a valid frame, which is then in *frame. */
bool uds_wire_feed(uds_wire_decoder_t *decoder, uint8_t byte, uds_wire_frame_t *frame);

#endif
