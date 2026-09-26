/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version. */
#include "uds_wire.h"

#include <string.h>

uint32_t uds_crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
    }
    return ~crc;
}

/* Returns the encoded length, or 0 if it does not fit. */
static size_t cobs_encode(const uint8_t *input, size_t length, uint8_t *out, size_t capacity)
{
    size_t write = 1;
    size_t code_index = 0;
    uint8_t code = 1;
    if (capacity < 1) return 0;
    for (size_t i = 0; i < length; ++i) {
        if (input[i] == 0) {
            out[code_index] = code;
            code_index = write;
            if (write >= capacity) return 0;
            out[write++] = 0;
            code = 1;
        } else {
            if (write >= capacity) return 0;
            out[write++] = input[i];
            if (++code == 0xFF) {
                out[code_index] = code;
                code_index = write;
                if (write >= capacity) return 0;
                out[write++] = 0;
                code = 1;
            }
        }
    }
    out[code_index] = code;
    return write;
}

/* Returns the decoded length, or -1 if the input is not valid COBS or does not fit. */
static int cobs_decode(const uint8_t *input, size_t length, uint8_t *out, size_t capacity)
{
    size_t index = 0;
    size_t write = 0;
    while (index < length) {
        uint8_t code = input[index++];
        if (code == 0) return -1;
        size_t run = (size_t)code - 1;
        if (index + run > length || write + run > capacity) return -1;
        memcpy(out + write, input + index, run);
        write += run;
        index += run;
        if (code != 0xFF && index < length) {
            if (write >= capacity) return -1;
            out[write++] = 0;
        }
    }
    return (int)write;
}

size_t uds_wire_encode(uint8_t type, uint8_t seq, uint8_t flags, const uint8_t *payload,
                       size_t length, uint8_t *out, size_t capacity)
{
    static uint8_t raw[UDS_WIRE_MAX_RAW]; /* callers serialize encodes with their own lock */
    if (length > UDS_WIRE_MAX_PAYLOAD) return 0;
    raw[0] = UDS_WIRE_VERSION;
    raw[1] = type;
    raw[2] = seq;
    raw[3] = flags;
    raw[4] = (uint8_t)length;
    raw[5] = (uint8_t)(length >> 8);
    if (length) memcpy(raw + UDS_WIRE_HEADER, payload, length);
    size_t raw_length = UDS_WIRE_HEADER + length;
    uint32_t crc = uds_crc32(raw, raw_length);
    for (int shift = 0; shift < 32; shift += 8) raw[raw_length++] = (uint8_t)(crc >> shift);
    size_t encoded = cobs_encode(raw, raw_length, out, capacity > 0 ? capacity - 1 : 0);
    if (encoded == 0) return 0;
    out[encoded++] = 0;
    return encoded;
}

void uds_wire_decoder_init(uds_wire_decoder_t *decoder)
{
    decoder->length = 0;
    decoder->overflowed = false;
    decoder->bad_frames = 0;
}

bool uds_wire_feed(uds_wire_decoder_t *decoder, uint8_t byte, uds_wire_frame_t *frame)
{
    if (byte != 0) {
        if (decoder->length >= sizeof(decoder->encoded)) {
            decoder->overflowed = true;
        } else if (!decoder->overflowed) {
            decoder->encoded[decoder->length++] = byte;
        }
        return false;
    }

    const bool had_overflow = decoder->overflowed;
    const size_t length = decoder->length;
    decoder->overflowed = false;
    decoder->length = 0;
    if (length == 0 && !had_overflow) return false; /* idle delimiter */

    int raw_length = had_overflow ? -1
                                  : cobs_decode(decoder->encoded, length, decoder->raw,
                                                sizeof(decoder->raw));
    if (raw_length < (int)(UDS_WIRE_HEADER + 4) || decoder->raw[0] != UDS_WIRE_VERSION) {
        ++decoder->bad_frames;
        return false;
    }
    const size_t payload_length = (size_t)decoder->raw[4] | ((size_t)decoder->raw[5] << 8);
    if (payload_length > UDS_WIRE_MAX_PAYLOAD ||
        (size_t)raw_length != UDS_WIRE_HEADER + payload_length + 4) {
        ++decoder->bad_frames;
        return false;
    }
    const uint8_t *crc_bytes = decoder->raw + raw_length - 4;
    const uint32_t expected = (uint32_t)crc_bytes[0] | ((uint32_t)crc_bytes[1] << 8) |
                              ((uint32_t)crc_bytes[2] << 16) | ((uint32_t)crc_bytes[3] << 24);
    if (uds_crc32(decoder->raw, (size_t)raw_length - 4) != expected) {
        ++decoder->bad_frames;
        return false;
    }
    frame->type = decoder->raw[1];
    frame->seq = decoder->raw[2];
    frame->flags = decoder->raw[3];
    frame->length = (uint16_t)payload_length;
    frame->payload = decoder->raw + UDS_WIRE_HEADER;
    return true;
}
