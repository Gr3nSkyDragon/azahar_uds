/* Host-side test of uds_wire.c:  gcc -I../main wire_test.c ../main/uds_wire.c -o wire_test && ./wire_test
 * The golden vectors were produced by an independent Python implementation and are shared with
 * src/tests/core/hle/service/nwm/esp32_wire.cpp in the emulator. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uds_wire.h"

static int failures;
#define CHECK(cond)                                                                        \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                         \
            ++failures;                                                                    \
        }                                                                                  \
    } while (0)

static size_t from_hex(const char *hex, uint8_t *out)
{
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; ++i) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static void golden(const char *hex, uint8_t type, uint8_t seq, uint8_t flags, const uint8_t *payload,
                   size_t length)
{
    uint8_t expected[UDS_WIRE_MAX_ENCODED], actual[UDS_WIRE_MAX_ENCODED];
    size_t expected_length = from_hex(hex, expected);
    size_t actual_length = uds_wire_encode(type, seq, flags, payload, length, actual, sizeof(actual));
    CHECK(actual_length == expected_length);
    CHECK(actual_length == expected_length && memcmp(actual, expected, expected_length) == 0);

    static uds_wire_decoder_t decoder;
    uds_wire_decoder_init(&decoder);
    uds_wire_frame_t frame;
    int completed = 0;
    for (size_t i = 0; i < expected_length; ++i)
        if (uds_wire_feed(&decoder, expected[i], &frame)) ++completed;
    CHECK(completed == 1);
    CHECK(frame.type == type && frame.seq == seq && frame.flags == flags);
    CHECK(frame.length == length && (length == 0 || memcmp(frame.payload, payload, length) == 0));
}

int main(void)
{
    golden("04010101010105d33c42ff00", 0x01, 1, 0, NULL, 0);
    const uint8_t start[] = {6, 0x00, 0x1F, 0x32, 0xAA, 0x00, 0x01};
    golden("0401020202070206041f32aa0601f3387e7a00", 0x02, 2, 0, start, sizeof(start));
    uint8_t rx[42] = {6, 0xC4};
    for (int i = 0; i < 40; ++i) rx[2 + i] = (uint8_t)i;
    golden("03018303012a0306c42c0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"
           "2223242526271ee9661600",
           0x83, 0, 1, rx, sizeof(rx));

    /* Round trip of large payloads full of zeros and 0xFF runs (COBS block boundaries). */
    static uint8_t payload[UDS_WIRE_MAX_PAYLOAD], encoded[UDS_WIRE_MAX_ENCODED];
    static uds_wire_decoder_t decoder;
    for (size_t length = 0; length <= UDS_WIRE_MAX_PAYLOAD; length += (length < 600 ? 1 : 97)) {
        for (size_t i = 0; i < length; ++i)
            payload[i] = (length % 3 == 0) ? 0 : (length % 3 == 1 ? 1 : (uint8_t)(i % 5 ? 0xFF : 0));
        size_t n = uds_wire_encode(0x06, 7, 0, payload, length, encoded, sizeof(encoded));
        CHECK(n > 0);
        uds_wire_decoder_init(&decoder);
        uds_wire_frame_t frame;
        int completed = 0;
        for (size_t i = 0; i < n; ++i)
            if (uds_wire_feed(&decoder, encoded[i], &frame)) ++completed;
        CHECK(completed == 1 && frame.length == length &&
              (length == 0 || memcmp(frame.payload, payload, length) == 0));
    }
    CHECK(uds_wire_encode(0x06, 0, 0, payload, UDS_WIRE_MAX_PAYLOAD + 1, encoded, sizeof(encoded)) == 0);

    /* A corrupt frame is counted and dropped; the next good frame still decodes. */
    uint8_t good[UDS_WIRE_MAX_ENCODED];
    size_t good_length = from_hex("0401020202070206041f32aa0601f3387e7a00", good);
    uint8_t bad[UDS_WIRE_MAX_ENCODED];
    memcpy(bad, good, good_length);
    bad[10] ^= 0x55;
    uds_wire_decoder_init(&decoder);
    uds_wire_frame_t frame;
    int completed = 0;
    const char *banner = "ESP-ROM:esp32s3-20210327\r\nBuild:Mar 27 2021\r\n"; /* boot text, no zeros */
    for (size_t i = 0; i < strlen(banner); ++i) uds_wire_feed(&decoder, (uint8_t)banner[i], &frame);
    for (size_t i = 0; i < good_length; ++i) /* first frame is corrupted by the banner + bad CRC */
        if (uds_wire_feed(&decoder, bad[i], &frame)) ++completed;
    for (size_t i = 0; i < good_length; ++i)
        if (uds_wire_feed(&decoder, good[i], &frame)) ++completed;
    CHECK(completed == 1);
    CHECK(decoder.bad_frames == 1);

    printf(failures ? "wire_test: %d failure(s)\n" : "wire_test: all passed\n", failures);
    return failures != 0;
}
