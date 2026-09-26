// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include "core/hle/service/nwm/uds_real/esp32_wire.h"

namespace Esp32 = Service::NWM::UdsReal::Esp32;

namespace {

std::vector<u8> FromHex(const std::string& hex) {
    std::vector<u8> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<u8>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::vector<Esp32::Frame> Decode(Esp32::Decoder& decoder, const std::vector<u8>& bytes) {
    std::vector<Esp32::Frame> frames;
    decoder.Feed(bytes, [&](Esp32::Frame&& frame) { frames.push_back(std::move(frame)); });
    return frames;
}

} // namespace

// Golden vectors shared with firmware/esp32-uds-bridge/test/wire_test.c (produced by an
// independent Python implementation of the same framing).
TEST_CASE("ESP32 wire: golden frames", "[core][nwm]") {
    const std::vector<u8> start_payload{6, 0x00, 0x1F, 0x32, 0xAA, 0x00, 0x01};
    std::vector<u8> rx_payload{6, 0xC4};
    for (u8 i = 0; i < 40; ++i) {
        rx_payload.push_back(i);
    }

    struct Case {
        const char* hex;
        Esp32::Type type;
        u8 seq;
        u8 flags;
        std::vector<u8> payload;
    };
    const std::vector<Case> cases{
        {"04010101010105d33c42ff00", Esp32::Type::Hello, 1, 0, {}},
        {"0401020202070206041f32aa0601f3387e7a00", Esp32::Type::Start, 2, 0, start_payload},
        {"03018303012a0306c42c0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"
         "2223242526271ee9661600",
         Esp32::Type::Rx, 0, 1, rx_payload},
    };
    for (const auto& c : cases) {
        const auto encoded = Esp32::Encode(c.type, c.seq, c.flags, c.payload);
        REQUIRE(encoded == FromHex(c.hex));

        Esp32::Decoder decoder;
        const auto frames = Decode(decoder, encoded);
        REQUIRE(frames.size() == 1);
        REQUIRE(frames[0].type == c.type);
        REQUIRE(frames[0].seq == c.seq);
        REQUIRE(frames[0].flags == c.flags);
        REQUIRE(frames[0].payload == c.payload);
    }
}

TEST_CASE("ESP32 wire: round trip across COBS block boundaries", "[core][nwm]") {
    Esp32::Decoder decoder;
    for (std::size_t length = 0; length <= Esp32::MaxPayload; length += (length < 600 ? 1 : 97)) {
        std::vector<u8> payload(length);
        for (std::size_t i = 0; i < length; ++i) {
            payload[i] = length % 3 == 0 ? 0 : (length % 3 == 1 ? 1 : (i % 5 ? 0xFF : 0));
        }
        const auto frames = Decode(decoder, Esp32::Encode(Esp32::Type::TxFrame, 7, 0, payload));
        REQUIRE(frames.size() == 1);
        REQUIRE(frames[0].payload == payload);
    }
    REQUIRE(Esp32::Encode(Esp32::Type::TxFrame, 0, 0, std::vector<u8>(Esp32::MaxPayload + 1))
                .empty());
}

TEST_CASE("ESP32 wire: corrupt frames are dropped and decoding resynchronizes", "[core][nwm]") {
    const auto good = FromHex("0401020202070206041f32aa0601f3387e7a00");
    auto bad = good;
    bad[10] ^= 0x55;
    const std::string banner = "ESP-ROM:esp32s3-20210327\r\n";

    Esp32::Decoder decoder;
    std::vector<u8> stream(banner.begin(), banner.end());
    stream.insert(stream.end(), bad.begin(), bad.end());
    stream.insert(stream.end(), good.begin(), good.end());
    const auto frames = Decode(decoder, stream);
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].type == Esp32::Type::Start);
    REQUIRE(decoder.BadFrames() == 1);
}
