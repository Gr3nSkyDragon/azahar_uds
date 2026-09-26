// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#include "core/hle/service/nwm/uds_real/esp32_wire.h"

#include <array>

namespace Service::NWM::UdsReal::Esp32 {
namespace {

constexpr std::array<u32, 256> MakeCrcTable() {
    std::array<u32, 256> table{};
    for (u32 i = 0; i < 256; ++i) {
        u32 value = i;
        for (int bit = 0; bit < 8; ++bit) {
            value = (value & 1) ? (value >> 1) ^ 0xEDB88320U : value >> 1;
        }
        table[i] = value;
    }
    return table;
}

constexpr std::array<u32, 256> CrcTable = MakeCrcTable();

std::vector<u8> CobsEncode(std::span<const u8> input) {
    std::vector<u8> output;
    output.reserve(input.size() + input.size() / 254 + 2);
    std::size_t code_index = 0;
    output.push_back(0);
    u8 code = 1;
    for (const u8 byte : input) {
        if (byte == 0) {
            output[code_index] = code;
            code_index = output.size();
            output.push_back(0);
            code = 1;
        } else {
            output.push_back(byte);
            if (++code == 0xFF) {
                output[code_index] = code;
                code_index = output.size();
                output.push_back(0);
                code = 1;
            }
        }
    }
    output[code_index] = code;
    return output;
}

// Returns false if the input is not valid COBS.
bool CobsDecode(std::span<const u8> input, std::vector<u8>& output) {
    output.clear();
    std::size_t index = 0;
    while (index < input.size()) {
        const u8 code = input[index++];
        if (code == 0) {
            return false;
        }
        const std::size_t run = static_cast<std::size_t>(code) - 1;
        if (index + run > input.size()) {
            return false;
        }
        output.insert(output.end(), input.begin() + index, input.begin() + index + run);
        index += run;
        if (code != 0xFF && index < input.size()) {
            output.push_back(0);
        }
    }
    return true;
}

u32 ReadU32(const u8* p) {
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

} // namespace

u32 Crc32(std::span<const u8> data) {
    u32 crc = 0xFFFFFFFFU;
    for (const u8 byte : data) {
        crc = CrcTable[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

std::vector<u8> Encode(Type type, u8 seq, u8 flags, std::span<const u8> payload) {
    if (payload.size() > MaxPayload) {
        return {};
    }
    std::vector<u8> raw;
    raw.reserve(WireHeaderSize + payload.size() + 4);
    raw.push_back(WireVersion);
    raw.push_back(static_cast<u8>(type));
    raw.push_back(seq);
    raw.push_back(flags);
    raw.push_back(static_cast<u8>(payload.size()));
    raw.push_back(static_cast<u8>(payload.size() >> 8));
    raw.insert(raw.end(), payload.begin(), payload.end());
    const u32 crc = Crc32(raw);
    for (int shift = 0; shift < 32; shift += 8) {
        raw.push_back(static_cast<u8>(crc >> shift));
    }
    std::vector<u8> encoded = CobsEncode(raw);
    encoded.push_back(0);
    return encoded;
}

void Decoder::Feed(std::span<const u8> bytes, const std::function<void(Frame&&)>& on_frame) {
    std::vector<u8> raw;
    for (const u8 byte : bytes) {
        if (byte != 0) {
            if (pending.size() > MaxRawFrame + MaxRawFrame / 254 + 4) {
                overflowed = true;
            } else if (!overflowed) {
                pending.push_back(byte);
            }
            continue;
        }

        const bool had_overflow = overflowed;
        overflowed = false;
        if (pending.empty() && !had_overflow) {
            continue; // Empty frame: idle delimiter.
        }
        const bool decoded = !had_overflow && CobsDecode(pending, raw);
        pending.clear();
        if (!decoded || raw.size() < WireHeaderSize + 4 || raw[0] != WireVersion) {
            ++bad_frames;
            continue;
        }
        const std::size_t length = static_cast<std::size_t>(raw[4]) | (static_cast<std::size_t>(raw[5]) << 8);
        if (length > MaxPayload || raw.size() != WireHeaderSize + length + 4) {
            ++bad_frames;
            continue;
        }
        const u32 expected = ReadU32(raw.data() + raw.size() - 4);
        if (Crc32(std::span<const u8>{raw.data(), raw.size() - 4}) != expected) {
            ++bad_frames;
            continue;
        }
        Frame frame;
        frame.type = static_cast<Type>(raw[1]);
        frame.seq = raw[2];
        frame.flags = raw[3];
        frame.payload.assign(raw.begin() + WireHeaderSize, raw.begin() + WireHeaderSize + length);
        on_frame(std::move(frame));
    }
}

std::optional<DeviceStats> ParseStats(std::span<const u8> payload) {
    if (payload.size() < 28) {
        return std::nullopt;
    }
    DeviceStats stats;
    stats.rx_seen = ReadU32(payload.data());
    stats.rx_forwarded = ReadU32(payload.data() + 4);
    stats.rx_dropped = ReadU32(payload.data() + 8);
    stats.tx_ok = ReadU32(payload.data() + 12);
    stats.tx_failed = ReadU32(payload.data() + 16);
    stats.beacons_sent = ReadU32(payload.data() + 20);
    stats.usb_dropped = ReadU32(payload.data() + 24);
    if (payload.size() >= 36) {
        stats.tx_unicast = ReadU32(payload.data() + 28);
        stats.acks_rx = ReadU32(payload.data() + 32);
    }
    return stats;
}

} // namespace Service::NWM::UdsReal::Esp32
