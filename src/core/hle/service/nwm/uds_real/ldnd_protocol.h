// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

#include "common/common_types.h"

namespace Service::NWM::UdsReal {

enum class LdndOp : u8 {
    Socket = 1,
    Bind = 2,
    SetSockOpt = 3,
    GetSockName = 4,
    Start = 5,
    SendTo = 6,
    Close = 7,
    Reply = 8,
    Data = 9,
};

enum class LdndError : u32 {
    None = 0,
    SidTaken = 1,
    MaxSids = 2,
    InvalidSid = 3,
    InvalidOp = 4,
    Other = 5,
};

struct LdndFrame {
    LdndOp op{};
    u32 socket_id{};
    u32 arg0{};
    u32 arg1{};
    u32 arg2{};
    std::vector<u8> blob;
};

namespace LdndProtocol {

constexpr std::size_t HeaderLength = 21;
constexpr std::size_t MaxBlobLength = 262144;
using Header = std::array<u8, HeaderLength>;

inline void WriteU32LittleEndian(std::span<u8, 4> output, u32 value) {
    output[0] = static_cast<u8>(value);
    output[1] = static_cast<u8>(value >> 8);
    output[2] = static_cast<u8>(value >> 16);
    output[3] = static_cast<u8>(value >> 24);
}

inline u32 ReadU32LittleEndian(std::span<const u8, 4> input) {
    return static_cast<u32>(input[0]) | (static_cast<u32>(input[1]) << 8) |
           (static_cast<u32>(input[2]) << 16) | (static_cast<u32>(input[3]) << 24);
}

inline Header SerializeHeader(const LdndFrame& frame) {
    if (frame.blob.size() > MaxBlobLength) {
        throw std::length_error("ldnd frame blob exceeds the protocol limit");
    }

    Header output{};
    output[0] = static_cast<u8>(frame.op);
    WriteU32LittleEndian(std::span<u8, 4>{output.data() + 1, 4}, frame.socket_id);
    WriteU32LittleEndian(std::span<u8, 4>{output.data() + 5, 4}, frame.arg0);
    WriteU32LittleEndian(std::span<u8, 4>{output.data() + 9, 4}, frame.arg1);
    WriteU32LittleEndian(std::span<u8, 4>{output.data() + 13, 4}, frame.arg2);
    WriteU32LittleEndian(std::span<u8, 4>{output.data() + 17, 4},
                         static_cast<u32>(frame.blob.size()));
    return output;
}

inline LdndFrame DeserializeHeader(const Header& input) {
    LdndFrame frame{};
    frame.op = static_cast<LdndOp>(input[0]);
    frame.socket_id = ReadU32LittleEndian(std::span<const u8, 4>{input.data() + 1, 4});
    frame.arg0 = ReadU32LittleEndian(std::span<const u8, 4>{input.data() + 5, 4});
    frame.arg1 = ReadU32LittleEndian(std::span<const u8, 4>{input.data() + 9, 4});
    frame.arg2 = ReadU32LittleEndian(std::span<const u8, 4>{input.data() + 13, 4});

    const u32 blob_length =
        ReadU32LittleEndian(std::span<const u8, 4>{input.data() + 17, 4});
    if (blob_length > MaxBlobLength) {
        throw std::length_error("ldnd reply blob exceeds the protocol limit");
    }
    frame.blob.reserve(blob_length);
    return frame;
}

inline u32 GetBlobLength(const Header& input) {
    const u32 length = ReadU32LittleEndian(std::span<const u8, 4>{input.data() + 17, 4});
    if (length > MaxBlobLength) {
        throw std::length_error("ldnd frame blob exceeds the protocol limit");
    }
    return length;
}

} // namespace LdndProtocol
} // namespace Service::NWM::UdsReal
