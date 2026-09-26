// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "common/common_types.h"

namespace Service::NWM::UdsReal::Esp32 {

// Serial framing between Azahar (Android) and the ESP32-S3 UDS radio firmware
// (firmware/esp32-uds-bridge). The device is a dumb 802.11 radio: it captures and injects raw
// MPDUs and hardware-ACKs frames addressed to the MAC it was started with. All UDS logic, CCMP
// and the connection handshake stay in nwm::UDS.
//
//   raw frame = | version=1 | type | seq | flags | length:u16 LE | payload | crc32:u32 LE |
//
// The CRC is CRC-32/ISO-HDLC (zlib) over everything before it. The raw frame is COBS encoded and
// terminated by one 0x00 byte. The C implementation of the same framing lives in
// firmware/esp32-uds-bridge/main/uds_wire.c; keep the two in step (see the wire test).

constexpr u8 WireVersion = 1;
constexpr std::size_t WireHeaderSize = 6;
constexpr std::size_t MaxPayload = 2432; // Largest 802.11 MPDU plus our small headers.
constexpr std::size_t MaxRawFrame = WireHeaderSize + MaxPayload + 4;

enum class Type : u8 {
    // Host -> device.
    Hello = 0x01,       // {} -> HelloAck
    Start = 0x02,       // {channel:u8, mac[6]} bring the radio up with this MAC. -> Status
    Stop = 0x03,        // {} radio down. -> Status
    SetChannel = 0x04,  // {channel:u8} -> Status
    TxFrame = 0x06,     // {tx_flags:u8, rate500k:u8, mpdu...} raw MPDU without FCS. -> Status
    SetBeacon = 0x07,   // {mpdu...} periodic beacon template, empty payload clears. -> Status
    SetWatch = 0x08,    // {mac[6]} also forward frames touching this address. -> Status
    Ping = 0x09,        // {token:u32} -> Pong

    // Device -> host.
    HelloAck = 0x81, // {proto:u8, fw_major:u8, fw_minor:u8, factory_mac[6]}
    Status = 0x82,   // {request_type:u8, result:s32 LE} reply to a command, echoes its seq
    Rx = 0x83,       // {channel:u8, rssi:s8, rx_flags:u8, mpdu...} captured MPDU without FCS
    Log = 0x84,      // {text...}
    Stats = 0x85,    // 7 or 9 x u32 LE, see DeviceStats
    Pong = 0x86,     // {token:u32}
    TxDone = 0x87,   // {acked:u8, length:u16 LE, first bytes of the frame} unicast TX outcome
};

enum TxFlags : u8 {
    TxNoAck = 1 << 0, // Group addressed: do not wait for an ACK.
};

enum RxFlags : u8 {
    RxTruncated = 1 << 0, // The radio delivered fewer bytes than the frame's length.
};

struct Frame {
    Type type{};
    u8 seq{};
    u8 flags{};
    std::vector<u8> payload;
};

struct DeviceStats {
    u32 rx_seen{};
    u32 rx_forwarded{};
    u32 rx_dropped{};
    u32 tx_ok{};
    u32 tx_failed{};
    u32 beacons_sent{};
    u32 usb_dropped{};
    u32 tx_unicast{}; // Unicast frames sent (each expects an ACK); 0 from older firmware.
    u32 acks_rx{};    // ACKs addressed to us: the peer received a unicast frame of ours.
};

u32 Crc32(std::span<const u8> data);

// Returns the encoded frame including the trailing 0x00 delimiter, or an empty vector if the
// payload is too large.
std::vector<u8> Encode(Type type, u8 seq, u8 flags, std::span<const u8> payload);

// Incremental decoder: feed received bytes, complete valid frames come out. A corrupt frame is
// dropped and counted; decoding resynchronizes at the next delimiter.
class Decoder {
public:
    void Feed(std::span<const u8> bytes, const std::function<void(Frame&&)>& on_frame);
    [[nodiscard]] u32 BadFrames() const {
        return bad_frames;
    }

private:
    std::vector<u8> pending;
    bool overflowed{};
    u32 bad_frames{};
};

std::optional<DeviceStats> ParseStats(std::span<const u8> payload);

} // namespace Service::NWM::UdsReal::Esp32
