// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "common/common_types.h"
#include "core/hle/service/nwm/uds_real/esp32_serial.h"

// A software stand-in for the air and for the ESP32 board (VC-Adapter's firmware/esp32-uds-bridge),
// so the ESP32 radio path can be exercised without hardware: in the unit tests (in process) and
// between emulator processes (azahar-virtual-air, over TCP).
//
// The board model follows the firmware's radio.c and main.c: wire v1 commands and replies, its Rx
// filter (Nintendo beacons, frames touching its MAC or the watched MAC; no probes, no control
// frames), the beacon template sent every 102.4 ms with a fresh timestamp and sequence number,
// TxDone reports, hardware ACKs for the MAC it was started with (or its twin, START's flag) and
// periodic Stats. What it cannot model: RF itself, the chip's real ACK and retry timing, USB
// latency, and the Wi-Fi driver's quirks.
namespace Service::NWM::UdsReal::VirtualAir {

using Mac = std::array<u8, 6>;
using Clock = std::chrono::steady_clock;

// How the air treats every transmission. Applied per receiver (and to each ACK).
struct Conditions {
    std::chrono::microseconds latency{300}; // One-way delay to every receiver.
    std::chrono::microseconds jitter{0};    // Up to this much extra, uniformly drawn.
    double loss = 0.0;                      // Chance that a receiver misses a frame (or its ACK).
    double duplicate = 0.0;                 // Chance that a receiver gets a frame twice.
    // Retransmissions of a unicast frame nobody acknowledged (the retry bit set), as a Wi-Fi
    // chip does. An approximation: the ESP32's real retry count is not known.
    int unacked_retries = 2;
};

struct AirFrame {
    u8 channel{};
    s8 rssi{-40};
    std::vector<u8> mpdu; // Without FCS.
};

// One channel-aware medium shared by every radio on it. Thread safe. Deliveries run on the air's
// own scheduler thread, after the configured latency.
class Air {
public:
    using EndpointId = u32;
    using Receiver = std::function<void(const AirFrame&)>;
    // Sees every transmission attempt: sender, channel, frame, and whether it was acknowledged.
    using Tap = std::function<void(EndpointId, u8, std::span<const u8>, bool)>;

    explicit Air(Conditions conditions = {}, u32 seed = 1);
    ~Air();
    Air(const Air&) = delete;
    Air& operator=(const Air&) = delete;

    EndpointId AddEndpoint(Receiver receiver);
    void RemoveEndpoint(EndpointId id);
    // 0 takes the radio off the air.
    void SetChannel(EndpointId id, u8 channel);
    // The address this radio's hardware acknowledges (unicast frames whose address 1 is it).
    void SetAckAddress(EndpointId id, std::optional<Mac> address);

    // Puts a frame on the sender's current channel. Returns true when a unicast frame was
    // acknowledged; group addressed frames are never acknowledged.
    bool Transmit(EndpointId from, std::span<const u8> mpdu);

    void SetConditions(const Conditions& conditions);
    Conditions GetConditions() const;
    void SetTap(Tap tap);

    // Runs fn on the scheduler thread at the given time (for the boards' beacon and stats timers).
    void Schedule(Clock::time_point when, std::function<void()> fn);

    struct Stats {
        u64 transmissions{};
        u64 deliveries{};
        u64 lost{};
        u64 acked{};
        u64 retries{};
    };
    Stats GetStats() const;

private:
    struct Impl;
    // Shared with the scheduler thread, which can outlive the Air by a moment: the last owner of
    // the Air may be a task running on that thread.
    std::shared_ptr<Impl> impl;
};

// The ESP32 board's firmware, on a virtual radio. The host side is a byte stream (the serial
// port): FromHost takes what the host wrote, and the sink set with Attach gets what the board
// writes back.
class Board : public std::enable_shared_from_this<Board> {
public:
    using HostSink = std::function<void(std::span<const u8>)>;

    static std::shared_ptr<Board> Create(std::shared_ptr<Air> air, u8 index = 0);
    ~Board();
    Board(const Board&) = delete;
    Board& operator=(const Board&) = delete;

    void Attach(HostSink sink);
    void Detach();
    void FromHost(std::span<const u8> bytes);

    // For tests and the server's log.
    bool Running() const;
    u8 Channel() const;
    Mac OwnAddress() const;
    Mac FactoryAddress() const;
    // Its radio on the air (Air::SetTap reports transmissions by this id).
    Air::EndpointId Endpoint() const;

    static constexpr u8 FirmwareMajor = 1;
    static constexpr u8 FirmwareMinor = 8;

private:
    Board(std::shared_ptr<Air> air, u8 index);
    struct Impl;
    std::unique_ptr<Impl> impl;
};

// An in-process serial port to a Board (Esp32::SetSerialFactory). Read blocks for up to its
// timeout for the board's output.
class BoardSerialPort final : public Esp32::SerialPort {
public:
    explicit BoardSerialPort(std::shared_ptr<Board> board);
    ~BoardSerialPort() override;
    int Read(std::span<u8> buffer, int timeout_ms) override;
    bool Write(std::span<const u8> data) override;

    // Makes Read and Write fail, as an unplugged board does.
    void Unplug();

private:
    struct Pipe;
    std::shared_ptr<Pipe> pipe;
    std::shared_ptr<Board> board;
};

// Helpers shared by the tests and the server.
bool IsGroupAddressed(std::span<const u8> mpdu);
std::string FormatMac(const Mac& mac);

} // namespace Service::NWM::UdsReal::VirtualAir
