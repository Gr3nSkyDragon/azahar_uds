// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

// The virtual air and board (virtual_air.h), and Azahar's ESP32 radio path running over them.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "common/settings.h"
#include "core/hle/service/nwm/nwm_uds.h"
#include "core/hle/service/nwm/uds_beacon.h"
#include "core/hle/service/nwm/uds_real/esp32_serial.h"
#include "core/hle/service/nwm/uds_real/esp32_wire.h"
#include "core/hle/service/nwm/uds_real/nl80211_monitor.h"
#include "core/hle/service/nwm/uds_real/virtual_air.h"

namespace UdsReal = Service::NWM::UdsReal;
namespace Esp32 = Service::NWM::UdsReal::Esp32;
using namespace Service::NWM::UdsReal::VirtualAir;
using namespace std::chrono_literals;

namespace {

constexpr Mac Broadcast{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
constexpr Mac HostMac{0x40, 0xF4, 0x07, 0x11, 0x22, 0x33};
constexpr Mac JoinerMac{0x40, 0xF4, 0x07, 0x44, 0x55, 0x66};
constexpr Mac StrangerA{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
constexpr Mac StrangerB{0x00, 0x11, 0x22, 0x33, 0x44, 0x66};

template <typename T>
class Queue {
public:
    void Push(T item) {
        {
            std::scoped_lock lock{mutex};
            items.push_back(std::move(item));
        }
        cv.notify_all();
    }

    // The first item matching pred, removed from the queue; waits up to timeout for it.
    template <typename Pred>
    std::optional<T> WaitFor(Pred pred, std::chrono::milliseconds timeout) {
        std::unique_lock lock{mutex};
        std::optional<T> found;
        cv.wait_for(lock, timeout, [&] {
            for (auto it = items.begin(); it != items.end(); ++it) {
                if (pred(*it)) {
                    found = std::move(*it);
                    items.erase(it);
                    return true;
                }
            }
            return false;
        });
        return found;
    }

    std::optional<T> WaitAny(std::chrono::milliseconds timeout) {
        return WaitFor([](const T&) { return true; }, timeout);
    }

    std::size_t Size() {
        std::scoped_lock lock{mutex};
        return items.size();
    }

    std::vector<T> Drain() {
        std::scoped_lock lock{mutex};
        std::vector<T> out{std::make_move_iterator(items.begin()),
                           std::make_move_iterator(items.end())};
        items.clear();
        return out;
    }

private:
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<T> items;
};

std::vector<u8> Header(u8 type, u8 subtype, const Mac& a1, const Mac& a2, const Mac& a3,
                       u16 sequence = 0) {
    std::vector<u8> frame;
    frame.push_back(static_cast<u8>((type << 2) | (subtype << 4)));
    frame.push_back(0);
    frame.push_back(0); // Duration.
    frame.push_back(0);
    frame.insert(frame.end(), a1.begin(), a1.end());
    frame.insert(frame.end(), a2.begin(), a2.end());
    frame.insert(frame.end(), a3.begin(), a3.end());
    const u16 sequence_control = static_cast<u16>(sequence << 4);
    frame.push_back(static_cast<u8>(sequence_control));
    frame.push_back(static_cast<u8>(sequence_control >> 8));
    return frame;
}

std::vector<u8> Management(u8 subtype, const Mac& a1, const Mac& a2, const Mac& a3,
                           std::vector<u8> body = {0, 0, 1, 0, 0, 0}) {
    std::vector<u8> frame = Header(0, subtype, a1, a2, a3);
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

std::vector<u8> Data(const Mac& a1, const Mac& a2, const Mac& a3) {
    std::vector<u8> frame = Header(2, 0, a1, a2, a3);
    for (u8 i = 0; i < 16; ++i) {
        frame.push_back(i);
    }
    return frame;
}

// A beacon with fixed fields and, optionally, a Nintendo vendor element.
std::vector<u8> Beacon(const Mac& source, bool nintendo) {
    std::vector<u8> frame = Header(0, 8, Broadcast, source, source);
    frame.insert(frame.end(), 12, 0); // Timestamp, interval, capability.
    frame.push_back(0);               // SSID, empty.
    frame.push_back(0);
    if (nintendo) {
        frame.insert(frame.end(), {221, 9, 0x00, 0x1F, 0x32, 21, 0x00, 0x17, 0x10, 0x10, 1});
    } else {
        frame.insert(frame.end(), {221, 4, 0x00, 0x50, 0xF2, 1});
    }
    return frame;
}

bool HasRetryBit(const std::vector<u8>& mpdu) {
    return mpdu.size() >= 2 && (mpdu[1] & 0x08) != 0;
}

Mac Address(std::span<const u8> mpdu, std::size_t offset) {
    Mac mac{};
    std::memcpy(mac.data(), mpdu.data() + offset, mac.size());
    return mac;
}

// A bare radio on the air that records what it hears.
struct Listener {
    explicit Listener(std::shared_ptr<Air> air_, u8 channel) : air{std::move(air_)} {
        id = air->AddEndpoint([this](const AirFrame& frame) { heard.Push(frame.mpdu); });
        air->SetChannel(id, channel);
    }
    ~Listener() {
        air->RemoveEndpoint(id);
    }
    std::shared_ptr<Air> air;
    Air::EndpointId id{};
    Queue<std::vector<u8>> heard;
};

// The host side of a board's serial link, speaking wire v1.
class HostLink {
public:
    explicit HostLink(std::shared_ptr<Board> board_) : board{std::move(board_)} {
        board->Attach([this](std::span<const u8> bytes) {
            decoder.Feed(bytes, [this](Esp32::Frame&& frame) { frames.Push(std::move(frame)); });
        });
    }
    ~HostLink() {
        board->Detach();
    }

    void Send(Esp32::Type type, std::vector<u8> payload, u8 seq = 7) {
        const std::vector<u8> encoded = Esp32::Encode(type, seq, 0, payload);
        board->FromHost(encoded);
    }

    std::optional<Esp32::Frame> WaitFor(Esp32::Type type, std::chrono::milliseconds timeout = 1s) {
        return frames.WaitFor([type](const Esp32::Frame& f) { return f.type == type; }, timeout);
    }

    // Sends a command and returns the result in its Status reply.
    s32 Command(Esp32::Type type, std::vector<u8> payload) {
        Send(type, std::move(payload));
        const auto status = WaitFor(Esp32::Type::Status);
        REQUIRE(status.has_value());
        REQUIRE(status->payload.size() == 5);
        CHECK(status->payload[0] == static_cast<u8>(type));
        s32 result{};
        std::memcpy(&result, status->payload.data() + 1, sizeof(result));
        return result;
    }

    s32 Start(u8 channel, const Mac& mac, bool twin = false) {
        std::vector<u8> payload{channel};
        payload.insert(payload.end(), mac.begin(), mac.end());
        payload.push_back(static_cast<u8>(twin ? 1 : 0));
        return Command(Esp32::Type::Start, std::move(payload));
    }

    void Transmit(const std::vector<u8>& mpdu) {
        std::vector<u8> payload{0, 2};
        payload.insert(payload.end(), mpdu.begin(), mpdu.end());
        Send(Esp32::Type::TxFrame, std::move(payload));
    }

    std::shared_ptr<Board> board;
    Esp32::Decoder decoder; // Only used from the board's sink, which the board serializes.
    Queue<Esp32::Frame> frames;
};

} // namespace

TEST_CASE("Virtual air: frames only reach radios on the same channel", "[core][nwm][virtual-air]") {
    auto air = std::make_shared<Air>();
    Listener sender{air, 6};
    Listener same{air, 6};
    Listener other{air, 11};
    air->Transmit(sender.id, Data(Broadcast, StrangerA, StrangerA));
    CHECK(same.heard.WaitAny(500ms).has_value());
    CHECK_FALSE(other.heard.WaitAny(100ms).has_value());
    CHECK_FALSE(sender.heard.WaitAny(10ms).has_value());

    // A radio that is off the air (channel 0) cannot send.
    air->SetChannel(sender.id, 0);
    CHECK_FALSE(air->Transmit(sender.id, Data(Broadcast, StrangerA, StrangerA)));
    CHECK_FALSE(same.heard.WaitAny(100ms).has_value());
}

TEST_CASE("Virtual air: only the addressed radio acknowledges; unacknowledged frames are retried",
          "[core][nwm][virtual-air]") {
    Conditions conditions;
    conditions.unacked_retries = 2;
    auto air = std::make_shared<Air>(conditions);
    Listener sender{air, 1};
    Listener receiver{air, 1};
    air->SetAckAddress(receiver.id, StrangerB);

    CHECK(air->Transmit(sender.id, Data(StrangerB, StrangerA, StrangerA)));
    REQUIRE(receiver.heard.WaitAny(500ms).has_value());
    CHECK_FALSE(receiver.heard.WaitAny(100ms).has_value()); // Acknowledged: sent once.

    CHECK_FALSE(air->Transmit(sender.id, Data(JoinerMac, StrangerA, StrangerA)));
    std::vector<std::vector<u8>> copies;
    while (auto copy = receiver.heard.WaitAny(300ms)) {
        copies.push_back(std::move(*copy));
    }
    REQUIRE(copies.size() == 3);
    CHECK_FALSE(HasRetryBit(copies[0]));
    CHECK(HasRetryBit(copies[1]));
    CHECK(HasRetryBit(copies[2]));

    // Group addressed frames are never acknowledged or retried.
    CHECK_FALSE(air->Transmit(sender.id, Data(Broadcast, StrangerA, StrangerA)));
    CHECK(receiver.heard.WaitAny(300ms).has_value());
    CHECK_FALSE(receiver.heard.WaitAny(100ms).has_value());
}

TEST_CASE("Virtual air: loss, duplication and latency follow the conditions",
          "[core][nwm][virtual-air]") {
    Conditions lossy;
    lossy.loss = 1.0;
    auto air = std::make_shared<Air>(lossy);
    Listener sender{air, 6};
    Listener receiver{air, 6};
    air->SetAckAddress(receiver.id, StrangerB);
    CHECK_FALSE(air->Transmit(sender.id, Data(StrangerB, StrangerA, StrangerA)));
    CHECK_FALSE(receiver.heard.WaitAny(200ms).has_value());
    CHECK(air->GetStats().lost >= 1);

    Conditions twice;
    twice.duplicate = 1.0;
    air->SetConditions(twice);
    air->Transmit(sender.id, Data(Broadcast, StrangerA, StrangerA));
    CHECK(receiver.heard.WaitAny(300ms).has_value());
    CHECK(receiver.heard.WaitAny(300ms).has_value());

    Conditions slow;
    slow.latency = 150ms;
    air->SetConditions(slow);
    const auto sent = Clock::now();
    air->Transmit(sender.id, Data(Broadcast, StrangerA, StrangerA));
    REQUIRE(receiver.heard.WaitAny(1s).has_value());
    CHECK(Clock::now() - sent >= 140ms);
}

TEST_CASE("Virtual board: answers commands like the firmware", "[core][nwm][virtual-air]") {
    auto air = std::make_shared<Air>();
    HostLink host{Board::Create(air, 3)};

    host.Send(Esp32::Type::Hello, {}, 42);
    const auto hello = host.WaitFor(Esp32::Type::HelloAck);
    REQUIRE(hello.has_value());
    CHECK(hello->seq == 42);
    REQUIRE(hello->payload.size() == 10);
    CHECK(hello->payload[0] == Esp32::WireVersion);
    CHECK(hello->payload[1] == Board::FirmwareMajor);
    CHECK(hello->payload[2] == Board::FirmwareMinor);

    constexpr s32 InvalidArg = 0x102;
    constexpr s32 InvalidState = 0x103;
    constexpr s32 InvalidSize = 0x104;
    constexpr s32 NotSupported = 0x106;
    CHECK(host.Command(Esp32::Type::SetChannel, {6}) == InvalidState); // Radio not started.
    CHECK(host.Command(Esp32::Type::Start, {6, 1, 2, 3}) == InvalidSize);
    CHECK(host.Start(14, HostMac) == InvalidArg);
    CHECK(host.Start(6, Broadcast) == InvalidArg); // The hardware needs an individual address.
    CHECK(host.Start(6, HostMac) == 0);
    CHECK(host.board->Running());
    CHECK(host.Command(Esp32::Type::SetChannel, {11}) == 0);
    CHECK(host.board->Channel() == 11);
    CHECK(host.Command(Esp32::Type::SetChannel, {0}) == InvalidArg);
    CHECK(host.Command(Esp32::Type::SetBeacon, std::vector<u8>(20, 0)) == InvalidSize);
    CHECK(host.Command(Esp32::Type::SetBeacon, {}) == 0);
    CHECK(host.Command(Esp32::Type::SetWatch, {1, 2, 3}) == InvalidSize);
    CHECK(host.Command(static_cast<Esp32::Type>(0x30), {}) == NotSupported);

    host.Send(Esp32::Type::Ping, {9, 8, 7, 6}, 99);
    const auto pong = host.WaitFor(Esp32::Type::Pong);
    REQUIRE(pong.has_value());
    CHECK(pong->seq == 99);
    CHECK(pong->payload == std::vector<u8>{9, 8, 7, 6});

    CHECK(host.Command(Esp32::Type::Stop, {}) == 0);
    CHECK_FALSE(host.board->Running());
}

TEST_CASE("Virtual board: sends its beacon template every 102.4 ms", "[core][nwm][virtual-air]") {
    auto air = std::make_shared<Air>();
    HostLink host{Board::Create(air)};
    Listener listener{air, 6};
    REQUIRE(host.Start(6, HostMac) == 0);
    REQUIRE(host.Command(Esp32::Type::SetBeacon, Beacon(HostMac, true)) == 0);

    std::this_thread::sleep_for(560ms);
    const auto beacons = listener.heard.Drain();
    CHECK(beacons.size() >= 4);
    CHECK(beacons.size() <= 6);
    for (std::size_t i = 1; i < beacons.size(); ++i) {
        const u16 previous = static_cast<u16>((beacons[i - 1][22] | (beacons[i - 1][23] << 8)) >> 4);
        const u16 current = static_cast<u16>((beacons[i][22] | (beacons[i][23] << 8)) >> 4);
        CHECK(current == static_cast<u16>((previous + 1) & 0x0FFF));
        u64 previous_time = 0;
        u64 current_time = 0;
        std::memcpy(&previous_time, beacons[i - 1].data() + 24, 8);
        std::memcpy(&current_time, beacons[i].data() + 24, 8);
        CHECK(current_time > previous_time);
    }

    // Clearing the template stops the beacons.
    REQUIRE(host.Command(Esp32::Type::SetBeacon, {}) == 0);
    listener.heard.Drain();
    std::this_thread::sleep_for(250ms);
    CHECK(listener.heard.Size() == 0);
}

TEST_CASE("Virtual board: forwards to the host what the firmware forwards",
          "[core][nwm][virtual-air]") {
    auto air = std::make_shared<Air>();
    HostLink host{Board::Create(air)};
    Listener peer{air, 1};
    REQUIRE(host.Start(1, HostMac) == 0);

    // Every copy that reached the host (an unacknowledged unicast frame is retried on the air).
    const auto forwarded = [&](const std::vector<u8>& mpdu) {
        air->Transmit(peer.id, mpdu);
        const bool any = host.WaitFor(Esp32::Type::Rx, 200ms).has_value();
        std::this_thread::sleep_for(30ms);
        while (host.WaitFor(Esp32::Type::Rx, 0ms)) {
        }
        return any;
    };
    CHECK(forwarded(Beacon(StrangerA, true)));
    CHECK_FALSE(forwarded(Beacon(StrangerA, false)));
    CHECK_FALSE(forwarded(Management(4, Broadcast, StrangerA, Broadcast))); // Probe request.
    CHECK(forwarded(Data(HostMac, StrangerA, StrangerA)));
    CHECK(forwarded(Management(11, HostMac, StrangerA, HostMac)));
    CHECK_FALSE(forwarded(Data(StrangerB, StrangerA, StrangerA)));
    REQUIRE(host.Command(Esp32::Type::SetWatch,
                         std::vector<u8>{StrangerA.begin(), StrangerA.end()}) == 0);
    CHECK(forwarded(Data(StrangerB, StrangerA, StrangerA)));

    // The Rx event: {channel, rssi, flags, mpdu}.
    air->Transmit(peer.id, Data(HostMac, StrangerA, StrangerA));
    const auto rx = host.WaitFor(Esp32::Type::Rx);
    REQUIRE(rx.has_value());
    REQUIRE(rx->payload.size() == 3 + 24 + 16);
    CHECK(rx->payload[0] == 1);
    CHECK(Address(std::span<const u8>{rx->payload}.subspan(3), 4) == HostMac);
}

TEST_CASE("Virtual board: hardware ACKs follow the twin address, TxDone reports them",
          "[core][nwm][virtual-air]") {
    Conditions conditions;
    conditions.unacked_retries = 1;
    auto air = std::make_shared<Air>(conditions);
    HostLink host{Board::Create(air)};
    Listener peer{air, 6};
    air->SetAckAddress(peer.id, StrangerA);
    REQUIRE(host.Start(6, HostMac, true) == 0); // As Azahar starts it: a twin hardware MAC.

    // Our unicast management frame to a radio that acknowledges it.
    host.Transmit(Management(11, StrangerA, HostMac, StrangerA));
    auto done = host.WaitFor(Esp32::Type::TxDone);
    REQUIRE(done.has_value());
    CHECK(done->payload[0] == 1);
    // ... and to nobody: not acknowledged, retried on the air.
    host.Transmit(Management(11, StrangerB, HostMac, StrangerB));
    done = host.WaitFor(Esp32::Type::TxDone);
    REQUIRE(done.has_value());
    CHECK(done->payload[0] == 0);
    peer.heard.Drain();

    // The twin hardware address is acknowledged, the emulated 3DS's own address is not (so the
    // peer retransmits, as a retail console does), but both reach the host.
    Mac twin = HostMac;
    twin[0] = static_cast<u8>(twin[0] ^ 0x02);
    CHECK(air->Transmit(peer.id, Data(twin, StrangerA, StrangerA)));
    CHECK_FALSE(air->Transmit(peer.id, Data(HostMac, StrangerA, StrangerA)));
    CHECK(host.WaitFor(Esp32::Type::Rx).has_value()); // The emulated address, first try ...
    CHECK(host.WaitFor(Esp32::Type::Rx).has_value()); // ... and its retry.
}

namespace {

// Two Nl80211Monitors (Azahar's radio layer) on virtual boards, the way nwm::UDS drives them.
struct MonitorPair {
    // in_process: boards on this process's own air. Otherwise the monitors open their port the
    // normal way (AZAHAR_ESP32_PORT, e.g. a running azahar-virtual-air).
    explicit MonitorPair(Conditions conditions, u32 seed = 7, bool in_process_ = true)
        : air{std::make_shared<Air>(conditions, seed)},
          boards{Board::Create(air, 1), Board::Create(air, 2)}, in_process{in_process_} {
        previous_setting = Settings::values.use_esp32_uds.GetValue();
        Settings::values.use_esp32_uds.SetValue(true);
        if (!in_process) {
            return;
        }
        Esp32::SetSerialFactory([this]() -> std::unique_ptr<Esp32::SerialPort> {
            const int index = opened++;
            if (index >= 2) {
                return nullptr;
            }
            return std::make_unique<BoardSerialPort>(boards[static_cast<std::size_t>(index)]);
        });
    }

    ~MonitorPair() {
        joiner.Stop();
        host.Stop();
        Esp32::SetSerialFactory({});
        Settings::values.use_esp32_uds.SetValue(previous_setting);
    }

    // The host advertises a network on hosted_channel, as nwm::UDS does once a game hosts.
    void StartHost(u8 hosted_channel) {
        host.Start(hosted_channel, HostMac, [](UdsReal::CapturedBeacon) {},
                   [this](UdsReal::CapturedFrame frame) { host_frames.Push(std::move(frame)); });
        if (in_process) {
            const auto deadline = Clock::now() + 5s;
            while (!boards[0]->Running() && Clock::now() < deadline) {
                std::this_thread::sleep_for(10ms);
            }
            REQUIRE(boards[0]->Running());
        } else {
            std::this_thread::sleep_for(1s); // Connect, HELLO and START over TCP.
        }

        Service::NWM::NetworkInfo info{};
        info.host_mac_address = HostMac;
        info.channel = hosted_channel;
        info.initialized = 1;
        info.oui_value = Service::NWM::NintendoOUI;
        info.oui_type = static_cast<u8>(Service::NWM::NintendoTagId::NetworkInfo);
        info.wlan_comm_id = WlanCommId;
        info.id = 1;
        info.update_counter = 1;
        info.network_id = 0x12345678;
        info.total_nodes = 1;
        info.max_nodes = 2;
        // nwm keeps one slot per possible node (GenerateBeaconFrame checks it).
        Service::NWM::NodeList nodes(info.max_nodes);
        nodes[0].network_node_id = 1;
        const std::vector<u8> beacon = Service::NWM::GenerateBeaconFrame(info, nodes);
        host.SubmitBeacon(beacon, HostMac);
    }

    void StartJoiner(u8 channel) {
        joiner.Start(
            channel, JoinerMac,
            [this](UdsReal::CapturedBeacon beacon) { joiner_beacons.Push(std::move(beacon)); },
            [this](UdsReal::CapturedFrame frame) { joiner_frames.Push(std::move(frame)); });
    }

    std::optional<UdsReal::CapturedBeacon> WaitForHostBeacon(std::chrono::milliseconds timeout) {
        return joiner_beacons.WaitFor(
            [](const UdsReal::CapturedBeacon& b) {
                return b.transmitter_address == HostMac && b.wlan_comm_id == WlanCommId;
            },
            timeout);
    }

    // The joiner's authentication request, resent until the host's radio hears it (the host
    // hops between channels until a station shows up). Returns how long that took.
    std::optional<std::chrono::milliseconds> JoinerReachesHost(std::chrono::milliseconds timeout) {
        const auto started = Clock::now();
        while (Clock::now() - started < timeout) {
            joiner.SubmitFrame(Management(11, HostMac, JoinerMac, HostMac));
            if (host_frames.WaitFor(
                    [](const UdsReal::CapturedFrame& f) {
                        return f.transmitter_address == JoinerMac && f.type == 0 && f.subtype == 11;
                    },
                    100ms)) {
                return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() -
                                                                             started);
            }
        }
        return std::nullopt;
    }

    bool HostReachesJoiner(std::chrono::milliseconds timeout) {
        const auto started = Clock::now();
        while (Clock::now() - started < timeout) {
            host.SubmitFrame(Management(11, JoinerMac, HostMac, HostMac, {0, 0, 2, 0, 0, 0}));
            if (joiner_frames.WaitFor(
                    [](const UdsReal::CapturedFrame& f) {
                        return f.transmitter_address == HostMac && f.type == 0 && f.subtype == 11;
                    },
                    100ms)) {
                return true;
            }
        }
        return false;
    }

    static constexpr u32 WlanCommId = 0x00171010;

    std::shared_ptr<Air> air;
    std::array<std::shared_ptr<Board>, 2> boards;
    bool in_process{};
    std::atomic<int> opened{0};
    bool previous_setting{};
    UdsReal::Nl80211Monitor host;
    UdsReal::Nl80211Monitor joiner;
    Queue<UdsReal::CapturedFrame> host_frames;
    Queue<UdsReal::CapturedBeacon> joiner_beacons;
    Queue<UdsReal::CapturedFrame> joiner_frames;
};

} // namespace

TEST_CASE("ESP32 path on the virtual air: a joiner finds the hosted network and frames go both ways",
          "[core][nwm][virtual-air]") {
    MonitorPair pair{Conditions{}};
    pair.StartHost(11);
    pair.StartJoiner(6);

    const auto beacon = pair.WaitForHostBeacon(5s);
    REQUIRE(beacon.has_value());
    CHECK(beacon->id == 1);
    // The beacon advertises the channel the host's radio is on when it sends it.
    CHECK((beacon->channel == 1 || beacon->channel == 6 || beacon->channel == 11));
    pair.joiner.SelectPeerChannel(beacon->channel); // As nwm::UDS does when the game picks it.

    const auto reached = pair.JoinerReachesHost(5s);
    REQUIRE(reached.has_value());
    INFO("joiner's first frame heard by the host after " << reached->count() << " ms");
    // A station in the network holds the host's radio on its channel: the reply arrives at once.
    CHECK(pair.HostReachesJoiner(1s));
    CHECK(pair.boards[0]->Channel() == pair.boards[1]->Channel());
}

TEST_CASE("ESP32 path on the virtual air: still works with loss and jitter",
          "[core][nwm][virtual-air]") {
    Conditions rough;
    rough.loss = 0.2;
    rough.jitter = 5ms;
    rough.latency = 2ms;
    MonitorPair pair{rough, 11};
    pair.StartHost(6);
    pair.StartJoiner(1);

    const auto beacon = pair.WaitForHostBeacon(10s);
    REQUIRE(beacon.has_value());
    pair.joiner.SelectPeerChannel(beacon->channel);
    REQUIRE(pair.JoinerReachesHost(10s).has_value());
    CHECK(pair.HostReachesJoiner(3s));
}

// Not part of the normal run. Start azahar-virtual-air first and set AZAHAR_ESP32_PORT to it, e.g.
//   azahar-virtual-air --port 45899 --trace
//   set AZAHAR_ESP32_PORT=tcp:127.0.0.1:45899 && tests "[virtual-air-tcp]"
TEST_CASE("ESP32 path over TCP to azahar-virtual-air", "[.][virtual-air-tcp]") {
    MonitorPair pair{Conditions{}, 7, false};
    pair.StartHost(11);
    pair.StartJoiner(6);
    const auto beacon = pair.WaitForHostBeacon(10s);
    REQUIRE(beacon.has_value());
    pair.joiner.SelectPeerChannel(beacon->channel);
    const auto reached = pair.JoinerReachesHost(10s);
    REQUIRE(reached.has_value());
    CHECK(pair.HostReachesJoiner(2s));
}

// Not part of the normal run: how long two Azahar radios take to find each other from every pair
// of starting channels (the host hops 1/6/11 until a station shows up; the joiner hops until it
// hears a beacon). Prints the times; fails only if a pair never meets within 15 s.
TEST_CASE("ESP32 path on the virtual air: discovery time from every starting channel",
          "[.][virtual-air-explore]") {
    for (const u8 hosted : {u8{1}, u8{6}, u8{11}}) {
        for (const u8 joiner_start : {u8{1}, u8{6}, u8{11}}) {
            MonitorPair pair{Conditions{}, 3};
            pair.StartHost(hosted);
            const auto started = Clock::now();
            pair.StartJoiner(joiner_start);
            const auto beacon = pair.WaitForHostBeacon(15s);
            const auto found = std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now() - started);
            std::optional<std::chrono::milliseconds> reached;
            if (beacon) {
                pair.joiner.SelectPeerChannel(beacon->channel);
                reached = pair.JoinerReachesHost(15s);
            }
            WARN("host starts on " << int{hosted} << ", joiner on " << int{joiner_start}
                                   << ": beacon after " << found.count() << " ms"
                                   << (beacon ? "" : " (NEVER)") << ", first frame to the host "
                                   << (reached ? std::to_string(reached->count()) + " ms later"
                                               : std::string{"NEVER"}));
            CHECK(beacon.has_value());
            CHECK(reached.has_value());
        }
    }
}
