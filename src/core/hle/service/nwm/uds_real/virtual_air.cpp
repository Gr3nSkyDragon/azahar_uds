// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <queue>
#include <random>
#include <thread>

#include "core/hle/service/nwm/uds_real/esp32_wire.h"
#include "core/hle/service/nwm/uds_real/virtual_air.h"

namespace Service::NWM::UdsReal::VirtualAir {

namespace {

// esp_err_t values the firmware puts in Status replies.
constexpr s32 EspOk = 0;
constexpr s32 EspErrInvalidArg = 0x102;
constexpr s32 EspErrInvalidState = 0x103;
constexpr s32 EspErrInvalidSize = 0x104;
constexpr s32 EspErrNotSupported = 0x106;

constexpr std::size_t MaxMpdu = 2346;          // radio.c MAX_MPDU
constexpr std::size_t TxDoneBytes = 48;        // radio.c TXDONE_BYTES
constexpr u32 TxDoneDataReports = 30;          // radio.c: data frames reported, then only management
constexpr auto BeaconInterval = std::chrono::microseconds{102400}; // 100 TU
constexpr auto StatsInterval = std::chrono::seconds{5};            // main.c STATS_INTERVAL_US
constexpr s8 Rssi = -40;

bool MacEqual(const u8* a, const Mac& b) {
    return std::memcmp(a, b.data(), b.size()) == 0;
}

u16 FrameControl(std::span<const u8> mpdu) {
    return mpdu.size() >= 2 ? static_cast<u16>(mpdu[0] | (mpdu[1] << 8)) : 0;
}

// radio.c has_nintendo_element: a vendor element with the Nintendo OUI 00:1F:32.
bool HasNintendoElement(std::span<const u8> frame) {
    std::size_t offset = 24 + 12; // Management header + beacon fixed fields.
    while (offset + 2 <= frame.size()) {
        const u8 tag = frame[offset];
        const u8 length = frame[offset + 1];
        offset += 2;
        if (offset + length > frame.size()) {
            return false;
        }
        if (tag == 221 && length >= 4 && frame[offset] == 0x00 && frame[offset + 1] == 0x1F &&
            frame[offset + 2] == 0x32) {
            return true;
        }
        offset += length;
    }
    return false;
}

void AppendU32(std::vector<u8>& out, u32 value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<u8>(value >> (8 * i)));
    }
}

} // namespace

bool IsGroupAddressed(std::span<const u8> mpdu) {
    return mpdu.size() >= 10 && (mpdu[4] & 1) != 0;
}

std::string FormatMac(const Mac& mac) {
    char text[18];
    std::snprintf(text, sizeof(text), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2],
                  mac[3], mac[4], mac[5]);
    return text;
}

// ---- Air ------------------------------------------------------------------------------------

struct Air::Impl {
    struct Endpoint {
        Receiver receiver;
        u8 channel{};
        std::optional<Mac> ack_address;
    };

    struct Task {
        Clock::time_point when;
        u64 order{};
        std::function<void()> fn;
        bool operator>(const Task& other) const {
            return when != other.when ? when > other.when : order > other.order;
        }
    };

    mutable std::mutex mutex;
    std::condition_variable idle_cv; // A delivery finished (RemoveEndpoint waits for them).
    std::map<EndpointId, Endpoint> endpoints;
    std::map<EndpointId, int> in_flight; // Deliveries running their receiver now.
    EndpointId next_id{1};
    Conditions conditions;
    std::mt19937 rng;
    Tap tap;
    Stats stats;

    std::mutex schedule_mutex;
    std::condition_variable schedule_cv;
    std::priority_queue<Task, std::vector<Task>, std::greater<Task>> tasks;
    u64 next_order{};
    bool stopping{};
    std::thread scheduler;

    bool Chance(double probability) {
        if (probability <= 0.0) {
            return false;
        }
        return std::uniform_real_distribution<double>{0.0, 1.0}(rng) < probability;
    }

    std::chrono::microseconds Delay() {
        auto delay = conditions.latency;
        if (conditions.jitter.count() > 0) {
            delay += std::chrono::microseconds{
                std::uniform_int_distribution<s64>{0, conditions.jitter.count()}(rng)};
        }
        return delay;
    }

    void Run() {
        std::unique_lock lock{schedule_mutex};
        while (!stopping) {
            if (tasks.empty()) {
                schedule_cv.wait(lock);
                continue;
            }
            const auto when = tasks.top().when;
            if (Clock::now() < when) {
                schedule_cv.wait_until(lock, when);
                continue;
            }
            auto fn = std::move(const_cast<Task&>(tasks.top()).fn);
            tasks.pop();
            lock.unlock();
            fn();
            lock.lock();
        }
    }
};

Air::Air(Conditions conditions, u32 seed) : impl{std::make_shared<Impl>()} {
    impl->conditions = conditions;
    impl->rng.seed(seed);
    impl->scheduler = std::thread{[shared = impl] { shared->Run(); }};
}

Air::~Air() {
    {
        std::scoped_lock lock{impl->schedule_mutex};
        impl->stopping = true;
    }
    impl->schedule_cv.notify_all();
    if (!impl->scheduler.joinable()) {
        return;
    }
    if (std::this_thread::get_id() == impl->scheduler.get_id()) {
        // The last owner was a task on the scheduler thread (a board's timer): it cannot join
        // itself. It finishes that task, sees stopping and exits, releasing the Impl it holds.
        impl->scheduler.detach();
    } else {
        impl->scheduler.join();
    }
}

Air::EndpointId Air::AddEndpoint(Receiver receiver) {
    std::scoped_lock lock{impl->mutex};
    const EndpointId id = impl->next_id++;
    impl->endpoints[id] = Impl::Endpoint{std::move(receiver), 0, std::nullopt};
    return id;
}

void Air::RemoveEndpoint(EndpointId id) {
    std::unique_lock lock{impl->mutex};
    impl->endpoints.erase(id);
    // Its owner may be going away: wait for a delivery to it that is running its receiver, unless
    // that delivery is us (deliveries run on the scheduler thread).
    if (std::this_thread::get_id() != impl->scheduler.get_id()) {
        impl->idle_cv.wait(lock, [&] {
            const auto it = impl->in_flight.find(id);
            return it == impl->in_flight.end() || it->second == 0;
        });
    }
    impl->in_flight.erase(id);
}

void Air::SetChannel(EndpointId id, u8 channel) {
    std::scoped_lock lock{impl->mutex};
    if (const auto it = impl->endpoints.find(id); it != impl->endpoints.end()) {
        it->second.channel = channel;
    }
}

void Air::SetAckAddress(EndpointId id, std::optional<Mac> address) {
    std::scoped_lock lock{impl->mutex};
    if (const auto it = impl->endpoints.find(id); it != impl->endpoints.end()) {
        it->second.ack_address = address;
    }
}

void Air::SetConditions(const Conditions& conditions) {
    std::scoped_lock lock{impl->mutex};
    impl->conditions = conditions;
}

Conditions Air::GetConditions() const {
    std::scoped_lock lock{impl->mutex};
    return impl->conditions;
}

void Air::SetTap(Tap tap) {
    std::scoped_lock lock{impl->mutex};
    impl->tap = std::move(tap);
}

Air::Stats Air::GetStats() const {
    std::scoped_lock lock{impl->mutex};
    return impl->stats;
}

void Air::Schedule(Clock::time_point when, std::function<void()> fn) {
    {
        std::scoped_lock lock{impl->schedule_mutex};
        impl->tasks.push(Impl::Task{when, impl->next_order++, std::move(fn)});
    }
    impl->schedule_cv.notify_all();
}

bool Air::Transmit(EndpointId from, std::span<const u8> mpdu) {
    if (mpdu.size() < 10) {
        return false;
    }
    struct Delivery {
        EndpointId to;
        Clock::time_point when;
    };
    std::vector<std::pair<std::vector<u8>, std::vector<Delivery>>> attempts;
    Tap tap;
    bool acked = false;
    u8 channel = 0;
    {
        std::scoped_lock lock{impl->mutex};
        const auto sender = impl->endpoints.find(from);
        if (sender == impl->endpoints.end() || sender->second.channel == 0) {
            return false;
        }
        channel = sender->second.channel;
        tap = impl->tap;
        const bool group = IsGroupAddressed(mpdu);
        const int tries = group ? 1 : 1 + std::max(impl->conditions.unacked_retries, 0);
        const auto now = Clock::now();
        for (int attempt = 0; attempt < tries && !acked; ++attempt) {
            std::vector<u8> frame{mpdu.begin(), mpdu.end()};
            if (attempt > 0) {
                frame[1] = static_cast<u8>(frame[1] | 0x08); // Retry.
                ++impl->stats.retries;
            }
            ++impl->stats.transmissions;
            std::vector<Delivery> deliveries;
            for (const auto& [id, endpoint] : impl->endpoints) {
                if (id == from || endpoint.channel != channel) {
                    continue;
                }
                if (impl->Chance(impl->conditions.loss)) {
                    ++impl->stats.lost;
                    continue;
                }
                deliveries.push_back({id, now + impl->Delay()});
                if (impl->Chance(impl->conditions.duplicate)) {
                    deliveries.push_back({id, now + impl->Delay() + std::chrono::microseconds{50}});
                }
                if (!group && endpoint.ack_address && MacEqual(frame.data() + 4, *endpoint.ack_address) &&
                    !impl->Chance(impl->conditions.loss)) {
                    acked = true;
                }
            }
            attempts.emplace_back(std::move(frame), std::move(deliveries));
        }
        if (acked) {
            ++impl->stats.acked;
        }
    }

    for (std::size_t index = 0; index < attempts.size(); ++index) {
        auto& [frame, deliveries] = attempts[index];
        if (tap) {
            tap(from, channel, frame, acked && index + 1 == attempts.size());
        }
        for (const Delivery& delivery : deliveries) {
            AirFrame air_frame{channel, Rssi, frame};
            std::weak_ptr<Impl> weak = impl;
            Schedule(delivery.when, [weak, to = delivery.to, air_frame = std::move(air_frame)] {
                const auto air_impl = weak.lock();
                if (!air_impl) {
                    return;
                }
                Receiver receiver;
                {
                    std::scoped_lock lock{air_impl->mutex};
                    const auto it = air_impl->endpoints.find(to);
                    // A radio that tuned away before the frame arrived misses it.
                    if (it == air_impl->endpoints.end() || it->second.channel != air_frame.channel) {
                        return;
                    }
                    receiver = it->second.receiver;
                    ++air_impl->stats.deliveries;
                    ++air_impl->in_flight[to];
                }
                if (receiver) {
                    receiver(air_frame);
                }
                {
                    std::scoped_lock lock{air_impl->mutex};
                    if (const auto it = air_impl->in_flight.find(to);
                        it != air_impl->in_flight.end()) {
                        --it->second;
                    }
                }
                air_impl->idle_cv.notify_all();
            });
        }
    }
    return acked;
}

// ---- Board ----------------------------------------------------------------------------------

struct Board::Impl {
    std::shared_ptr<Air> air;
    Air::EndpointId endpoint{};
    u8 index{};
    Mac factory_address{};
    Clock::time_point created = Clock::now();

    mutable std::mutex mutex;
    HostSink sink;
    Esp32::Decoder decoder;

    bool running{};
    u8 channel{1};
    Mac own_address{};
    bool watch_set{};
    Mac watch_address{};
    std::vector<u8> beacon;
    u16 beacon_sequence{};
    u64 timer_generation{};
    u32 txdone_data_reports{};
    Esp32::DeviceStats stats{};

    void Send(Esp32::Type type, u8 seq, std::span<const u8> payload) {
        if (!sink) {
            return;
        }
        const std::vector<u8> encoded = Esp32::Encode(type, seq, 0, payload);
        if (!encoded.empty()) {
            sink(encoded);
        }
    }

    void SendStatus(Esp32::Type request, u8 seq, s32 result) {
        std::vector<u8> payload{static_cast<u8>(request)};
        AppendU32(payload, static_cast<u32>(result));
        Send(Esp32::Type::Status, seq, payload);
    }

    // radio.c wanted(): what is worth the USB bandwidth.
    bool Wanted(std::span<const u8> frame) const {
        const u16 frame_control = FrameControl(frame);
        const int type = (frame_control >> 2) & 3;
        const int subtype = (frame_control >> 4) & 0xF;
        if (type == 0 && subtype == 8) {
            return HasNintendoElement(frame);
        }
        if (type == 0 && (subtype == 4 || subtype == 5)) {
            return false;
        }
        if (type == 1) {
            return false;
        }
        const u8* a1 = frame.data() + 4;
        const u8* a2 = frame.data() + 10;
        const u8* a3 = frame.data() + 16;
        if (MacEqual(a1, own_address) || MacEqual(a2, own_address) || MacEqual(a3, own_address)) {
            return true;
        }
        return watch_set && (MacEqual(a1, watch_address) || MacEqual(a2, watch_address) ||
                             MacEqual(a3, watch_address));
    }

    void Stop() {
        running = false;
        beacon.clear();
        ++timer_generation;
        air->SetChannel(endpoint, 0);
        air->SetAckAddress(endpoint, std::nullopt);
    }
};

std::shared_ptr<Board> Board::Create(std::shared_ptr<Air> air, u8 index) {
    std::shared_ptr<Board> board{new Board(std::move(air), index)};
    std::weak_ptr<Board> weak = board;
    board->impl->endpoint = board->impl->air->AddEndpoint([weak](const AirFrame& frame) {
        const auto self = weak.lock();
        if (!self) {
            return;
        }
        auto& impl = *self->impl;
        std::scoped_lock lock{impl.mutex};
        if (!impl.running) {
            return;
        }
        ++impl.stats.rx_seen;
        if (frame.mpdu.size() < 24 || !impl.Wanted(frame.mpdu)) {
            return;
        }
        std::vector<u8> event{frame.channel, static_cast<u8>(frame.rssi), 0};
        const std::size_t length = std::min(frame.mpdu.size(), MaxMpdu);
        event.insert(event.end(), frame.mpdu.begin(),
                     frame.mpdu.begin() + static_cast<std::ptrdiff_t>(length));
        if (impl.sink) {
            ++impl.stats.rx_forwarded;
            impl.Send(Esp32::Type::Rx, 0, event);
        } else {
            ++impl.stats.rx_dropped;
        }
    });

    // Stats every 5 s, as the firmware's stats_task.
    struct StatsTick {
        static void Arm(std::weak_ptr<Board> weak_board, Clock::time_point when) {
            const auto self = weak_board.lock();
            if (!self) {
                return;
            }
            self->impl->air->Schedule(when, [weak_board, when] {
                const auto board_now = weak_board.lock();
                if (!board_now) {
                    return;
                }
                {
                    auto& impl = *board_now->impl;
                    std::scoped_lock lock{impl.mutex};
                    std::vector<u8> payload;
                    for (const u32 value :
                         {impl.stats.rx_seen, impl.stats.rx_forwarded, impl.stats.rx_dropped,
                          impl.stats.tx_ok, impl.stats.tx_failed, impl.stats.beacons_sent,
                          impl.stats.usb_dropped, impl.stats.tx_unicast, impl.stats.acks_rx}) {
                        AppendU32(payload, value);
                    }
                    impl.Send(Esp32::Type::Stats, 0, payload);
                }
                Arm(weak_board, when + StatsInterval);
            });
        }
    };
    StatsTick::Arm(board, Clock::now() + StatsInterval);
    return board;
}

Board::Board(std::shared_ptr<Air> air, u8 index) : impl{std::make_unique<Impl>()} {
    impl->air = std::move(air);
    impl->index = index;
    // A locally administered factory address, so a virtual board is never mistaken for a chip.
    impl->factory_address = {0x02, 0x56, 0x41, 0x49, 0x52, index};
}

Board::~Board() {
    impl->air->RemoveEndpoint(impl->endpoint);
}

void Board::Attach(HostSink sink) {
    std::scoped_lock lock{impl->mutex};
    impl->sink = std::move(sink);
    impl->decoder = Esp32::Decoder{};
    // Opening the native USB port resets the chip: the radio comes back stopped.
    if (impl->running) {
        impl->Stop();
    }
}

void Board::Detach() {
    std::scoped_lock lock{impl->mutex};
    impl->sink = nullptr;
}

bool Board::Running() const {
    std::scoped_lock lock{impl->mutex};
    return impl->running;
}

u8 Board::Channel() const {
    std::scoped_lock lock{impl->mutex};
    return impl->channel;
}

Mac Board::OwnAddress() const {
    std::scoped_lock lock{impl->mutex};
    return impl->own_address;
}

Mac Board::FactoryAddress() const {
    return impl->factory_address;
}

Air::EndpointId Board::Endpoint() const {
    return impl->endpoint;
}

void Board::FromHost(std::span<const u8> bytes) {
    std::scoped_lock lock{impl->mutex};
    impl->decoder.Feed(bytes, [this](Esp32::Frame&& frame) {
        auto& b = *impl;
        const std::span<const u8> p{frame.payload};
        const std::size_t n = p.size();
        s32 result = EspOk;
        switch (frame.type) {
        case Esp32::Type::Hello: {
            std::vector<u8> payload{Esp32::WireVersion, FirmwareMajor, FirmwareMinor};
            payload.insert(payload.end(), b.factory_address.begin(), b.factory_address.end());
            payload.push_back(0); // Features: no link port.
            b.Send(Esp32::Type::HelloAck, frame.seq, payload);
            return;
        }
        case Esp32::Type::Start: {
            // {channel, mac[6]} plus an optional flags byte: bit 0 = twin hardware MAC.
            if (n != 7 && n != 8) {
                result = EspErrInvalidSize;
                break;
            }
            const u8 channel = p[0];
            if (channel < 1 || channel > 13 || (p[1] & 1) != 0) {
                result = EspErrInvalidArg;
                break;
            }
            std::copy(p.begin() + 1, p.begin() + 7, b.own_address.begin());
            Mac hardware = b.own_address;
            if (n == 8 && (p[7] & 1) != 0) {
                hardware[0] = static_cast<u8>(hardware[0] ^ 0x02);
            }
            b.stats = {};
            b.txdone_data_reports = 0;
            b.running = true;
            b.channel = channel;
            b.air->SetChannel(b.endpoint, channel);
            b.air->SetAckAddress(b.endpoint, hardware);
            const u64 generation = ++b.timer_generation;
            struct BeaconTick {
                static void Arm(std::weak_ptr<Board> weak_board, u64 gen, Clock::time_point when) {
                    const auto self = weak_board.lock();
                    if (!self) {
                        return;
                    }
                    self->impl->air->Schedule(when, [weak_board, gen, when] {
                        const auto board_now = weak_board.lock();
                        if (!board_now) {
                            return;
                        }
                        {
                            auto& impl = *board_now->impl;
                            std::scoped_lock tick_lock{impl.mutex};
                            if (impl.timer_generation != gen) {
                                return; // Stopped or restarted.
                            }
                            if (impl.running && impl.beacon.size() >= 36) {
                                const u64 timestamp = static_cast<u64>(
                                    std::chrono::duration_cast<std::chrono::microseconds>(
                                        Clock::now() - impl.created)
                                        .count());
                                for (int i = 0; i < 8; ++i) {
                                    impl.beacon[24 + i] = static_cast<u8>(timestamp >> (8 * i));
                                }
                                const u16 sequence_control =
                                    static_cast<u16>((impl.beacon_sequence++ & 0x0FFF) << 4);
                                impl.beacon[22] = static_cast<u8>(sequence_control);
                                impl.beacon[23] = static_cast<u8>(sequence_control >> 8);
                                ++impl.stats.tx_ok;
                                ++impl.stats.beacons_sent;
                                impl.air->Transmit(impl.endpoint, impl.beacon);
                            }
                        }
                        Arm(weak_board, gen, when + BeaconInterval);
                    });
                }
            };
            BeaconTick::Arm(weak_from_this(), generation, Clock::now() + BeaconInterval);
            break;
        }
        case Esp32::Type::Stop:
            b.Stop();
            break;
        case Esp32::Type::SetChannel:
            if (n != 1) {
                result = EspErrInvalidSize;
            } else if (!b.running) {
                result = EspErrInvalidState;
            } else if (p[0] < 1 || p[0] > 13) {
                result = EspErrInvalidArg;
            } else {
                b.channel = p[0];
                b.air->SetChannel(b.endpoint, p[0]);
            }
            break;
        case Esp32::Type::TxFrame: {
            // {tx_flags, rate500k, mpdu...}. Fire and forget: no Status.
            if (n < 2 + 10 || !b.running) {
                return;
            }
            const std::span<const u8> mpdu = p.subspan(2);
            if (mpdu.size() > MaxMpdu) {
                return;
            }
            ++b.stats.tx_ok;
            const bool unicast = !IsGroupAddressed(mpdu);
            if (unicast) {
                ++b.stats.tx_unicast;
            }
            const bool acked = b.air->Transmit(b.endpoint, mpdu);
            if (acked) {
                ++b.stats.acks_rx;
            }
            // radio.c tx_done: unicast only; management always, data for the first few.
            if (!unicast || mpdu.size() < 24) {
                return;
            }
            const int type = (FrameControl(mpdu) >> 2) & 3;
            if (type == 2) {
                if (b.txdone_data_reports >= TxDoneDataReports) {
                    return;
                }
                ++b.txdone_data_reports;
            } else if (type != 0) {
                return;
            }
            std::vector<u8> event{static_cast<u8>(acked ? 1 : 0), static_cast<u8>(mpdu.size()),
                                  static_cast<u8>(mpdu.size() >> 8)};
            const std::size_t copy = std::min(mpdu.size(), TxDoneBytes);
            event.insert(event.end(), mpdu.begin(),
                         mpdu.begin() + static_cast<std::ptrdiff_t>(copy));
            b.Send(Esp32::Type::TxDone, 0, event);
            return;
        }
        case Esp32::Type::SetBeacon:
            if (n > MaxMpdu || (n != 0 && n < 36)) {
                result = EspErrInvalidSize;
            } else {
                b.beacon.assign(p.begin(), p.end());
            }
            break;
        case Esp32::Type::SetWatch:
            if (n == 6) {
                std::copy(p.begin(), p.end(), b.watch_address.begin());
                b.watch_set = b.watch_address != Mac{};
            } else {
                result = EspErrInvalidSize;
            }
            break;
        case Esp32::Type::Ping:
            b.Send(Esp32::Type::Pong, frame.seq, p);
            return;
        default:
            result = EspErrNotSupported;
            break;
        }
        b.SendStatus(frame.type, frame.seq, result);
    });
}

// ---- BoardSerialPort ------------------------------------------------------------------------

struct BoardSerialPort::Pipe {
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<u8> bytes;
    bool closed{};
};

BoardSerialPort::BoardSerialPort(std::shared_ptr<Board> board_)
    : pipe{std::make_shared<Pipe>()}, board{std::move(board_)} {
    std::weak_ptr<Pipe> weak = pipe;
    board->Attach([weak](std::span<const u8> data) {
        const auto p = weak.lock();
        if (!p) {
            return;
        }
        {
            std::scoped_lock lock{p->mutex};
            p->bytes.insert(p->bytes.end(), data.begin(), data.end());
        }
        p->cv.notify_all();
    });
}

BoardSerialPort::~BoardSerialPort() {
    board->Detach();
}

void BoardSerialPort::Unplug() {
    {
        std::scoped_lock lock{pipe->mutex};
        pipe->closed = true;
    }
    pipe->cv.notify_all();
}

int BoardSerialPort::Read(std::span<u8> buffer, int timeout_ms) {
    std::unique_lock lock{pipe->mutex};
    pipe->cv.wait_for(lock, std::chrono::milliseconds{std::max(timeout_ms, 0)},
                      [this] { return pipe->closed || !pipe->bytes.empty(); });
    if (pipe->closed) {
        return -1;
    }
    const std::size_t count = std::min(buffer.size(), pipe->bytes.size());
    std::copy_n(pipe->bytes.begin(), count, buffer.begin());
    pipe->bytes.erase(pipe->bytes.begin(), pipe->bytes.begin() + static_cast<std::ptrdiff_t>(count));
    return static_cast<int>(count);
}

bool BoardSerialPort::Write(std::span<const u8> data) {
    {
        std::scoped_lock lock{pipe->mutex};
        if (pipe->closed) {
            return false;
        }
    }
    board->FromHost(data);
    return true;
}

} // namespace Service::NWM::UdsReal::VirtualAir
