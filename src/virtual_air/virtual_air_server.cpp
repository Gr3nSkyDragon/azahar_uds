// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

// azahar-virtual-air: virtual ESP32 boards on one virtual air, over TCP. Every connection is one
// board (the byte stream a USB serial port would carry), so two emulators started with
// AZAHAR_ESP32_PORT=tcp:127.0.0.1:<port> talk to each other through the ESP32 code path with no
// hardware. The air can delay, jitter, drop and duplicate frames, and --trace prints what goes
// over it.

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketHandle = SOCKET;
constexpr SocketHandle NoSocket = INVALID_SOCKET;
static void CloseSocket(SocketHandle s) {
    closesocket(s);
}
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
constexpr SocketHandle NoSocket = -1;
static void CloseSocket(SocketHandle s) {
    close(s);
}
#endif

#include "core/hle/service/nwm/uds_real/virtual_air.h"

using namespace Service::NWM::UdsReal::VirtualAir;

namespace {

struct Options {
    int port = 45800;
    bool any_address = false;
    Conditions conditions;
    unsigned seed = 1;
    bool trace = false;
    bool trace_beacons = false;
    int summary_seconds = 10;
};

const auto start_time = Clock::now();
std::mutex print_mutex;

double Seconds() {
    return std::chrono::duration<double>(Clock::now() - start_time).count();
}

template <typename... Args>
void Print(const char* format, Args... args) {
    std::scoped_lock lock{print_mutex};
    std::printf("[%9.3f] ", Seconds());
    std::printf(format, args...);
    std::printf("\n");
    std::fflush(stdout);
}

void Usage() {
    std::printf(
        "azahar-virtual-air: virtual ESP32 boards on a virtual air, for UDS tests without hardware.\n"
        "\n"
        "Start it, then start each emulator with AZAHAR_ESP32_PORT=tcp:127.0.0.1:<port> and the\n"
        "ESP32 radio enabled in its network settings. Every connection is one board.\n"
        "\n"
        "  --port N           TCP port (default 45800)\n"
        "  --any              listen on every interface, not only 127.0.0.1\n"
        "  --latency-ms X     one-way delay (default 0.3)\n"
        "  --jitter-ms X      up to this much extra delay (default 0)\n"
        "  --loss P           chance a receiver misses a frame or its ACK, 0..1 (default 0)\n"
        "  --duplicate P      chance a receiver gets a frame twice, 0..1 (default 0)\n"
        "  --retries N        retransmissions of an unacknowledged unicast frame (default 2)\n"
        "  --seed N           random seed for loss and jitter (default 1)\n"
        "  --trace            print every frame on the air (beacons only when they change)\n"
        "  --trace-beacons    with --trace, print every beacon too\n"
        "  --summary S        print the air's counters every S seconds, 0 = never (default 10)\n");
}

bool ParseOptions(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const auto value = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        const auto micros = [](const char* text) {
            return std::chrono::microseconds{static_cast<long long>(std::atof(text) * 1000.0)};
        };
        const char* v = nullptr;
        if (arg == "--help" || arg == "-h") {
            Usage();
            std::exit(0);
        } else if (arg == "--any") {
            options.any_address = true;
        } else if (arg == "--trace") {
            options.trace = true;
        } else if (arg == "--trace-beacons") {
            options.trace_beacons = true;
        } else if ((v = (arg == "--port" ? value() : nullptr))) {
            options.port = std::atoi(v);
        } else if ((v = (arg == "--latency-ms" ? value() : nullptr))) {
            options.conditions.latency = micros(v);
        } else if ((v = (arg == "--jitter-ms" ? value() : nullptr))) {
            options.conditions.jitter = micros(v);
        } else if ((v = (arg == "--loss" ? value() : nullptr))) {
            options.conditions.loss = std::atof(v);
        } else if ((v = (arg == "--duplicate" ? value() : nullptr))) {
            options.conditions.duplicate = std::atof(v);
        } else if ((v = (arg == "--retries" ? value() : nullptr))) {
            options.conditions.unacked_retries = std::atoi(v);
        } else if ((v = (arg == "--seed" ? value() : nullptr))) {
            options.seed = static_cast<unsigned>(std::strtoul(v, nullptr, 10));
        } else if ((v = (arg == "--summary" ? value() : nullptr))) {
            options.summary_seconds = std::atoi(v);
        } else {
            std::fprintf(stderr, "unknown or incomplete option: %s\n\n", arg.c_str());
            Usage();
            return false;
        }
    }
    return true;
}

const char* FrameName(int type, int subtype) {
    if (type == 0) {
        switch (subtype) {
        case 0: return "assoc-req";
        case 1: return "assoc-resp";
        case 4: return "probe-req";
        case 5: return "probe-resp";
        case 8: return "beacon";
        case 10: return "disassoc";
        case 11: return "auth";
        case 12: return "deauth";
        case 13: return "action";
        default: return "mgmt";
        }
    }
    if (type == 1) {
        return "control";
    }
    if (type == 2) {
        return "data";
    }
    return "other";
}

Mac AddressAt(std::span<const u8> mpdu, std::size_t offset) {
    Mac mac{};
    if (mpdu.size() >= offset + 6) {
        std::memcpy(mac.data(), mpdu.data() + offset, 6);
    }
    return mac;
}

struct Server {
    Options options;
    std::shared_ptr<Air> air;
    std::mutex boards_mutex;
    std::map<Air::EndpointId, std::pair<int, std::weak_ptr<Board>>> boards; // endpoint -> number
    std::map<Air::EndpointId, std::vector<u8>> last_beacon;                 // under boards_mutex
    std::atomic<int> next_board{1};

    int BoardNumber(Air::EndpointId id) {
        std::scoped_lock lock{boards_mutex};
        const auto it = boards.find(id);
        return it == boards.end() ? 0 : it->second.first;
    }

    void OnTransmit(Air::EndpointId from, u8 channel, std::span<const u8> mpdu, bool acked) {
        if (!options.trace || mpdu.size() < 24) {
            return;
        }
        const u16 frame_control = static_cast<u16>(mpdu[0] | (mpdu[1] << 8));
        const int type = (frame_control >> 2) & 3;
        const int subtype = (frame_control >> 4) & 0xF;
        if (type == 0 && subtype == 8 && !options.trace_beacons && mpdu.size() >= 36) {
            // Only a beacon whose content changed (past the timestamp and sequence number).
            std::vector<u8> body(mpdu.begin() + 32, mpdu.end());
            std::scoped_lock lock{boards_mutex};
            auto& last = last_beacon[from];
            if (last == body) {
                return;
            }
            last = std::move(body);
        }
        const bool group = IsGroupAddressed(mpdu);
        const u16 sequence = static_cast<u16>((mpdu[22] | (mpdu[23] << 8)) >> 4);
        Print("board%d ch%u %-10s %s%s%s a1=%s a2=%s a3=%s seq=%u len=%u%s", BoardNumber(from),
              static_cast<unsigned>(channel), FrameName(type, subtype),
              (frame_control & 0x4000) ? "protected " : "", (frame_control & 0x0800) ? "retry " : "",
              group ? "group" : (acked ? "acked" : "NOT-ACKED"),
              FormatMac(AddressAt(mpdu, 4)).c_str(), FormatMac(AddressAt(mpdu, 10)).c_str(),
              FormatMac(AddressAt(mpdu, 16)).c_str(), static_cast<unsigned>(sequence),
              static_cast<unsigned>(mpdu.size()), type == 0 && subtype == 8 ? " (changed)" : "");
    }

    void Serve(SocketHandle client) {
        const int number = next_board++;
        const auto board = Board::Create(air, static_cast<u8>(number));
        {
            std::scoped_lock lock{boards_mutex};
            boards[board->Endpoint()] = {number, board};
        }
        Print("board%d: connected (factory MAC %s)", number,
              FormatMac(board->FactoryAddress()).c_str());
        std::mutex send_mutex;
        board->Attach([&](std::span<const u8> bytes) {
            std::scoped_lock lock{send_mutex};
            std::size_t sent = 0;
            while (sent < bytes.size()) {
                const int count = static_cast<int>(
                    send(client, reinterpret_cast<const char*>(bytes.data() + sent),
                         static_cast<int>(bytes.size() - sent), 0));
                if (count <= 0) {
                    return;
                }
                sent += static_cast<std::size_t>(count);
            }
        });
        bool was_running = false;
        u8 last_channel = 0;
        std::vector<u8> buffer(16384);
        for (;;) {
            const int count = static_cast<int>(
                recv(client, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0));
            if (count <= 0) {
                break;
            }
            board->FromHost(std::span<const u8>{buffer.data(), static_cast<std::size_t>(count)});
            const bool running = board->Running();
            const u8 channel = board->Channel();
            if (running != was_running || (running && channel != last_channel)) {
                if (running) {
                    Print("board%d: radio on channel %u, MAC %s", number,
                          static_cast<unsigned>(channel), FormatMac(board->OwnAddress()).c_str());
                } else {
                    Print("board%d: radio stopped", number);
                }
                was_running = running;
                last_channel = channel;
            }
        }
        board->Detach();
        CloseSocket(client);
        {
            std::scoped_lock lock{boards_mutex};
            boards.erase(board->Endpoint());
            last_beacon.erase(board->Endpoint());
        }
        Print("board%d: disconnected", number);
    }
};

} // namespace

int main(int argc, char** argv) {
    Options options;
    if (!ParseOptions(argc, argv, options)) {
        return 2;
    }
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    Server server;
    server.options = options;
    server.air = std::make_shared<Air>(options.conditions, options.seed);
    server.air->SetTap([&server](Air::EndpointId from, u8 channel, std::span<const u8> mpdu,
                                 bool acked) { server.OnTransmit(from, channel, mpdu, acked); });

    const SocketHandle listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == NoSocket) {
        std::fprintf(stderr, "cannot create a socket\n");
        return 1;
    }
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
               sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<u16>(options.port));
    address.sin_addr.s_addr = htonl(options.any_address ? INADDR_ANY : INADDR_LOOPBACK);
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(listener, 8) != 0) {
        std::fprintf(stderr, "cannot listen on port %d (already in use?)\n", options.port);
        return 1;
    }
    Print("virtual air on %s:%d: latency %.1f ms, jitter %.1f ms, loss %.3f, duplicate %.3f, "
          "retries %d, seed %u",
          options.any_address ? "0.0.0.0" : "127.0.0.1", options.port,
          static_cast<double>(options.conditions.latency.count()) / 1000.0,
          static_cast<double>(options.conditions.jitter.count()) / 1000.0, options.conditions.loss,
          options.conditions.duplicate, options.conditions.unacked_retries, options.seed);
    Print("start each emulator with AZAHAR_ESP32_PORT=tcp:127.0.0.1:%d", options.port);

    if (options.summary_seconds > 0) {
        std::thread{[&server] {
            for (;;) {
                std::this_thread::sleep_for(std::chrono::seconds{server.options.summary_seconds});
                const auto stats = server.air->GetStats();
                Print("air: %llu transmissions (%llu retries), %llu deliveries, %llu lost, %llu acked",
                      static_cast<unsigned long long>(stats.transmissions),
                      static_cast<unsigned long long>(stats.retries),
                      static_cast<unsigned long long>(stats.deliveries),
                      static_cast<unsigned long long>(stats.lost),
                      static_cast<unsigned long long>(stats.acked));
            }
        }}.detach();
    }

    for (;;) {
        const SocketHandle client = accept(listener, nullptr, nullptr);
        if (client == NoSocket) {
            continue;
        }
        int no_delay = 1;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&no_delay),
                   sizeof(no_delay));
        std::thread{[&server, client] { server.Serve(client); }}.detach();
    }
}
