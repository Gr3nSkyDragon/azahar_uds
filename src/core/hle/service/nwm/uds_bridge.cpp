// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#include <array>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <thread>
#include <vector>
#include <boost/asio.hpp>
#include "common/logging/log.h"
#include "common/settings.h"
#include "core/hle/service/nwm/uds_bridge.h"

namespace Service::NWM {

namespace {
constexpr std::array<u8, 4> Magic{'U', 'D', 'S', 'B'};
constexpr u8 Version = 1;
constexpr std::size_t MaxDatagram = 4096;
// Packets logged in full detail before the log goes quiet (the link can carry thousands).
constexpr std::size_t LoggedPackets = 60;
} // namespace

class UdsBridge::Impl {
public:
    Impl(u16 listen_port, u16 send_port, std::function<void(const Network::WifiPacket&)> callback)
        : on_packet(std::move(callback)),
          target(boost::asio::ip::address_v4::loopback(), send_port) {
        boost::system::error_code error;
        socket.open(boost::asio::ip::udp::v4(), error);
        if (!error) {
            socket.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(),
                                                       listen_port),
                        error);
        }
        if (error) {
            LOG_ERROR(Service_NWM, "UDS bridge: cannot listen on 127.0.0.1:{}: {}", listen_port,
                      error.message());
            return;
        }
        running = true;
        LOG_INFO(Service_NWM, "UDS bridge: listening on 127.0.0.1:{}, sending to 127.0.0.1:{}",
                 listen_port, send_port);
        StartReceive();
        worker = std::thread([this] { io_context.run(); });
    }

    ~Impl() {
        running = false;
        io_context.stop();
        if (worker.joinable()) {
            worker.join();
        }
    }

    bool IsRunning() const {
        return running;
    }

    void Send(const Network::WifiPacket& packet) {
        if (!running) {
            return;
        }
        std::vector<u8> datagram(HeaderSize + packet.data.size());
        std::memcpy(datagram.data(), Magic.data(), Magic.size());
        datagram[4] = Version;
        datagram[5] = static_cast<u8>(packet.type);
        datagram[6] = packet.channel;
        datagram[7] = 0;
        std::memcpy(datagram.data() + 8, packet.transmitter_address.data(), 6);
        std::memcpy(datagram.data() + 14, packet.destination_address.data(), 6);
        if (!packet.data.empty()) {
            std::memcpy(datagram.data() + HeaderSize, packet.data.data(), packet.data.size());
        }
        if (datagram.size() > MaxDatagram) {
            LOG_WARNING(Service_NWM, "UDS bridge: dropped an oversized packet ({} bytes)",
                        datagram.size());
            return;
        }

        boost::system::error_code error;
        socket.send_to(boost::asio::buffer(datagram), target, 0, error);
        const std::size_t number = sent++;
        if (error) {
            // Nobody listening on the other side is normal until mGBA starts.
            if (number < LoggedPackets) {
                LOG_INFO(Service_NWM, "UDS bridge: send failed (no listener yet?): {}",
                         error.message());
            }
        } else if (number < LoggedPackets) {
            LOG_INFO(Service_NWM, "UDS bridge: sent #{} type={} channel={} bytes={}", number,
                     static_cast<u32>(packet.type), packet.channel, packet.data.size());
        }
    }

private:
    void StartReceive() {
        socket.async_receive_from(boost::asio::buffer(buffer), remote,
                                  [this](const boost::system::error_code& error, std::size_t size) {
                                      HandleReceive(error, size);
                                  });
    }

    void HandleReceive(const boost::system::error_code& error, std::size_t size) {
        if (error == boost::asio::error::operation_aborted) {
            return;
        }
        // On Windows an earlier send to a port nobody listens on comes back here as a connection
        // reset; it is not a problem with the next datagram, so carry on.
        if (!error) {
            Dispatch(size);
        }
        StartReceive();
    }

    void Dispatch(std::size_t size) {
        if (size < HeaderSize || std::memcmp(buffer.data(), Magic.data(), Magic.size()) != 0 ||
            buffer[4] != Version) {
            LOG_WARNING(Service_NWM, "UDS bridge: ignored a datagram of {} bytes", size);
            return;
        }
        Network::WifiPacket packet{};
        packet.type = static_cast<Network::WifiPacket::PacketType>(buffer[5]);
        packet.channel = buffer[6];
        std::memcpy(packet.transmitter_address.data(), buffer.data() + 8, 6);
        std::memcpy(packet.destination_address.data(), buffer.data() + 14, 6);
        packet.data.assign(buffer.begin() + HeaderSize, buffer.begin() + size);

        const std::size_t number = received++;
        if (number < LoggedPackets) {
            LOG_INFO(Service_NWM, "UDS bridge: received #{} type={} channel={} bytes={}", number,
                     static_cast<u32>(packet.type), packet.channel, packet.data.size());
        }
        on_packet(packet);
    }

    std::function<void(const Network::WifiPacket&)> on_packet;
    boost::asio::io_context io_context;
    boost::asio::ip::udp::socket socket{io_context};
    boost::asio::ip::udp::endpoint target;
    boost::asio::ip::udp::endpoint remote;
    std::array<u8, MaxDatagram> buffer{};
    std::thread worker;
    std::atomic<bool> running{false};
    std::atomic<std::size_t> sent{0};
    std::atomic<std::size_t> received{0};
};

std::unique_ptr<UdsBridge> UdsBridge::CreateFromConfiguration(
    std::function<void(const Network::WifiPacket&)> on_packet) {
    // The environment variable, when set, wins (it can also move the ports); otherwise the menu setting.
    unsigned long port = DefaultListenPort;
    const char* value = std::getenv("AZAHAR_UDS_BRIDGE");
    if (value && *value) {
        if (std::string_view{value} == "0") {
            return nullptr;
        }
        port = std::strtoul(value, nullptr, 0);
        if (port <= 1 || port >= 65535) {
            port = DefaultListenPort;
        }
    } else if (!Settings::values.use_mgba_vc_bridge.GetValue()) {
        return nullptr;
    }
    return std::make_unique<UdsBridge>(static_cast<u16>(port), static_cast<u16>(port + 1),
                                       std::move(on_packet));
}

UdsBridge::UdsBridge(u16 listen_port, u16 send_port,
                     std::function<void(const Network::WifiPacket&)> on_packet)
    : impl(std::make_unique<Impl>(listen_port, send_port, std::move(on_packet))) {}

UdsBridge::~UdsBridge() = default;

bool UdsBridge::IsRunning() const {
    return impl->IsRunning();
}

void UdsBridge::Send(const Network::WifiPacket& packet) {
    impl->Send(packet);
}

} // namespace Service::NWM
