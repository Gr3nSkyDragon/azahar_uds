// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include "common/common_types.h"
#include "network/room_member.h"

namespace Service::NWM {

/// A localhost UDP link that carries nwm::UDS WifiPackets to and from another program (the mGBA
/// Virtual Console wrapper) instead of a radio. Nothing is encrypted: the packets are the same
/// plaintext room-multiplayer representation that SendPacket hands to the room and that
/// OnWifiPacketReceived accepts, so a joiner on the other end sees a hosted network without any
/// 802.11 or CCMP work.
///
/// Enabled by the "Local mGBA Virtual Console" entry of the Multiplayer menu (the use_mgba_vc_bridge
/// setting), which selects the default ports, or by the environment variable AZAHAR_UDS_BRIDGE, which
/// takes precedence: "1" selects the default ports, a number N makes Azahar listen on N and send to
/// N + 1 (the other program does the reverse; mGBA's default is the same pair). Either is read when a
/// game starts.
///
/// One datagram is one packet:
///   0..3   'U' 'D' 'S' 'B'
///   4      version (1)
///   5      WifiPacket::PacketType
///   6      channel
///   7      reserved (0)
///   8..13  transmitter MAC
///   14..19 destination MAC
///   20..   WifiPacket::data
class UdsBridge {
public:
    static constexpr u16 DefaultListenPort = 45710;
    static constexpr std::size_t HeaderSize = 20;

    /// Returns a bridge when AZAHAR_UDS_BRIDGE or the use_mgba_vc_bridge setting asks for one, else
    /// nullptr.
    static std::unique_ptr<UdsBridge> CreateFromConfiguration(
        std::function<void(const Network::WifiPacket&)> on_packet);

    UdsBridge(u16 listen_port, u16 send_port,
              std::function<void(const Network::WifiPacket&)> on_packet);
    ~UdsBridge();

    bool IsRunning() const;

    void Send(const Network::WifiPacket& packet);

private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Service::NWM
