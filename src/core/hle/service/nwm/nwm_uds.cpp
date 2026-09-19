// Copyright 2014-2026 Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <cstring>
#include <fstream>
#include <string>
#include <boost/serialization/list.hpp>
#include <boost/serialization/map.hpp>
#include <cryptopp/osrng.h>
#include "common/archives.h"
#include "common/common_types.h"
#include "common/file_util.h"
#include "common/hacks/hack_manager.h"
#include "common/logging/log.h"
#include "common/settings.h"
#include "core/core.h"
#include "core/core_timing.h"
#include "core/hle/ipc_helpers.h"
#include "core/hle/kernel/event.h"
#include "core/hle/kernel/shared_memory.h"
#include "core/hle/kernel/shared_page.h"
#include "core/hle/result.h"
#include "core/hle/service/cfg/cfg.h"
#include "core/hle/service/cfg/cfg_u.h"
#include "core/hle/service/nwm/nwm_uds.h"
#include "core/hle/service/nwm/uds_beacon.h"
#include "core/hle/service/nwm/uds_connection.h"
#include "core/hle/service/nwm/uds_data.h"
#include "core/hle/service/nwm/uds_real/nl80211_monitor.h"
#include "core/memory.h"

SERIALIZE_EXPORT_IMPL(Service::NWM::NWM_UDS)
SERVICE_CONSTRUCT_IMPL(Service::NWM::NWM_UDS)

namespace Service::NWM {

template <class Archive>
void NWM_UDS::serialize(Archive& ar, const unsigned int) {
    DEBUG_SERIALIZATION_POINT;
    ar& boost::serialization::base_object<Kernel::SessionRequestHandler>(*this);
    ar & node_map;
    ar & connection_event;
    ar & received_beacons;
    // wifi_packet_received set in constructor
}

namespace ErrCodes {
enum {
    NotInitialized = 2,
    WrongStatus = 490,
};
} // namespace ErrCodes

// Number of beacons to store before we start dropping the old ones.
// TODO(Subv): Find a more accurate value for this limit.
constexpr std::size_t MaxBeaconFrames = 15;

// Network node id used when a SecureData packet is addressed to every connected node.
constexpr u16 BroadcastNetworkNodeId = 0xFFFF;

// The Host has always dest_node_id 1
constexpr u16 HostDestNodeId = 1;

u32 FingerprintBytes(std::span<const u8> bytes) {
    // FNV-1a is sufficient for correlating changing diagnostic payloads without dumping the
    // game's full application data into the log.
    u32 fingerprint = 2166136261U;
    for (const u8 byte : bytes) {
        fingerprint ^= byte;
        fingerprint *= 16777619U;
    }
    return fingerprint;
}

u32 FingerprintUsername(const NodeInfo& node) {
    return FingerprintBytes(std::span<const u8>{
        reinterpret_cast<const u8*>(node.username.data()), sizeof(node.username)});
}

u32 FingerprintFriendCodeSeed(const NodeInfo& node) {
    return FingerprintBytes(std::span<const u8>{
        reinterpret_cast<const u8*>(&node.friend_code_seed), sizeof(node.friend_code_seed)});
}

u32 FingerprintNodeInfo(const NodeInfo& node) {
    return FingerprintBytes(std::span<const u8>{reinterpret_cast<const u8*>(&node), sizeof(node)});
}

std::string FormatHexBytes(std::span<const u8> bytes) {
    constexpr char Hex[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(bytes.size() * 3);
    for (const u8 byte : bytes) {
        if (!output.empty()) {
            output.push_back(':');
        }
        output.push_back(Hex[byte >> 4]);
        output.push_back(Hex[byte & 0x0F]);
    }
    return output.empty() ? "<none>" : output;
}

void AppendU16(std::vector<u8>& output, u16 value) {
    output.push_back(static_cast<u8>(value));
    output.push_back(static_cast<u8>(value >> 8));
}

std::vector<u8> GeneratePhysicalManagementFrame(u16 frame_control,
                                                 const MacAddress& transmitter,
                                                 const MacAddress& destination,
                                                 const MacAddress& bssid, u16 sequence_number,
                                                 std::span<const u8> body) {
    std::vector<u8> frame;
    frame.reserve(24 + body.size());
    AppendU16(frame, frame_control);
    AppendU16(frame, 0); // Duration.
    frame.insert(frame.end(), destination.begin(), destination.end());
    frame.insert(frame.end(), transmitter.begin(), transmitter.end());
    frame.insert(frame.end(), bssid.begin(), bssid.end());
    AppendU16(frame, static_cast<u16>((sequence_number & 0x0FFF) << 4));
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

std::vector<u8> GeneratePhysicalDataFrame(std::span<const u8> payload,
                                          const DataCCMPKey& ccmp_key,
                                          const MacAddress& transmitter,
                                          const MacAddress& destination,
                                          const MacAddress& bssid, bool from_ds,
                                          u64 packet_number, u16 sequence_number) {
    // Retail UDS uses an infrastructure-style address layout around the UDS host/BSSID.
    constexpr u16 DataFrameControl = 0x0008;
    constexpr u16 ToDS = 0x0100;
    constexpr u16 FromDS = 0x0200;
    constexpr u16 Protected = 0x4000;
    // Restore the last known-good address layout. The FromDS host-broadcast experiment did not
    // change the retail failure timing, so group-addressed UDS data remains NoDS while we inspect
    // the exact injected bytes and separately request no link-layer acknowledgement in radiotap.
    const bool no_ds = destination == Network::BroadcastMac;
    const u16 ds_bits = no_ds ? 0 : (from_ds ? FromDS : ToDS);
    const u16 frame_control = static_cast<u16>(DataFrameControl | Protected | ds_bits);
    const u16 sequence_control = static_cast<u16>((sequence_number & 0x0FFF) << 4);

    const auto encrypted = EncryptDataFrame(payload, ccmp_key, transmitter, destination, bssid,
                                            packet_number, frame_control, sequence_control);
    if (encrypted.empty()) {
        return {};
    }

    std::vector<u8> frame;
    frame.reserve(24 + 8 + encrypted.size());
    AppendU16(frame, frame_control);
    AppendU16(frame, 0);
    if (no_ds) {
        frame.insert(frame.end(), destination.begin(), destination.end()); // A1: broadcast/DA
        frame.insert(frame.end(), transmitter.begin(), transmitter.end()); // A2: source/TA
        frame.insert(frame.end(), bssid.begin(), bssid.end());              // A3: UDS BSSID
    } else if (from_ds) {
        frame.insert(frame.end(), destination.begin(), destination.end()); // A1: station/DA
        frame.insert(frame.end(), bssid.begin(), bssid.end());             // A2: BSSID/TA
        frame.insert(frame.end(), transmitter.begin(), transmitter.end()); // A3: source
    } else {
        frame.insert(frame.end(), bssid.begin(), bssid.end());             // A1: BSSID/RA
        frame.insert(frame.end(), transmitter.begin(), transmitter.end()); // A2: station/TA
        frame.insert(frame.end(), destination.begin(), destination.end()); // A3: destination
    }
    AppendU16(frame, sequence_control);

    // Eight-byte CCMP header: PN0, PN1, reserved, KeyID/ExtIV, PN2..PN5.
    frame.push_back(static_cast<u8>(packet_number));
    frame.push_back(static_cast<u8>(packet_number >> 8));
    frame.push_back(0);
    frame.push_back(0x20);
    frame.push_back(static_cast<u8>(packet_number >> 16));
    frame.push_back(static_cast<u8>(packet_number >> 24));
    frame.push_back(static_cast<u8>(packet_number >> 32));
    frame.push_back(static_cast<u8>(packet_number >> 40));
    frame.insert(frame.end(), encrypted.begin(), encrypted.end());
    return frame;
}

u64 ReadCCMPPacketNumber(std::span<const u8> header) {
    return static_cast<u64>(header[0]) | (static_cast<u64>(header[1]) << 8) |
           (static_cast<u64>(header[4]) << 16) | (static_cast<u64>(header[5]) << 24) |
           (static_cast<u64>(header[6]) << 32) | (static_cast<u64>(header[7]) << 40);
}

namespace {
// Temporary diagnostic: decrypts raw MPDU captures from a passive monitor-mode observation of a
// genuine retail-to-retail trade, reusing this build's own (already-working) CCMP key derivation
// and frame decryption, so the result can be compared against what Azahar produces in its own
// failed connection attempts. Runs once, triggered from NWM_UDS::Initialize.
std::vector<u8> ParseHexColonBytesOffline(const char* hex) {
    std::vector<u8> result;
    std::string current;
    for (const char* p = hex; *p; ++p) {
        if (*p == ':') {
            continue;
        }
        current += *p;
        if (current.size() == 2) {
            result.push_back(static_cast<u8>(std::stoul(current, nullptr, 16)));
            current.clear();
        }
    }
    return result;
}

void RunOfflineDecryptDiagnostic() {
    static bool already_ran = false;
    if (already_ran) {
        return;
    }
    already_ran = true;

    const auto passphrase =
        ParseHexColonBytesOffline("47:4E:67:42:77:4D:63:56:6F:74:59:73:00");

    NetworkInfo net_info{};
    net_info.host_mac_address = {0x7C, 0xBB, 0x8A, 0x7A, 0xBB, 0xB7};
    net_info.wlan_comm_id = 0x00055D10;
    // Confirmed directly from the SSID tag of the real association request frame captured at the
    // moment of the actual handshake (network "A9F62420", id=1) rather than the stale PSS-search
    // beacon values (id=2, networkId=0x98E6B725) sampled much earlier in the same capture.
    net_info.id = 1;
    net_info.network_id = 0xA9F62420;

    const DataCCMPKey key = GenerateDataCCMPKey(passphrase, net_info);
    LOG_INFO(Service_NWM, "OFFLINE DECRYPT: derived key={}",
             FormatHexBytes(std::vector<u8>(key.begin(), key.end())));

    struct CapturedFrameSample {
        const char* label;
        const char* mpdu_hex;
    };
    static const CapturedFrameSample samples[] = {
        {"real-handshake EAPoL frame #34 (3DSXL->2DS)",
         "08:41:2C:00:7C:BB:8A:7A:BB:B7:B8:AE:6E:A8:D0:10:7C:BB:8A:7A:BB:B7:50:0E:00:00:00:20:"
         "00:00:00:00:BF:0B:CB:E8:8F:3D:19:3B:29:E4:D3:5C:73:D6:6D:CF:F1:0B:57:85:BC:7D:1E:56:"
         "24:76:4E:E9:FE:BB:AB:1D:7B:06:2D:6A:04:2A:03:B4:EA:28:4E:A2:5A:B5:EC:05:DB:42:9D:8C:"
         "7D:3A:34:41:F9:CC:42:F7:20:4C:D7:7F"},
        {"real-handshake EAPoL frame #35 (2DS->3DSXL)",
         "08:42:2C:00:B8:AE:6E:A8:D0:10:7C:BB:8A:7A:BB:B7:7C:BB:8A:7A:BB:B7:70:0F:01:00:00:20:"
         "00:00:00:00:FA:8E:57:42:B3:5C:5D:E4:B8:CA:B5:8E:7D:E0:FE:91:F9:24:14:CB:A8:6F:FE:AC:"
         "33:B8:DB:94:34:7B:07:EE:D2:CB:15:70:F3:AB:B0:A3:15:56:B1:22:EE:9C:65:05:EA:6D:B1:C6:"
         "08:B5:F6:B0:F2:1A:07:47:CE:76:0F:DD:41:3B:6D:12:73:F3:51:FE:02:6E:4B:7A:7E:05:24:BF:"
         "02:A5:AF:2E:95:CA:D3:CE:F4:76:B9:B5:59:4E:40:7A:E1:8D:F6:88:CE:54:01:F3:36:EC:07:ED:"
         "AA:32:92:94:87:DF:CD:DC:BC:BC:09:85:4E:DD:B4:6F:B5:B7:C4:0A:A3:F5:E8:70:79:57:C7:F2:"
         "CB:D5:0F:53:E4:5A:D9:88:EC:FF:61:01:B7:38:49:94:7A:27:30:63:E9:89:83:EF:1D:DA:D5:EB:"
         "7E:28:1B:71:54:85:71:0E:CE:24:EC:80:17:E2:CE:74:6E:7D:AB:BB:CC:27:84:88:F9:85:EC:1F:"
         "D7:C9:8F:3A:C5:AC:DA:25:75:79:DA:8F:05:5D:12:17:5B:95:FD:2E:72:CF:DD:E6:95:3D:47:D0:"
         "2F:1C:71:2D:2C:23:4F:FD:BA:23:2B:EA:25:FA:44:A7:40:AA:9A:95:AF:42:83:98:89:5E:CA:65:"
         "C3:5A:DE:62:84:41:9C:3C:49:39:EF:FD:AF:CA:C9:B1:B3:B8:A7:F1:C0:55:B0:3D:43:6F:68:9E:"
         "1D:05:26:FD:D7:F4:8D:A7:AC:86:D2:BE:66:92:F7:C6:A7:6B:FF:8B:A6:A6:5F:41:5B:17:56:22:"
         "1A:99:20:AC:64:53:0B:E9:9E:AF:04:AE:F9:32:00:2E:5D:2F:73:9C:BA:FC:37:F7:28:4D:20:49:"
         "0F:5B:2E:6D:6E:99:0F:BE:D3:1E:A5:48:A8:AC:DB:98:D0:20:B7:46:67:FD:D2:0A:49:70:3F:78:"
         "B0:1F:2B:1D:53:1C:61:47:92:83:14:1A:84:E5:98:40:34:38:0D:2F:24:24:5E:AA:05:9B:BB:7D:"
         "CF:03:F5:A6:00:29:18:F2:82:63:DA:31:CF:D2:01:DE:38:D3:C4:60:CE:81:43:23:30:C1:52:36:"
         "6D:EB:07:D9:BB:EC:E2:F9:EE:A5:64:41:4E:0E:35:7C:CE:C2:AD:9C:A3:47:D2:4C:40:70:64:C1:"
         "6C:10:F5:27:3F:81:06:D2:C6:B4:FE:09:6A:AC:90:26:4E:3A:34:C2:5B:00:FF:10:19:9B:0E:7F:"
         "4A:6C:E2:F5:6D:4B:99:65:75:FE:F6:D5:ED:89:EF:73:F1:5E:4C:33:40:2A:4D:9C:95:2F:6A:C1:"
         "81:FC:CA:51:F5:E2:32:DF:08:3B:A2:F2:C7:CC:67:C5:8C:FE:A3:04:EC:C7:46:69:C7:4A:F5:84:"
         "C3:7F:80:E3:9A:33:C1:00:4B:69:AF:F5:2F:8A:67:9A:AE:A9:AA:47:15:08:00:96:08:EF:28:4C:"
         "AD:6B:4A:E7:5D:EC:58:8D:06:83:E8:90:26:22:86:4C:3E:05:CD:A2:C8:B4:EF:B9:EE:D4:55:CD:"
         "50:83:EE:DA:43:D9:49:EB:2A:FC:51:4B:3E:89:8D:CC:20:A9:80:47:41:62:5D:71:A6:CB:63:36:"
         "67:A3:10:7E:4B:C3:E9:0E:13:5B:B2:A7:ED:B5:89:AD:76:73:06:F1:D2:65:07:0B:82:19:AD:A1:"
         "2B:1D:34:37:6E:71:DE:C9:93:3D:35:E9:BC:76:9B:B8:99:87:A4:83:0A:CC:98:9E:89:4D:DE:82:"
         "5A:AE:08:54:FE:E2:75:20:8D:70:E3:58"},
    };

    std::vector<std::pair<std::string, std::string>> all_samples;
    for (const auto& sample : samples) {
        all_samples.emplace_back(sample.label, sample.mpdu_hex);
    }
    // Additional frames: one "<label>\t<colon-separated MPDU hex>" per line.
    {
        std::ifstream extra(FileUtil::GetUserPath(FileUtil::UserPath::UserDir) +
                            "offline_frames.txt");
        std::string line;
        while (std::getline(extra, line)) {
            const auto tab = line.find('\t');
            if (tab == std::string::npos) {
                continue;
            }
            std::string hex = line.substr(tab + 1);
            while (!hex.empty() && (hex.back() == '\r' || hex.back() == ' ')) {
                hex.pop_back();
            }
            all_samples.emplace_back(line.substr(0, tab), hex);
        }
    }

    for (const auto& [sample_label, sample_hex] : all_samples) {
        struct {
            const char* label;
            const char* mpdu_hex;
        } sample{sample_label.c_str(), sample_hex.c_str()};
        const auto mpdu = ParseHexColonBytesOffline(sample.mpdu_hex);
        if (mpdu.size() < 24 + 8) {
            LOG_WARNING(Service_NWM, "OFFLINE DECRYPT [{}]: sample too short", sample.label);
            continue;
        }

        MacAddress destination{}, source{}, bssid{};
        std::copy(mpdu.begin() + 4, mpdu.begin() + 10, destination.begin());
        std::copy(mpdu.begin() + 10, mpdu.begin() + 16, source.begin());
        std::copy(mpdu.begin() + 16, mpdu.begin() + 22, bssid.begin());
        const u16 frame_control = static_cast<u16>(mpdu[0]) | (static_cast<u16>(mpdu[1]) << 8);
        const u16 sequence_control =
            static_cast<u16>(mpdu[22]) | (static_cast<u16>(mpdu[23]) << 8);

        const std::span<const u8> body{mpdu.data() + 24, mpdu.size() - 24};
        const u64 packet_number = ReadCCMPPacketNumber(body.subspan(0, 8));
        auto decrypted = DecryptDataFrame(body.subspan(8), key, source, destination, bssid,
                                          packet_number, frame_control, sequence_control);
        if (decrypted) {
            LOG_INFO(Service_NWM,
                     "OFFLINE DECRYPT SUCCESS [{}]: packetNumber={}, plaintextBytes={}, "
                     "plaintext={}",
                     sample.label, packet_number, decrypted->size(), FormatHexBytes(*decrypted));
        } else {
            LOG_WARNING(Service_NWM, "OFFLINE DECRYPT FAILED [{}]: packetNumber={}", sample.label,
                        packet_number);
        }
    }
}
} // namespace

std::list<Network::WifiPacket> NWM_UDS::GetReceivedBeacons(const MacAddress& sender) {
    std::scoped_lock lock(beacon_mutex);
    if (sender != Network::BroadcastMac) {
        std::list<Network::WifiPacket> filtered_list;
        const auto beacon = std::find_if(received_beacons.begin(), received_beacons.end(),
                                         [&sender](const Network::WifiPacket& packet) {
                                             return packet.transmitter_address == sender;
                                         });
        if (beacon != received_beacons.end()) {
            filtered_list.push_back(*beacon);
            // TODO(B3N30): Check if the complete deque is cleared or just the fetched entries
            received_beacons.erase(beacon);
        }
        return filtered_list;
    }
    return std::move(received_beacons);
}

/// Sends a WifiPacket to the room we're currently connected to and to a physical 3DS.
void NWM_UDS::SendPacket(Network::WifiPacket& packet) {
    packet.transmitter_address = GetMacAddress();

    if (auto room_member = Network::GetRoomMember().lock()) {
        if (room_member->GetState() == Network::RoomMember::State::Joined ||
            room_member->GetState() == Network::RoomMember::State::Moderator) {
            room_member->SendWifiPacket(packet);
        }
    }

#ifdef _WIN32
    SendPhysicalPacket(packet);
#endif
}

u16 NWM_UDS::GetNextAvailableNodeId() {
    for (u16 index = 0; index < connection_status.max_nodes; ++index) {
        if ((connection_status.node_bitmask & (1 << index)) == 0)
            return index + 1;
    }

    // Any connection attempts to an already full network should have been refused.
    UNREACHABLE_MSG("No available connection slots in the network");
    return 0;
}

void NWM_UDS::BroadcastNodeMap() {
    // Note: This is not how UDS on a 3ds does it but it shouldn't be
    // necessary for citra
    Network::WifiPacket packet;
    packet.channel = network_channel;
    packet.type = Network::WifiPacket::PacketType::NodeMap;
    packet.destination_address = Network::BroadcastMac;
    auto node_can_broad = [](auto& node) -> bool {
        return node.second.connected && !node.second.spec;
    };
    std::size_t num_entries =
        std::count_if(node_map.begin(), node_map.end(),
                      [&node_can_broad](const auto& node) { return node_can_broad(node); });
    using node_t = decltype(node_map)::value_type;
    packet.data.resize(sizeof(num_entries) +
                       (sizeof(node_t::first) + sizeof(node_t::second.node_id)) * num_entries);
    std::memcpy(packet.data.data(), &num_entries, sizeof(num_entries));
    std::size_t offset = sizeof(num_entries);
    for (const auto& node : node_map) {
        if (node_can_broad(node)) {
            std::memcpy(packet.data.data() + offset, node.first.data(), sizeof(node.first));
            std::memcpy(packet.data.data() + offset + sizeof(node.first), &node.second.node_id,
                        sizeof(node.second.node_id));
            offset += sizeof(node.first) + sizeof(node.second.node_id);
        }
    }

    SendPacket(packet);
}

void NWM_UDS::HandleNodeMapPacket(const Network::WifiPacket& packet) {
    std::scoped_lock lock(connection_status_mutex);
    if (connection_status.status == NetworkStatus::ConnectedAsHost) {
        LOG_DEBUG(Service_NWM, "Ignored NodeMapPacket since connection_status is host");
        return;
    }

    node_map.clear();
    std::size_t num_entries;
    Network::MacAddress address;
    u16 id;
    std::memcpy(&num_entries, packet.data.data(), sizeof(num_entries));
    std::size_t offset = sizeof(num_entries);
    for (std::size_t i = 0; i < num_entries; ++i) {
        std::memcpy(&address, packet.data.data() + offset, sizeof(address));
        std::memcpy(&id, packet.data.data() + offset + sizeof(address), sizeof(id));
        node_map[address].connected = true;
        node_map[address].node_id = id;
        offset += sizeof(address) + sizeof(id);
    }
}

void NWM_UDS::HandleBeaconFrame(const Network::WifiPacket& packet) {
    std::scoped_lock lock(beacon_mutex);
    const auto unique_beacon =
        std::find_if(received_beacons.begin(), received_beacons.end(),
                     [&packet](const Network::WifiPacket& new_packet) {
                         return new_packet.transmitter_address == packet.transmitter_address;
                     });
    if (unique_beacon != received_beacons.end()) {
        // We already have a beacon from the same mac in the deque, remove the old one;
        received_beacons.erase(unique_beacon);
    }

    received_beacons.emplace_back(packet);

    // Discard old beacons if the buffer is full.
    if (received_beacons.size() > MaxBeaconFrames)
        received_beacons.pop_front();
}

void NWM_UDS::HandleAssociationResponseFrame(const Network::WifiPacket& packet) {
    auto assoc_result = GetAssociationResult(packet.data);

    ASSERT_MSG(std::get<AssocStatus>(assoc_result) == AssocStatus::Successful,
               "Could not join network");
    {
        std::scoped_lock lock(connection_status_mutex);
        if (connection_status.status != NetworkStatus::Connecting) {
            LOG_DEBUG(Service_NWM,
                      "Ignored AssociationResponseFrame because connection status is {}",
                      static_cast<u32>(connection_status.status));
            return;
        }
        if (association_response_handled) {
            LOG_DEBUG(Service_NWM,
                      "Ignored retried AssociationResponseFrame after EAPoL-Start was sent");
            return;
        }
        association_response_handled = true;
    }

    // Send the EAPoL-Start packet to the server.
    using Network::WifiPacket;
    WifiPacket eapol_start;
    eapol_start.channel = network_channel;
    eapol_start.data =
        GenerateEAPoLStartFrame(std::get<u16>(assoc_result), conn_type, current_node);
    // TODO(B3N30): Encrypt the packet.
    eapol_start.destination_address = packet.transmitter_address;
    eapol_start.type = WifiPacket::PacketType::Data;

    SendPacket(eapol_start);
}

void NWM_UDS::HandleEAPoLPacket(const Network::WifiPacket& packet) {
    std::scoped_lock lock{connection_status_mutex};

    // Monitor-mode capture delivers every 802.11 link-layer retransmission as a separate frame.
    // Reprocessing an identical EAPoL frame corrupts state that must only be updated once (see
    // last_eapol_frame_data's declaration), so drop exact repeats from the same transmitter.
    auto& last_seen = last_eapol_frame_data[packet.transmitter_address];
    if (last_seen == packet.data) {
        LOG_TRACE(Service_NWM,
                  "UDS Real: suppressed duplicate EAPoL frame from "
                  "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                  packet.transmitter_address[0], packet.transmitter_address[1],
                  packet.transmitter_address[2], packet.transmitter_address[3],
                  packet.transmitter_address[4], packet.transmitter_address[5]);
        return;
    }
    last_seen = packet.data;

    if (GetEAPoLFrameType(packet.data) == EAPoLStartMagic) {
        if (connection_status.status != NetworkStatus::ConnectedAsHost) {
            LOG_DEBUG(Service_NWM, "Connection sequence aborted, because connection status is {}",
                      static_cast<u32>(connection_status.status));
            return;
        }

        auto node_it = node_map.find(packet.transmitter_address);
        if (node_it == node_map.end()) {
            LOG_DEBUG(Service_NWM, "Connection sequence aborted, because the AuthenticationFrame "
                                   "of the client wasn't recieved");
            return;
        }
        if (node_it->second.connected) {
            LOG_DEBUG(Service_NWM,
                      "Connection sequence aborted, because the client is already connected");
            return;
        }

        ASSERT(connection_status.max_nodes != connection_status.total_nodes);

        auto eapol_start = DeserializeEAPolStartPacket(packet.data);

        auto node = DeserializeNodeInfo(eapol_start.node);

        LOG_INFO(Service_NWM,
                 "UDS JOIN TRACE RX EAPOL-START: plaintextBytes={}, plaintextFingerprint="
                 "0x{:08X}, associationId={}, connectionType=0x{:04X}, wireNodeId={}, "
                 "friendCodeSeedNonzero={}, friendCodeSeedFingerprint=0x{:08X}, "
                 "usernameFingerprint=0x{:08X}, nodeFingerprint=0x{:08X}, plaintext={}",
                 packet.data.size(), FingerprintBytes(packet.data),
                 static_cast<u16>(eapol_start.association_id),
                 static_cast<u16>(eapol_start.connection_type),
                 static_cast<u16>(eapol_start.node.network_node_id),
                 static_cast<u64>(node.friend_code_seed) != 0, FingerprintFriendCodeSeed(node),
                 FingerprintUsername(node), FingerprintNodeInfo(node), FormatHexBytes(packet.data));

        const u16 wire_connection_type = static_cast<u16>(eapol_start.connection_type);
        const bool is_client = wire_connection_type == static_cast<u16>(ConnectionType::Client);

        if (is_client) {
            // Get an unused network node id
            u16 node_id = GetNextAvailableNodeId();
            node.network_node_id = node_id;

            connection_status.node_bitmask |= 1 << (node_id - 1);
            connection_status.changed_nodes |= 1 << (node_id - 1);
            connection_status.nodes[node_id - 1] = node.network_node_id;
            connection_status.total_nodes++;

            node_info[node_id - 1] = node;
            network_info.total_nodes++;

            node_map[packet.transmitter_address].node_id = node.network_node_id;
            node_map[packet.transmitter_address].connected = true;
            node_map[packet.transmitter_address].spec = false;

            LOG_INFO(Service_NWM,
                     "UDS Real: accepted client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, "
                     "assignedNodeId={}, connectedNodes={}, maxNodes={}",
                     packet.transmitter_address[0], packet.transmitter_address[1],
                     packet.transmitter_address[2], packet.transmitter_address[3],
                     packet.transmitter_address[4], packet.transmitter_address[5], node_id,
                     network_info.total_nodes, network_info.max_nodes);

            BroadcastNodeMap();
        } else if (wire_connection_type == static_cast<u16>(ConnectionType::Spectator)) {
            node_map[packet.transmitter_address].node_id = NodeIDSpec;
            node_map[packet.transmitter_address].connected = true;
            node_map[packet.transmitter_address].spec = true;
        } else {
            LOG_ERROR(Service_NWM, "Client tried connecting with unknown connection type: 0x{:x}",
                      static_cast<u32>(wire_connection_type));
        }

        // Send the EAPoL-Logoff packet.
        using Network::WifiPacket;
        WifiPacket eapol_logoff;
        eapol_logoff.channel = network_channel;
        eapol_logoff.data =
            GenerateEAPoLLogoffFrame(packet.transmitter_address, node.network_node_id, node_info,
                                     network_info.max_nodes, network_info.total_nodes);
        // TODO(Subv): Encrypt the packet.

        // A retail 3DS expects this response to be unicast to the joining station. Room peers
        // receive the updated node map separately through BroadcastNodeMap above.
        eapol_logoff.destination_address = packet.transmitter_address;
        eapol_logoff.type = WifiPacket::PacketType::Data;

        const NodeInfo& host_node = node_info[0];
        const u16 client_node_id = node.network_node_id;
        const NodeInfo* client_node =
            client_node_id > 0 && client_node_id <= node_info.size()
                ? &node_info[client_node_id - 1]
                : nullptr;
        LOG_INFO(Service_NWM,
                 "UDS JOIN TRACE TX EAPOL-LOGOFF: assignedNodeId={}, connectedNodes={}, "
                 "maxNodes={}, hostNodeId={}, hostFriendCodeSeedNonzero={}, "
                 "hostFriendCodeSeedFingerprint=0x{:08X}, hostUsernameFingerprint=0x{:08X}, "
                 "hostNodeFingerprint=0x{:08X}, clientNodeId={}, "
                 "clientFriendCodeSeedNonzero={}, clientFriendCodeSeedFingerprint=0x{:08X}, "
                 "clientUsernameFingerprint=0x{:08X}, clientNodeFingerprint=0x{:08X}, "
                 "plaintextBytes={}, plaintextFingerprint=0x{:08X}, plaintext={}",
                 static_cast<u16>(node.network_node_id), network_info.total_nodes,
                 network_info.max_nodes, static_cast<u16>(host_node.network_node_id),
                 static_cast<u64>(host_node.friend_code_seed) != 0,
                 FingerprintFriendCodeSeed(host_node), FingerprintUsername(host_node),
                 FingerprintNodeInfo(host_node),
                 client_node ? static_cast<u16>(client_node->network_node_id) : 0,
                 client_node && static_cast<u64>(client_node->friend_code_seed) != 0,
                 client_node ? FingerprintFriendCodeSeed(*client_node) : 0,
                 client_node ? FingerprintUsername(*client_node) : 0,
                 client_node ? FingerprintNodeInfo(*client_node) : 0, eapol_logoff.data.size(),
                 FingerprintBytes(eapol_logoff.data), FormatHexBytes(eapol_logoff.data));

        SendPacket(eapol_logoff);

        SignalEventAsync(connection_status_event);
    } else if (connection_status.status == NetworkStatus::Connecting) {
        auto logoff = ParseEAPoLLogoffFrame(packet.data);

        network_info.host_mac_address = packet.transmitter_address;
        network_info.total_nodes = logoff.connected_nodes;
        network_info.max_nodes = logoff.max_nodes;

        connection_status.network_node_id = logoff.assigned_node_id;
        connection_status.total_nodes = logoff.connected_nodes;
        connection_status.max_nodes = beacon_max_nodes;

        node_info.clear();
        node_info.resize(network_info.max_nodes);
        for (const auto& node : logoff.nodes) {
            const u16 index = node.network_node_id;
            if (!index) {
                continue;
            }

            connection_status.node_bitmask |= 1 << (index - 1);
            connection_status.changed_nodes |= 1 << (index - 1);
            connection_status.nodes[index - 1] = index;

            node_info[index - 1] = DeserializeNodeInfo(node);
        }

        if (conn_type == ConnectionType::Client) {
            connection_status.status = NetworkStatus::ConnectedAsClient;
        } else if (conn_type == ConnectionType::Spectator) {
            connection_status.status = NetworkStatus::ConnectedAsSpectator;
        } else {
            LOG_ERROR(Service_NWM, "Unknown connection type: 0x{:x}", static_cast<u32>(conn_type));
        }

        // We're now connected, signal the application
        connection_status.status_change_reason = NetworkStatusChangeReason::ConnectionEstablished;
        // Some games require ConnectToNetwork to block, for now it doesn't
        // If blocking is implemented this lock needs to be changed,
        // otherwise it might cause deadlocks
        LOG_INFO(Service_NWM,
                 "UDS IPC: signaling connection_status_event and connection_event (client joined)");
        SignalEventAsync(connection_status_event);
        SignalEventAsync(connection_event);
    } else if (connection_status.status == NetworkStatus::ConnectedAsClient ||
               connection_status.status == NetworkStatus::ConnectedAsSpectator) {
        // TODO(B3N30): Remove that section and send/receive a proper connection_status packet
        // On a 3ds this packet wouldn't be addressed to already connected clients
        // We use this information because in the current implementation the host
        // isn't broadcasting the node information
        auto logoff = ParseEAPoLLogoffFrame(packet.data);

        network_info.total_nodes = logoff.connected_nodes;
        connection_status.total_nodes = logoff.connected_nodes;
        std::memset(connection_status.nodes, 0, sizeof(connection_status.nodes));

        const auto old_bitmask = connection_status.node_bitmask;
        connection_status.node_bitmask = 0;

        node_info.clear();
        node_info.resize(network_info.max_nodes);
        for (const auto& node : logoff.nodes) {
            const u16 index = node.network_node_id;
            if (!index) {
                continue;
            }

            connection_status.node_bitmask |= 1 << (index - 1);
            connection_status.nodes[index - 1] = index;

            node_info[index - 1] = DeserializeNodeInfo(node);
        }
        connection_status.changed_nodes = old_bitmask ^ connection_status.node_bitmask;

        SignalEventAsync(connection_status_event);
    }
}

void NWM_UDS::HandleSecureDataPacket(const Network::WifiPacket& packet) {
    constexpr std::size_t SecureDataPrefixSize = sizeof(LLCHeader) + sizeof(SecureDataHeader);
    if (packet.data.size() < SecureDataPrefixSize) {
        LOG_WARNING(Service_NWM,
                    "UDS Real: discarded truncated SecureData packet, packetBytes={}",
                    packet.data.size());
        return;
    }

    // A real host may aggregate several SecureData packets into one frame: the container header
    // (protocol_size, packet_count) is followed by packet_count packets, each starting with its own
    // securedata_size (which counts itself). Split such a frame into ordinary single-packet frames
    // and handle each one separately so the rest of this function only ever sees one packet.
    {
        const auto container = ParseSecureDataHeader(packet.data);
        const std::size_t container_size = container.protocol_size;
        const u16 packet_count = container.packet_count;
        if (packet_count > 1 && container_size >= 4 &&
            packet.data.size() >= sizeof(LLCHeader) + container_size) {
            const u8* const llc = packet.data.data();
            std::size_t offset = sizeof(LLCHeader) + 4;
            const std::size_t end = sizeof(LLCHeader) + container_size;
            for (u16 index = 0; index < packet_count; ++index) {
                if (offset + 2 > end) {
                    break;
                }
                const std::size_t size =
                    (static_cast<std::size_t>(llc[offset]) << 8) | llc[offset + 1];
                // 2 (size) + 8 (management, channel, sequence, destination, source) at minimum.
                if (size < 10 || offset + size > end) {
                    LOG_WARNING(Service_NWM,
                                "UDS Real: aggregated SecureData frame has a malformed sub-packet, "
                                "index={}, size={}, remaining={}",
                                index, size, end - offset);
                    break;
                }
                Network::WifiPacket sub_packet = packet;
                sub_packet.data.assign(llc, llc + sizeof(LLCHeader));
                const u16 sub_protocol_size = static_cast<u16>(size + 4);
                sub_packet.data.push_back(static_cast<u8>(sub_protocol_size >> 8));
                sub_packet.data.push_back(static_cast<u8>(sub_protocol_size & 0xFF));
                sub_packet.data.push_back(0);
                sub_packet.data.push_back(1);
                sub_packet.data.insert(sub_packet.data.end(), llc + offset, llc + offset + size);
                LOG_INFO(Service_NWM,
                         "UDS Real: split aggregated SecureData frame, index={}/{}, "
                         "subPacketBytes={}",
                         index + 1, packet_count, size);
                HandleSecureDataPacket(sub_packet);
                offset += size;
            }
            return;
        }
    }

    const auto secure_data = ParseSecureDataHeader(packet.data);
    const u16 protocol_size = secure_data.protocol_size;
    const u16 securedata_size = secure_data.securedata_size;
    if (protocol_size < sizeof(SecureDataHeader) || securedata_size + 4 != protocol_size ||
        packet.data.size() < sizeof(LLCHeader) + protocol_size) {
        LOG_WARNING(Service_NWM,
                    "UDS Real: discarded malformed SecureData packet, packetBytes={}, "
                    "protocolSize={}, securedataSize={}",
                    packet.data.size(), protocol_size, securedata_size);
        return;
    }

    std::scoped_lock lock{connection_status_mutex};

    if (connection_status.status != NetworkStatus::ConnectedAsHost &&
        connection_status.status != NetworkStatus::ConnectedAsClient &&
        connection_status.status != NetworkStatus::ConnectedAsSpectator) {
        LOG_TRACE(Service_NWM, "Ignored SecureDataPacket because connection status is {}",
                  static_cast<u32>(connection_status.status));
        return;
    }

    if (secure_data.src_node_id == connection_status.network_node_id) {
        // Ignore packets that came from ourselves.
        return;
    }

    if (secure_data.dest_node_id != connection_status.network_node_id &&
        secure_data.dest_node_id != BroadcastNetworkNodeId) {
        // The packet wasn't addressed to us, we can only act as a router if we're the host.
        // However, we might have received this packet due to a broadcast from the host, in that
        // case just ignore it.
        if (packet.destination_address != Network::BroadcastMac &&
            connection_status.status != NetworkStatus::ConnectedAsHost) {
            LOG_ERROR(Service_NWM, "Received packet addressed to others but we're not a host");
            return;
        }

        if (connection_status.status == NetworkStatus::ConnectedAsHost &&
            secure_data.dest_node_id != BroadcastNetworkNodeId) {
            // Broadcast the packet so the right receiver can get it.
            // TODO(B3N30): Is there a flag that makes this kind of routing be unicast instead of
            // multicast? Perhaps this is a way to allow spectators to see some of the packets.
            Network::WifiPacket out_packet = packet;
            out_packet.destination_address = Network::BroadcastMac;
            SendPacket(out_packet);
        }
        return;
    }

    // Management payloads are consumed by nwm::UDS itself and are not exposed through PullPacket.
    // A retail client sends a one-byte channel-3 management packet periodically after joining.
    // Mirror each new request back to that client using the host's own SecureData sequence.
    // Monitor-mode capture sees the client's link-layer retries, so suppress repeated copies of
    // the same client management sequence.
    if (secure_data.is_management) {
        const std::size_t payload_size = protocol_size - sizeof(SecureDataHeader);
        const std::span<const u8> payload{
            packet.data.data() + SecureDataPrefixSize, payload_size};
        const u16 source_node = secure_data.src_node_id;
        const u16 destination_node = secure_data.dest_node_id;
        const u16 sequence = secure_data.sequence_number;
        const bool is_client_ping =
            connection_status.status == NetworkStatus::ConnectedAsHost &&
            secure_data.data_channel == 3 && payload.size() == 1 && payload.front() == 0;

        if (is_client_ping) {
            const auto previous = physical_management_reply_sequences.find(source_node);
            if (previous != physical_management_reply_sequences.end() &&
                previous->second == sequence) {
                LOG_TRACE(Service_NWM,
                          "UDS Real: suppressed duplicate management SecureData request, "
                          "channel={}, sequence={}, sourceNode={}",
                          secure_data.data_channel, sequence, source_node);
                return;
            }
            physical_management_reply_sequences[source_node] = sequence;

            const u16 reply_sequence = secure_data_tx_sequence_number++;
            Network::WifiPacket reply;
            reply.destination_address = packet.transmitter_address;
            reply.channel = packet.channel;
            reply.data = GenerateDataPayload(payload, secure_data.data_channel, source_node,
                                             connection_status.network_node_id, reply_sequence,
                                             true);
            reply.type = Network::WifiPacket::PacketType::Data;
            SendPacket(reply);

            LOG_INFO(Service_NWM,
                     "UDS Real: replied to management SecureData request, channel={}, "
                     "requestSequence={}, replySequence={}, sourceNode={}, destinationNode={}, "
                     "payloadBytes={}, payload={}",
                     secure_data.data_channel, sequence, reply_sequence,
                     static_cast<u16>(connection_status.network_node_id), source_node,
                     payload.size(), FormatHexBytes(payload));
            return;
        }

        LOG_INFO(Service_NWM,
                 "UDS Real: consumed unsupported management SecureData packet, management={}, "
                 "channel={}, sequence={}, sourceNode={}, destinationNode={}, payloadBytes={}, "
                 "payload={}",
                 secure_data.is_management, secure_data.data_channel, sequence, source_node,
                 destination_node, payload.size(), FormatHexBytes(payload));
        return;
    }

    // The packet is addressed to us (or to everyone using the broadcast node id), handle it.

    // TODO(B3N30): Allow more than one bind node per channel.
    auto channel_info = channel_data.find(secure_data.data_channel);
    // Ignore packets from channels we're not interested in.
    if (channel_info == channel_data.end()) {
        LOG_INFO(Service_NWM,
                 "UDS Real: discarded application SecureData for unbound channel, channel={}, "
                 "sequence={}, sourceNode={}, destinationNode={}, payloadBytes={}",
                 secure_data.data_channel, static_cast<u16>(secure_data.sequence_number),
                 static_cast<u16>(secure_data.src_node_id),
                 static_cast<u16>(secure_data.dest_node_id),
                 protocol_size - sizeof(SecureDataHeader));
        return;
    }

    if (channel_info->second.network_node_id != BroadcastNetworkNodeId &&
        channel_info->second.network_node_id != secure_data.src_node_id) {
        LOG_INFO(Service_NWM,
                 "UDS Real: discarded application SecureData for filtered source, channel={}, "
                 "sequence={}, sourceNode={}, bindSourceNode={}",
                 secure_data.data_channel, static_cast<u16>(secure_data.sequence_number),
                 static_cast<u16>(secure_data.src_node_id),
                 channel_info->second.network_node_id);
        return;
    }

    // Add the received packet to the data queue.
    channel_info->second.received_packets.emplace_back(packet.data);

    const std::size_t application_payload_size = protocol_size - sizeof(SecureDataHeader);
    const std::span<const u8> application_payload{
        packet.data.data() + SecureDataPrefixSize, application_payload_size};

    LOG_INFO(Service_NWM,
             "UDS DATA TRACE RX QUEUE: channel={}, secureSequence={}, sourceNode={}, "
             "destinationNode={}, payloadBytes={}, payloadFingerprint=0x{:08X}, payload={}, "
             "secureDataBytes={}, secureDataFingerprint=0x{:08X}, queueDepth={}",
             secure_data.data_channel, static_cast<u16>(secure_data.sequence_number),
             static_cast<u16>(secure_data.src_node_id),
             static_cast<u16>(secure_data.dest_node_id), application_payload_size,
             FingerprintBytes(application_payload), FormatHexBytes(application_payload),
             packet.data.size(), FingerprintBytes(packet.data),
             channel_info->second.received_packets.size());

    // Signal the data event. We can do this directly because we use SignalEventAsync
    SignalEventAsync(channel_info->second.event);
}

void NWM_UDS::StartConnectionSequence(const MacAddress& server) {
    using Network::WifiPacket;
    WifiPacket auth_request;
    {
        std::scoped_lock lock(connection_status_mutex);
        connection_status.status = NetworkStatus::Connecting;

        // TODO(Subv): Handle timeout.

        // Send an authentication frame with SEQ1
        auth_request.channel = network_channel;
        auth_request.data = GenerateAuthenticationFrame(AuthenticationSeq::SEQ1);
        auth_request.destination_address = server;
        auth_request.type = WifiPacket::PacketType::Authentication;
    }

    SendPacket(auth_request);
}

void NWM_UDS::SendAssociationResponseFrame(const MacAddress& address) {
    using Network::WifiPacket;
    WifiPacket assoc_response;

    {
        std::scoped_lock lock(connection_status_mutex);
        if (connection_status.status != NetworkStatus::ConnectedAsHost) {
            LOG_ERROR(Service_NWM, "Connection sequence aborted, because connection status is {}",
                      static_cast<u32>(connection_status.status));
            return;
        }

        assoc_response.channel = network_channel;
        // TODO(Subv): This will cause multiple clients to end up with the same association id, but
        // we're not using that for anything.
        u16 association_id = 1;
        assoc_response.data = GenerateAssocResponseFrame(AssocStatus::Successful, association_id,
                                                         network_info.network_id);
        assoc_response.destination_address = address;
        assoc_response.type = WifiPacket::PacketType::AssociationResponse;
    }

    SendPacket(assoc_response);
}

void NWM_UDS::HandleAuthenticationFrame(const Network::WifiPacket& packet) {
    const AuthenticationSeq sequence = GetAuthenticationSeqNumber(packet.data);

    // Room multiplayer historically treats auth SEQ2 as sufficient and waits for the synthetic
    // AssociationResponse packet. A physical UDS client must instead transmit a real 802.11
    // association request after the host authenticates it. The exact request body below was
    // captured from a retail 3DS joining an Azahar-hosted Pokemon X network.
    if (sequence == AuthenticationSeq::SEQ2) {
#ifdef _WIN32
        bool send_association_request = false;
        {
            std::scoped_lock lock(connection_status_mutex);
            if (connection_status.status == NetworkStatus::Connecting &&
                packet.transmitter_address == network_info.host_mac_address &&
                !physical_association_request_sent) {
                physical_association_request_sent = true;
                send_association_request = true;
            }
        }
        if (send_association_request) {
            SendPhysicalAssociationRequest(packet.transmitter_address);
        }
#endif
        return;
    }

    if (sequence == AuthenticationSeq::SEQ1) {
        using Network::WifiPacket;
        AuthenticationFrame auth_request;
        memcpy(&auth_request, packet.data.data(), sizeof(auth_request));
        WifiPacket auth_response;
        {
            std::scoped_lock lock(connection_status_mutex);
            if (connection_status.status != NetworkStatus::ConnectedAsHost) {
                LOG_ERROR(Service_NWM,
                          "Connection sequence aborted, because connection status is {}",
                          static_cast<u32>(connection_status.status));
                return;
            }
            const auto existing_node = node_map.find(packet.transmitter_address);
            if (existing_node != node_map.end() && existing_node->second.connected) {
                LOG_INFO(Service_NWM,
                         "UDS Real: repeated authentication from already connected client "
                         "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} ignored",
                         packet.transmitter_address[0], packet.transmitter_address[1],
                         packet.transmitter_address[2], packet.transmitter_address[3],
                         packet.transmitter_address[4], packet.transmitter_address[5]);
                return;
            }

            if (connection_status.max_nodes == connection_status.total_nodes) {
                // Reject connection attempt
                LOG_ERROR(Service_NWM, "Reached maximum nodes, but reject packet wasn't sent.");
                // TODO(B3N30): Figure out what packet is sent here
                return;
            }
            // Respond with an authentication response frame with SEQ2
            auth_response.channel = network_channel;
            auth_response.data = GenerateAuthenticationFrame(AuthenticationSeq::SEQ2);
            auth_response.destination_address = packet.transmitter_address;
            auth_response.type = WifiPacket::PacketType::Authentication;
            node_map[packet.transmitter_address].connected = false;
        }
        SendPacket(auth_response);

        SendAssociationResponseFrame(packet.transmitter_address);
    }
}

void NWM_UDS::HandleDeauthenticationFrame(const Network::WifiPacket& packet) {
    LOG_DEBUG(Service_NWM, "called");
    std::scoped_lock lock{connection_status_mutex};

    if (connection_status.status != NetworkStatus::ConnectedAsHost) {
        LOG_ERROR(Service_NWM, "Got deauthentication frame but we are not the host");
        return;
    }
    if (node_map.find(packet.transmitter_address) == node_map.end()) {
        LOG_ERROR(Service_NWM, "Got deauthentication frame from unknown node");
        return;
    }

    Node node = node_map[packet.transmitter_address];
    node_map.erase(packet.transmitter_address);

    if (!node.connected) {
        LOG_DEBUG(Service_NWM, "Received DeauthenticationFrame from a not connected MAC Address");
        return;
    }

    auto node_it = std::find_if(node_info.begin(), node_info.end(), [&node](const NodeInfo& info) {
        return info.network_node_id == node.node_id;
    });
    if (node_it == node_info.end()) {
        LOG_ERROR(Service_NWM, "node_it is last node of node_info");
        return;
    }

    if (!node.spec) {
        connection_status.node_bitmask &= ~(1 << (node.node_id - 1));
        connection_status.changed_nodes |= 1 << (node.node_id - 1);
        connection_status.total_nodes--;
        connection_status.nodes[node.node_id - 1] = 0;

        network_info.total_nodes--;
        // TODO(B3N30): broadcast new connection_status to clients
    }
    node_it->Reset();
    SignalEventAsync(connection_status_event);
}

void NWM_UDS::HandleDataFrame(const Network::WifiPacket& packet) {
    switch (GetFrameEtherType(packet.data)) {
    case EtherType::EAPoL:
        HandleEAPoLPacket(packet);
        break;
    case EtherType::SecureData:
        HandleSecureDataPacket(packet);
        break;
    }
}

/// Callback to parse and handle a received wifi packet.
void NWM_UDS::OnWifiPacketReceived(const Network::WifiPacket& packet) {
    if (!initialized) {
        return;
    }
    switch (packet.type) {
    case Network::WifiPacket::PacketType::Beacon:
        HandleBeaconFrame(packet);
        break;
    case Network::WifiPacket::PacketType::Authentication:
        HandleAuthenticationFrame(packet);
        break;
    case Network::WifiPacket::PacketType::AssociationResponse:
        HandleAssociationResponseFrame(packet);
        break;
    case Network::WifiPacket::PacketType::Data:
        HandleDataFrame(packet);
        break;
    case Network::WifiPacket::PacketType::Deauthentication:
        HandleDeauthenticationFrame(packet);
        break;
    case Network::WifiPacket::PacketType::NodeMap:
        HandleNodeMapPacket(packet);
        break;
    }
}

void NWM_UDS::SendPhysicalPacket(const Network::WifiPacket& packet) {
#ifdef _WIN32
    if (!real_monitor || !real_monitor->IsRunning()) {
        return;
    }

    NetworkStatus status;
    MacAddress host_address{};
    std::optional<DataCCMPKey> ccmp_key;
    {
        std::scoped_lock lock{connection_status_mutex};
        status = connection_status.status;
        host_address = network_info.host_mac_address;
        ccmp_key = physical_data_ccmp_key;
    }

    if (packet.type == Network::WifiPacket::PacketType::Beacon ||
        packet.type == Network::WifiPacket::PacketType::NodeMap ||
        status == NetworkStatus::NotConnected) {
        return;
    }

    const MacAddress transmitter = packet.transmitter_address;
    const MacAddress destination = packet.destination_address;
    std::vector<u8> frame;
    switch (packet.type) {
    case Network::WifiPacket::PacketType::Authentication:
        frame = GeneratePhysicalManagementFrame(0x00B0, transmitter, destination, host_address,
                                                physical_tx_sequence_number++, packet.data);
        break;
    case Network::WifiPacket::PacketType::AssociationResponse: {
        std::vector<u8> body = packet.data;
        // Supply the standard rate IEs omitted by the room-multiplayer representation.
        constexpr std::array<u8, 8> SupportedRates{0x82, 0x84, 0x8B, 0x96,
                                                   0x0C, 0x12, 0x18, 0x24};
        constexpr std::array<u8, 4> ExtendedRates{0x30, 0x48, 0x60, 0x6C};
        body.push_back(1);
        body.push_back(static_cast<u8>(SupportedRates.size()));
        body.insert(body.end(), SupportedRates.begin(), SupportedRates.end());
        body.push_back(50);
        body.push_back(static_cast<u8>(ExtendedRates.size()));
        body.insert(body.end(), ExtendedRates.begin(), ExtendedRates.end());
        frame = GeneratePhysicalManagementFrame(0x0010, transmitter, destination, host_address,
                                                physical_tx_sequence_number++, body);
        break;
    }
    case Network::WifiPacket::PacketType::Deauthentication:
        frame = GeneratePhysicalManagementFrame(0x00C0, transmitter, destination, host_address,
                                                physical_tx_sequence_number++, packet.data);
        break;
    case Network::WifiPacket::PacketType::Data: {
        if (!ccmp_key) {
            LOG_WARNING(Service_NWM,
                        "UDS Real: physical data TX skipped because no CCMP key is configured");
            return;
        }
        // Deliberate rollback to the last proven transport. The 2026-09-17 10:43 and 11:20
        // tests exchanged bidirectional Pokemon SecureData when every protected frame used the
        // software CCMP/monitor-injection path. Enabling the companion kernel AP displaced that
        // working path and introduced separate CCMP state plus host-stack traffic on udsap0.
        const bool from_ds = status == NetworkStatus::ConnectedAsHost;
        const u64 packet_number = physical_tx_packet_number++;
        const u16 dot11_sequence = physical_tx_sequence_number++;
        frame = GeneratePhysicalDataFrame(packet.data, *ccmp_key, transmitter, destination,
                                          host_address, from_ds, packet_number, dot11_sequence);

        if (packet.data.size() >= sizeof(LLCHeader) &&
            GetFrameEtherType(packet.data) == EtherType::EAPoL) {
            LOG_INFO(Service_NWM,
                     "UDS JOIN TRACE TX EAPOL MPDU: dot11Sequence={}, ccmpPN={}, broadcast={}, "
                     "fromDS={}, destinationMac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, "
                     "plaintextBytes={}, plaintextFingerprint=0x{:08X}, mpduBytes={}, "
                     "mpduFingerprint=0x{:08X}, mpdu={}",
                     dot11_sequence, packet_number, destination == Network::BroadcastMac,
                     from_ds, destination[0], destination[1], destination[2], destination[3],
                     destination[4], destination[5], packet.data.size(),
                     FingerprintBytes(packet.data), frame.size(), FingerprintBytes(frame),
                     FormatHexBytes(frame));
        }

        if (packet.data.size() >= sizeof(LLCHeader) + sizeof(SecureDataHeader) &&
            GetFrameEtherType(packet.data) == EtherType::SecureData) {
            const auto secure_data = ParseSecureDataHeader(packet.data);
            if (!secure_data.is_management) {
                LOG_INFO(Service_NWM,
                         "UDS DATA TRACE TX MPDU: channel={}, secureSequence={}, "
                         "sourceNode={}, destinationNode={}, protocolSize={}, secureDataSize={}, "
                         "dot11Sequence={}, ccmpPN={}, broadcast={}, fromDS={}, dsMode={}, "
                         "destinationMac={:02X}:{:02X}:{:02X}:"
                         "{:02X}:{:02X}:{:02X}, plaintextBytes={}, plaintextFingerprint="
                         "0x{:08X}, plaintext={}, mpduBytes={}, mpduFingerprint=0x{:08X}, "
                         "mpdu={}",
                         secure_data.data_channel,
                         static_cast<u16>(secure_data.sequence_number),
                         static_cast<u16>(secure_data.src_node_id),
                         static_cast<u16>(secure_data.dest_node_id),
                         static_cast<u16>(secure_data.protocol_size),
                         static_cast<u16>(secure_data.securedata_size), dot11_sequence,
                         packet_number, destination == Network::BroadcastMac, from_ds,
                         from_ds ? "FromDS"
                                 : (destination == Network::BroadcastMac ? "NoDS" : "ToDS"),
                         destination[0], destination[1], destination[2], destination[3],
                         destination[4], destination[5], packet.data.size(),
                         FingerprintBytes(packet.data), FormatHexBytes(packet.data), frame.size(),
                         FingerprintBytes(frame), FormatHexBytes(frame));
            } else {
                LOG_INFO(Service_NWM,
                         "UDS CONTROL TRACE TX MPDU: channel={}, secureSequence={}, "
                         "sourceNode={}, destinationNode={}, protocolSize={}, secureDataSize={}, "
                         "dot11Sequence={}, ccmpPN={}, destinationMac={:02X}:{:02X}:{:02X}:"
                         "{:02X}:{:02X}:{:02X}, plaintextBytes={}, plaintextFingerprint="
                         "0x{:08X}, plaintext={}, mpduBytes={}, mpduFingerprint=0x{:08X}, "
                         "mpdu={}",
                         secure_data.data_channel,
                         static_cast<u16>(secure_data.sequence_number),
                         static_cast<u16>(secure_data.src_node_id),
                         static_cast<u16>(secure_data.dest_node_id),
                         static_cast<u16>(secure_data.protocol_size),
                         static_cast<u16>(secure_data.securedata_size), dot11_sequence,
                         packet_number, destination[0], destination[1], destination[2],
                         destination[3], destination[4], destination[5], packet.data.size(),
                         FingerprintBytes(packet.data), FormatHexBytes(packet.data), frame.size(),
                         FingerprintBytes(frame), FormatHexBytes(frame));
            }
        }
        break;
    }
    default:
        return;
    }

    if (!frame.empty()) {
        real_monitor->SubmitFrame(frame);
    }
#else
    (void)packet;
#endif
}

void NWM_UDS::SendPhysicalAssociationRequest(const MacAddress& host_address) {
#ifdef _WIN32
    if (!real_monitor || !real_monitor->IsRunning()) {
        return;
    }

    u32 network_id{};
    u8 channel{};
    {
        std::scoped_lock lock{connection_status_mutex};
        if (connection_status.status != NetworkStatus::Connecting) {
            return;
        }
        network_id = static_cast<u32>(network_info.network_id);
        channel = network_channel;
    }

    // Retail Pokemon X association request captured on the air:
    //   capability=0x0431, listen interval=1
    //   SSID=<network id as eight uppercase hexadecimal characters>
    //   supported rates=82 84 8B 0C 12 96 18 24
    //   extended rates=30 48 60 6C
    std::vector<u8> body;
    body.reserve(30);
    AppendU16(body, 0x0431);
    AppendU16(body, 1);

    body.push_back(static_cast<u8>(TagId::SSID));
    body.push_back(8);
    constexpr char Hex[] = "0123456789ABCDEF";
    for (int shift = 28; shift >= 0; shift -= 4) {
        body.push_back(static_cast<u8>(Hex[(network_id >> shift) & 0x0F]));
    }

    constexpr std::array<u8, 8> SupportedRates{0x82, 0x84, 0x8B, 0x0C,
                                               0x12, 0x96, 0x18, 0x24};
    constexpr std::array<u8, 4> ExtendedRates{0x30, 0x48, 0x60, 0x6C};
    body.push_back(static_cast<u8>(TagId::SupportedRates));
    body.push_back(static_cast<u8>(SupportedRates.size()));
    body.insert(body.end(), SupportedRates.begin(), SupportedRates.end());
    body.push_back(50); // Extended Supported Rates.
    body.push_back(static_cast<u8>(ExtendedRates.size()));
    body.insert(body.end(), ExtendedRates.begin(), ExtendedRates.end());

    const MacAddress transmitter = GetMacAddress();
    const u16 dot11_sequence = physical_tx_sequence_number++;
    const std::vector<u8> frame =
        GeneratePhysicalManagementFrame(0x0000, transmitter, host_address, host_address,
                                        dot11_sequence, body);

    LOG_INFO(Service_NWM,
             "UDS JOIN TRACE TX ASSOCIATION REQUEST: dot11Sequence={}, channel={}, "
             "source={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, "
             "host={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, networkId=0x{:08X}, "
             "bodyBytes={}, bodyFingerprint=0x{:08X}, body={}, mpduBytes={}, "
             "mpduFingerprint=0x{:08X}, mpdu={}",
             dot11_sequence, channel, transmitter[0], transmitter[1], transmitter[2],
             transmitter[3], transmitter[4], transmitter[5], host_address[0], host_address[1],
             host_address[2], host_address[3], host_address[4], host_address[5], network_id,
             body.size(), FingerprintBytes(body), FormatHexBytes(body), frame.size(),
             FingerprintBytes(frame), FormatHexBytes(frame));

    real_monitor->SubmitFrame(frame);
#else
    (void)host_address;
#endif
}

void NWM_UDS::OnPhysicalFrameReceived(UdsReal::CapturedFrame frame) {
#ifdef _WIN32
    ++physical_rx_frame_count;

    Network::WifiPacket packet{};
    packet.channel = frame.channel;
    packet.transmitter_address = frame.transmitter_address;
    packet.destination_address = frame.destination_address;

    std::optional<u64> received_packet_number;
    if (frame.type == 0) {
        switch (frame.subtype) {
        case 11: // Authentication.
            if (frame.body.size() < sizeof(AuthenticationFrame)) {
                LOG_WARNING(Service_NWM, "UDS Real: truncated physical authentication frame");
                return;
            }
            if (real_monitor) {
                real_monitor->ActivateAccessPoint();
            }
            packet.type = Network::WifiPacket::PacketType::Authentication;
            packet.data = std::move(frame.body);
            break;
        case 1: // Association response.
            if (frame.body.size() < sizeof(AssociationResponseFrame)) {
                LOG_WARNING(Service_NWM, "UDS Real: truncated physical association response");
                return;
            }
            packet.type = Network::WifiPacket::PacketType::AssociationResponse;
            packet.data = std::move(frame.body);
            break;
        case 12: // Deauthentication.
            if (real_monitor) {
                real_monitor->RemoveAccessPointStation(frame.transmitter_address);
            }
            if (frame.body.size() >= 2) {
                const u16 reason = static_cast<u16>(frame.body[0]) |
                                   (static_cast<u16>(frame.body[1]) << 8);
                LOG_INFO(Service_NWM,
                         "UDS Real: received physical deauthentication from "
                         "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, reason={}",
                         frame.transmitter_address[0], frame.transmitter_address[1],
                         frame.transmitter_address[2], frame.transmitter_address[3],
                         frame.transmitter_address[4], frame.transmitter_address[5], reason);
            }
            packet.type = Network::WifiPacket::PacketType::Deauthentication;
            packet.data = std::move(frame.body);
            break;
        case 0: // Association request.
            LOG_INFO(Service_NWM,
                     "UDS Real: observed physical association request from {:02X}:{:02X}:"
                     "{:02X}:{:02X}:{:02X}:{:02X}; sending association response",
                     frame.transmitter_address[0], frame.transmitter_address[1],
                     frame.transmitter_address[2], frame.transmitter_address[3],
                     frame.transmitter_address[4], frame.transmitter_address[5]);
            if (real_monitor) {
                real_monitor->RegisterAccessPointStation(frame.transmitter_address, frame.body);
            }
            SendAssociationResponseFrame(frame.transmitter_address);
            return;
        default:
            return;
        }
    } else if (frame.type == 2) {
        packet.type = Network::WifiPacket::PacketType::Data;
        const bool protected_frame = (frame.frame_control & 0x4000) != 0;
        if (!protected_frame) {
            packet.data = std::move(frame.body);
        } else {
            if (frame.body.size() < 16 || (frame.body[3] & 0x20) == 0) {
                LOG_WARNING(Service_NWM, "UDS Real: malformed physical CCMP data frame");
                return;
            }

            std::optional<DataCCMPKey> ccmp_key;
            {
                std::scoped_lock lock{connection_status_mutex};
                ccmp_key = physical_data_ccmp_key;
            }
            if (!ccmp_key) {
                LOG_WARNING(Service_NWM,
                            "UDS Real: protected physical data received without a CCMP key");
                return;
            }

            const u64 packet_number = ReadCCMPPacketNumber(
                std::span<const u8>{frame.body.data(), std::size_t{8}});
            received_packet_number = packet_number;
            auto decrypted = DecryptDataFrame(
                std::span<const u8>{frame.body.data() + 8, frame.body.size() - 8}, *ccmp_key,
                frame.transmitter_address, frame.destination_address, frame.bssid, packet_number,
                frame.frame_control, frame.sequence_control);
            if (!decrypted) {
                ++physical_rx_ccmp_failure_count;
                if (physical_rx_ccmp_failure_count <= 20 ||
                    physical_rx_ccmp_failure_count % 100 == 0) {
                    LOG_WARNING(Service_NWM,
                                "UDS Real: CCMP authentication failed for physical RX #{} "
                                "(failure #{}, packetNumber={})",
                                physical_rx_frame_count, physical_rx_ccmp_failure_count,
                                packet_number);
                }
                return;
            }
            packet.data = std::move(*decrypted);
        }

        if (packet.data.size() < sizeof(LLCHeader) || packet.data[0] != 0xAA ||
            packet.data[1] != 0xAA || packet.data[2] != 0x03) {
            LOG_WARNING(Service_NWM,
                        "UDS Real: physical data frame did not contain a Nintendo SNAP payload");
            return;
        }

        if (packet.data.size() >= sizeof(LLCHeader) + sizeof(SecureDataHeader) &&
            GetFrameEtherType(packet.data) == EtherType::SecureData) {
            const auto secure_data = ParseSecureDataHeader(packet.data);
            if (!secure_data.is_management) {
                const bool retry = (frame.frame_control & 0x0800) != 0;
                LOG_INFO(Service_NWM,
                         "UDS DATA TRACE RX MPDU: channel={}, secureSequence={}, "
                         "sourceNode={}, destinationNode={}, protocolSize={}, secureDataSize={}, "
                         "dot11Sequence={}, retry={}, ccmpPN={}, broadcast={}, "
                         "sourceMac={:02X}:{:02X}:{:02X}:{:02X}:"
                         "{:02X}:{:02X}, destinationMac={:02X}:{:02X}:{:02X}:{:02X}:"
                         "{:02X}:{:02X}, mpduBodyBytes={}, mpduBodyFingerprint=0x{:08X}, "
                         "mpduBody={}",
                         secure_data.data_channel,
                         static_cast<u16>(secure_data.sequence_number),
                         static_cast<u16>(secure_data.src_node_id),
                         static_cast<u16>(secure_data.dest_node_id),
                         static_cast<u16>(secure_data.protocol_size),
                         static_cast<u16>(secure_data.securedata_size),
                         frame.sequence_control >> 4, retry, received_packet_number.value_or(0),
                         frame.destination_address == Network::BroadcastMac,
                         frame.transmitter_address[0], frame.transmitter_address[1],
                         frame.transmitter_address[2], frame.transmitter_address[3],
                         frame.transmitter_address[4], frame.transmitter_address[5],
                         frame.destination_address[0], frame.destination_address[1],
                         frame.destination_address[2], frame.destination_address[3],
                         frame.destination_address[4], frame.destination_address[5],
                         frame.body.size(), FingerprintBytes(frame.body),
                         FormatHexBytes(frame.body));
                LOG_INFO(Service_NWM,
                         "UDS DATA TRACE RX SECUREDATA: channel={}, secureSequence={}, "
                         "sourceNode={}, destinationNode={}, protocolSize={}, secureDataSize={}, "
                         "plaintextBytes={}, "
                         "plaintextFingerprint=0x{:08X}, plaintext={}",
                         secure_data.data_channel,
                         static_cast<u16>(secure_data.sequence_number),
                         static_cast<u16>(secure_data.src_node_id),
                         static_cast<u16>(secure_data.dest_node_id),
                         static_cast<u16>(secure_data.protocol_size),
                         static_cast<u16>(secure_data.securedata_size), packet.data.size(),
                         FingerprintBytes(packet.data), FormatHexBytes(packet.data));
            } else {
                LOG_INFO(Service_NWM,
                         "UDS CONTROL TRACE RX MPDU: channel={}, secureSequence={}, "
                         "sourceNode={}, destinationNode={}, protocolSize={}, secureDataSize={}, "
                         "dot11Sequence={}, retry={}, ccmpPN={}, sourceMac={:02X}:{:02X}:"
                         "{:02X}:{:02X}:{:02X}:{:02X}, destinationMac={:02X}:{:02X}:{:02X}:"
                         "{:02X}:{:02X}:{:02X}, plaintextBytes={}, plaintextFingerprint="
                         "0x{:08X}, plaintext={}, mpduBodyBytes={}, mpduBodyFingerprint="
                         "0x{:08X}, mpduBody={}",
                         secure_data.data_channel,
                         static_cast<u16>(secure_data.sequence_number),
                         static_cast<u16>(secure_data.src_node_id),
                         static_cast<u16>(secure_data.dest_node_id),
                         static_cast<u16>(secure_data.protocol_size),
                         static_cast<u16>(secure_data.securedata_size),
                         frame.sequence_control >> 4,
                         (frame.frame_control & 0x0800) != 0,
                         received_packet_number.value_or(0), frame.transmitter_address[0],
                         frame.transmitter_address[1], frame.transmitter_address[2],
                         frame.transmitter_address[3], frame.transmitter_address[4],
                         frame.transmitter_address[5], frame.destination_address[0],
                         frame.destination_address[1], frame.destination_address[2],
                         frame.destination_address[3], frame.destination_address[4],
                         frame.destination_address[5], packet.data.size(),
                         FingerprintBytes(packet.data), FormatHexBytes(packet.data),
                         frame.body.size(), FingerprintBytes(frame.body),
                         FormatHexBytes(frame.body));
            }
        } else if (packet.data.size() >= sizeof(LLCHeader) &&
                   GetFrameEtherType(packet.data) == EtherType::EAPoL) {
            LOG_INFO(Service_NWM,
                     "UDS JOIN TRACE RX EAPOL MPDU: dot11Sequence={}, retry={}, ccmpPN={}, "
                     "sourceMac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, "
                     "destinationMac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, "
                     "plaintextBytes={}, plaintextFingerprint=0x{:08X}, plaintext={}, "
                     "mpduBodyBytes={}, mpduBodyFingerprint=0x{:08X}, mpduBody={}",
                     frame.sequence_control >> 4, (frame.frame_control & 0x0800) != 0,
                     received_packet_number.value_or(0), frame.transmitter_address[0],
                     frame.transmitter_address[1], frame.transmitter_address[2],
                     frame.transmitter_address[3], frame.transmitter_address[4],
                     frame.transmitter_address[5], frame.destination_address[0],
                     frame.destination_address[1], frame.destination_address[2],
                     frame.destination_address[3], frame.destination_address[4],
                     frame.destination_address[5], packet.data.size(),
                     FingerprintBytes(packet.data), FormatHexBytes(packet.data),
                     frame.body.size(), FingerprintBytes(frame.body), FormatHexBytes(frame.body));
        }
    } else {
        return;
    }

    LOG_INFO(Service_NWM,
             "UDS Real: delivering physical frame #{}, packetType={}, source={:02X}:{:02X}:"
             "{:02X}:{:02X}:{:02X}:{:02X}, destination={:02X}:{:02X}:{:02X}:{:02X}:"
             "{:02X}:{:02X}, bodyBytes={}",
             physical_rx_frame_count, static_cast<u32>(packet.type), packet.transmitter_address[0],
             packet.transmitter_address[1], packet.transmitter_address[2],
             packet.transmitter_address[3], packet.transmitter_address[4],
             packet.transmitter_address[5], packet.destination_address[0],
             packet.destination_address[1], packet.destination_address[2],
             packet.destination_address[3], packet.destination_address[4],
             packet.destination_address[5], packet.data.size());
    OnWifiPacketReceived(packet);
#else
    (void)frame;
#endif
}

boost::optional<Network::MacAddress> NWM_UDS::GetNodeMacAddress(u16 dest_node_id, u8 flags) {
    constexpr u8 BroadcastFlag = 0x2;
    if ((flags & BroadcastFlag) || dest_node_id == BroadcastNetworkNodeId) {
        // Broadcast
        return Network::BroadcastMac;
    } else if (dest_node_id == HostDestNodeId) {
        // Destination is host
        return network_info.host_mac_address;
    }
    // Destination is a specific client
    auto destination =
        std::find_if(node_map.begin(), node_map.end(), [dest_node_id](const auto& node) {
            return node.second.node_id == dest_node_id && node.second.connected;
        });
    if (destination == node_map.end()) {
        return {};
    }
    return destination->first;
}

void NWM_UDS::ShutdownHLE() {
#ifdef _WIN32
    if (real_monitor) {
        real_monitor->Stop();
    }
#endif

    initialized = false;

    for (auto& bind_node : channel_data) {
        SignalEventAsync(bind_node.second.event);
    }
    channel_data.clear();
    node_map.clear();

    recv_buffer_memory.reset();
}

void NWM_UDS::Shutdown(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    ShutdownHLE();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ResultSuccess);
    LOG_DEBUG(Service_NWM, "called");
}

void NWM_UDS::RecvBeaconBroadcastData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    u32 out_buffer_size = rp.Pop<u32>();

    // scan input struct
    u32 unk1 = rp.Pop<u32>();
    u32 unk2 = rp.Pop<u32>();

    MacAddress mac_address;
    rp.PopRaw(mac_address);

    // uninitialized data in scan input struct
    rp.Skip(9, false);

    // end scan input struct

    u32 wlan_comm_id = rp.Pop<u32>();
    u32 id = rp.Pop<u32>();
    // From 3dbrew:
    // 'Official user processes create a new event handle which is then passed to this command.
    // However, those user processes don't save that handle anywhere afterwards.'
    // So we don't save/use that event too.
    std::shared_ptr<Kernel::Event> input_event = rp.PopObject<Kernel::Event>();

    Kernel::MappedBuffer& out_buffer = rp.PopMappedBuffer();
    ASSERT(out_buffer.GetSize() == out_buffer_size);

    std::size_t cur_buffer_size = sizeof(BeaconDataReplyHeader);

    auto beacons = GetReceivedBeacons(mac_address);

    ++beacon_scan_request_count;
    if (!beacons.empty()) {
        ++beacon_scan_nonempty_reply_count;
    }
    const bool log_scan = beacon_scan_request_count <= 8 ||
                          beacon_scan_request_count % 25 == 0 ||
                          (!beacons.empty() && beacon_scan_nonempty_reply_count <= 5);
    if (log_scan) {
        const std::size_t first_frame_size = beacons.empty() ? 0 : beacons.front().data.size();
        LOG_INFO(Service_NWM,
                 "UDS Real: game beacon scan #{}, filterMac={:02X}:{:02X}:{:02X}:{:02X}:"
                 "{:02X}:{:02X}, wlanCommId=0x{:08X}, id={}, queuedReplyCount={}, "
                 "firstFrameBytes={}, outputCapacity={}",
                 beacon_scan_request_count, mac_address[0], mac_address[1], mac_address[2],
                 mac_address[3], mac_address[4], mac_address[5], wlan_comm_id, id,
                 beacons.size(), first_frame_size, out_buffer_size);
    }

    BeaconDataReplyHeader data_reply_header{};
    data_reply_header.total_entries = static_cast<u32>(beacons.size());
    data_reply_header.max_output_size = out_buffer_size;

    // Write each of the received beacons into the buffer
    for (const auto& beacon : beacons) {
        BeaconEntryHeader entry{};
        // TODO(Subv): Figure out what this size is used for.
        entry.unk_size = static_cast<u32>(sizeof(BeaconEntryHeader) + beacon.data.size());
        entry.total_size = static_cast<u32>(sizeof(BeaconEntryHeader) + beacon.data.size());
        entry.wifi_channel = beacon.channel;
        entry.header_size = sizeof(BeaconEntryHeader);
        entry.mac_address = beacon.transmitter_address;

        ASSERT(cur_buffer_size < out_buffer_size);

        out_buffer.Write(&entry, cur_buffer_size, sizeof(BeaconEntryHeader));
        cur_buffer_size += sizeof(BeaconEntryHeader);
        const unsigned char* beacon_data = beacon.data.data();
        out_buffer.Write(beacon_data, cur_buffer_size, beacon.data.size());
        cur_buffer_size += beacon.data.size();
    }

    // Update the total size in the structure and write it to the buffer again.
    data_reply_header.total_size = static_cast<u32>(cur_buffer_size);
    out_buffer.Write(&data_reply_header, 0, sizeof(BeaconDataReplyHeader));

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(ResultSuccess);
    rb.PushMappedBuffer(out_buffer);

    // on a real 3ds this is about 0.38 seconds
    static constexpr std::chrono::nanoseconds UDSBeaconScanInterval{300000000};

    ctx.SleepClientThread("uds::RecvBeaconBroadcastData", UDSBeaconScanInterval, nullptr);

    LOG_DEBUG(Service_NWM,
              "called out_buffer_size=0x{:08X}, wlan_comm_id=0x{:08X}, id=0x{:08X},"
              "unk1=0x{:08X}, unk2=0x{:08X}, offset={}",
              out_buffer_size, wlan_comm_id, id, unk1, unk2, cur_buffer_size);
}

void NWM_UDS::SetProbeResponseParam(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    const u32 oui_type = rp.Pop<u32>();
    const u32 data = rp.Pop<u32>();
    const bool changed = !have_probe_response_param || probe_response_oui_type != oui_type ||
                         probe_response_data != data;
    have_probe_response_param = true;
    probe_response_oui_type = oui_type;
    probe_response_data = data;

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ResultSuccess);

    if (changed) {
        LOG_INFO(Service_NWM,
                 "UDS Real: SetProbeResponseParam accepted ouiType=0x{:08X} "
                 "(bytes={:02X}:{:02X}:{:02X}:{:02X}), data=0x{:08X} "
                 "(bytes={:02X}:{:02X}:{:02X}:{:02X}); physical probe-response transmission "
                 "not yet implemented",
                 oui_type, static_cast<u8>(oui_type), static_cast<u8>(oui_type >> 8),
                 static_cast<u8>(oui_type >> 16), static_cast<u8>(oui_type >> 24), data,
                 static_cast<u8>(data), static_cast<u8>(data >> 8),
                 static_cast<u8>(data >> 16), static_cast<u8>(data >> 24));
    }
}

void NWM_UDS::Unknown0x23(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(ResultSuccess);
    rb.Push<u16>(0);
    LOG_INFO(Service_NWM,
             "UDS Real: guest IPC command nwm::UDS 0x23 returned success with output=0; no "
             "wireless packet was received or transmitted");
}

ResultVal<std::shared_ptr<Kernel::Event>> NWM_UDS::Initialize(
    u32 sharedmem_size, const NodeInfo& node, u16 version,
    std::shared_ptr<Kernel::SharedMemory> sharedmem) {

    current_node = node;
    initialized = true;
    connection_status_trace_count = 0;

    RunOfflineDecryptDiagnostic();

    LOG_INFO(Service_NWM,
             "UDS STATE TRACE Initialize: version=0x{:04X}, nodeId={}, "
             "friendCodeSeedNonzero={}, friendCodeSeedFingerprint=0x{:08X}, "
             "usernameFingerprint=0x{:08X}, nodeFingerprint=0x{:08X}",
             version, static_cast<u16>(current_node.network_node_id),
             static_cast<u64>(current_node.friend_code_seed) != 0,
             FingerprintFriendCodeSeed(current_node), FingerprintUsername(current_node),
             FingerprintNodeInfo(current_node));

    recv_buffer_memory = std::move(sharedmem);
    ASSERT_MSG(recv_buffer_memory->GetSize() == sharedmem_size, "Invalid shared memory size.");

    {
        std::scoped_lock lock(connection_status_mutex);

        // Reset the connection status, it contains all zeros after initialization,
        // except for the actual status value.
        connection_status = {};
        connection_status.status = NetworkStatus::NotConnected;
        node_info.clear();
        node_info.push_back(current_node);
        channel_data.clear();
    }

#ifdef _WIN32
    if (!real_monitor) {
        real_monitor = std::make_unique<UdsReal::Nl80211Monitor>();
    }
    if (!real_monitor->IsRunning()) {
        real_monitor->Start(
            network_channel, GetMacAddress(), [this](UdsReal::CapturedBeacon beacon) {
                Network::WifiPacket packet{};
                packet.type = Network::WifiPacket::PacketType::Beacon;
                packet.data = std::move(beacon.frame);
                packet.transmitter_address = beacon.transmitter_address;
                packet.destination_address = beacon.destination_address;
                packet.channel = beacon.channel;
                HandleBeaconFrame(packet);
            },
            [this](UdsReal::CapturedFrame frame) {
                OnPhysicalFrameReceived(std::move(frame));
            });
        LOG_INFO(Service_NWM, "UDS Real: physical beacon monitor requested by nwm::UDS");
    }
#endif

    return connection_status_event;
}

// allows people who haven't set up their
// 3ds to play local play on games which
// require a unique friend code seed
void NWM_UDS::CheckSpoofFriendCodeSeed(Kernel::HLERequestContext& ctx, NodeInfo& node) {
    u64 caller_tid = ctx.ClientThread()->owner_process.lock()->codeset->program_id;
    if (Common::Hacks::hack_manager.GetHackAllowMode(
            Common::Hacks::HackType::SPOOF_FRIEND_CODE_SEED, caller_tid,
            Common::Hacks::HackAllowMode::DISALLOW) == Common::Hacks::HackAllowMode::FORCE) {
        auto mac_address = GetMacAddress();
        memcpy(&node.friend_code_seed, mac_address.data(), mac_address.size());
    }
}

void NWM_UDS::InitializeWithVersion(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    u32 sharedmem_size = rp.Pop<u32>();
    auto node = rp.PopRaw<NodeInfo>();
    u16 version = rp.Pop<u16>();
    auto sharedmem = rp.PopObject<Kernel::SharedMemory>();

    CheckSpoofFriendCodeSeed(ctx, node);

    auto result = Initialize(sharedmem_size, node, version, std::move(sharedmem));

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(result.Code());
    rb.PushCopyObjects(result.ValueOr(nullptr));

    LOG_DEBUG(Service_NWM, "called sharedmem_size=0x{:08X}, version=0x{:08X}", sharedmem_size,
              version);
}

void NWM_UDS::InitializeDeprecated(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    u32 sharedmem_size = rp.Pop<u32>();
    auto node = rp.PopRaw<NodeInfo>();
    auto sharedmem = rp.PopObject<Kernel::SharedMemory>();

    CheckSpoofFriendCodeSeed(ctx, node);

    // The deprecated version uses fixed 0x100 as the version
    auto result = Initialize(sharedmem_size, node, 0x100, std::move(sharedmem));

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(result.Code());
    rb.PushCopyObjects(result.ValueOr(nullptr));

    LOG_DEBUG(Service_NWM, "called sharedmem_size=0x{:08X}", sharedmem_size);
}

ConnectionStatus NWM_UDS::GetConnectionStatusHLE() {
    std::scoped_lock lock(connection_status_mutex);
    ConnectionStatus cs_out = connection_status;

    if (connection_status_trace_count < 8 || cs_out.changed_nodes != 0) {
        // rawBytes/rawStruct dump the entire IPC response exactly as it will be pushed to the
        // game via PushRaw, including the nodes[UDSMaxNodes] array and any padding, none of which
        // 3dbrew documents for this specific command. Since this struct's exact layout has never
        // been independently verified against real hardware (unlike the wire-protocol frames),
        // this lets us check every byte the game actually receives, not just the summary fields.
        const std::span<const u8> raw_bytes{reinterpret_cast<const u8*>(&cs_out), sizeof(cs_out)};
        LOG_INFO(Service_NWM,
                 "UDS STATE TRACE GetConnectionStatus #{}: status={}, reason={}, nodeId={}, "
                 "totalNodes={}, maxNodes={}, nodeBitmask=0x{:04X}, changedNodes=0x{:04X}, "
                 "nodesArray=[{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}], "
                 "stateFingerprint=0x{:08X}, rawBytes={}, rawStruct={}",
                 connection_status_trace_count + 1, static_cast<u32>(cs_out.status),
                 static_cast<u32>(cs_out.status_change_reason),
                 static_cast<u16>(cs_out.network_node_id), cs_out.total_nodes, cs_out.max_nodes,
                 static_cast<u16>(cs_out.node_bitmask), static_cast<u16>(cs_out.changed_nodes),
                 static_cast<u16>(cs_out.nodes[0]), static_cast<u16>(cs_out.nodes[1]),
                 static_cast<u16>(cs_out.nodes[2]), static_cast<u16>(cs_out.nodes[3]),
                 static_cast<u16>(cs_out.nodes[4]), static_cast<u16>(cs_out.nodes[5]),
                 static_cast<u16>(cs_out.nodes[6]), static_cast<u16>(cs_out.nodes[7]),
                 static_cast<u16>(cs_out.nodes[8]), static_cast<u16>(cs_out.nodes[9]),
                 static_cast<u16>(cs_out.nodes[10]), static_cast<u16>(cs_out.nodes[11]),
                 static_cast<u16>(cs_out.nodes[12]), static_cast<u16>(cs_out.nodes[13]),
                 static_cast<u16>(cs_out.nodes[14]), static_cast<u16>(cs_out.nodes[15]),
                 FingerprintBytes(raw_bytes), raw_bytes.size(), FormatHexBytes(raw_bytes));
    }
    ++connection_status_trace_count;

    // Reset the bitmask of changed nodes after each call to this
    // function to prevent falsely informing games of outstanding
    // changes in subsequent calls.
    // TODO(Subv): Find exactly where the NWM module resets this value.
    connection_status.changed_nodes = 0;

    return cs_out;
}

void NWM_UDS::GetConnectionStatus(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    IPC::RequestBuilder rb = rp.MakeBuilder(13, 0);

    rb.Push(ResultSuccess);
    rb.PushRaw(GetConnectionStatusHLE());

    LOG_DEBUG(Service_NWM, "called");
}

std::unique_ptr<NodeInfo> NWM_UDS::GetNodeInformationHLE(u16 network_node_id) {
    std::scoped_lock lock(connection_status_mutex);
    auto itr =
        std::find_if(node_info.begin(), node_info.end(), [network_node_id](const NodeInfo& node) {
            return node.network_node_id == network_node_id;
        });
    if (itr == node_info.end()) {
        return nullptr;
    }
    return std::make_unique<NodeInfo>(*itr);
}

void NWM_UDS::GetNodeInformation(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    u16 network_node_id = rp.Pop<u16>();

    if (!initialized) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(Result(ErrorDescription::NotInitialized, ErrorModule::UDS,
                       ErrorSummary::StatusChanged, ErrorLevel::Status));
        return;
    }

    {
        auto node = GetNodeInformationHLE(network_node_id);
        if (!node) {
            IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
            rb.Push(Result(ErrorDescription::NotFound, ErrorModule::UDS,
                           ErrorSummary::WrongArgument, ErrorLevel::Status));
            return;
        }

        IPC::RequestBuilder rb = rp.MakeBuilder(11, 0);
        rb.Push(ResultSuccess);
        rb.PushRaw<NodeInfo>(*node);

        LOG_INFO(Service_NWM,
                 "UDS STATE TRACE GetNodeInformation: requestedNodeId={}, returnedNodeId={}, "
                 "friendCodeSeedNonzero={}, friendCodeSeedFingerprint=0x{:08X}, "
                 "usernameFingerprint=0x{:08X}, nodeFingerprint=0x{:08X}",
                 network_node_id, static_cast<u16>(node->network_node_id),
                 static_cast<u64>(node->friend_code_seed) != 0,
                 FingerprintFriendCodeSeed(*node), FingerprintUsername(*node),
                 FingerprintNodeInfo(*node));
    }
    LOG_DEBUG(Service_NWM, "called");
}

std::pair<ResultStatus, std::shared_ptr<Kernel::Event>> NWM_UDS::BindHLE(u32 bind_node_id,
                                                                         u32 recv_buffer_size,
                                                                         u8 data_channel,
                                                                         u16 network_node_id) {
    if (data_channel == 0 || bind_node_id == 0) {
        LOG_WARNING(Service_NWM, "data_channel = {}, bind_node_id = {}", data_channel,
                    bind_node_id);
        return std::make_pair(ResultStatus::BindError_ArgsZero, nullptr);
    }

    constexpr std::size_t MaxBindNodes = 16;
    if (channel_data.size() >= MaxBindNodes) {
        LOG_WARNING(Service_NWM, "max bind nodes");
        return std::make_pair(ResultStatus::BindError_MaxBinds, nullptr);
    }

    constexpr u32 MinRecvBufferSize = 0x5F4;
    if (recv_buffer_size < MinRecvBufferSize) {
        LOG_WARNING(Service_NWM, "MinRecvBufferSize");
        return std::make_pair(ResultStatus::BindError_RecvBufferTooLarge, nullptr);
    }

    // Create a new event for this bind node.
    auto event = system.Kernel().CreateEvent(Kernel::ResetType::OneShot,
                                             "NWM::BindNodeEvent" + std::to_string(bind_node_id));
    std::scoped_lock lock(connection_status_mutex);

    ASSERT(channel_data.find(data_channel) == channel_data.end());
    // TODO(B3N30): Support more than one bind node per channel.
    channel_data[data_channel] = {bind_node_id, data_channel, network_node_id, event};
    return std::make_pair(ResultStatus::ResultSuccess, std::move(event));
}

void NWM_UDS::Bind(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    u32 bind_node_id = rp.Pop<u32>();
    u32 recv_buffer_size = rp.Pop<u32>();
    u8 data_channel = rp.Pop<u8>();
    u16 network_node_id = rp.Pop<u16>();

    auto [ret, event] = BindHLE(bind_node_id, recv_buffer_size, data_channel, network_node_id);

    switch (ret) {
    case ResultStatus::BindError_ArgsZero: {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(Result(ErrorDescription::NotAuthorized, ErrorModule::UDS,
                       ErrorSummary::WrongArgument, ErrorLevel::Usage));
        return;
    }
    case ResultStatus::BindError_MaxBinds: {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(Result(ErrorDescription::OutOfMemory, ErrorModule::UDS, ErrorSummary::OutOfResource,
                       ErrorLevel::Status));
        return;
    }
    case ResultStatus::BindError_RecvBufferTooLarge: {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(Result(ErrorDescription::TooLarge, ErrorModule::UDS, ErrorSummary::WrongArgument,
                       ErrorLevel::Usage));
        return;
    }
    default:;
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(ResultSuccess);
    rb.PushCopyObjects(event);
}

void NWM_UDS::UnbindHLE(u32 bind_node_id) {
    std::scoped_lock lock(connection_status_mutex);

    auto itr =
        std::find_if(channel_data.begin(), channel_data.end(), [bind_node_id](const auto& data) {
            return data.second.bind_node_id == bind_node_id;
        });

    if (itr != channel_data.end()) {
        // TODO(B3N30): Check out what Unbind does if the bind_node_id wasn't in the map
        SignalEventAsync(itr->second.event);
        channel_data.erase(itr);
    }
}

void NWM_UDS::Unbind(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    u32 bind_node_id = rp.Pop<u32>();
    if (bind_node_id == 0) {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(Result(ErrorDescription::NotAuthorized, ErrorModule::UDS,
                       ErrorSummary::WrongArgument, ErrorLevel::Usage));
        return;
    }

    UnbindHLE(bind_node_id);

    IPC::RequestBuilder rb = rp.MakeBuilder(5, 0);
    rb.Push(ResultSuccess);
    rb.Push(bind_node_id);
    // TODO(B3N30): Find out what the other return values are
    rb.Push<u32>(0);
    rb.Push<u32>(0);
    rb.Push<u32>(0);
}

Result NWM_UDS::BeginHostingNetwork(std::span<const u8> network_info_buffer,
                                    std::vector<u8> passphrase) {
    {
        std::scoped_lock lock(connection_status_mutex);
        network_info = {};
        std::memcpy(&network_info, network_info_buffer.data(), network_info_buffer.size());

        // The real UDS module throws a fatal error if this assert fails.
        ASSERT_MSG(network_info.max_nodes > 1, "Trying to host a network of only one member.");

        connection_status.status = NetworkStatus::ConnectedAsHost;
        connection_status.status_change_reason = NetworkStatusChangeReason::ConnectionEstablished;

        // Ensure the application data size is less than the maximum value.
        ASSERT_MSG(network_info.application_data_size <= ApplicationDataSize,
                   "Data size is too big.");

        // Set up basic information for this network.
        network_info.oui_value = NintendoOUI;
        network_info.oui_type = static_cast<u8>(NintendoTagId::NetworkInfo);

        connection_status.max_nodes = network_info.max_nodes;

        // Resize the nodes list to hold max_nodes.
        node_info.clear();
        node_info.resize(network_info.max_nodes);

        // There's currently only one node in the network (the host).
        connection_status.total_nodes = 1;
        network_info.total_nodes = 1;

        // The host is always the first node
        connection_status.network_node_id = 1;
        current_node.network_node_id = 1;
        connection_status.nodes[0] = connection_status.network_node_id;
        // Set the bit 0 in the nodes bitmask to indicate that node 1 is already taken.
        connection_status.node_bitmask |= 1;
        // Notify the application that the first node was set.
        connection_status.changed_nodes |= 1;

        network_info.host_mac_address = GetMacAddress();

        // The retail NWM service generates a new nonzero network id when the application asks it
        // to create a network. Pokemon supplies zero and expects NWM to fill this field; the id is
        // also advertised as the eight-character UDS SSID and participates in beacon encryption.
        if (static_cast<u32>(network_info.network_id) == 0) {
            CryptoPP::AutoSeededRandomPool random;
            network_info.network_id = random.GenerateWord32(1, 0xFFFFFFFFU);
        }

        node_info[0] = current_node;

        // Room multiplayer carries plaintext WifiPacket bodies, but the retail radio encrypts
        // every data MPDU with the network's pre-shared UDS CCMP key.
        physical_data_ccmp_key = GenerateDataCCMPKey(passphrase, network_info);
        secure_data_tx_sequence_number = 0;
        physical_tx_packet_number = 1;
        physical_tx_sequence_number = 0;
        physical_association_request_sent = false;
        association_response_handled = false;
        physical_rx_frame_count = 0;
        physical_rx_ccmp_failure_count = 0;
        physical_management_reply_sequences.clear();
        last_eapol_frame_data.clear();

        // If the game has a preferred channel, use that instead.
        if (network_info.channel != 0)
            network_channel = network_info.channel;
        else
            network_info.channel = DefaultNetworkChannel;
    }

    ++begin_hosting_request_count;
    const std::size_t application_data_size =
        std::min<std::size_t>(network_info.application_data_size, ApplicationDataSize);
    const u32 application_fingerprint = FingerprintBytes(std::span<const u8>{
        network_info.application_data.data(), application_data_size});
    LOG_INFO(Service_NWM,
             "UDS Real: BeginHostingNetwork #{}, hostMac={:02X}:{:02X}:{:02X}:{:02X}:"
             "{:02X}:{:02X}, wlanCommId=0x{:08X}, id={}, networkId=0x{:08X}, channel={}, "
             "maxNodes={}, applicationDataSize={}, applicationFingerprint=0x{:08X}; "
             "Azahar beacon generation scheduled",
             begin_hosting_request_count, network_info.host_mac_address[0],
             network_info.host_mac_address[1], network_info.host_mac_address[2],
             network_info.host_mac_address[3], network_info.host_mac_address[4],
             network_info.host_mac_address[5], static_cast<u32>(network_info.wlan_comm_id),
             network_info.id, static_cast<u32>(network_info.network_id), network_channel,
             network_info.max_nodes, application_data_size, application_fingerprint);

#ifdef _WIN32
    if (real_monitor && physical_data_ccmp_key) {
        const u8 maximum_clients = network_info.max_nodes > 1 ? network_info.max_nodes - 1 : 1;
        real_monitor->ConfigureAccessPoint(network_info.host_mac_address,
                                           *physical_data_ccmp_key,
                                           static_cast<u32>(network_info.network_id),
                                           maximum_clients);
    }
#endif

    SignalEventAsync(connection_status_event);

    // Start broadcasting the network, send a beacon frame every 102.4ms.
    system.CoreTiming().ScheduleEvent(msToCycles(DefaultBeaconInterval * MillisecondsPerTU),
                                      beacon_broadcast_event, 0);

    return ResultSuccess;
}

void NWM_UDS::BeginHostingNetwork(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    const u32 passphrase_size = rp.Pop<u32>();

    const std::vector<u8> network_info_buffer = rp.PopStaticBuffer();
    ASSERT(network_info_buffer.size() == sizeof(NetworkInfo));
    std::vector<u8> passphrase = rp.PopStaticBuffer();
    ASSERT(passphrase.size() == passphrase_size);

    LOG_DEBUG(Service_NWM, "called");
    auto result = BeginHostingNetwork(network_info_buffer, std::move(passphrase));
    LOG_DEBUG(Service_NWM, "An UDS network has been created.");

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(result);
}

void NWM_UDS::BeginHostingNetworkDeprecated(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    // Real NWM module reads 0x108 bytes from the command buffer into the network info, where the
    // last 0xCC bytes (application_data and size) are undefined values. Here we just read the first
    // 0x3C defined bytes and zero application_data in BeginHostingNetwork.
    const auto network_info_buffer = rp.PopRaw<std::array<u8, 0x3C>>();
    const u32 passphrase_size = rp.Pop<u32>();
    std::vector<u8> passphrase = rp.PopStaticBuffer();
    ASSERT(passphrase.size() == passphrase_size);

    LOG_DEBUG(Service_NWM, "called");
    auto result = BeginHostingNetwork(network_info_buffer, std::move(passphrase));
    LOG_DEBUG(Service_NWM, "An UDS network has been created.");

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(result);
}

Result NWM_UDS::EjectClientHLE(u16 network_node_id) {
    // The host can not be kicked.
    if (network_node_id == 1) {
        return Result(ErrorDescription::NotAuthorized, ErrorModule::UDS,
                      ErrorSummary::WrongArgument, ErrorLevel::Usage);
    }

    std::scoped_lock lock(connection_status_mutex);
    if (connection_status.status != NetworkStatus::ConnectedAsHost) {
        // Only the host can kick people.
        LOG_WARNING(Service_NWM, "called with status {}", connection_status.status);
        return Result(ErrorDescription::NotAuthorized, ErrorModule::UDS, ErrorSummary::InvalidState,
                      ErrorLevel::Usage);
    }

    using Network::WifiPacket;
    Network::MacAddress dest_address = Network::BroadcastMac;

    if (network_node_id != BroadcastNetworkNodeId) {
        auto address = GetNodeMacAddress(network_node_id, 0);

        if (!address) {
            // There is no error if the network node id was not found.
            return ResultSuccess;
        }
        dest_address = *address;
    }

    WifiPacket deauth;
    deauth.channel = network_channel;
    deauth.destination_address = dest_address;
    deauth.type = WifiPacket::PacketType::Deauthentication;
    deauth.data = {0x03, 0x00}; // Reason: station is leaving.
    SendPacket(deauth);
    if (network_node_id == BroadcastNetworkNodeId) {
        SendPacket(deauth);
        SendPacket(deauth);
    }

    // This function always returns success if the status is valid.
    return ResultSuccess;
}

void NWM_UDS::EjectClient(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    const u16 network_node_id = rp.Pop<u16>();

    LOG_WARNING(Service_NWM, "(stubbed) called");

    auto res = EjectClientHLE(network_node_id);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(res);
}

Result NWM_UDS::UpdateNetworkAttributeHLE(u16 node_bitmask, u8 flag) {
    [[maybe_unused]] constexpr u8 flag_disconnect_and_block_non_bitmasked_nodes = 0x1;

    // stubbed

    return ResultSuccess;
}

void NWM_UDS::UpdateNetworkAttribute(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    u16 bitmask = rp.Pop<u16>();
    u8 flag = rp.Pop<u8>();

    auto res = UpdateNetworkAttributeHLE(bitmask, flag);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ResultSuccess);
}

Result NWM_UDS::DestroyNetworkHLE() {
    // Unschedule the beacon broadcast event.
    system.CoreTiming().UnscheduleEvent(beacon_broadcast_event, 0);

    std::scoped_lock lock(connection_status_mutex);
    if (connection_status.status != NetworkStatus::ConnectedAsHost) {
        // Pokemon's guest-side trade code calls DestroyNetwork (not DisconnectNetwork) when
        // abandoning a connection it joined as a client, which used to leave the host with no
        // deauth at all. Handle it the same way DisconnectNetwork does so the host actually
        // learns we're leaving instead of silently vanishing on it.
        LOG_INFO(Service_NWM, "called with status {}; treating as DisconnectNetwork",
                 static_cast<u32>(connection_status.status));
        DisconnectNetworkHLE();
        return ResultSuccess;
    }

    using Network::WifiPacket;
    WifiPacket deauth;
    deauth.channel = network_channel;
    deauth.destination_address = Network::BroadcastMac;
    deauth.type = WifiPacket::PacketType::Deauthentication;
    deauth.data = {0x03, 0x00}; // Reason: station is leaving.
    SendPacket(deauth);
    SendPacket(deauth);
    SendPacket(deauth);

    u16_le tmp_node_id = connection_status.network_node_id;
    connection_status = {};
    connection_status.status = NetworkStatus::NotConnected;
    connection_status.network_node_id = tmp_node_id;
    node_map.clear();
    physical_management_reply_sequences.clear();
    last_eapol_frame_data.clear();
#ifdef _WIN32
    if (real_monitor) {
        real_monitor->ResetAccessPoint();
    }
#endif
    SignalEventAsync(connection_status_event);

    for (auto& bind_node : channel_data) {
        SignalEventAsync(bind_node.second.event);
    }
    channel_data.clear();

    return ResultSuccess;
}

void NWM_UDS::DestroyNetwork(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    auto res = DestroyNetworkHLE();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);

    rb.Push(res);

    LOG_DEBUG(Service_NWM, "called");
}

void NWM_UDS::SendTo(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    rp.Skip(1, false);
    u16 dest_node_id = rp.Pop<u16>();
    u8 data_channel = rp.Pop<u8>();
    rp.Skip(1, false);
    u32 data_size = rp.Pop<u32>();
    u8 flags = rp.Pop<u8>();

    std::vector<u8> input_buffer = rp.PopStaticBuffer();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);

    auto res = SendToHLE(dest_node_id, data_channel, data_size, flags, input_buffer);

    switch (res) {
    case ResultStatus::SendError_PacketSizeTooLarge:
        rb.Push(Result(ErrorDescription::TooLarge, ErrorModule::UDS, ErrorSummary::WrongArgument,
                       ErrorLevel::Usage));
        return;
    case ResultStatus::SendError_NotConnected:
        rb.Push(Result(ErrorDescription::NotAuthorized, ErrorModule::UDS,
                       ErrorSummary::InvalidState, ErrorLevel::Status));
        return;
    case ResultStatus::SendError_BadNode:
    case ResultStatus::SendError_BadMacAddress:
        rb.Push(Result(ErrorDescription::NotFound, ErrorModule::UDS, ErrorSummary::WrongArgument,
                       ErrorLevel::Status));
        return;
    default:;
    }

    rb.Push(ResultSuccess);
}

ResultStatus NWM_UDS::SendToHLE(u32 dest_node_id, u8 data_channel, u32 data_size, u8 flags,
                                std::vector<u8> input_buffer) {
    ASSERT(input_buffer.size() >= data_size);
    input_buffer.resize(data_size);

    std::scoped_lock lock(connection_status_mutex);
    if (connection_status.status != NetworkStatus::ConnectedAsClient &&
        connection_status.status != NetworkStatus::ConnectedAsHost) {
        LOG_ERROR(Service_NWM,
                  "You are not connected as a client or a host. (you are connected as type {})",
                  connection_status.status);
        return ResultStatus::SendError_NotConnected;
    }

    // There should never be a dest_node_id of 0
    if (dest_node_id == 0) {
        LOG_ERROR(Service_NWM, "dest_node_id is 0");
        return ResultStatus::SendError_BadNode;
    }

    if (dest_node_id == connection_status.network_node_id) {
        LOG_ERROR(Service_NWM, "tried to send packet to itself");
        return ResultStatus::SendError_BadNode;
    }

    if (flags >> 2) {
        LOG_ERROR(Service_NWM, "Unexpected flags 0x{:02X}", flags);
    }

    auto dest_address = GetNodeMacAddress(dest_node_id, flags);
    if (!dest_address) {
        LOG_ERROR(Service_NWM, "Destination address was 0");
        return ResultStatus::SendError_BadMacAddress;
    }

    constexpr std::size_t MaxSize = 0x5C6;
    if (data_size > MaxSize) {
        LOG_ERROR(Service_NWM, "Data size was greater than the max packet size {} > {}", data_size,
                  MaxSize);
        return ResultStatus::SendError_PacketSizeTooLarge;
    }
    const u16 sequence_number = secure_data_tx_sequence_number++;
    std::vector<u8> data_payload =
        GenerateDataPayload(input_buffer, data_channel, dest_node_id,
                            connection_status.network_node_id, sequence_number);
    const auto generated_secure_data = ParseSecureDataHeader(data_payload);

    LOG_INFO(Service_NWM,
             "UDS DATA TRACE TX GAME: channel={}, secureSequence={}, sourceNode={}, "
             "destinationNode={}, flags=0x{:02X}, payloadBytes={}, "
             "payloadFingerprint=0x{:08X}, payload={}",
             data_channel, sequence_number,
             static_cast<u16>(connection_status.network_node_id), dest_node_id, flags, data_size,
             FingerprintBytes(input_buffer), FormatHexBytes(input_buffer));
    LOG_INFO(Service_NWM,
             "UDS DATA TRACE TX SECUREDATA: channel={}, secureSequence={}, sourceNode={}, "
             "destinationNode={}, protocolSize={}, secureDataSize={}, secureDataBytes={}, "
             "secureDataFingerprint=0x{:08X}, secureData={}",
             data_channel, sequence_number,
             static_cast<u16>(connection_status.network_node_id), dest_node_id,
             static_cast<u16>(generated_secure_data.protocol_size),
             static_cast<u16>(generated_secure_data.securedata_size),
             data_payload.size(), FingerprintBytes(data_payload), FormatHexBytes(data_payload));

    // TODO(B3N30): Use the MAC address of the dest_node_id and our own to encrypt
    // and encapsulate the payload.

    Network::WifiPacket packet;

    packet.destination_address = *dest_address;
    packet.channel = network_channel;
    packet.data = std::move(data_payload);
    packet.type = Network::WifiPacket::PacketType::Data;

    SendPacket(packet);

    return ResultStatus::ResultSuccess;
}

void NWM_UDS::PullPacket(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    u32 bind_node_id = rp.Pop<u32>();
    u32 max_out_buff_size_aligned = rp.Pop<u32>();
    u32 max_out_buff_size = rp.Pop<u32>();
    std::vector<u8> output_buffer;

    SecureDataHeader secure_data;

    auto ret = PullPacketHLE(bind_node_id, max_out_buff_size, max_out_buff_size_aligned,
                             output_buffer, &secure_data);

    switch (ret.error()) {
    case ResultStatus::RecvError_NotConnected: {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(Result(ErrorDescription::NotAuthorized, ErrorModule::UDS,
                       ErrorSummary::InvalidState, ErrorLevel::Status));
        return;
    }
    case ResultStatus::RecvError_BadNode: {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(Result(ErrorDescription::NotAuthorized, ErrorModule::UDS,
                       ErrorSummary::InvalidState, ErrorLevel::Status));
        return;
    }
    case ResultStatus::RecvError_PacketSizeTooLarge: {
        IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
        rb.Push(Result(ErrorDescription::TooLarge, ErrorModule::UDS, ErrorSummary::WrongArgument,
                       ErrorLevel::Usage));
        return;
    }
    default:;
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(3, 2);

    rb.Push(ResultSuccess);
    rb.Push<u32>(*ret);
    rb.Push<u16>(secure_data.src_node_id);
    rb.PushStaticBuffer(std::move(output_buffer), 0);
}

Common::Expected<int, ResultStatus> NWM_UDS::PullPacketHLE(u32 bind_node_id, u32 max_out_buff_size,
                                                           u32 max_out_buff_size_aligned,
                                                           std::vector<u8>& output_buffer,
                                                           void* secure_data_out) {
    // This size is hard coded into the uds module. We don't know the meaning yet.
    u32 buff_size = std::min<u32>(max_out_buff_size_aligned, 0x172) << 2;

    std::scoped_lock lock(connection_status_mutex);
    if (connection_status.status != NetworkStatus::ConnectedAsHost &&
        connection_status.status != NetworkStatus::ConnectedAsClient &&
        connection_status.status != NetworkStatus::ConnectedAsSpectator) {
        LOG_ERROR(Service_NWM, "Not connected yet.");
        return Common::Unexpected(ResultStatus::RecvError_NotConnected);
    }

    auto channel =
        std::find_if(channel_data.begin(), channel_data.end(), [bind_node_id](const auto& data) {
            return data.second.bind_node_id == bind_node_id;
        });

    if (channel == channel_data.end()) {
        LOG_ERROR(Service_NWM, "Could not find channel bn 0x{:x}.", bind_node_id);
        return Common::Unexpected(ResultStatus::RecvError_BadNode);
    }

    if (channel->second.received_packets.empty()) {
        output_buffer.resize(buff_size);
        return int(0);
    }

    const auto& next_packet = channel->second.received_packets.front();

    auto secure_data = ParseSecureDataHeader(next_packet);
    auto data_size = secure_data.GetActualDataSize();

    if (secure_data_out) {
        *reinterpret_cast<SecureDataHeader*>(secure_data_out) = secure_data;
    }

    if (data_size > max_out_buff_size) {
        LOG_ERROR(Service_NWM, "Data size was too large.");
        return Common::Unexpected(ResultStatus::RecvError_PacketSizeTooLarge);
    }
    output_buffer.resize(buff_size);

    // Write the actual data.
    std::memcpy(output_buffer.data(),
                next_packet.data() + sizeof(LLCHeader) + sizeof(SecureDataHeader), data_size);

    const std::span<const u8> delivered_payload{output_buffer.data(), data_size};

    channel->second.received_packets.pop_front();
    LOG_INFO(Service_NWM,
             "UDS DATA TRACE RX GAME: channel={}, secureSequence={}, sourceNode={}, "
             "destinationNode={}, payloadBytes={}, payloadFingerprint=0x{:08X}, payload={}, "
             "remainingQueueDepth={}",
             secure_data.data_channel, static_cast<u16>(secure_data.sequence_number),
             static_cast<u16>(secure_data.src_node_id),
             static_cast<u16>(secure_data.dest_node_id), data_size,
             FingerprintBytes(delivered_payload), FormatHexBytes(delivered_payload),
             channel->second.received_packets.size());
    return int(data_size);
}

void NWM_UDS::GetChannel(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);

    std::scoped_lock lock(connection_status_mutex);
    bool is_connected = connection_status.status != NetworkStatus::NotConnected;

    u8 channel = is_connected ? network_channel : 0;

    rb.Push(ResultSuccess);
    rb.Push(channel);

    LOG_DEBUG(Service_NWM, "called");
}

class NWM_UDS::ThreadCallback : public Kernel::HLERequestContext::WakeupCallback {
public:
    explicit ThreadCallback(u16 command_id_) : command_id(command_id_) {}

    void WakeUp(std::shared_ptr<Kernel::Thread> thread, Kernel::HLERequestContext& ctx,
                Kernel::ThreadWakeupReason reason) {
        IPC::RequestBuilder rb(ctx, command_id, 1, 0);
        LOG_INFO(Service_NWM, "UDS IPC: ConnectToNetwork thread woken, reason={}",
                 static_cast<u32>(reason));
        if (reason == Kernel::ThreadWakeupReason::Timeout) {
            LOG_ERROR(Service_NWM, "timed out when trying to connect to UDS server");
            rb.Push(Result(ErrorDescription::Timeout, ErrorModule::UDS, ErrorSummary::Canceled,
                           ErrorLevel::Status));
            return;
        }
        rb.Push(ResultSuccess);
        LOG_DEBUG(Service_NWM, "connection sequence finished");
    }

private:
    ThreadCallback() = default;
    u16 command_id;

    template <class Archive>
    void serialize(Archive& ar, const unsigned int) {
        ar& boost::serialization::base_object<Kernel::HLERequestContext::WakeupCallback>(*this);
        ar & command_id;
    }
    friend class boost::serialization::access;
};

void NWM_UDS::ConnectToNetworkHLE(NetworkInfo net_info, u8 connection_type,
                                  std::vector<u8> passphrase) {
    network_info = net_info;
    beacon_max_nodes = net_info.max_nodes;

    // Temporary diagnostic: this value is a fixed constant baked into the game binary (not a
    // secret exchanged over the air, and not user data), used only as an input to the public
    // CCMP key derivation formula. Capturing it once lets us derive the CCMP key for any Pokemon
    // X UDS session we later observe passively, including one entirely between two other
    // consoles.
    LOG_INFO(Service_NWM,
             "UDS Real: ConnectToNetwork key-derivation input bytes={}, fingerprint=0x{:08X}, "
             "inputBytes={}, wlanCommId=0x{:08X}, networkId=0x{:08X}, "
             "hostMac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
             passphrase.size(), FingerprintBytes(passphrase), FormatHexBytes(passphrase),
             static_cast<u32>(network_info.wlan_comm_id), static_cast<u32>(network_info.network_id),
             network_info.host_mac_address[0], network_info.host_mac_address[1],
             network_info.host_mac_address[2], network_info.host_mac_address[3],
             network_info.host_mac_address[4], network_info.host_mac_address[5]);

    // The monitor starts on the service's default channel before the game selects a peer. Once
    // ConnectToNetwork supplies the chosen beacon, use its advertised channel immediately rather
    // than spending most of the IPC timeout rediscovering that same host.
    if (network_info.channel >= 1 && network_info.channel <= 13) {
        network_channel = network_info.channel;
#ifdef _WIN32
        if (real_monitor) {
            real_monitor->SelectPeerChannel(network_channel);
        }
#endif
    }

    conn_type = static_cast<ConnectionType>(connection_type);

    physical_data_ccmp_key = GenerateDataCCMPKey(passphrase, network_info);
    secure_data_tx_sequence_number = 0;
    physical_tx_packet_number = 1;
    physical_tx_sequence_number = 0;
    physical_association_request_sent = false;
    association_response_handled = false;
    physical_rx_frame_count = 0;
    physical_rx_ccmp_failure_count = 0;

    // Start the connection sequence
    StartConnectionSequence(network_info.host_mac_address);
}

void NWM_UDS::ConnectToNetwork(Kernel::HLERequestContext& ctx, u16 command_id,
                               std::span<const u8> network_info_buffer, u8 connection_type,
                               std::vector<u8> passphrase) {
    NetworkInfo net_info;
    std::memcpy(&net_info, network_info_buffer.data(), network_info_buffer.size());
    ConnectToNetworkHLE(net_info, connection_type, passphrase);
    // Physical monitor creation can take several seconds before the selected channel is ready.
    // The old five-second limit expired 31 ms before a verified retail join completed.
    // Since this timing is handled by core_timing it could differ from real-world time.
    static constexpr std::chrono::nanoseconds UDSConnectionTimeout{15000000000};

    connection_event = ctx.SleepClientThread("uds::ConnectToNetwork", UDSConnectionTimeout,
                                             std::make_shared<ThreadCallback>(command_id));
}

void NWM_UDS::ConnectToNetwork(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    const auto connection_type = rp.Pop<u8>();
    [[maybe_unused]] const auto passphrase_size = rp.Pop<u32>();

    const std::vector<u8> network_info_buffer = rp.PopStaticBuffer();
    ASSERT(network_info_buffer.size() == sizeof(NetworkInfo));

    std::vector<u8> passphrase = rp.PopStaticBuffer();

    ConnectToNetwork(ctx, 0x1E, network_info_buffer, connection_type, std::move(passphrase));

    LOG_DEBUG(Service_NWM, "called");
}

void NWM_UDS::ConnectToNetworkDeprecated(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    // Similar to BeginHostingNetworkDeprecated, we only read the first 0x3C bytes into the network
    // info
    const auto network_info_buffer = rp.PopRaw<std::array<u8, 0x3C>>();

    const auto connection_type = rp.Pop<u8>();
    [[maybe_unused]] const auto passphrase_size = rp.Pop<u32>();

    std::vector<u8> passphrase = rp.PopStaticBuffer();

    ConnectToNetwork(ctx, 0x09, network_info_buffer, connection_type, std::move(passphrase));

    LOG_DEBUG(Service_NWM, "called");
}

ResultStatus NWM_UDS::DisconnectNetworkHLE() {
    using Network::WifiPacket;
    WifiPacket deauth;
    {
        std::scoped_lock lock(connection_status_mutex);
        if (connection_status.status == NetworkStatus::ConnectedAsHost) {
            // A real 3ds makes strange things here. We do the same
            u16_le tmp_node_id = connection_status.network_node_id;
            connection_status = {};
            connection_status.status = NetworkStatus::ConnectedAsHost;
            connection_status.network_node_id = tmp_node_id;
            node_map.clear();
            return ResultStatus::DisconError_CalledAsHost;
        }
        u16_le tmp_node_id = connection_status.network_node_id;
        connection_status = {};
        connection_status.status = NetworkStatus::NotConnected;
        connection_status.network_node_id = tmp_node_id;
        node_map.clear();
        physical_management_reply_sequences.clear();
        last_eapol_frame_data.clear();
        SignalEventAsync(connection_status_event);

        deauth.channel = network_channel;
        deauth.data = {0x03, 0x00}; // Reason: station is leaving.
        deauth.destination_address = network_info.host_mac_address;
        deauth.type = WifiPacket::PacketType::Deauthentication;
    }

    SendPacket(deauth);

    for (auto& bind_node : channel_data) {
        SignalEventAsync(bind_node.second.event);
    }
    channel_data.clear();

    return ResultStatus::ResultSuccess;
}

void NWM_UDS::DisconnectNetwork(Kernel::HLERequestContext& ctx) {
    LOG_DEBUG(Service_NWM, "disconnecting from network");
    IPC::RequestParser rp(ctx);
    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);

    auto res = DisconnectNetworkHLE();
    if (res == ResultStatus::DisconError_CalledAsHost) {
        LOG_DEBUG(Service_NWM, "called as a host");
        rb.Push(Result(ErrCodes::WrongStatus, ErrorModule::UDS, ErrorSummary::InvalidState,
                       ErrorLevel::Status));
        return;
    }

    rb.Push(ResultSuccess);
}

void NWM_UDS::SetApplicationData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    u32 size = rp.Pop<u32>();

    const std::vector<u8> application_data = rp.PopStaticBuffer();
    ASSERT(application_data.size() == size);

    LOG_DEBUG(Service_NWM, "called");

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);

    if (size > ApplicationDataSize) {
        rb.Push(Result(ErrorDescription::TooLarge, ErrorModule::UDS, ErrorSummary::WrongArgument,
                       ErrorLevel::Usage));
        return;
    }

    network_info.application_data_size = static_cast<u8>(size);
    std::memcpy(network_info.application_data.data(), application_data.data(), size);

    rb.Push(ResultSuccess);
}

void NWM_UDS::GetApplicationData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    u32 input_size = rp.Pop<u32>();
    u8 appdata_size = network_info.application_data_size;

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 2);
    rb.Push(ResultSuccess);

    if (input_size < appdata_size) {
        rb.Push(0);
        return;
    }

    rb.Push(appdata_size);
    std::vector<u8> appdata(appdata_size);
    std::memcpy(appdata.data(), network_info.application_data.data(), appdata_size);
    rb.PushStaticBuffer(std::move(appdata), 0);
}

void NWM_UDS::DecryptBeaconData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    const std::vector<u8> network_struct_buffer = rp.PopStaticBuffer();
    ASSERT(network_struct_buffer.size() == sizeof(NetworkInfo));

    const std::vector<u8> encrypted_data0_buffer = rp.PopStaticBuffer();
    const std::vector<u8> encrypted_data1_buffer = rp.PopStaticBuffer();

    LOG_DEBUG(Service_NWM, "called");

    NetworkInfo net_info;
    std::memcpy(&net_info, network_struct_buffer.data(), sizeof(net_info));

    // Read the encrypted data.
    // The first 4 bytes should be the OUI and the OUI Type of the tags.
    std::array<u8, 3> oui;
    std::memcpy(oui.data(), encrypted_data0_buffer.data(), oui.size());
    ASSERT_MSG(oui == NintendoOUI, "Unexpected OUI");

    ASSERT_MSG(encrypted_data0_buffer[3] == static_cast<u8>(NintendoTagId::EncryptedData0),
               "Unexpected tag id");

    // The IPC buffers have fixed 0xFE-byte capacities and are not sized to the tags' actual
    // contents. The meaningful encrypted length is determined by max_nodes. Tag0 carries at most
    // 0xFA bytes after its four-byte OUI/type prefix; tag1 carries any remainder.
    const std::size_t encrypted_size =
        sizeof(BeaconData) + static_cast<std::size_t>(net_info.max_nodes) * sizeof(BeaconNodeInfo);
    const std::size_t tag0_payload_size =
        std::min(EncryptedBeaconDataTagCapacity, encrypted_size);
    const std::size_t tag1_payload_size = encrypted_size - tag0_payload_size;

    ASSERT_MSG(encrypted_data0_buffer.size() >= 4 + tag0_payload_size,
               "Encrypted beacon tag0 buffer is too small");
    ASSERT_MSG(encrypted_data1_buffer.size() >= 4 + tag1_payload_size,
               "Encrypted beacon tag1 buffer is too small");

    if (tag1_payload_size != 0) {
        std::array<u8, 3> tag1_oui;
        std::memcpy(tag1_oui.data(), encrypted_data1_buffer.data(), tag1_oui.size());
        ASSERT_MSG(tag1_oui == NintendoOUI, "Unexpected tag1 OUI");
        ASSERT_MSG(encrypted_data1_buffer[3] ==
                       static_cast<u8>(NintendoTagId::EncryptedData1),
                   "Unexpected tag1 id");
    }

    std::vector<u8> beacon_data(encrypted_size);
    std::memcpy(beacon_data.data(), encrypted_data0_buffer.data() + 4, tag0_payload_size);
    if (tag1_payload_size != 0) {
        std::memcpy(beacon_data.data() + tag0_payload_size, encrypted_data1_buffer.data() + 4,
                    tag1_payload_size);
    }

    // Decrypt the data
    const bool md5_valid = DecryptBeacon(net_info, beacon_data);

    ++beacon_decrypt_request_count;
    const bool first_valid_decryption = md5_valid && !beacon_decrypt_valid_seen;
    if (beacon_decrypt_request_count <= 5 || beacon_decrypt_request_count % 25 == 0 ||
        first_valid_decryption) {
        LOG_INFO(Service_NWM,
                 "UDS Real: DecryptBeaconData #{}, source={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:"
                 "{:02X}, wlanCommId=0x{:08X}, id={}, networkId=0x{:08X}, maxNodes={}, "
                 "ipcTagBytes={}/{}, usedCipherBytes={} (tag0={}, tag1={}), "
                 "decryptedMd5Valid={}",
                 beacon_decrypt_request_count, net_info.host_mac_address[0],
                 net_info.host_mac_address[1], net_info.host_mac_address[2],
                 net_info.host_mac_address[3], net_info.host_mac_address[4],
                 net_info.host_mac_address[5], static_cast<u32>(net_info.wlan_comm_id),
                 net_info.id, static_cast<u32>(net_info.network_id), net_info.max_nodes,
                 encrypted_data0_buffer.size(), encrypted_data1_buffer.size(), encrypted_size,
                 tag0_payload_size, tag1_payload_size, md5_valid);
    }
    beacon_decrypt_valid_seen |= md5_valid;

    // The beacon data header contains the MD5 hash of the data.
    BeaconData beacon_header;
    std::memcpy(&beacon_header, beacon_data.data(), sizeof(beacon_header));

    // TODO(Subv): Verify the MD5 hash of the data and return 0xE1211005 if invalid.

    const std::size_t num_nodes = net_info.max_nodes;

    std::vector<NodeInfo> nodes;
    nodes.reserve(num_nodes);

    for (std::size_t i = 0; i < num_nodes; ++i) {
        BeaconNodeInfo info;
        std::memcpy(&info, beacon_data.data() + sizeof(beacon_header) + i * sizeof(info),
                    sizeof(info));

        // Deserialize the node information.
        auto& node = nodes.emplace_back();
        node.friend_code_seed = info.friend_code_seed;
        node.network_node_id = info.network_node_id;
        for (std::size_t j = 0; j < info.username.size(); ++j) {
            node.username[j] = info.username[j];
        }
    }

    const std::size_t application_data_size =
        std::min<std::size_t>(net_info.application_data_size, ApplicationDataSize);
    const u32 application_fingerprint = FingerprintBytes(std::span<const u8>{
        net_info.application_data.data(), application_data_size});
    const bool payload_changed =
        !have_beacon_payload_fingerprint ||
        last_beacon_application_fingerprint != application_fingerprint ||
        last_beacon_node_md5 != beacon_header.md5_hash;
    if (beacon_decrypt_request_count <= 5 || beacon_decrypt_request_count % 25 == 0 ||
        payload_changed) {
        const NodeInfo* first_node = nodes.empty() ? nullptr : &nodes.front();
        LOG_INFO(Service_NWM,
                 "UDS Real: retail beacon payload #{}, changed={}, applicationDataSize={}, "
                 "applicationFingerprint=0x{:08X}, nodeDataFingerprint=0x{:08X}, "
                 "firstNodeId={}, firstNodeUsernameFingerprint=0x{:08X}, totalDecodedNodes={}",
                 beacon_decrypt_request_count, payload_changed, application_data_size,
                 application_fingerprint,
                 FingerprintBytes(std::span<const u8>{beacon_header.md5_hash.data(),
                                                      beacon_header.md5_hash.size()}),
                 first_node ? static_cast<u16>(first_node->network_node_id) : 0,
                 first_node ? FingerprintUsername(*first_node) : 0, nodes.size());
    }
    have_beacon_payload_fingerprint = true;
    last_beacon_application_fingerprint = application_fingerprint;
    last_beacon_node_md5 = beacon_header.md5_hash;

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(ResultSuccess);

    std::vector<u8> output_buffer(sizeof(NodeInfo) * UDSMaxNodes);
    std::memcpy(output_buffer.data(), nodes.data(), sizeof(NodeInfo) * nodes.size());
    rb.PushStaticBuffer(std::move(output_buffer), 0);
}

void NWM_UDS::EjectSpectators(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    LOG_WARNING(Service_NWM, "(STUBBED) called");

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);

    rb.Push(ResultSuccess);
}

// Sends a 802.11 beacon frame with information about the current network.
void NWM_UDS::BeaconBroadcastCallback(std::uintptr_t user_data, s64 cycles_late) {
    // Don't do anything if we're not actually hosting a network
    if (connection_status.status != NetworkStatus::ConnectedAsHost)
        return;

    std::vector<u8> frame = GenerateBeaconFrame(network_info, node_info);

    bool physical_beacon_queued = false;
#ifdef _WIN32
    if (real_monitor && real_monitor->IsRunning()) {
        real_monitor->SubmitBeacon(std::span<const u8>{frame.data(), frame.size()},
                                   network_info.host_mac_address);
        physical_beacon_queued = true;
    }
#endif

    ++beacon_broadcast_callback_count;
    if (beacon_broadcast_callback_count <= 5 || beacon_broadcast_callback_count % 100 == 0) {
        LOG_INFO(Service_NWM,
                 "UDS Real: internal beacon generation #{}, hostMac={:02X}:{:02X}:{:02X}:"
                 "{:02X}:{:02X}:{:02X}, channel={}, wlanCommId=0x{:08X}, "
                 "networkId=0x{:08X}, nodes={}, beaconBodyBytes={}, bodyFingerprint=0x{:08X}; "
                 "physicalBeaconQueued={}",
                 beacon_broadcast_callback_count, network_info.host_mac_address[0],
                 network_info.host_mac_address[1], network_info.host_mac_address[2],
                 network_info.host_mac_address[3], network_info.host_mac_address[4],
                 network_info.host_mac_address[5], network_channel,
                 static_cast<u32>(network_info.wlan_comm_id),
                 static_cast<u32>(network_info.network_id), node_info.size(), frame.size(),
                 FingerprintBytes(std::span<const u8>{frame.data(), frame.size()}),
                 physical_beacon_queued);
    }

    using Network::WifiPacket;
    WifiPacket packet;
    packet.type = WifiPacket::PacketType::Beacon;
    packet.data = std::move(frame);
    packet.destination_address = Network::BroadcastMac;
    packet.channel = network_channel;

    SendPacket(packet);

    // Start broadcasting the network, send a beacon frame every 102.4ms.
    system.CoreTiming().ScheduleEvent(msToCycles(DefaultBeaconInterval * MillisecondsPerTU) -
                                          cycles_late,
                                      beacon_broadcast_event, 0);
}

Network::MacAddress NWM_UDS::GetMacAddress() {
    MacAddress mac;

    if (auto room_member = Network::GetRoomMember().lock();
        room_member && room_member->IsConnected()) {
        mac = room_member->GetMacAddress();
        if (mac != CFG::GetConsoleMacAddress(system)) {
            LOG_WARNING(Service_NWM, "Room member mac address is different from the console mac "
                                     "address. Using room member mac address.");
        }
    } else {
        // if we are not connected to the room, we can
        // use the system mac address. In hopefully all cases
        // this will match the room member mac addr anyways
        mac = CFG::GetConsoleMacAddress(system);
    }
    return mac;
}

void NWM_UDS::SignalEventAsync(std::shared_ptr<Kernel::Event> event) {
    if (system.GetCoreLoopThreadId() == std::this_thread::get_id()) {
        event->Signal();
        return;
    }
    pending_async_event_signals.Push(event);
    system.CoreTiming().ScheduleEvent(0, handle_async_event_signals_event, 0, 1, true);
}

void NWM_UDS::DispatchQueuedAsyncEventSignals() {
    std::shared_ptr<Kernel::Event> event;
    pending_async_event_signals.Pop(event);
    if (!event) {
        LOG_WARNING(Service_NWM, "Tried to signal async event, but event was null");
        return;
    }
    event->Signal();
}

NWM_UDS::NWM_UDS(Core::System& system) : ServiceFramework("nwm::UDS"), system(system) {
    static const FunctionInfo functions[] = {
        // clang-format off
        {0x0001, &NWM_UDS::InitializeDeprecated, "Initialize (deprecated)"},
        {0x0002, nullptr, "Scrap"},
        {0x0003, &NWM_UDS::Shutdown, "Shutdown"},
        {0x0004, &NWM_UDS::BeginHostingNetworkDeprecated, "BeginHostingNetwork (deprecated)"},
        {0x0005, &NWM_UDS::EjectClient, "EjectClient"},
        {0x0006, &NWM_UDS::EjectSpectators, "EjectSpectators"},
        {0x0007, &NWM_UDS::UpdateNetworkAttribute, "UpdateNetworkAttribute"},
        {0x0008, &NWM_UDS::DestroyNetwork, "DestroyNetwork"},
        {0x0009, &NWM_UDS::ConnectToNetworkDeprecated, "ConnectToNetwork (deprecated)"},
        {0x000A, &NWM_UDS::DisconnectNetwork, "DisconnectNetwork"},
        {0x000B, &NWM_UDS::GetConnectionStatus, "GetConnectionStatus"},
        {0x000D, &NWM_UDS::GetNodeInformation, "GetNodeInformation"},
        {0x000E, &NWM_UDS::DecryptBeaconData, "DecryptBeaconData (deprecated)"},
        {0x000F, &NWM_UDS::RecvBeaconBroadcastData, "RecvBeaconBroadcastData"},
        {0x0010, &NWM_UDS::SetApplicationData, "SetApplicationData"},
        {0x0011, &NWM_UDS::GetApplicationData, "GetApplicationData"},
        {0x0012, &NWM_UDS::Bind, "Bind"},
        {0x0013, &NWM_UDS::Unbind, "Unbind"},
        {0x0014, &NWM_UDS::PullPacket, "PullPacket"},
        {0x0015, nullptr, "SetMaxSendDelay"},
        {0x0017, &NWM_UDS::SendTo, "SendTo"},
        {0x001A, &NWM_UDS::GetChannel, "GetChannel"},
        {0x001B, &NWM_UDS::InitializeWithVersion, "InitializeWithVersion"},
        {0x001D, &NWM_UDS::BeginHostingNetwork, "BeginHostingNetwork"},
        {0x001E, &NWM_UDS::ConnectToNetwork, "ConnectToNetwork"},
        {0x001F, &NWM_UDS::DecryptBeaconData, "DecryptBeaconData"},
        {0x0020, nullptr, "Flush"},
        {0x0021, &NWM_UDS::SetProbeResponseParam, "SetProbeResponseParam"},
        {0x0022, nullptr, "ScanOnConnection"},
        {0x0023, &NWM_UDS::Unknown0x23, "Unknown0x23"},
        // clang-format on
    };
    connection_status_event =
        system.Kernel().CreateEvent(Kernel::ResetType::OneShot, "NWM::connection_status_event");

    RegisterHandlers(functions);

    beacon_broadcast_event = system.CoreTiming().RegisterEvent(
        "UDS::BeaconBroadcastCallback", [this](std::uintptr_t user_data, s64 cycles_late) {
            BeaconBroadcastCallback(user_data, cycles_late);
        });

    handle_async_event_signals_event = system.CoreTiming().RegisterEvent(
        "UDS::handle_async_event_signals_event",
        [this]([[maybe_unused]] std::uintptr_t user_data, [[maybe_unused]] s64 cycles_late) {
            DispatchQueuedAsyncEventSignals();
        });

    system.Kernel().GetSharedPageHandler().SetMacAddress(GetMacAddress());

    if (auto room_member = Network::GetRoomMember().lock()) {
        wifi_packet_received = room_member->BindOnWifiPacketReceived(
            [this](const Network::WifiPacket& packet) { OnWifiPacketReceived(packet); });
    } else {
        LOG_ERROR(Service_NWM, "Network isn't initalized");
    }
}

NWM_UDS::~NWM_UDS() {
#ifdef _WIN32
    if (real_monitor) {
        real_monitor->Stop();
    }
#endif

    if (auto room_member = Network::GetRoomMember().lock())
        room_member->Unbind(wifi_packet_received);

    system.CoreTiming().UnscheduleEvent(beacon_broadcast_event, 0);
}

} // namespace Service::NWM

SERIALIZE_EXPORT_IMPL(Service::NWM::NWM_UDS::ThreadCallback)
