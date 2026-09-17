// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#include "core/hle/service/nwm/uds_real/nl80211_monitor.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "common/common_types.h"
#include "common/logging/log.h"
#include "core/hle/service/nwm/uds_real/ldnd_connection.h"

namespace Service::NWM::UdsReal {
namespace {

constexpr int AfNetlink = 16;
constexpr int AfPacket = 17;
constexpr int SockDgram = 2;
constexpr int SockRaw = 3;
constexpr int NetlinkRoute = 0;
constexpr int NetlinkGeneric = 16;

constexpr u16 EthPAll = 0x0003;
constexpr u16 GenlIdCtrl = 0x10;
constexpr u8 CtrlCmdGetFamily = 3;
constexpr u16 CtrlAttrFamilyId = 1;
constexpr u16 CtrlAttrFamilyName = 2;

constexpr u8 Nl80211CmdGetInterface = 5;
constexpr u8 Nl80211CmdNewInterface = 7;
constexpr u8 Nl80211CmdDelInterface = 8;
constexpr u8 Nl80211CmdSetChannel = 65;
constexpr u16 Nl80211AttrWiphy = 1;
constexpr u16 Nl80211AttrIfIndex = 3;
constexpr u16 Nl80211AttrIfName = 4;
constexpr u16 Nl80211AttrIfType = 5;
constexpr u16 Nl80211AttrMac = 6;
constexpr u16 Nl80211AttrMntrFlags = 23;
constexpr u16 Nl80211AttrWiphyFreq = 38;
constexpr u32 Nl80211IfTypeMonitor = 6;
constexpr u16 Nl80211MntrFlagOtherBss = 4;

constexpr u16 NlmFRequest = 0x0001;
constexpr u16 NlmFMulti = 0x0002;
constexpr u16 NlmFAck = 0x0004;
constexpr u16 NlmFRoot = 0x0100;
constexpr u16 NlmFMatch = 0x0200;
constexpr u16 NlmFDump = NlmFRoot | NlmFMatch;
constexpr u16 NlmsgError = 2;
constexpr u16 NlmsgDone = 3;
constexpr u16 NlaFNested = 1 << 15;
constexpr u16 NlaTypeMask = 0x3FFF;

constexpr u16 RtmNewLink = 16;
constexpr u32 IffUp = 1;

constexpr std::size_t NetlinkHeaderLength = 16;
constexpr std::size_t GenericHeaderLength = 4;
constexpr char MonitorName[] = "udsmon0";
constexpr std::chrono::milliseconds DiscoveryChannelDwell{250};
constexpr std::chrono::seconds DiscoveryChannelHold{30};
constexpr std::chrono::seconds ActiveProbeInterval{1};
constexpr std::chrono::milliseconds PhysicalBeaconInterval{102};
constexpr std::array<u16, 3> PrimaryDiscoveryChannels{1, 6, 11};
constexpr std::size_t Ieee80211ManagementHeaderSize = 24;
constexpr std::string_view NintendoContinuousScanSsid =
    "Nintendo_3DS_continuous_scan_000";
static_assert(NintendoContinuousScanSsid.size() == 32);

struct PhysicalBeaconSnapshot {
    std::vector<u8> body;
    std::array<u8, 6> host_address{};
};

using PhysicalBeaconProvider = std::function<std::optional<PhysicalBeaconSnapshot>()>;
using PhysicalFrameProvider = std::function<std::optional<std::vector<u8>>() >;

u32 ChannelToFrequency(u16 channel) {
    if (channel >= 1 && channel <= 13) {
        return 2407U + static_cast<u32>(channel) * 5U;
    }
    if (channel == 14) {
        return 2484;
    }
    throw std::invalid_argument("UDS Real supports 2.4 GHz channels 1 through 14");
}

std::size_t Align4(std::size_t value) {
    return (value + 3) & ~std::size_t{3};
}

void AppendU16(std::vector<u8>& output, u16 value) {
    output.push_back(static_cast<u8>(value));
    output.push_back(static_cast<u8>(value >> 8));
}

void AppendU32(std::vector<u8>& output, u32 value) {
    output.push_back(static_cast<u8>(value));
    output.push_back(static_cast<u8>(value >> 8));
    output.push_back(static_cast<u8>(value >> 16));
    output.push_back(static_cast<u8>(value >> 24));
}

void WriteU64(u8* output, u64 value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        output[index] = static_cast<u8>(value >> (index * 8));
    }
}

u16 ReadU16(const u8* input) {
    return static_cast<u16>(input[0]) | static_cast<u16>(input[1] << 8);
}

u32 ReadU32(const u8* input) {
    return static_cast<u32>(input[0]) | (static_cast<u32>(input[1]) << 8) |
           (static_cast<u32>(input[2]) << 16) | (static_cast<u32>(input[3]) << 24);
}

u32 ReadU32BigEndian(const u8* input) {
    return (static_cast<u32>(input[0]) << 24) | (static_cast<u32>(input[1]) << 16) |
           (static_cast<u32>(input[2]) << 8) | static_cast<u32>(input[3]);
}

void AppendAttribute(std::vector<u8>& output, u16 type, const u8* data, std::size_t size) {
    const std::size_t length = 4 + size;
    AppendU16(output, static_cast<u16>(length));
    AppendU16(output, type);
    if (size != 0) {
        output.insert(output.end(), data, data + size);
    }
    output.resize(Align4(output.size()), 0);
}

void AppendU32Attribute(std::vector<u8>& output, u16 type, u32 value) {
    const u8 bytes[] = {static_cast<u8>(value), static_cast<u8>(value >> 8),
                        static_cast<u8>(value >> 16), static_cast<u8>(value >> 24)};
    AppendAttribute(output, type, bytes, sizeof(bytes));
}

std::vector<u8> PackSockaddrNl() {
    std::vector<u8> address;
    address.reserve(12);
    AppendU16(address, AfNetlink);
    AppendU16(address, 0);
    AppendU32(address, 0);
    AppendU32(address, 0);
    return address;
}

std::vector<u8> PackSockaddrLl(u32 ifindex) {
    std::vector<u8> address(20, 0);
    address[0] = static_cast<u8>(AfPacket);
    address[1] = static_cast<u8>(AfPacket >> 8);
    // sll_protocol is network byte order.
    address[2] = static_cast<u8>(EthPAll >> 8);
    address[3] = static_cast<u8>(EthPAll);
    address[4] = static_cast<u8>(ifindex);
    address[5] = static_cast<u8>(ifindex >> 8);
    address[6] = static_cast<u8>(ifindex >> 16);
    address[7] = static_cast<u8>(ifindex >> 24);
    return address;
}

u32 ParseSockaddrNlPort(const std::vector<u8>& address) {
    if (address.size() < 12 || ReadU16(address.data()) != AfNetlink) {
        throw std::runtime_error("ldnd returned an invalid sockaddr_nl");
    }
    return ReadU32(address.data() + 4);
}

std::vector<u8> PackGenericRequest(u16 family, u16 flags, u32 sequence, u32 port_id,
                                   u8 command, const std::vector<u8>& attributes = {}) {
    std::vector<u8> output;
    const u32 length = static_cast<u32>(NetlinkHeaderLength + GenericHeaderLength +
                                        attributes.size());
    output.reserve(length);
    AppendU32(output, length);
    AppendU16(output, family);
    AppendU16(output, static_cast<u16>(flags | NlmFRequest));
    AppendU32(output, sequence);
    AppendU32(output, port_id);
    output.push_back(command);
    output.push_back(1);
    AppendU16(output, 0);
    output.insert(output.end(), attributes.begin(), attributes.end());
    return output;
}

struct NetlinkMessageView {
    u16 type{};
    u16 flags{};
    u32 sequence{};
    const u8* payload{};
    std::size_t payload_size{};
};

std::vector<NetlinkMessageView> ParseMessages(const std::vector<u8>& data) {
    std::vector<NetlinkMessageView> result;
    std::size_t offset = 0;
    while (offset + NetlinkHeaderLength <= data.size()) {
        const u32 length = ReadU32(data.data() + offset);
        if (length < NetlinkHeaderLength || offset + length > data.size()) {
            throw std::runtime_error("received a malformed netlink message");
        }
        result.push_back(NetlinkMessageView{
            ReadU16(data.data() + offset + 4), ReadU16(data.data() + offset + 6),
            ReadU32(data.data() + offset + 8), data.data() + offset + NetlinkHeaderLength,
            length - NetlinkHeaderLength});
        offset += Align4(length);
    }
    return result;
}

template <typename Callback>
bool ForEachAttribute(const NetlinkMessageView& message, Callback callback) {
    if (message.payload_size < GenericHeaderLength) {
        return false;
    }
    std::size_t offset = GenericHeaderLength;
    while (offset + 4 <= message.payload_size) {
        const u16 length = ReadU16(message.payload + offset);
        const u16 type = ReadU16(message.payload + offset + 2) & NlaTypeMask;
        if (length < 4 || offset + length > message.payload_size) {
            return false;
        }
        callback(type, message.payload + offset + 4, length - 4);
        offset += Align4(length);
    }
    return true;
}

void ThrowNetlinkError(const NetlinkMessageView& message, const char* operation) {
    if (message.payload_size < 4) {
        throw std::runtime_error(std::string{operation} + " returned a truncated NLMSG_ERROR");
    }
    const s32 error = static_cast<s32>(ReadU32(message.payload));
    if (error != 0) {
        throw std::runtime_error(std::string{operation} + " failed with netlink error " +
                                 std::to_string(error));
    }
}

void WaitForAck(LdndConnection& connection, u32 socket_id, u32 sequence,
                const char* operation) {
    for (;;) {
        for (const auto& message : ParseMessages(connection.ReceiveData(socket_id))) {
            if (message.sequence != sequence) {
                continue;
            }
            if (message.type == NlmsgError) {
                ThrowNetlinkError(message, operation);
                return;
            }
        }
    }
}

u16 ResolveNl80211Family(LdndConnection& connection, u32 socket_id, u32 port_id,
                         u32& sequence) {
    std::vector<u8> attributes;
    constexpr char FamilyName[] = "nl80211";
    AppendAttribute(attributes, CtrlAttrFamilyName, reinterpret_cast<const u8*>(FamilyName),
                    sizeof(FamilyName));
    const u32 request_sequence = ++sequence;
    connection.SendTo(socket_id, PackGenericRequest(GenlIdCtrl, 0, request_sequence, port_id,
                                                    CtrlCmdGetFamily, attributes));
    for (;;) {
        for (const auto& message : ParseMessages(connection.ReceiveData(socket_id))) {
            if (message.sequence != request_sequence) {
                continue;
            }
            if (message.type == NlmsgError) {
                ThrowNetlinkError(message, "resolve nl80211");
                continue;
            }
            u16 family_id = 0;
            ForEachAttribute(message, [&](u16 type, const u8* value, std::size_t size) {
                if (type == CtrlAttrFamilyId && size >= 2) {
                    family_id = ReadU16(value);
                }
            });
            if (family_id != 0) {
                return family_id;
            }
        }
    }
}

struct InterfaceInfo {
    u32 wiphy{};
    u32 ifindex{};
    u32 iftype{};
    std::string name;
    std::vector<u8> mac;
};

std::vector<InterfaceInfo> EnumerateInterfaces(LdndConnection& connection, u32 socket_id,
                                                u32 port_id, u16 family_id, u32& sequence) {
    const u32 request_sequence = ++sequence;
    connection.SendTo(socket_id, PackGenericRequest(family_id, NlmFDump, request_sequence,
                                                    port_id, Nl80211CmdGetInterface));
    std::vector<InterfaceInfo> interfaces;
    for (;;) {
        for (const auto& message : ParseMessages(connection.ReceiveData(socket_id))) {
            if (message.sequence != request_sequence) {
                continue;
            }
            if (message.type == NlmsgError) {
                ThrowNetlinkError(message, "enumerate interfaces");
                continue;
            }
            if (message.type == NlmsgDone) {
                return interfaces;
            }

            InterfaceInfo info;
            ForEachAttribute(message, [&](u16 type, const u8* value, std::size_t size) {
                if (type == Nl80211AttrWiphy && size >= 4) {
                    info.wiphy = ReadU32(value);
                } else if (type == Nl80211AttrIfIndex && size >= 4) {
                    info.ifindex = ReadU32(value);
                } else if (type == Nl80211AttrIfType && size >= 4) {
                    info.iftype = ReadU32(value);
                } else if (type == Nl80211AttrIfName && size != 0) {
                    const std::size_t length = value[size - 1] == 0 ? size - 1 : size;
                    info.name.assign(reinterpret_cast<const char*>(value), length);
                } else if (type == Nl80211AttrMac) {
                    info.mac.assign(value, value + size);
                }
            });
            interfaces.push_back(std::move(info));
            if ((message.flags & NlmFMulti) == 0) {
                return interfaces;
            }
        }
    }
}

void SendGenericAckRequest(LdndConnection& connection, u32 socket_id, u32 port_id,
                           u16 family_id, u8 command, const std::vector<u8>& attributes,
                           u32& sequence, const char* operation) {
    const u32 request_sequence = ++sequence;
    connection.SendTo(socket_id, PackGenericRequest(family_id, NlmFAck, request_sequence,
                                                    port_id, command, attributes));
    WaitForAck(connection, socket_id, request_sequence, operation);
}

void DeleteInterface(LdndConnection& connection, u32 socket_id, u32 port_id, u16 family_id,
                     u32 ifindex, u32& sequence) {
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrIfIndex, ifindex);
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdDelInterface,
                          attributes, sequence, "delete monitor interface");
}

void CreateMonitorInterface(LdndConnection& connection, u32 socket_id, u32 port_id,
                            u16 family_id, u32 wiphy, u32& sequence) {
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrWiphy, wiphy);
    AppendAttribute(attributes, Nl80211AttrIfName, reinterpret_cast<const u8*>(MonitorName),
                    sizeof(MonitorName));
    AppendU32Attribute(attributes, Nl80211AttrIfType, Nl80211IfTypeMonitor);

    std::vector<u8> monitor_flags;
    AppendAttribute(monitor_flags, Nl80211MntrFlagOtherBss, nullptr, 0);
    AppendAttribute(attributes, static_cast<u16>(Nl80211AttrMntrFlags | NlaFNested),
                    monitor_flags.data(), monitor_flags.size());
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdNewInterface,
                          attributes, sequence, "create monitor interface");
}

void SetChannel(LdndConnection& connection, u32 socket_id, u32 port_id, u16 family_id,
                u32 ifindex, u32 frequency, u32& sequence) {
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrIfIndex, ifindex);
    AppendU32Attribute(attributes, Nl80211AttrWiphyFreq, frequency);
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdSetChannel,
                          attributes, sequence, "set monitor channel");
}

void SetInterfaceUp(LdndConnection& connection, u32 ifindex) {
    const u32 socket_id = connection.Socket(AfNetlink, SockDgram, NetlinkRoute);
    try {
        connection.Bind(socket_id, PackSockaddrNl());
        const u32 port_id = ParseSockaddrNlPort(connection.GetSockName(socket_id));
        connection.Start(socket_id);

        std::vector<u8> request;
        request.reserve(NetlinkHeaderLength + 16);
        AppendU32(request, NetlinkHeaderLength + 16);
        AppendU16(request, RtmNewLink);
        AppendU16(request, NlmFRequest | NlmFAck);
        AppendU32(request, 1);
        AppendU32(request, port_id);
        request.resize(NetlinkHeaderLength + 16, 0);
        request[NetlinkHeaderLength + 4] = static_cast<u8>(ifindex);
        request[NetlinkHeaderLength + 5] = static_cast<u8>(ifindex >> 8);
        request[NetlinkHeaderLength + 6] = static_cast<u8>(ifindex >> 16);
        request[NetlinkHeaderLength + 7] = static_cast<u8>(ifindex >> 24);
        request[NetlinkHeaderLength + 8] = static_cast<u8>(IffUp);
        request[NetlinkHeaderLength + 12] = static_cast<u8>(IffUp);
        connection.SendTo(socket_id, request);
        WaitForAck(connection, socket_id, 1, "bring monitor interface up");
        connection.CloseSocket(socket_id);
    } catch (...) {
        connection.CloseSocket(socket_id);
        throw;
    }
}

std::string FormatMac(const u8* mac) {
    constexpr char Hex[] = "0123456789ABCDEF";
    std::string output;
    for (std::size_t index = 0; index < 6; ++index) {
        if (index != 0) {
            output.push_back(':');
        }
        output.push_back(Hex[mac[index] >> 4]);
        output.push_back(Hex[mac[index] & 0xF]);
    }
    return output;
}

std::string FormatHexBytes(const std::vector<u8>& bytes) {
    constexpr char Hex[] = "0123456789ABCDEF";
    std::string output;
    for (const u8 byte : bytes) {
        if (!output.empty()) {
            output.push_back(':');
        }
        output.push_back(Hex[byte >> 4]);
        output.push_back(Hex[byte & 0xF]);
    }
    return output.empty() ? "<none>" : output;
}

bool IsNintendoContinuousScanSsid(const std::vector<u8>& ssid) {
    return ssid.size() == NintendoContinuousScanSsid.size() &&
           std::equal(ssid.begin(), ssid.end(), NintendoContinuousScanSsid.begin(),
                      [](u8 left, char right) { return left == static_cast<u8>(right); });
}

std::string FormatChannelPacketCounts(const std::array<std::size_t, 14>& packet_counts) {
    std::string output;
    for (const u16 channel : PrimaryDiscoveryChannels) {
        if (!output.empty()) {
            output += ", ";
        }
        output += std::to_string(channel);
        output += ':';
        output += std::to_string(packet_counts[channel]);
    }
    return output;
}

struct RadiotapInfo {
    std::size_t length{};
    bool includes_fcs{};
};

struct ProbeFrameDiagnostic {
    u8 subtype{};
    std::array<u8, 6> destination_address{};
    std::array<u8, 6> transmitter_address{};
    std::array<u8, 6> bssid{};
    bool has_nintendo_vendor_ie{};
    u8 nintendo_oui_type{};
    std::vector<u8> nintendo_data;
    std::vector<u8> ssid;
};

std::optional<RadiotapInfo> ParseRadiotap(const std::vector<u8>& packet) {
    if (packet.size() < 8 || packet[0] != 0 || packet[1] != 0) {
        return std::nullopt;
    }

    const std::size_t length = ReadU16(packet.data() + 2);
    if (length < 8 || length > packet.size()) {
        return std::nullopt;
    }

    std::size_t present_offset = 4;
    u32 first_present = 0;
    bool first = true;
    for (;;) {
        if (present_offset + 4 > length) {
            return std::nullopt;
        }
        const u32 present = ReadU32(packet.data() + present_offset);
        if (first) {
            first_present = present;
            first = false;
        }
        present_offset += 4;
        if ((present & (1U << 31)) == 0) {
            break;
        }
    }

    std::size_t field_offset = present_offset;
    if ((first_present & (1U << 0)) != 0) {
        field_offset = (field_offset + 7) & ~std::size_t{7};
        if (field_offset + 8 > length) {
            return std::nullopt;
        }
        field_offset += 8;
    }

    bool includes_fcs = false;
    if ((first_present & (1U << 1)) != 0) {
        if (field_offset >= length) {
            return std::nullopt;
        }
        constexpr u8 RadiotapFlagFcs = 0x10;
        includes_fcs = (packet[field_offset] & RadiotapFlagFcs) != 0;
    }
    return RadiotapInfo{length, includes_fcs};
}

std::optional<ProbeFrameDiagnostic> ParseProbeFrame(const std::vector<u8>& packet) {
    const auto radiotap = ParseRadiotap(packet);
    if (!radiotap) {
        return std::nullopt;
    }

    const std::size_t frame_offset = radiotap->length;
    std::size_t frame_end = packet.size();
    if (radiotap->includes_fcs && frame_end >= frame_offset + Ieee80211ManagementHeaderSize + 4) {
        frame_end -= 4;
    }
    if (frame_offset + Ieee80211ManagementHeaderSize > frame_end) {
        return std::nullopt;
    }

    const u16 frame_control = ReadU16(packet.data() + frame_offset);
    const u8 type = static_cast<u8>((frame_control >> 2) & 0x3);
    const u8 subtype = static_cast<u8>((frame_control >> 4) & 0xF);
    constexpr u8 ProbeRequestSubtype = 4;
    constexpr u8 ProbeResponseSubtype = 5;
    if (type != 0 || (subtype != ProbeRequestSubtype && subtype != ProbeResponseSubtype)) {
        return std::nullopt;
    }

    ProbeFrameDiagnostic result;
    result.subtype = subtype;
    std::memcpy(result.destination_address.data(), packet.data() + frame_offset + 4,
                result.destination_address.size());
    std::memcpy(result.transmitter_address.data(), packet.data() + frame_offset + 10,
                result.transmitter_address.size());
    std::memcpy(result.bssid.data(), packet.data() + frame_offset + 16, result.bssid.size());

    // Probe responses have the same 12-byte fixed-parameters block as beacons. Probe requests
    // begin their information elements immediately after the management header.
    std::size_t offset = frame_offset + Ieee80211ManagementHeaderSize;
    if (subtype == ProbeResponseSubtype) {
        if (offset + 12 > frame_end) {
            return std::nullopt;
        }
        offset += 12;
    }

    while (offset + 2 <= frame_end) {
        const u8 tag = packet[offset];
        const u8 length = packet[offset + 1];
        offset += 2;
        if (offset + length > frame_end) {
            break;
        }
        if (tag == 0) {
            result.ssid.assign(packet.data() + offset, packet.data() + offset + length);
        } else if (tag == 221 && length >= 4 && packet[offset] == 0x00 &&
                   packet[offset + 1] == 0x1F && packet[offset + 2] == 0x32) {
            result.has_nintendo_vendor_ie = true;
            result.nintendo_oui_type = packet[offset + 3];
            result.nintendo_data.assign(packet.data() + offset + 4,
                                        packet.data() + offset + length);
        }
        offset += length;
    }
    return result;
}

std::vector<u8> GenerateNintendoScanProbeRequest(const std::array<u8, 6>& source_address,
                                                 u16 sequence_number, u8 channel) {
    std::vector<u8> frame;
    frame.reserve(64);

    // Minimal radiotap header. The Linux monitor-mode injection path uses this to identify the
    // following bytes as a raw 802.11 frame; the driver supplies its own transmit parameters.
    frame.push_back(0); // Radiotap version.
    frame.push_back(0); // Padding.
    AppendU16(frame, 8);
    AppendU32(frame, 0); // No radiotap fields are present.

    // IEEE 802.11 probe request management header.
    AppendU16(frame, 0x0040); // Type=management, subtype=probe request.
    AppendU16(frame, 0);      // Duration.
    frame.insert(frame.end(), 6, 0xFF); // Destination: broadcast.
    frame.insert(frame.end(), source_address.begin(), source_address.end());
    frame.insert(frame.end(), 6, 0xFF); // BSSID: wildcard/broadcast.
    AppendU16(frame, static_cast<u16>((sequence_number & 0x0FFF) << 4));

    // The 3DS continuous scanner uses this directed 32-byte SSID. Nintendo services can ignore
    // wildcard probes even though they are actively discoverable to another 3DS.
    frame.push_back(0);
    frame.push_back(static_cast<u8>(NintendoContinuousScanSsid.size()));
    frame.insert(frame.end(), NintendoContinuousScanSsid.begin(),
                 NintendoContinuousScanSsid.end());

    // Common 2.4 GHz supported rates: 1, 2, 5.5, 11, 6, 9, 12 and 18 Mbit/s.
    constexpr std::array<u8, 8> SupportedRates{0x82, 0x84, 0x8B, 0x96,
                                               0x0C, 0x12, 0x18, 0x24};
    frame.push_back(1);
    frame.push_back(static_cast<u8>(SupportedRates.size()));
    frame.insert(frame.end(), SupportedRates.begin(), SupportedRates.end());

    // Remaining common OFDM rates: 24, 36, 48 and 54 Mbit/s.
    constexpr std::array<u8, 4> ExtendedRates{0x30, 0x48, 0x60, 0x6C};
    frame.push_back(50);
    frame.push_back(static_cast<u8>(ExtendedRates.size()));
    frame.insert(frame.end(), ExtendedRates.begin(), ExtendedRates.end());

    frame.push_back(3); // DS Parameter Set.
    frame.push_back(1);
    frame.push_back(channel);
    return frame;
}

std::vector<u8> GeneratePhysicalNintendoBeacon(const PhysicalBeaconSnapshot& beacon,
                                               u16 sequence_number, u8 channel) {
    constexpr std::size_t BeaconFixedParametersSize = 12;
    if (beacon.body.size() < BeaconFixedParametersSize) {
        throw std::runtime_error("generated UDS beacon body is missing fixed parameters");
    }

    std::vector<u8> body = beacon.body;

    // Keep the physical timestamp increasing even though Azahar's emulated beacon generator uses
    // a fixed placeholder timestamp. This prevents a retail scanner from treating repeated frames
    // as stale copies of one beacon.
    const u64 timestamp = static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(
                                               std::chrono::steady_clock::now().time_since_epoch())
                                               .count());
    WriteU64(body.data(), timestamp);

    // The monitor interface may have discovered and locked to a different channel than the
    // emulated default. Advertise the channel on which this frame is actually transmitted.
    bool found_ds_parameter = false;
    std::size_t offset = BeaconFixedParametersSize;
    while (offset + 2 <= body.size()) {
        const u8 tag = body[offset];
        const u8 length = body[offset + 1];
        offset += 2;
        if (offset + length > body.size()) {
            throw std::runtime_error("generated UDS beacon contains a malformed information element");
        }
        if (tag == 3 && length >= 1) {
            body[offset] = channel;
            found_ds_parameter = true;
            break;
        }
        offset += length;
    }
    if (!found_ds_parameter) {
        body.push_back(3);
        body.push_back(1);
        body.push_back(channel);
    }

    std::vector<u8> frame;
    frame.reserve(8 + Ieee80211ManagementHeaderSize + body.size());

    // Minimal radiotap header for monitor-mode injection. The adapter selects the transmit rate.
    frame.push_back(0);
    frame.push_back(0);
    AppendU16(frame, 8);
    AppendU32(frame, 0);

    // IEEE 802.11 beacon management header. The transmitter and BSSID deliberately use Azahar's
    // emulated host MAC because that address is also an input to the Nintendo beacon encryption.
    AppendU16(frame, 0x0080);
    AppendU16(frame, 0);
    frame.insert(frame.end(), 6, 0xFF);
    frame.insert(frame.end(), beacon.host_address.begin(), beacon.host_address.end());
    frame.insert(frame.end(), beacon.host_address.begin(), beacon.host_address.end());
    AppendU16(frame, static_cast<u16>((sequence_number & 0x0FFF) << 4));
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

std::optional<CapturedBeacon> ParseNintendoBeacon(const std::vector<u8>& packet,
                                                   u8 fallback_channel) {
    const auto radiotap = ParseRadiotap(packet);
    if (!radiotap) {
        return std::nullopt;
    }

    const std::size_t frame_offset = radiotap->length;
    std::size_t frame_end = packet.size();
    if (radiotap->includes_fcs && frame_end >= frame_offset + 40) {
        frame_end -= 4;
    }
    if (frame_offset + 36 > frame_end) {
        return std::nullopt;
    }

    const u16 frame_control = ReadU16(packet.data() + frame_offset);
    const u8 type = static_cast<u8>((frame_control >> 2) & 0x3);
    const u8 subtype = static_cast<u8>((frame_control >> 4) & 0xF);
    if (type != 0 || subtype != 8) {
        return std::nullopt;
    }

    u8 channel = fallback_channel;
    bool has_nintendo_network_info = false;
    u32 wlan_comm_id = 0;
    u8 id = 0;
    std::size_t offset = frame_offset + 36;
    while (offset + 2 <= frame_end) {
        const u8 tag = packet[offset];
        const u8 length = packet[offset + 1];
        offset += 2;
        if (offset + length > frame_end) {
            break;
        }
        if (tag == 3 && length >= 1) {
            channel = packet[offset];
        } else if (tag == 221 && length >= 9 && packet[offset] == 0x00 &&
                   packet[offset + 1] == 0x1F && packet[offset + 2] == 0x32 &&
                   packet[offset + 3] == 21) {
            has_nintendo_network_info = true;
            wlan_comm_id = ReadU32BigEndian(packet.data() + offset + 4);
            id = packet[offset + 8];
        }
        offset += length;
    }

    if (!has_nintendo_network_info) {
        return std::nullopt;
    }

    CapturedBeacon result;
    result.channel = channel;
    result.wlan_comm_id = wlan_comm_id;
    result.id = id;
    std::memcpy(result.destination_address.data(), packet.data() + frame_offset + 4,
                result.destination_address.size());
    std::memcpy(result.transmitter_address.data(), packet.data() + frame_offset + 10,
                result.transmitter_address.size());
    // WifiPacket::data and nwm::UDS RecvBeaconBroadcastData contain the beacon body beginning
    // with the 12-byte fixed-parameters block. The over-the-air 24-byte 802.11 management header
    // is represented separately by WifiPacket's MAC fields and BeaconEntryHeader.
    result.frame.assign(packet.data() + frame_offset + Ieee80211ManagementHeaderSize,
                        packet.data() + frame_end);
    return result;
}

std::optional<CapturedFrame> ParseCapturedFrame(const std::vector<u8>& packet, u8 channel) {
    const auto radiotap = ParseRadiotap(packet);
    if (!radiotap) {
        return std::nullopt;
    }

    const std::size_t frame_offset = radiotap->length;
    std::size_t frame_end = packet.size();
    if (radiotap->includes_fcs && frame_end >= frame_offset + Ieee80211ManagementHeaderSize + 4) {
        frame_end -= 4;
    }
    if (frame_offset + Ieee80211ManagementHeaderSize > frame_end) {
        return std::nullopt;
    }

    CapturedFrame result;
    result.channel = channel;
    result.frame_control = ReadU16(packet.data() + frame_offset);
    result.sequence_control = ReadU16(packet.data() + frame_offset + 22);
    result.type = static_cast<u8>((result.frame_control >> 2) & 0x3);
    result.subtype = static_cast<u8>((result.frame_control >> 4) & 0xF);

    // Control frames have different/shorter headers and are not part of the UDS connection path.
    if (result.type == 1) {
        return std::nullopt;
    }

    std::array<u8, 6> address1{};
    std::array<u8, 6> address2{};
    std::array<u8, 6> address3{};
    std::memcpy(address1.data(), packet.data() + frame_offset + 4, address1.size());
    std::memcpy(address2.data(), packet.data() + frame_offset + 10, address2.size());
    std::memcpy(address3.data(), packet.data() + frame_offset + 16, address3.size());
    result.transmitter_address = address2;

    const bool to_ds = (result.frame_control & 0x0100) != 0;
    const bool from_ds = (result.frame_control & 0x0200) != 0;
    if (result.type == 2 && to_ds && !from_ds) {
        result.destination_address = address3;
        result.bssid = address1;
    } else if (result.type == 2 && from_ds && !to_ds) {
        result.destination_address = address1;
        result.bssid = address2;
    } else {
        result.destination_address = address1;
        result.bssid = address3;
    }

    result.body.assign(packet.data() + frame_offset + Ieee80211ManagementHeaderSize,
                       packet.data() + frame_end);
    return result;
}

std::vector<u8> AddRadiotapHeader(std::span<const u8> frame) {
    std::vector<u8> packet;
    packet.reserve(8 + frame.size());
    packet.push_back(0);
    packet.push_back(0);
    AppendU16(packet, 8);
    AppendU32(packet, 0);
    packet.insert(packet.end(), frame.begin(), frame.end());
    return packet;
}

void RunMonitorBody(std::atomic<bool>& stop_requested, u16 requested_channel,
                    const Nl80211Monitor::BeaconCallback& beacon_callback,
                    const Nl80211Monitor::FrameCallback& frame_callback,
                    const PhysicalBeaconProvider& physical_beacon_provider,
                    const PhysicalFrameProvider& physical_frame_provider) {
    LdndConnection connection;
    u32 generic_socket_id = 0;
    u32 packet_socket_id = 0;
    u32 monitor_ifindex = 0;
    u16 family_id = 0;
    u32 port_id = 0;
    u32 sequence = 0;

    try {
        const u32 frequency = ChannelToFrequency(requested_channel);
        LOG_INFO(Service_NWM,
                 "UDS Real: starting physical beacon monitor, channel={}, frequency={}",
                 requested_channel, frequency);
        connection.Connect();
        generic_socket_id = connection.Socket(AfNetlink, SockDgram, NetlinkGeneric);
        connection.Bind(generic_socket_id, PackSockaddrNl());
        port_id = ParseSockaddrNlPort(connection.GetSockName(generic_socket_id));
        connection.Start(generic_socket_id);
        family_id = ResolveNl80211Family(connection, generic_socket_id, port_id, sequence);

        auto interfaces = EnumerateInterfaces(connection, generic_socket_id, port_id, family_id,
                                              sequence);
        if (const auto old = std::find_if(interfaces.begin(), interfaces.end(),
                                          [](const InterfaceInfo& item) {
                                              return item.name == MonitorName;
                                          });
            old != interfaces.end()) {
            LOG_INFO(Service_NWM, "UDS Real: removing stale {} ifindex={}", MonitorName,
                     old->ifindex);
            DeleteInterface(connection, generic_socket_id, port_id, family_id, old->ifindex,
                            sequence);
            interfaces = EnumerateInterfaces(connection, generic_socket_id, port_id, family_id,
                                             sequence);
        }

        const auto physical = std::find_if(interfaces.begin(), interfaces.end(),
                                           [](const InterfaceInfo& item) {
                                               return item.iftype != Nl80211IfTypeMonitor;
                                           });
        if (physical == interfaces.end()) {
            throw std::runtime_error("no physical nl80211 interface was found");
        }

        CreateMonitorInterface(connection, generic_socket_id, port_id, family_id,
                               physical->wiphy, sequence);
        interfaces = EnumerateInterfaces(connection, generic_socket_id, port_id, family_id,
                                         sequence);
        const auto monitor = std::find_if(interfaces.begin(), interfaces.end(),
                                          [](const InterfaceInfo& item) {
                                              return item.name == MonitorName;
                                          });
        if (monitor == interfaces.end()) {
            throw std::runtime_error("nl80211 accepted monitor creation but udsmon0 was not found");
        }
        monitor_ifindex = monitor->ifindex;

        SetInterfaceUp(connection, monitor_ifindex);
        SetChannel(connection, generic_socket_id, port_id, family_id, monitor_ifindex, frequency,
                   sequence);

        // socket(2) receives the protocol argument in host byte order, while Linux expects
        // htons(ETH_P_ALL), hence 0x0300 here.
        packet_socket_id = connection.Socket(AfPacket, SockRaw, 0x0300);
        connection.Bind(packet_socket_id, PackSockaddrLl(monitor_ifindex));
        connection.Start(packet_socket_id);
        LOG_INFO(Service_NWM,
                 "UDS Real: physical beacon monitor ready, interface={}, ifindex={}, wiphy={}, "
                 "channel={}",
                 monitor->name, monitor->ifindex, monitor->wiphy, requested_channel);

        std::vector<u16> discovery_channels;
        discovery_channels.reserve(PrimaryDiscoveryChannels.size() + 1);
        discovery_channels.push_back(requested_channel);
        for (const u16 channel : PrimaryDiscoveryChannels) {
            if (channel != requested_channel) {
                discovery_channels.push_back(channel);
            }
        }
        LOG_INFO(Service_NWM,
                 "UDS Real: discovery channel hopping active, primaryChannels=1,6,11, "
                 "dwellMs={}, foundChannelIdleTimeoutSeconds={}, startingChannel={}",
                 DiscoveryChannelDwell.count(), DiscoveryChannelHold.count(),
                 requested_channel);

        std::size_t packet_count = 0;
        std::size_t delivered_beacon_count = 0;
        std::size_t transmitted_beacon_count = 0;
        std::size_t transmitted_beacon_echo_count = 0;
        std::size_t probe_frame_count = 0;
        std::size_t relevant_probe_frame_count = 0;
        std::size_t delivered_frame_count = 0;
        std::size_t transmitted_frame_count = 0;
        std::size_t completed_sweeps = 0;
        std::size_t channel_index = 0;
        u16 current_channel = requested_channel;
        std::array<std::size_t, 14> packets_by_channel{};
        std::array<bool, 15> unavailable_channels{};
        bool have_recent_nintendo_beacon = false;
        bool have_nintendo_source = false;
        std::array<u8, 6> nintendo_source{};
        std::array<u8, 6> probe_source{};
        if (monitor->mac.size() == probe_source.size()) {
            std::copy(monitor->mac.begin(), monitor->mac.end(), probe_source.begin());
        } else {
            // Locally administered diagnostic address used only if nl80211 omitted the monitor
            // interface MAC attribute.
            probe_source = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        }
        std::size_t transmitted_probe_count = 0;
        u16 transmitted_probe_sequence = 0;
        u16 transmitted_beacon_sequence = 0;
        std::optional<PhysicalBeaconSnapshot> latest_physical_beacon;
        auto last_nintendo_beacon = std::chrono::steady_clock::time_point{};
        auto next_channel_hop = std::chrono::steady_clock::now() + DiscoveryChannelDwell;
        auto next_active_probe = std::chrono::steady_clock::now();
        auto next_physical_beacon = std::chrono::steady_clock::now();
        while (!stop_requested.load(std::memory_order_relaxed)) {
            std::vector<u8> packet;
            if (connection.TryReceiveData(packet_socket_id, packet, 50)) {
                ++packet_count;
                if (current_channel <= 13) {
                    ++packets_by_channel[current_channel];
                }
                auto beacon = ParseNintendoBeacon(packet, static_cast<u8>(current_channel));
                if (beacon) {
                    const bool is_transmitted_beacon_echo =
                        latest_physical_beacon &&
                        beacon->transmitter_address == latest_physical_beacon->host_address;
                    if (is_transmitted_beacon_echo) {
                        ++transmitted_beacon_echo_count;
                        if (transmitted_beacon_echo_count <= 5 ||
                            transmitted_beacon_echo_count % 100 == 0) {
                            LOG_INFO(Service_NWM,
                                     "UDS Real: captured physical Nintendo beacon echo #{}, "
                                     "source={}, channel={}, beaconBodyBytes={}",
                                     transmitted_beacon_echo_count,
                                     FormatMac(beacon->transmitter_address.data()),
                                     beacon->channel, beacon->frame.size());
                        }
                    } else {
                        ++delivered_beacon_count;
                        last_nintendo_beacon = std::chrono::steady_clock::now();
                        if (!have_recent_nintendo_beacon) {
                            LOG_INFO(Service_NWM,
                                     "UDS Real: Nintendo beacon found; locking discovery scanner "
                                     "to channel {} with a {} second idle timeout",
                                     beacon->channel, DiscoveryChannelHold.count());
                        }
                        have_recent_nintendo_beacon = true;
                        have_nintendo_source = true;
                        nintendo_source = beacon->transmitter_address;
                        if (delivered_beacon_count == 1 || delivered_beacon_count % 100 == 0) {
                            LOG_INFO(Service_NWM,
                                     "UDS Real: delivered Nintendo beacon #{}, source={}, "
                                     "channel={}, wlanCommId=0x{:08X}, id={}, beaconBodyBytes={}",
                                     delivered_beacon_count,
                                     FormatMac(beacon->transmitter_address.data()),
                                     beacon->channel, beacon->wlan_comm_id, beacon->id,
                                     beacon->frame.size());
                        }
                        beacon_callback(std::move(*beacon));
                    }
                }

                // Deliver only non-beacon/probe traffic involving Azahar's advertised host MAC.
                // This avoids flooding nwm::UDS with unrelated traffic from the surrounding WLAN.
                if (latest_physical_beacon) {
                    auto frame = ParseCapturedFrame(packet, static_cast<u8>(current_channel));
                    if (frame && frame->transmitter_address != latest_physical_beacon->host_address &&
                        (frame->destination_address == latest_physical_beacon->host_address ||
                         frame->bssid == latest_physical_beacon->host_address)) {
                        const bool is_beacon = frame->type == 0 && frame->subtype == 8;
                        const bool is_probe =
                            frame->type == 0 && (frame->subtype == 4 || frame->subtype == 5);
                        if (!is_beacon && !is_probe) {
                            ++delivered_frame_count;
                            if (delivered_frame_count <= 40 || delivered_frame_count % 100 == 0) {
                                LOG_INFO(Service_NWM,
                                         "UDS Real: physical RX #{}, channel={}, type={}, "
                                         "subtype={}, protected={}, toDS={}, fromDS={}, "
                                         "source={}, destination={}, bssid={}, bodyBytes={}",
                                         delivered_frame_count, current_channel, frame->type,
                                         frame->subtype,
                                         (frame->frame_control & 0x4000) != 0,
                                         (frame->frame_control & 0x0100) != 0,
                                         (frame->frame_control & 0x0200) != 0,
                                         FormatMac(frame->transmitter_address.data()),
                                         FormatMac(frame->destination_address.data()),
                                         FormatMac(frame->bssid.data()), frame->body.size());
                            }
                            frame_callback(std::move(*frame));
                        }
                    }
                }

                const auto probe = ParseProbeFrame(packet);
                if (probe) {
                    ++probe_frame_count;
                    const bool from_nintendo_source =
                        have_nintendo_source && probe->transmitter_address == nintendo_source;
                    const bool from_probe_source =
                        probe->transmitter_address == probe_source;
                    const bool nintendo_scan_ssid = IsNintendoContinuousScanSsid(probe->ssid);
                    if (probe->has_nintendo_vendor_ie || from_nintendo_source ||
                        from_probe_source || nintendo_scan_ssid) {
                        ++relevant_probe_frame_count;
                        if (relevant_probe_frame_count <= 40 ||
                            relevant_probe_frame_count % 100 == 0) {
                            const char* kind = probe->subtype == 4 ? "request" : "response";
                            LOG_INFO(Service_NWM,
                                     "UDS Real: captured relevant probe {} #{}, channel={}, "
                                     "source={}, destination={}, bssid={}, fromBeaconSource={}, "
                                     "fromOurProbeSource={}, nintendoScanSsid={}, nintendoIe={}, "
                                     "ouiType=0x{:02X}, data={}, ssid={}",
                                     kind, relevant_probe_frame_count, current_channel,
                                     FormatMac(probe->transmitter_address.data()),
                                     FormatMac(probe->destination_address.data()),
                                     FormatMac(probe->bssid.data()), from_nintendo_source,
                                     from_probe_source, nintendo_scan_ssid,
                                     probe->has_nintendo_vendor_ie,
                                     probe->nintendo_oui_type, FormatHexBytes(probe->nintendo_data),
                                     FormatHexBytes(probe->ssid));
                        }
                    }
                }
            }

            const auto now = std::chrono::steady_clock::now();
            while (auto pending_frame = physical_frame_provider()) {
                const auto physical_frame = AddRadiotapHeader(*pending_frame);
                connection.SendTo(packet_socket_id, physical_frame);
                ++transmitted_frame_count;
                if (transmitted_frame_count <= 40 || transmitted_frame_count % 100 == 0) {
                    const u16 frame_control =
                        pending_frame->size() >= 2 ? ReadU16(pending_frame->data()) : 0;
                    LOG_INFO(Service_NWM,
                             "UDS Real: physical TX #{}, channel={}, type={}, subtype={}, "
                             "protected={}, toDS={}, fromDS={}, frameBytes={}",
                             transmitted_frame_count, current_channel,
                             static_cast<u8>((frame_control >> 2) & 0x3),
                             static_cast<u8>((frame_control >> 4) & 0xF),
                             (frame_control & 0x4000) != 0,
                             (frame_control & 0x0100) != 0,
                             (frame_control & 0x0200) != 0, pending_frame->size());
                }
            }
            if (now >= next_physical_beacon) {
                if (auto pending_beacon = physical_beacon_provider(); pending_beacon) {
                    latest_physical_beacon = std::move(*pending_beacon);
                    const auto physical_frame = GeneratePhysicalNintendoBeacon(
                        *latest_physical_beacon, transmitted_beacon_sequence++,
                        static_cast<u8>(current_channel));
                    connection.SendTo(packet_socket_id, physical_frame);
                    ++transmitted_beacon_count;
                    if (transmitted_beacon_count <= 5 || transmitted_beacon_count % 100 == 0) {
                        LOG_INFO(Service_NWM,
                                 "UDS Real: transmitted physical Nintendo beacon #{}, source={}, "
                                 "channel={}, beaconBodyBytes={}, frameBytes={}",
                                 transmitted_beacon_count,
                                 FormatMac(latest_physical_beacon->host_address.data()),
                                 current_channel, latest_physical_beacon->body.size(),
                                 physical_frame.size());
                    }
                }
                next_physical_beacon = now + PhysicalBeaconInterval;
            }

            const bool beacon_is_recent =
                have_recent_nintendo_beacon && now - last_nintendo_beacon < DiscoveryChannelHold;
            if (have_recent_nintendo_beacon && !beacon_is_recent) {
                have_recent_nintendo_beacon = false;
                LOG_INFO(Service_NWM,
                         "UDS Real: Nintendo beacon timed out on channel {}; resuming discovery "
                         "channel hopping",
                         current_channel);
            }

            if (beacon_is_recent && now >= next_active_probe) {
                const auto probe_request = GenerateNintendoScanProbeRequest(
                    probe_source, transmitted_probe_sequence++, static_cast<u8>(current_channel));
                connection.SendTo(packet_socket_id, probe_request);
                ++transmitted_probe_count;
                if (transmitted_probe_count <= 5 || transmitted_probe_count % 10 == 0) {
                    LOG_INFO(Service_NWM,
                             "UDS Real: transmitted directed Nintendo scan probe request #{}, "
                             "source={}, channel={}, frameBytes={}",
                             transmitted_probe_count, FormatMac(probe_source.data()),
                             current_channel, probe_request.size());
                }
                next_active_probe = now + ActiveProbeInterval;
            }
            if (now < next_channel_hop || beacon_is_recent) {
                continue;
            }

            bool channel_changed = false;
            for (std::size_t attempt = 0; attempt < discovery_channels.size(); ++attempt) {
                channel_index = (channel_index + 1) % discovery_channels.size();
                const u16 next_channel = discovery_channels[channel_index];
                if (unavailable_channels[next_channel]) {
                    continue;
                }
                try {
                    SetChannel(connection, generic_socket_id, port_id, family_id,
                               monitor_ifindex, ChannelToFrequency(next_channel), sequence);
                    current_channel = next_channel;
                    channel_changed = true;
                    if (channel_index == 0) {
                        ++completed_sweeps;
                        LOG_INFO(Service_NWM,
                                 "UDS Real: discovery sweep #{} complete, rawPacketsByChannel=[{}]",
                                 completed_sweeps, FormatChannelPacketCounts(packets_by_channel));
                    }
                    break;
                } catch (const std::exception& exception) {
                    unavailable_channels[next_channel] = true;
                    LOG_WARNING(Service_NWM,
                                "UDS Real: channel {} unavailable during discovery scan: {}",
                                next_channel, exception.what());
                }
            }
            if (!channel_changed) {
                throw std::runtime_error("no usable channel remained in the discovery scan");
            }
            next_channel_hop = std::chrono::steady_clock::now() + DiscoveryChannelDwell;
        }

        LOG_INFO(Service_NWM,
                 "UDS Real: stopping physical beacon monitor, packets={}, deliveredBeacons={}, "
                 "transmittedBeacons={}, beaconEchoes={}, transmittedProbes={}, probeFrames={}, "
                 "relevantProbeFrames={}, deliveredFrames={}, transmittedFrames={}, "
                 "completedSweeps={}, finalChannel={}",
                 packet_count, delivered_beacon_count, transmitted_beacon_count,
                 transmitted_beacon_echo_count, transmitted_probe_count, probe_frame_count,
                 relevant_probe_frame_count, delivered_frame_count, transmitted_frame_count,
                 completed_sweeps, current_channel);

        connection.CloseSocket(packet_socket_id);
        packet_socket_id = 0;
        DeleteInterface(connection, generic_socket_id, port_id, family_id, monitor_ifindex,
                        sequence);
        monitor_ifindex = 0;
        connection.CloseSocket(generic_socket_id);
        generic_socket_id = 0;
        LOG_INFO(Service_NWM, "UDS Real: physical beacon monitor stopped; udsmon0 removed");
    } catch (const std::exception& exception) {
        LOG_ERROR(Service_NWM, "UDS Real: physical beacon monitor failed: {}", exception.what());
        if (packet_socket_id != 0) {
            try {
                connection.CloseSocket(packet_socket_id);
            } catch (...) {
            }
        }
        if (monitor_ifindex != 0 && generic_socket_id != 0) {
            try {
                DeleteInterface(connection, generic_socket_id, port_id, family_id,
                                monitor_ifindex, sequence);
            } catch (const std::exception& cleanup_exception) {
                LOG_WARNING(Service_NWM, "UDS Real: monitor cleanup failed: {}",
                            cleanup_exception.what());
            }
        }
        if (generic_socket_id != 0) {
            try {
                connection.CloseSocket(generic_socket_id);
            } catch (...) {
            }
        }
    }
}

} // namespace

struct Nl80211Monitor::Impl {
    std::atomic<bool> stop_requested{false};
    std::atomic<bool> running{false};
    std::mutex mutex;
    std::thread worker;
    bool have_pending_beacon{};
    PhysicalBeaconSnapshot pending_beacon;
    std::deque<std::vector<u8>> pending_frames;
};

Nl80211Monitor::Nl80211Monitor() : impl{std::make_unique<Impl>()} {}

Nl80211Monitor::~Nl80211Monitor() {
    Stop();
}

void Nl80211Monitor::Start(u16 channel, BeaconCallback beacon_callback,
                           FrameCallback frame_callback) {
    Stop();
    if (!beacon_callback || !frame_callback) {
        throw std::invalid_argument("UDS Real monitor requires beacon and frame callbacks");
    }

    std::scoped_lock lock{impl->mutex};
    impl->stop_requested.store(false, std::memory_order_relaxed);
    impl->running.store(true, std::memory_order_relaxed);
    impl->have_pending_beacon = false;
    impl->pending_beacon = {};
    impl->pending_frames.clear();
    impl->worker = std::thread{[this, channel, beacon_callback = std::move(beacon_callback),
                                frame_callback = std::move(frame_callback)]() mutable {
#ifdef _WIN32
        const PhysicalBeaconProvider physical_beacon_provider = [this]() {
            std::scoped_lock lock{impl->mutex};
            if (!impl->have_pending_beacon) {
                return std::optional<PhysicalBeaconSnapshot>{};
            }
            return std::optional<PhysicalBeaconSnapshot>{impl->pending_beacon};
        };
        const PhysicalFrameProvider physical_frame_provider = [this]() {
            std::scoped_lock lock{impl->mutex};
            if (impl->pending_frames.empty()) {
                return std::optional<std::vector<u8>>{};
            }
            std::vector<u8> frame = std::move(impl->pending_frames.front());
            impl->pending_frames.pop_front();
            return std::optional<std::vector<u8>>{std::move(frame)};
        };
        RunMonitorBody(impl->stop_requested, channel, beacon_callback, frame_callback,
                       physical_beacon_provider, physical_frame_provider);
#else
        (void)channel;
        (void)beacon_callback;
        (void)frame_callback;
        LOG_WARNING(Service_NWM, "UDS Real: physical monitor unavailable on this platform");
#endif
        impl->running.store(false, std::memory_order_relaxed);
    }};
}

void Nl80211Monitor::SubmitFrame(std::span<const u8> frame) {
    if (frame.empty()) {
        return;
    }

    std::scoped_lock lock{impl->mutex};
    constexpr std::size_t MaxPendingFrames = 256;
    if (impl->pending_frames.size() >= MaxPendingFrames) {
        impl->pending_frames.pop_front();
        LOG_WARNING(Service_NWM, "UDS Real: physical TX queue full; dropped oldest frame");
    }
    impl->pending_frames.emplace_back(frame.begin(), frame.end());
}

void Nl80211Monitor::SubmitBeacon(std::span<const u8> beacon_body,
                                  const std::array<u8, 6>& host_address) {
    if (beacon_body.empty()) {
        return;
    }

    std::scoped_lock lock{impl->mutex};
    impl->pending_beacon.body.assign(beacon_body.begin(), beacon_body.end());
    impl->pending_beacon.host_address = host_address;
    impl->have_pending_beacon = true;
}

void Nl80211Monitor::Stop() {
    std::thread worker;
    {
        std::scoped_lock lock{impl->mutex};
        impl->stop_requested.store(true, std::memory_order_relaxed);
        worker = std::move(impl->worker);
    }
    if (worker.joinable()) {
        worker.join();
    }
    impl->running.store(false, std::memory_order_relaxed);
}

bool Nl80211Monitor::IsRunning() const {
    return impl->running.load(std::memory_order_relaxed);
}

} // namespace Service::NWM::UdsReal
