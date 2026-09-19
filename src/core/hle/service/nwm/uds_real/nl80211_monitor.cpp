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
#include <iterator>
#include <mutex>
#include <optional>
#include <set>
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
constexpr u8 Nl80211CmdSetBeacon = 14;
constexpr u8 Nl80211CmdStartAp = 15;
constexpr u8 Nl80211CmdStopAp = 16;
constexpr u8 Nl80211CmdSetStation = 18;
constexpr u8 Nl80211CmdNewStation = 19;
constexpr u8 Nl80211CmdDelStation = 20;
constexpr u8 Nl80211CmdSetChannel = 65;
constexpr u16 Nl80211AttrWiphy = 1;
constexpr u16 Nl80211AttrIfIndex = 3;
constexpr u16 Nl80211AttrIfName = 4;
constexpr u16 Nl80211AttrIfType = 5;
constexpr u16 Nl80211AttrMac = 6;
constexpr u16 Nl80211AttrBeaconInterval = 12;
constexpr u16 Nl80211AttrDtimPeriod = 13;
constexpr u16 Nl80211AttrBeaconHead = 14;
constexpr u16 Nl80211AttrBeaconTail = 15;
constexpr u16 Nl80211AttrStaAid = 16;
constexpr u16 Nl80211AttrStaListenInterval = 18;
constexpr u16 Nl80211AttrStaSupportedRates = 19;
constexpr u16 Nl80211AttrMntrFlags = 23;
constexpr u16 Nl80211AttrHtCapability = 31;
constexpr u16 Nl80211AttrWiphyFreq = 38;
constexpr u16 Nl80211AttrSsid = 52;
constexpr u16 Nl80211AttrAuthType = 53;
constexpr u16 Nl80211AttrPrivacy = 70;
constexpr u16 Nl80211AttrCipherSuitesPairwise = 73;
constexpr u16 Nl80211AttrCipherSuiteGroup = 74;
constexpr u16 Nl80211AttrAkmSuites = 76;
constexpr u16 Nl80211AttrHiddenSsid = 126;
constexpr u16 Nl80211AttrStaCapability = 171;
constexpr u16 Nl80211AttrStaExtCapability = 172;
constexpr u16 Nl80211AttrStaSupportedChannels = 189;
constexpr u16 Nl80211AttrSocketOwner = 204;
constexpr u32 Nl80211IfTypeAccessPoint = 3;
constexpr u32 Nl80211IfTypeMonitor = 6;
constexpr u16 Nl80211MntrFlagOtherBss = 4;
constexpr u16 Nl80211MntrFlagActive = 6;
constexpr u32 WlanCipherSuiteCcmp = 0x000FAC04;
constexpr u32 WlanAkmSuitePsk = 0x000FAC02;
constexpr u32 AuthTypeOpenSystem = 0;
constexpr u32 HiddenSsidZeroContents = 2;

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
constexpr u16 IflaAddress = 1;
constexpr u32 IffUp = 1;

constexpr std::size_t NetlinkHeaderLength = 16;
constexpr std::size_t GenericHeaderLength = 4;
constexpr char MonitorName[] = "udsmon0";
constexpr char AccessPointName[] = "udsap0";
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
    // True for the minimal beacon used only to bring up the client-role ACK shell: it is never
    // transmitted as a raw Nintendo beacon and never treated as a hosted network.
    bool ack_shell_only{};
};

struct AccessPointConfiguration {
    std::array<u8, 6> host_address{};
    std::array<u8, 8> ssid{};
    u8 max_stations{};
    u64 generation{};
    bool enabled{};
};

struct AccessPointStationRequest {
    std::array<u8, 6> station_address{};
    std::vector<u8> association_body;
    bool remove{};
};

struct AccessPointDataFrame {
    std::vector<u8> payload;
    std::array<u8, 6> transmitter_address{};
    std::array<u8, 6> destination_address{};
};

struct AccessPointBeaconParts {
    std::vector<u8> head;
    std::vector<u8> tail;
};

using PhysicalBeaconProvider = std::function<std::optional<PhysicalBeaconSnapshot>()>;
using PhysicalFrameProvider = std::function<std::optional<std::vector<u8>>() >;
using AccessPointConfigurationProvider = std::function<AccessPointConfiguration()>;
using AccessPointActivationProvider = std::function<bool()>;
using AccessPointStationProvider =
    std::function<std::optional<AccessPointStationRequest>()>;
using AccessPointDataProvider = std::function<std::optional<AccessPointDataFrame>()>;

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

u64 ReadCCMPPacketNumber(const u8* header) {
    return static_cast<u64>(header[0]) | (static_cast<u64>(header[1]) << 8) |
           (static_cast<u64>(header[4]) << 16) | (static_cast<u64>(header[5]) << 24) |
           (static_cast<u64>(header[6]) << 32) | (static_cast<u64>(header[7]) << 40);
}

u32 FingerprintBytes(std::span<const u8> bytes) {
    u32 fingerprint = 2166136261U;
    for (const u8 byte : bytes) {
        fingerprint ^= byte;
        fingerprint *= 16777619U;
    }
    return fingerprint;
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

void AppendU16Attribute(std::vector<u8>& output, u16 type, u16 value) {
    const u8 bytes[] = {static_cast<u8>(value), static_cast<u8>(value >> 8)};
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
                            u16 family_id, u32 wiphy, bool active, u32& sequence) {
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrWiphy, wiphy);
    AppendAttribute(attributes, Nl80211AttrIfName, reinterpret_cast<const u8*>(MonitorName),
                    sizeof(MonitorName));
    AppendU32Attribute(attributes, Nl80211AttrIfType, Nl80211IfTypeMonitor);

    std::vector<u8> monitor_flags;
    AppendAttribute(monitor_flags, Nl80211MntrFlagOtherBss, nullptr, 0);
    if (active) {
        // Active monitor mode makes mac80211 use the interface's configured MAC address and
        // generate timing-critical ACKs for unicast frames addressed to it. Frame contents,
        // CCMP, and UDS state remain owned by Azahar's monitor transport.
        AppendAttribute(monitor_flags, Nl80211MntrFlagActive, nullptr, 0);
    }
    AppendAttribute(attributes, static_cast<u16>(Nl80211AttrMntrFlags | NlaFNested),
                    monitor_flags.data(), monitor_flags.size());
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdNewInterface,
                          attributes, sequence,
                          active ? "create active monitor interface" : "create monitor interface");
}

void CreateAccessPointInterface(LdndConnection& connection, u32 socket_id, u32 port_id,
                                u16 family_id, u32 wiphy,
                                const std::array<u8, 6>& host_address, u32& sequence) {
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrWiphy, wiphy);
    AppendAttribute(attributes, Nl80211AttrIfName,
                    reinterpret_cast<const u8*>(AccessPointName), sizeof(AccessPointName));
    AppendU32Attribute(attributes, Nl80211AttrIfType, Nl80211IfTypeAccessPoint);
    AppendAttribute(attributes, Nl80211AttrMac, host_address.data(), host_address.size());
    // Have cfg80211 remove the virtual interface if ldnd's owning netlink socket disappears.
    AppendAttribute(attributes, Nl80211AttrSocketOwner, nullptr, 0);
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdNewInterface,
                          attributes, sequence, "create UDS access-point interface");
}

AccessPointBeaconParts GenerateAccessPointBeaconParts(const PhysicalBeaconSnapshot& beacon,
                                                       u8 channel) {
    constexpr std::size_t BeaconFixedParametersSize = 12;
    if (beacon.body.size() < BeaconFixedParametersSize) {
        throw std::runtime_error("generated UDS beacon body is missing fixed parameters");
    }

    std::vector<u8> body = beacon.body;
    bool found_ds_parameter = false;
    std::size_t offset = BeaconFixedParametersSize;
    while (offset + 2 <= body.size()) {
        const u8 tag = body[offset];
        const std::size_t length = body[offset + 1];
        if (offset + 2 + length > body.size()) {
            throw std::runtime_error("generated UDS beacon contains a malformed information element");
        }
        if (tag == 3 && length >= 1) {
            body[offset + 2] = channel;
            found_ds_parameter = true;
        }
        offset += 2 + length;
    }
    if (!found_ds_parameter) {
        body.push_back(3);
        body.push_back(1);
        body.push_back(channel);
    }

    AccessPointBeaconParts result;
    result.head.reserve(Ieee80211ManagementHeaderSize + body.size());
    AppendU16(result.head, 0x0080); // Beacon management frame.
    AppendU16(result.head, 0);
    result.head.insert(result.head.end(), 6, 0xFF);
    result.head.insert(result.head.end(), beacon.host_address.begin(), beacon.host_address.end());
    result.head.insert(result.head.end(), beacon.host_address.begin(), beacon.host_address.end());
    AppendU16(result.head, 0); // mac80211 supplies the live sequence number.
    result.head.insert(result.head.end(), body.begin(),
                       body.begin() + BeaconFixedParametersSize);

    // mac80211 owns the TIM element. Keep every Nintendo vendor element after that generated TIM
    // so the firmware beacon is byte-for-byte compatible with Azahar's proven raw beacon body.
    offset = BeaconFixedParametersSize;
    bool found_tim = false;
    while (offset + 2 <= body.size()) {
        const std::size_t element_start = offset;
        const u8 tag = body[offset];
        const std::size_t length = body[offset + 1];
        offset += 2;
        if (offset + length > body.size()) {
            throw std::runtime_error("generated UDS beacon contains a malformed information element");
        }
        if (tag == 5) {
            result.tail.assign(body.begin() + offset + length, body.end());
            found_tim = true;
            break;
        }
        result.head.insert(result.head.end(), body.begin() + element_start,
                           body.begin() + offset + length);
        offset += length;
    }
    if (!found_tim) {
        result.tail.clear();
    }
    return result;
}

void StartAccessPoint(LdndConnection& connection, u32 socket_id, u32 port_id, u16 family_id,
                      u32 ifindex, const AccessPointConfiguration& config,
                      const PhysicalBeaconSnapshot& beacon, u8 channel, u32& sequence) {
    const auto beacon_parts = GenerateAccessPointBeaconParts(beacon, channel);
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrIfIndex, ifindex);
    AppendU32Attribute(attributes, Nl80211AttrWiphyFreq, ChannelToFrequency(channel));
    AppendU32Attribute(attributes, Nl80211AttrBeaconInterval, 100);
    AppendU32Attribute(attributes, Nl80211AttrDtimPeriod, 3);
    AppendAttribute(attributes, Nl80211AttrBeaconHead, beacon_parts.head.data(),
                    beacon_parts.head.size());
    AppendAttribute(attributes, Nl80211AttrBeaconTail, beacon_parts.tail.data(),
                    beacon_parts.tail.size());
    AppendAttribute(attributes, Nl80211AttrSsid, config.ssid.data(), config.ssid.size());
    AppendAttribute(attributes, Nl80211AttrMac, config.host_address.data(),
                    config.host_address.size());
    AppendU32Attribute(attributes, Nl80211AttrAuthType, AuthTypeOpenSystem);
    AppendAttribute(attributes, Nl80211AttrPrivacy, nullptr, 0);
    AppendU32Attribute(attributes, Nl80211AttrCipherSuitesPairwise, WlanCipherSuiteCcmp);
    AppendU32Attribute(attributes, Nl80211AttrCipherSuiteGroup, WlanCipherSuiteCcmp);
    AppendU32Attribute(attributes, Nl80211AttrAkmSuites, WlanAkmSuitePsk);
    AppendU32Attribute(attributes, Nl80211AttrHiddenSsid, HiddenSsidZeroContents);
    AppendAttribute(attributes, Nl80211AttrSocketOwner, nullptr, 0);
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdStartAp,
                          attributes, sequence, "start UDS access point");
}

void SetAccessPointBeacon(LdndConnection& connection, u32 socket_id, u32 port_id,
                          u16 family_id, u32 ifindex, const PhysicalBeaconSnapshot& beacon,
                          u8 channel, u32& sequence) {
    const auto beacon_parts = GenerateAccessPointBeaconParts(beacon, channel);
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrIfIndex, ifindex);
    AppendAttribute(attributes, Nl80211AttrBeaconHead, beacon_parts.head.data(),
                    beacon_parts.head.size());
    AppendAttribute(attributes, Nl80211AttrBeaconTail, beacon_parts.tail.data(),
                    beacon_parts.tail.size());
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdSetBeacon,
                          attributes, sequence, "update UDS ACK-shell beacon");
}

void StopAccessPoint(LdndConnection& connection, u32 socket_id, u32 port_id, u16 family_id,
                     u32 ifindex, u32& sequence) {
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrIfIndex, ifindex);
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdStopAp,
                          attributes, sequence, "stop UDS access point");
}

std::vector<u8> GenerateAccessPointEthernetFrame(const AccessPointDataFrame& frame) {
    constexpr std::size_t LlcHeaderSize = 8;
    if (frame.payload.size() < LlcHeaderSize || frame.payload[0] != 0xAA ||
        frame.payload[1] != 0xAA || frame.payload[2] != 0x03) {
        throw std::runtime_error("UDS AP data payload does not contain an LLC/SNAP header");
    }

    std::vector<u8> result;
    result.reserve(14 + frame.payload.size() - LlcHeaderSize);
    result.insert(result.end(), frame.destination_address.begin(),
                  frame.destination_address.end());
    result.insert(result.end(), frame.transmitter_address.begin(),
                  frame.transmitter_address.end());
    // Ethernet carries the SNAP EtherType directly; mac80211 reconstructs LLC/SNAP on air.
    result.push_back(frame.payload[6]);
    result.push_back(frame.payload[7]);
    result.insert(result.end(), frame.payload.begin() + LlcHeaderSize, frame.payload.end());
    return result;
}

std::optional<std::span<const u8>> FindInformationElement(std::span<const u8> body, u8 id) {
    std::size_t offset = 4; // Capability and listen interval precede association-request IEs.
    while (offset + 2 <= body.size()) {
        const u8 element_id = body[offset];
        const std::size_t length = body[offset + 1];
        offset += 2;
        if (offset + length > body.size()) {
            return std::nullopt;
        }
        if (element_id == id) {
            return body.subspan(offset, length);
        }
        offset += length;
    }
    return std::nullopt;
}

void RegisterAccessPointStation(LdndConnection& connection, u32 socket_id, u32 port_id,
                                u16 family_id, u32 ifindex,
                                const AccessPointConfiguration& config,
                                const AccessPointStationRequest& request, u16 aid,
                                u32& sequence) {
    if (request.association_body.size() < 4) {
        throw std::runtime_error("retail association request is missing fixed parameters");
    }
    const auto requested_ssid = FindInformationElement(request.association_body, 0);
    const auto supported_rates = FindInformationElement(request.association_body, 1);
    if (!requested_ssid || requested_ssid->size() != config.ssid.size() ||
        !std::equal(requested_ssid->begin(), requested_ssid->end(), config.ssid.begin())) {
        throw std::runtime_error("retail association request contains a different UDS SSID");
    }
    if (!supported_rates || supported_rates->empty()) {
        throw std::runtime_error("retail association request has no supported rates");
    }

    const u16 capability = ReadU16(request.association_body.data());
    const u16 listen_interval = ReadU16(request.association_body.data() + 2);
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrIfIndex, ifindex);
    AppendAttribute(attributes, Nl80211AttrMac, request.station_address.data(),
                    request.station_address.size());
    AppendU16Attribute(attributes, Nl80211AttrStaListenInterval, listen_interval);
    AppendAttribute(attributes, Nl80211AttrStaSupportedRates, supported_rates->data(),
                    supported_rates->size());
    AppendU16Attribute(attributes, Nl80211AttrStaCapability, capability);
    AppendU16Attribute(attributes, Nl80211AttrStaAid, aid);
    const auto append_optional = [&](u8 information_element, u16 attribute) {
        if (const auto value = FindInformationElement(request.association_body,
                                                      information_element);
            value && !value->empty()) {
            AppendAttribute(attributes, attribute, value->data(), value->size());
        }
    };
    append_optional(45, Nl80211AttrHtCapability);
    append_optional(36, Nl80211AttrStaSupportedChannels);
    append_optional(127, Nl80211AttrStaExtCapability);
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdNewStation,
                          attributes, sequence, "register retail UDS station");
}

void RemoveAccessPointStation(LdndConnection& connection, u32 socket_id, u32 port_id,
                              u16 family_id, u32 ifindex,
                              const std::array<u8, 6>& station, u32& sequence) {
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrIfIndex, ifindex);
    AppendAttribute(attributes, Nl80211AttrMac, station.data(), station.size());
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdDelStation,
                          attributes, sequence, "remove retail UDS station");
}

void SetChannel(LdndConnection& connection, u32 socket_id, u32 port_id, u16 family_id,
                u32 ifindex, u32 frequency, u32& sequence) {
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrIfIndex, ifindex);
    AppendU32Attribute(attributes, Nl80211AttrWiphyFreq, frequency);
    SendGenericAckRequest(connection, socket_id, port_id, family_id, Nl80211CmdSetChannel,
                          attributes, sequence, "set monitor channel");
}

void SetInterfaceState(LdndConnection& connection, u32 ifindex, bool up,
                       const char* operation) {
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
        request[NetlinkHeaderLength + 8] = up ? static_cast<u8>(IffUp) : 0;
        request[NetlinkHeaderLength + 12] = static_cast<u8>(IffUp);
        connection.SendTo(socket_id, request);
        WaitForAck(connection, socket_id, 1, operation);
        connection.CloseSocket(socket_id);
    } catch (...) {
        connection.CloseSocket(socket_id);
        throw;
    }
}

void SetInterfaceMac(LdndConnection& connection, u32 ifindex,
                     const std::array<u8, 6>& address) {
    const u32 socket_id = connection.Socket(AfNetlink, SockDgram, NetlinkRoute);
    try {
        connection.Bind(socket_id, PackSockaddrNl());
        const u32 port_id = ParseSockaddrNlPort(connection.GetSockName(socket_id));
        connection.Start(socket_id);

        constexpr std::size_t IfInfoMessageLength = 16;
        constexpr std::size_t AddressAttributeLength = 12;
        const u32 message_length = static_cast<u32>(NetlinkHeaderLength + IfInfoMessageLength +
                                                    AddressAttributeLength);
        std::vector<u8> request;
        request.reserve(message_length);
        AppendU32(request, message_length);
        AppendU16(request, RtmNewLink);
        AppendU16(request, NlmFRequest | NlmFAck);
        AppendU32(request, 1);
        AppendU32(request, port_id);
        request.resize(NetlinkHeaderLength + IfInfoMessageLength, 0);
        request[NetlinkHeaderLength + 4] = static_cast<u8>(ifindex);
        request[NetlinkHeaderLength + 5] = static_cast<u8>(ifindex >> 8);
        request[NetlinkHeaderLength + 6] = static_cast<u8>(ifindex >> 16);
        request[NetlinkHeaderLength + 7] = static_cast<u8>(ifindex >> 24);
        AppendAttribute(request, IflaAddress, address.data(), address.size());
        connection.SendTo(socket_id, request);
        WaitForAck(connection, socket_id, 1, "set active monitor MAC address");
        connection.CloseSocket(socket_id);
    } catch (...) {
        connection.CloseSocket(socket_id);
        throw;
    }
}

void SetInterfaceUp(LdndConnection& connection, u32 ifindex) {
    SetInterfaceState(connection, ifindex, true, "bring wireless interface up");
}

void SetInterfaceDown(LdndConnection& connection, u32 ifindex) {
    SetInterfaceState(connection, ifindex, false, "bring wireless interface down");
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

// Per-frame radio details from a captured radiotap header: transmit/receive rate, signal strength
// and channel. Only used to log link quality; unknown or malformed fields are simply left empty.
struct RadiotapSignal {
    std::optional<u8> rate_500kbps;
    std::optional<s8> signal_dbm;
    std::optional<u16> channel_mhz;
    std::optional<std::array<u8, 3>> mcs;
};

RadiotapSignal DescribeRadiotapSignal(const std::vector<u8>& packet) {
    RadiotapSignal out;
    if (packet.size() < 8 || packet[0] != 0) {
        return out;
    }
    const std::size_t length = ReadU16(packet.data() + 2);
    if (length < 8 || length > packet.size()) {
        return out;
    }
    std::size_t present_offset = 4;
    u32 first_present = 0;
    bool have_first = false;
    for (;;) {
        if (present_offset + 4 > length) {
            return out;
        }
        const u32 present = ReadU32(packet.data() + present_offset);
        if (!have_first) {
            first_present = present;
            have_first = true;
        }
        present_offset += 4;
        if ((present & (1U << 31)) == 0) {
            break;
        }
    }

    std::size_t offset = present_offset;
    // Returns the offset of a present field (after alignment) and advances past it.
    const auto field = [&](unsigned bit, std::size_t align,
                           std::size_t size) -> std::optional<std::size_t> {
        if ((first_present & (1U << bit)) == 0) {
            return std::nullopt;
        }
        offset = (offset + align - 1) & ~(align - 1);
        if (offset + size > length) {
            offset = length + 1;
            return std::nullopt;
        }
        const std::size_t at = offset;
        offset += size;
        return at;
    };
    field(0, 8, 8); // TSFT
    field(1, 1, 1); // Flags
    if (const auto at = field(2, 1, 1)) {
        out.rate_500kbps = packet[*at];
    }
    if (const auto at = field(3, 2, 4)) {
        out.channel_mhz = ReadU16(packet.data() + *at);
    }
    field(4, 2, 2); // FHSS
    if (const auto at = field(5, 1, 1)) {
        out.signal_dbm = static_cast<s8>(packet[*at]);
    }
    field(6, 1, 1);  // dBm antenna noise
    field(7, 2, 2);  // Lock quality
    field(8, 2, 2);  // TX attenuation
    field(9, 2, 2);  // dB TX attenuation
    field(10, 1, 1); // dBm TX power
    field(11, 1, 1); // Antenna
    field(12, 1, 1); // dB antenna signal
    field(13, 1, 1); // dB antenna noise
    field(14, 2, 2); // RX flags
    field(15, 2, 2); // TX flags
    field(16, 1, 1); // RTS retries
    field(17, 1, 1); // Data retries
    field(18, 4, 8); // XChannel
    if (const auto at = field(19, 1, 3)) {
        out.mcs = std::array<u8, 3>{packet[*at], packet[*at + 1], packet[*at + 2]};
    }
    return out;
}

// Transmit rate, in 500 kbps units, for game data frames a client originates (NoDS/ToDS data).
// 11 Mbps was the rate that worked in testing: the injection default (1 Mbps) leaves a client's
// data on the air too long, and 54 Mbps got no replies from the retail host.
constexpr u8 ClientDataTxRate500kbps = 22;

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
    result.mpdu.assign(packet.data() + frame_offset, packet.data() + frame_end);
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

bool IsGroupAddressedFrame(std::span<const u8> frame) {
    // Address 1 starts at byte four in every three-address 802.11 management/data header. The
    // low bit of its first octet distinguishes an individual address from multicast/broadcast.
    return frame.size() >= 10 && (frame[4] & 0x01) != 0;
}

std::vector<u8> AddRadiotapHeader(std::span<const u8> frame, bool no_ack) {
    constexpr u32 RadiotapPresentRate = 1U << 2;
    constexpr u32 RadiotapPresentTxFlags = 1U << 15;
    constexpr u16 RadiotapTxNoAck = 0x0008;

    // Optional experiment: fixed rate for data frames a client originates (NoDS/ToDS). Frames a
    // host sends (FromDS) and all management frames keep the driver's default rate.
    std::optional<u8> rate;
    if (frame.size() >= 2) {
        const u16 frame_control = ReadU16(frame.data());
        const bool is_data = ((frame_control >> 2) & 0x3) == 2;
        const bool from_ds = (frame_control & 0x0200) != 0;
        if (is_data && !from_ds) {
            rate = ClientDataTxRate500kbps;
        }
    }

    u32 present = 0;
    u16 radiotap_length = 8;
    if (rate) {
        present |= RadiotapPresentRate;
        radiotap_length = 9;
    }
    if (no_ack) {
        present |= RadiotapPresentTxFlags;
        radiotap_length = rate ? 12 : 10; // TX flags are 2-byte aligned: pad after the rate.
    }

    std::vector<u8> packet;
    packet.reserve(radiotap_length + frame.size());
    packet.push_back(0);
    packet.push_back(0);
    AppendU16(packet, radiotap_length);
    AppendU32(packet, present);
    if (rate) {
        packet.push_back(*rate);
    }
    if (no_ack) {
        if (rate) {
            packet.push_back(0); // Alignment padding before TX flags.
        }
        // Broadcast/group frames cannot be ACKed; explicitly saying so prevents mac80211/rtw88
        // from waiting for an impossible TX report.
        AppendU16(packet, RadiotapTxNoAck);
    }
    packet.insert(packet.end(), frame.begin(), frame.end());
    return packet;
}

void RunMonitorBody(std::atomic<bool>& stop_requested,
                    std::atomic<u16>& selected_peer_channel, u16 requested_channel,
                    const std::array<u8, 6>& local_address,
                    const Nl80211Monitor::BeaconCallback& beacon_callback,
                    const Nl80211Monitor::FrameCallback& frame_callback,
                    const PhysicalBeaconProvider& physical_beacon_provider,
                    const PhysicalFrameProvider& physical_frame_provider,
                    const AccessPointConfigurationProvider& access_point_config_provider,
                    const AccessPointActivationProvider& access_point_activation_provider,
                    const AccessPointStationProvider& access_point_station_provider,
                    const AccessPointDataProvider& access_point_data_provider) {
    LdndConnection connection;
    u32 generic_socket_id = 0;
    u32 packet_socket_id = 0;
    u32 access_point_packet_socket_id = 0;
    u32 monitor_ifindex = 0;
    u32 access_point_ifindex = 0;
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
        if (const auto old = std::find_if(interfaces.begin(), interfaces.end(),
                                          [](const InterfaceInfo& item) {
                                              return item.name == AccessPointName;
                                          });
            old != interfaces.end()) {
            LOG_INFO(Service_NWM, "UDS Real: removing stale {} ifindex={}", AccessPointName,
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
        const u32 physical_wiphy = physical->wiphy;
        const auto initial_physical_beacon = physical_beacon_provider();

        bool active_monitor_enabled = false;
        try {
            CreateMonitorInterface(connection, generic_socket_id, port_id, family_id,
                                   physical_wiphy, true, sequence);
            active_monitor_enabled = true;
            LOG_INFO(Service_NWM,
                     "UDS Real: NL80211_MNTR_FLAG_ACTIVE accepted; hardware ACK mode requested");
        } catch (const std::exception& exception) {
            LOG_WARNING(Service_NWM,
                        "UDS Real: active monitor creation failed; falling back to passive "
                        "monitor mode: {}",
                        exception.what());
            const auto partial_interfaces = EnumerateInterfaces(
                connection, generic_socket_id, port_id, family_id, sequence);
            const auto partial_monitor = std::find_if(
                partial_interfaces.begin(), partial_interfaces.end(),
                [](const InterfaceInfo& item) { return item.name == MonitorName; });
            if (partial_monitor != partial_interfaces.end()) {
                DeleteInterface(connection, generic_socket_id, port_id, family_id,
                                partial_monitor->ifindex, sequence);
            }
            CreateMonitorInterface(connection, generic_socket_id, port_id, family_id,
                                   physical_wiphy, false, sequence);
        }
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

        std::optional<std::array<u8, 6>> active_monitor_mac;
        bool active_monitor_mac_failed = false;
        if (active_monitor_enabled && initial_physical_beacon) {
            try {
                SetInterfaceMac(connection, monitor_ifindex,
                                initial_physical_beacon->host_address);
                active_monitor_mac = initial_physical_beacon->host_address;
                LOG_INFO(Service_NWM,
                         "UDS Real: active monitor MAC configured before interface start, "
                         "interface={}, hostMac={}",
                         MonitorName, FormatMac(active_monitor_mac->data()));
            } catch (const std::exception& exception) {
                active_monitor_mac_failed = true;
                LOG_WARNING(Service_NWM,
                            "UDS Real: active monitor MAC assignment failed; continuing with "
                            "the working passive-ACK behavior for this session: {}",
                            exception.what());
            }
        }

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
                 "channel={}, activeMonitor={}, activeAckReady={}",
                 monitor->name, monitor->ifindex, monitor->wiphy, requested_channel,
                 active_monitor_enabled, active_monitor_mac.has_value());

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
        std::size_t retry_frame_count = 0;
        std::size_t transmitted_frame_count = 0;
        std::size_t raw_tx_boundary_count = 0;
        std::size_t kernel_data_echo_count = 0;
        std::size_t completed_sweeps = 0;
        std::size_t channel_index = 0;
        u16 current_channel = requested_channel;
        std::array<std::size_t, 14> packets_by_channel{};
        std::array<bool, 15> unavailable_channels{};
        bool have_recent_nintendo_beacon = false;
        bool have_active_peer = false;
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
        if (active_monitor_mac) {
            probe_source = *active_monitor_mac;
        }
        std::size_t transmitted_probe_count = 0;
        u16 transmitted_probe_sequence = 0;
        u16 transmitted_beacon_sequence = 0;
        std::optional<PhysicalBeaconSnapshot> latest_physical_beacon;
        std::optional<PhysicalBeaconSnapshot> ack_shell_beacon;
        AccessPointConfiguration access_point_config{};
        u64 applied_access_point_generation = 0;
        bool access_point_prepared = false;
        bool access_point_started = false;
        bool access_point_failed = false;
        std::vector<u8> applied_access_point_beacon_body;
        std::size_t access_point_beacon_update_count = 0;
        std::vector<std::array<u8, 6>> registered_access_point_stations;
        auto last_nintendo_beacon = std::chrono::steady_clock::time_point{};
        auto last_active_peer_frame = std::chrono::steady_clock::time_point{};
        auto next_channel_hop = std::chrono::steady_clock::now() + DiscoveryChannelDwell;
        auto next_active_probe = std::chrono::steady_clock::now();
        auto next_physical_beacon = std::chrono::steady_clock::now();
        while (!stop_requested.load(std::memory_order_relaxed)) {
            if (const u16 selected_channel = selected_peer_channel.exchange(
                    0, std::memory_order_acq_rel);
                selected_channel != 0) {
                // Retune only if needed, but always hold the channel: when the peer is already on
                // the monitor's current channel, skipping the hold let discovery hop away right
                // after our authentication frame and the peer's reply was never received.
                if (selected_channel != current_channel) {
                    SetChannel(connection, generic_socket_id, port_id, family_id,
                               monitor_ifindex, ChannelToFrequency(selected_channel), sequence);
                }
                current_channel = selected_channel;
                if (const auto selected =
                        std::find(discovery_channels.begin(), discovery_channels.end(),
                                  selected_channel);
                    selected != discovery_channels.end()) {
                    channel_index = static_cast<std::size_t>(
                        std::distance(discovery_channels.begin(), selected));
                }
                // Give the selected peer a full hold interval to answer before discovery resumes.
                // Its next beacon or management frame refreshes the same hold normally.
                have_recent_nintendo_beacon = true;
                last_nintendo_beacon = std::chrono::steady_clock::now();
                next_channel_hop = last_nintendo_beacon + DiscoveryChannelHold;
                LOG_INFO(Service_NWM,
                         "UDS Real: tuned directly to selected peer channel {} and suspended "
                         "discovery hopping",
                         current_channel);
            }

            const auto requested_access_point_config = access_point_config_provider();
            if (requested_access_point_config.generation != applied_access_point_generation) {
                try {
                    if (access_point_started) {
                        StopAccessPoint(connection, generic_socket_id, port_id, family_id,
                                        access_point_ifindex, sequence);
                        SetInterfaceDown(connection, access_point_ifindex);
                    }
                    access_point_started = false;
                    applied_access_point_beacon_body.clear();
                    registered_access_point_stations.clear();

                    const bool host_changed =
                        access_point_prepared &&
                        requested_access_point_config.host_address != access_point_config.host_address;
                    if ((!requested_access_point_config.enabled || host_changed) &&
                        access_point_ifindex != 0) {
                        if (access_point_packet_socket_id != 0) {
                            connection.CloseSocket(access_point_packet_socket_id);
                            access_point_packet_socket_id = 0;
                        }
                        DeleteInterface(connection, generic_socket_id, port_id, family_id,
                                        access_point_ifindex, sequence);
                        access_point_ifindex = 0;
                        access_point_prepared = false;
                    }

                    access_point_config = requested_access_point_config;
                    applied_access_point_generation = requested_access_point_config.generation;
                    access_point_failed = false;
                    if (access_point_config.enabled && !access_point_prepared) {
                        CreateAccessPointInterface(connection, generic_socket_id, port_id,
                                                   family_id, monitor->wiphy,
                                                   access_point_config.host_address, sequence);
                        const auto updated_interfaces = EnumerateInterfaces(
                            connection, generic_socket_id, port_id, family_id, sequence);
                        const auto access_point = std::find_if(
                            updated_interfaces.begin(), updated_interfaces.end(),
                            [](const InterfaceInfo& item) {
                                return item.name == AccessPointName;
                            });
                        if (access_point == updated_interfaces.end()) {
                            throw std::runtime_error(
                                "nl80211 accepted AP creation but udsap0 was not found");
                        }
                        access_point_ifindex = access_point->ifindex;
                        if (access_point->mac.size() != access_point_config.host_address.size() ||
                            !std::equal(access_point->mac.begin(), access_point->mac.end(),
                                        access_point_config.host_address.begin())) {
                            throw std::runtime_error(
                                "udsap0 did not adopt Azahar's advertised host MAC");
                        }
                        access_point_prepared = true;
                        LOG_INFO(Service_NWM,
                                 "UDS Real AP: prepared DOWN interface={}, ifindex={}, "
                                 "hostMac={}, ssid={}; discovery radio remains unlocked",
                                 AccessPointName, access_point_ifindex,
                                 FormatMac(access_point_config.host_address.data()),
                                 FormatHexBytes(std::vector<u8>{access_point_config.ssid.begin(),
                                                               access_point_config.ssid.end()}));
                    }
                    if (!access_point_config.enabled) {
                        LOG_INFO(Service_NWM,
                                 "UDS Real AP: disabled; physical discovery remains active");
                    }
                } catch (const std::exception& exception) {
                    access_point_failed = true;
                    applied_access_point_generation = requested_access_point_config.generation;
                    try {
                        const auto cleanup_interfaces = EnumerateInterfaces(
                            connection, generic_socket_id, port_id, family_id, sequence);
                        const auto partial_access_point = std::find_if(
                            cleanup_interfaces.begin(), cleanup_interfaces.end(),
                            [](const InterfaceInfo& item) {
                                return item.name == AccessPointName;
                            });
                        if (partial_access_point != cleanup_interfaces.end()) {
                            if (access_point_packet_socket_id != 0) {
                                connection.CloseSocket(access_point_packet_socket_id);
                                access_point_packet_socket_id = 0;
                            }
                            DeleteInterface(connection, generic_socket_id, port_id, family_id,
                                            partial_access_point->ifindex, sequence);
                        }
                        access_point_ifindex = 0;
                        access_point_prepared = false;
                    } catch (const std::exception& cleanup_exception) {
                        LOG_WARNING(Service_NWM,
                                    "UDS Real AP: partial-interface cleanup failed: {}",
                                    cleanup_exception.what());
                    }
                    LOG_WARNING(Service_NWM,
                                "UDS Real AP: preparation failed; continuing with monitor-only "
                                "transport: {}",
                                exception.what());
                }
            }

            const auto ensure_access_point_started = [&] {
                if (access_point_started || access_point_failed || !access_point_prepared ||
                    !access_point_config.enabled) {
                    return;
                }
                // The client-role shell is requested and started in the same worker pass, before
                // the periodic beacon poll below has loaded its beacon, so fetch it directly.
                if (!latest_physical_beacon && !ack_shell_beacon) {
                    if (auto pending = physical_beacon_provider();
                        pending && pending->ack_shell_only) {
                        ack_shell_beacon = std::move(*pending);
                    }
                }
                // A hosted network's beacon wins; the client-role shell has only its own minimal one.
                const std::optional<PhysicalBeaconSnapshot>& shell_beacon =
                    latest_physical_beacon ? latest_physical_beacon : ack_shell_beacon;
                if (!shell_beacon) {
                    LOG_WARNING(Service_NWM,
                                "UDS Real ACK shell: activation deferred until the first host "
                                "beacon is available");
                    return;
                }
                SetInterfaceUp(connection, access_point_ifindex);
                SetChannel(connection, generic_socket_id, port_id, family_id,
                           access_point_ifindex, ChannelToFrequency(current_channel), sequence);
                StartAccessPoint(connection, generic_socket_id, port_id, family_id,
                                 access_point_ifindex, access_point_config, *shell_beacon,
                                 static_cast<u8>(current_channel), sequence);
                access_point_started = true;
                applied_access_point_beacon_body = shell_beacon->body;
                LOG_INFO(Service_NWM,
                         "UDS Real ACK shell: START_AP accepted, interface={}, ifindex={}, "
                         "channel={}, hardware MAC acknowledgements requested; kernelKeys=false, "
                         "stationAuthorized=false, kernelDataCarrier=false",
                         AccessPointName, access_point_ifindex, current_channel);
            };

            if (access_point_activation_provider()) {
                try {
                    ensure_access_point_started();
                } catch (const std::exception& exception) {
                    access_point_failed = true;
                    try {
                        if (access_point_ifindex != 0) {
                            StopAccessPoint(connection, generic_socket_id, port_id, family_id,
                                            access_point_ifindex, sequence);
                        }
                    } catch (...) {
                    }
                    try {
                        if (access_point_ifindex != 0) {
                            if (access_point_packet_socket_id != 0) {
                                connection.CloseSocket(access_point_packet_socket_id);
                                access_point_packet_socket_id = 0;
                            }
                            DeleteInterface(connection, generic_socket_id, port_id, family_id,
                                            access_point_ifindex, sequence);
                            access_point_ifindex = 0;
                            access_point_prepared = false;
                        }
                    } catch (const std::exception& cleanup_exception) {
                        LOG_WARNING(Service_NWM,
                                    "UDS Real AP: activation cleanup failed: {}",
                                    cleanup_exception.what());
                    }
                    access_point_started = false;
                    LOG_WARNING(Service_NWM,
                                "UDS Real AP: activation failed; continuing with monitor-only "
                                "transport: {}",
                                exception.what());
                }
            }

            while (auto station_request = access_point_station_provider()) {
                const auto existing = std::find(registered_access_point_stations.begin(),
                                                registered_access_point_stations.end(),
                                                station_request->station_address);
                try {
                    if (station_request->remove) {
                        if (access_point_started &&
                            existing != registered_access_point_stations.end()) {
                            RemoveAccessPointStation(connection, generic_socket_id, port_id,
                                                     family_id, access_point_ifindex,
                                                     station_request->station_address, sequence);
                            registered_access_point_stations.erase(existing);
                            LOG_INFO(Service_NWM, "UDS Real AP: removed retail station {}",
                                     FormatMac(station_request->station_address.data()));
                            if (registered_access_point_stations.empty()) {
                                StopAccessPoint(connection, generic_socket_id, port_id, family_id,
                                                access_point_ifindex, sequence);
                                SetInterfaceDown(connection, access_point_ifindex);
                                access_point_started = false;
                                LOG_INFO(Service_NWM,
                                         "UDS Real AP: stopped after final station departed");
                            }
                        }
                        continue;
                    }

                    ensure_access_point_started();
                    if (!access_point_started ||
                        existing != registered_access_point_stations.end()) {
                        continue;
                    }
                    if (registered_access_point_stations.size() >=
                        access_point_config.max_stations) {
                        throw std::runtime_error("UDS AP station limit reached");
                    }
                    const u16 aid = static_cast<u16>(registered_access_point_stations.size() + 1);
                    RegisterAccessPointStation(connection, generic_socket_id, port_id, family_id,
                                               access_point_ifindex, access_point_config,
                                               *station_request, aid, sequence);
                    registered_access_point_stations.push_back(station_request->station_address);
                    LOG_INFO(Service_NWM,
                             "UDS Real ACK shell: retail station registered for hardware ACKs, "
                             "station={}, aid={}, pairwiseKeyInstalled=false, authorized=false",
                             FormatMac(station_request->station_address.data()), aid);
                } catch (const std::exception& exception) {
                    access_point_failed = true;
                    LOG_WARNING(Service_NWM,
                                "UDS Real AP: station operation failed for {}: {}",
                                FormatMac(station_request->station_address.data()),
                                exception.what());
                }
            }

            // Transmit queued management/data frames only after pending ACK-shell station work.
            // In particular, a physical association request queues both NEW_STATION and an
            // association response from nwm::UDS. Deferring the response guarantees that the
            // firmware knows the peer MAC before protected retail traffic begins. No key is
            // installed here; software CCMP remains authoritative.
            while (auto pending_frame = physical_frame_provider()) {
                const bool radiotap_no_ack = IsGroupAddressedFrame(*pending_frame);
                const auto physical_frame =
                    AddRadiotapHeader(*pending_frame, radiotap_no_ack);

                const u16 frame_control =
                    pending_frame->size() >= 2 ? ReadU16(pending_frame->data()) : 0;
                const u8 frame_type = static_cast<u8>((frame_control >> 2) & 0x3);
                const bool protected_frame = (frame_control & 0x4000) != 0;
                if (frame_type == 2 && protected_frame && pending_frame->size() >= 32) {
                    ++raw_tx_boundary_count;
                    const u16 duration = ReadU16(pending_frame->data() + 2);
                    const u16 sequence_control = ReadU16(pending_frame->data() + 22);
                    const u8* ccmp_header = pending_frame->data() + 24;
                    const u16 radiotap_length = ReadU16(physical_frame.data() + 2);
                    const u32 radiotap_present = ReadU32(physical_frame.data() + 4);
                    const u16 radiotap_tx_flags =
                        radiotap_length >= 10 ? ReadU16(physical_frame.data() + 8) : 0;
                    const bool radiotap_length_valid =
                        radiotap_length == (radiotap_no_ack ? 10 : 8) ||
                        radiotap_length == (radiotap_no_ack ? 12 : 9);
                    const bool packet_length_valid =
                        physical_frame.size() == radiotap_length + pending_frame->size();
                    const bool ccmp_header_valid = ccmp_header[2] == 0 &&
                                                   (ccmp_header[3] & 0x20) != 0 &&
                                                   (ccmp_header[3] & 0xC0) == 0;
                    const bool group_ds_layout_valid =
                        !radiotap_no_ack || (frame_control & 0x0300) == 0;
                    const std::span<const u8> mpdu_span{pending_frame->data(),
                                                       pending_frame->size()};
                    const std::span<const u8> packet_span{physical_frame.data(),
                                                         physical_frame.size()};

                    // This is the last representation before LdndConnection serializes the
                    // SendTo request. The matching LDND RAW TX PIPE line is emitted inside
                    // WriteFrame, so fingerprints and bytes can be compared across both sides of
                    // the boundary without inferring endianness or offsets from parsed state.
                    LOG_INFO(
                        Service_NWM,
                        "UDS RAW TX BOUNDARY #{}: channel={}, mpduBytes={}, radiotapBytes={}, "
                        "packetBytes={}, frameControlLE=0x{:04X}, frameControlRaw={:02X}:{:02X}, "
                        "durationLE={}, sequenceControlLE=0x{:04X}, dot11Sequence={}, "
                        "fragment={}, type={}, subtype={}, toDS={}, fromDS={}, protected={}, "
                        "address1={}, address2={}, address3={}, groupAddressed={}, "
                        "ccmpHeaderOffset=24, ccmpPN={}, ccmpKeyId={}, ccmpExtIV={}, "
                        "encryptedBodyAndMicOffset=32, encryptedBodyAndMicBytes={}, "
                        "radiotapLengthLE={}, radiotapPresentLE=0x{:08X}, "
                        "radiotapTxFlagsLE=0x{:04X}, radiotapNoAck={}, "
                        "checks={{radiotapLength:{},packetLength:{},ccmpHeader:{},"
                        "groupNoDS:{}}}, "
                        "mpduFingerprint=0x{:08X}, packetFingerprint=0x{:08X}, mpdu={}, packet={}",
                        raw_tx_boundary_count, current_channel, pending_frame->size(),
                        radiotap_length, physical_frame.size(), frame_control,
                        (*pending_frame)[0], (*pending_frame)[1], duration, sequence_control,
                        sequence_control >> 4, sequence_control & 0xF, frame_type,
                        static_cast<u8>((frame_control >> 4) & 0xF),
                        (frame_control & 0x0100) != 0, (frame_control & 0x0200) != 0,
                        protected_frame, FormatMac(pending_frame->data() + 4),
                        FormatMac(pending_frame->data() + 10),
                        FormatMac(pending_frame->data() + 16), radiotap_no_ack,
                        ReadCCMPPacketNumber(ccmp_header), (ccmp_header[3] >> 6) & 0x3,
                        (ccmp_header[3] & 0x20) != 0, pending_frame->size() - 32,
                        radiotap_length, radiotap_present, radiotap_tx_flags,
                        radiotap_no_ack, radiotap_length_valid, packet_length_valid,
                        ccmp_header_valid, group_ds_layout_valid, FingerprintBytes(mpdu_span),
                        FingerprintBytes(packet_span), FormatHexBytes(*pending_frame),
                        FormatHexBytes(physical_frame));
                }

                if (frame_type == 0 && pending_frame->size() >= 24) {
                    const u16 sequence_control = ReadU16(pending_frame->data() + 22);
                    const std::span<const u8> mpdu_span{pending_frame->data(),
                                                       pending_frame->size()};
                    LOG_INFO(Service_NWM,
                             "UDS MANAGEMENT TRACE TX: channel={}, subtype={}, "
                             "sequence={}, fragment={}, address1={}, address2={}, address3={}, "
                             "bodyBytes={}, mpduBytes={}, mpduFingerprint=0x{:08X}, mpdu={}",
                             current_channel, static_cast<u8>((frame_control >> 4) & 0xF),
                             sequence_control >> 4, sequence_control & 0xF,
                             FormatMac(pending_frame->data() + 4),
                             FormatMac(pending_frame->data() + 10),
                             FormatMac(pending_frame->data() + 16),
                             pending_frame->size() - 24, pending_frame->size(),
                             FingerprintBytes(mpdu_span), FormatHexBytes(*pending_frame));
                }

                connection.SendTo(packet_socket_id, physical_frame);
                ++transmitted_frame_count;
                if (transmitted_frame_count <= 40 || transmitted_frame_count % 100 == 0) {
                    LOG_INFO(Service_NWM,
                             "UDS Real: physical TX #{}, channel={}, type={}, subtype={}, "
                             "protected={}, toDS={}, fromDS={}, groupAddressed={}, "
                             "radiotapNoAck={}, frameBytes={}, packetBytes={}",
                             transmitted_frame_count, current_channel,
                             frame_type,
                             static_cast<u8>((frame_control >> 4) & 0xF),
                             protected_frame,
                             (frame_control & 0x0100) != 0,
                             (frame_control & 0x0200) != 0, radiotap_no_ack,
                             radiotap_no_ack, pending_frame->size(), physical_frame.size());
                }
            }

            while (auto data_frame = access_point_data_provider()) {
                try {
                    if (!access_point_started || access_point_packet_socket_id == 0) {
                        throw std::runtime_error(
                            "kernel AP data carrier is not active");
                    }
                    if (data_frame->payload.size() < 8) {
                        throw std::runtime_error("UDS AP data payload is shorter than LLC/SNAP");
                    }
                    const u16 ethertype = static_cast<u16>(data_frame->payload[6] << 8) |
                                          data_frame->payload[7];
                    const auto ethernet_frame = GenerateAccessPointEthernetFrame(*data_frame);
                    connection.SendTo(access_point_packet_socket_id, ethernet_frame);
                    LOG_INFO(Service_NWM,
                             "UDS Real AP: kernel data TX, destination={}, "
                             "ethertype=0x{:04X}, ethernetBytes={}",
                             FormatMac(data_frame->destination_address.data()), ethertype,
                             ethernet_frame.size());
                } catch (const std::exception& exception) {
                    LOG_WARNING(Service_NWM, "UDS Real AP: data TX failed: {}",
                                exception.what());
                }
            }

            std::vector<u8> packet;
            if (connection.TryReceiveData(packet_socket_id, packet, 50)) {
                ++packet_count;
                if (current_channel <= 13) {
                    ++packets_by_channel[current_channel];
                }
                auto beacon = ParseNintendoBeacon(packet, static_cast<u8>(current_channel));
                if (beacon) {
                    // Temporary diagnostic: dump every distinct beacon body (ignoring the 8-byte
                    // timestamp) once, for retail beacons and for the beacons we transmit, so the
                    // information elements can be compared offline.
                    if (beacon->frame.size() > 8) {
                        u64 body_hash = 1469598103934665603ULL;
                        for (std::size_t i = 8; i < beacon->frame.size(); ++i) {
                            body_hash = (body_hash ^ beacon->frame[i]) * 1099511628211ULL;
                        }
                        const bool ours = latest_physical_beacon &&
                                          beacon->transmitter_address ==
                                              latest_physical_beacon->host_address;
                        static std::array<std::set<u64>, 2> dumped_bodies;
                        auto& dumped = dumped_bodies[ours ? 1 : 0];
                        if (dumped.size() < 400 && dumped.insert(body_hash).second) {
                            LOG_INFO(Service_NWM,
                                     "UDS BEACON DUMP {} #{}: source={}, channel={}, bytes={}, "
                                     "hash=0x{:016X}, body={}",
                                     ours ? "ours" : "retail", dumped.size(),
                                     FormatMac(beacon->transmitter_address.data()),
                                     beacon->channel, beacon->frame.size(), body_hash,
                                     FormatHexBytes(beacon->frame));
                        }
                    }
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

                // Deliver only non-beacon/probe traffic involving Azahar's local MAC or the
                // discovered Nintendo BSSID. The local address must not be derived from
                // latest_physical_beacon: that object exists only while Azahar hosts. When
                // Azahar joins a retail-hosted network there is no local beacon, and the old gate
                // consequently discarded every authentication response before nwm::UDS saw it.
                // Temporary diagnostic: signal strength and rate of the retail host's frames and of
                // our own transmissions as captured back by the monitor (which shows the rate the
                // radio really used). Rate-limited to the first frames of each kind, then 1 in 200.
                // Link-layer ACKs addressed to us show whether the retail host actually receives our
                // unicast frames (a data frame with no following ACK was lost or not decoded).
                if (const auto ack_radiotap = ParseRadiotap(packet);
                    ack_radiotap && packet.size() >= ack_radiotap->length + 10) {
                    const u16 ack_frame_control = ReadU16(packet.data() + ack_radiotap->length);
                    if (((ack_frame_control >> 2) & 0x3) == 1 &&
                        ((ack_frame_control >> 4) & 0xF) == 13 &&
                        std::memcmp(packet.data() + ack_radiotap->length + 4, local_address.data(),
                                    6) == 0) {
                        static std::size_t ack_count = 0;
                        ++ack_count;
                        if (ack_count <= 400 || ack_count % 200 == 0) {
                            const auto radio = DescribeRadiotapSignal(packet);
                            LOG_INFO(Service_NWM, "UDS Real RADIO ACK-RX #{}: rate={}, signalDbm={}",
                                     ack_count,
                                     radio.rate_500kbps
                                         ? fmt::format("{} Mbps", *radio.rate_500kbps / 2.0)
                                         : std::string{"n/a"},
                                     radio.signal_dbm ? std::to_string(*radio.signal_dbm)
                                                      : std::string{"n/a"});
                        }
                    }
                }
                if (const auto radiotap = ParseRadiotap(packet);
                    radiotap && packet.size() >= radiotap->length + 16) {
                    const u16 radio_frame_control = ReadU16(packet.data() + radiotap->length);
                    if (((radio_frame_control >> 2) & 0x3) != 1) { // Control frames have no A2.
                        std::array<u8, 6> radio_transmitter{};
                        std::memcpy(radio_transmitter.data(),
                                    packet.data() + radiotap->length + 10, 6);
                        const bool radio_local = radio_transmitter == local_address;
                        const bool radio_retail =
                            have_nintendo_source && radio_transmitter == nintendo_source;
                        if (radio_retail) {
                            // Capture completeness: the retail host numbers every frame it sends
                            // (beacons and data) consecutively, so a gap in what we captured is a
                            // frame the monitor missed. Duplicates (retries) repeat a number.
                            static int last_seq = -1;
                            static std::size_t seen = 0;
                            static std::size_t missed = 0;
                            static auto window_start = std::chrono::steady_clock::now();
                            const int seq = ReadU16(packet.data() + radiotap->length + 22) >> 4;
                            if (last_seq >= 0) {
                                const int gap = (seq - last_seq) & 0xFFF;
                                if (gap > 1 && gap < 64) {
                                    missed += static_cast<std::size_t>(gap - 1);
                                }
                            }
                            last_seq = seq;
                            ++seen;
                            const auto now = std::chrono::steady_clock::now();
                            if (now - window_start >= std::chrono::seconds(3)) {
                                LOG_INFO(Service_NWM,
                                         "UDS Real RADIO retail-capture: last 3s captured={}, "
                                         "missedByGap={}",
                                         seen, missed);
                                seen = 0;
                                missed = 0;
                                window_start = now;
                            }
                        }
                        if (radio_local || radio_retail) {
                            // Data frames get their own counters: beacons and probes would otherwise
                            // use up the budget before any data frame is seen.
                            const bool radio_data = ((radio_frame_control >> 2) & 0x3) == 2;
                            static std::array<std::size_t, 4> radio_counts{};
                            const std::size_t count =
                                ++radio_counts[(radio_local ? 0 : 1) + (radio_data ? 2 : 0)];
                            if (count <= (radio_data ? 300U : 20U) || count % 200 == 0) {
                                const auto radio = DescribeRadiotapSignal(packet);
                                LOG_INFO(Service_NWM,
                                         "UDS Real RADIO {} #{}: type={}, subtype={}, "
                                         "rate={}, signalDbm={}, channelMhz={}, mcs={}, "
                                         "frameBytes={}, retry={}, dot11Seq={}",
                                         radio_local ? "our-TX-echo" : "retail-RX", count,
                                         (radio_frame_control >> 2) & 0x3,
                                         (radio_frame_control >> 4) & 0xF,
                                         radio.rate_500kbps
                                             ? fmt::format("{} Mbps", *radio.rate_500kbps / 2.0)
                                             : std::string{"n/a"},
                                         radio.signal_dbm ? std::to_string(*radio.signal_dbm)
                                                          : std::string{"n/a"},
                                         radio.channel_mhz ? std::to_string(*radio.channel_mhz)
                                                           : std::string{"n/a"},
                                         radio.mcs ? fmt::format("{:02X}:{:02X}:{:02X}",
                                                                 (*radio.mcs)[0], (*radio.mcs)[1],
                                                                 (*radio.mcs)[2])
                                                   : std::string{"n/a"},
                                         packet.size() - radiotap->length,
                                         (radio_frame_control & 0x0800) != 0,
                                         ReadU16(packet.data() + radiotap->length + 22) >> 4);
                            }
                        }
                    }
                }
                {
                    auto frame = ParseCapturedFrame(packet, static_cast<u8>(current_channel));
                    const bool from_local =
                        frame && frame->transmitter_address == local_address;
                    if (frame && frame->type == 2 && from_local) {
                        ++kernel_data_echo_count;
                        if (kernel_data_echo_count <= 40 || kernel_data_echo_count % 100 == 0) {
                            const bool protected_frame = (frame->frame_control & 0x4000) != 0;
                            const u64 packet_number =
                                protected_frame && frame->body.size() >= 8
                                    ? ReadU16(frame->body.data()) |
                                          (static_cast<u64>(frame->body[4]) << 16) |
                                          (static_cast<u64>(frame->body[5]) << 24) |
                                          (static_cast<u64>(frame->body[6]) << 32) |
                                          (static_cast<u64>(frame->body[7]) << 40)
                                    : 0;
                            LOG_INFO(Service_NWM,
                                     "UDS Real AP: captured kernel data TX #{}, channel={}, "
                                     "protected={}, toDS={}, fromDS={}, destination={}, "
                                     "packetNumber={}, bodyBytes={}",
                                     kernel_data_echo_count, current_channel, protected_frame,
                                     (frame->frame_control & 0x0100) != 0,
                                     (frame->frame_control & 0x0200) != 0,
                                     FormatMac(frame->destination_address.data()), packet_number,
                                     frame->body.size());
                        }
                    }
                    const bool targets_local =
                        frame && frame->destination_address == local_address;
                    const bool uses_local_bssid = frame && frame->bssid == local_address;
                    const bool uses_discovered_nintendo_bssid =
                        frame && have_nintendo_source && frame->bssid == nintendo_source;
                    // Temporary diagnostic: record every data frame the radio sees, and whether
                    // the delivery filter below accepts it, to tell "the host sent nothing" apart
                    // from "we discarded what it sent".
                    if (frame && frame->type == 2 && !from_local) {
                        static std::size_t any_data_frame_count = 0;
                        ++any_data_frame_count;
                        if (any_data_frame_count <= 400) {
                            LOG_INFO(Service_NWM,
                                     "UDS Real: any-data RX #{}, channel={}, subtype={}, "
                                     "protected={}, toDS={}, fromDS={}, transmitter={}, "
                                     "destination={}, bssid={}, bodyBytes={}, retry={}, "
                                     "passesFilter={}",
                                     any_data_frame_count, current_channel, frame->subtype,
                                     (frame->frame_control & 0x4000) != 0,
                                     (frame->frame_control & 0x0100) != 0,
                                     (frame->frame_control & 0x0200) != 0,
                                     FormatMac(frame->transmitter_address.data()),
                                     FormatMac(frame->destination_address.data()),
                                     FormatMac(frame->bssid.data()), frame->body.size(),
                                     (frame->frame_control & 0x0800) != 0,
                                     targets_local || uses_local_bssid ||
                                         uses_discovered_nintendo_bssid);
                        }
                    }
                    if (frame && !from_local &&
                        (targets_local || uses_local_bssid || uses_discovered_nintendo_bssid)) {
                        const bool is_beacon = frame->type == 0 && frame->subtype == 8;
                        const bool is_probe =
                            frame->type == 0 && (frame->subtype == 4 || frame->subtype == 5);
                        if (!is_beacon && !is_probe) {
                            last_active_peer_frame = std::chrono::steady_clock::now();
                            if (!have_active_peer) {
                                LOG_INFO(Service_NWM,
                                         "UDS Real: active peer traffic found; locking radio to "
                                         "channel {} while the peer remains active",
                                         current_channel);
                            }
                            have_active_peer = true;
                            ++delivered_frame_count;
                            const bool retry = (frame->frame_control & 0x0800) != 0;
                            if (retry) {
                                ++retry_frame_count;
                            }
                            if (delivered_frame_count <= 40 || delivered_frame_count % 100 == 0) {
                                LOG_INFO(Service_NWM,
                                         "UDS Real: physical RX #{}, channel={}, type={}, "
                                         "subtype={}, retry={}, sequence={}, fragment={}, "
                                         "protected={}, toDS={}, fromDS={}, source={}, "
                                         "destination={}, bssid={}, bodyBytes={}, mpduBytes={}, "
                                         "mpduFingerprint=0x{:08X}, mpdu={}",
                                         delivered_frame_count, current_channel, frame->type,
                                         frame->subtype, retry, frame->sequence_control >> 4,
                                         frame->sequence_control & 0xF,
                                         (frame->frame_control & 0x4000) != 0,
                                         (frame->frame_control & 0x0100) != 0,
                                         (frame->frame_control & 0x0200) != 0,
                                         FormatMac(frame->transmitter_address.data()),
                                         FormatMac(frame->destination_address.data()),
                                         FormatMac(frame->bssid.data()), frame->body.size(),
                                         frame->mpdu.size(), FingerprintBytes(frame->mpdu),
                                         FormatHexBytes(frame->mpdu));
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
            if (now >= next_physical_beacon) {
                auto pending_beacon = physical_beacon_provider();
                if (pending_beacon && pending_beacon->ack_shell_only) {
                    // Client-role ACK shell: keep it only for the AP start, never transmit it.
                    ack_shell_beacon = std::move(*pending_beacon);
                    pending_beacon.reset();
                    latest_physical_beacon.reset();
                } else if (!pending_beacon) {
                    // Nothing is hosted any more. The monitor now outlives UDS sessions, so drop
                    // the previous session's beacons instead of continuing to use them.
                    latest_physical_beacon.reset();
                    ack_shell_beacon.reset();
                }
                if (pending_beacon) {
                    if (active_monitor_enabled && !active_monitor_mac &&
                        !active_monitor_mac_failed) {
                        try {
                            // Normally the host MAC is already available when udsmon0 is created.
                            // This path covers slower game startup without recreating the monitor
                            // interface or enabling the experimental AP transport.
                            SetInterfaceDown(connection, monitor_ifindex);
                            SetInterfaceMac(connection, monitor_ifindex,
                                            pending_beacon->host_address);
                            SetInterfaceUp(connection, monitor_ifindex);
                            SetChannel(connection, generic_socket_id, port_id, family_id,
                                       monitor_ifindex, ChannelToFrequency(current_channel),
                                       sequence);
                            active_monitor_mac = pending_beacon->host_address;
                            probe_source = *active_monitor_mac;
                            LOG_INFO(Service_NWM,
                                     "UDS Real: active monitor MAC configured after startup, "
                                     "interface={}, hostMac={}, channel={}",
                                     MonitorName, FormatMac(active_monitor_mac->data()),
                                     current_channel);
                        } catch (const std::exception& exception) {
                            active_monitor_mac_failed = true;
                            try {
                                SetInterfaceUp(connection, monitor_ifindex);
                                SetChannel(connection, generic_socket_id, port_id, family_id,
                                           monitor_ifindex, ChannelToFrequency(current_channel),
                                           sequence);
                            } catch (const std::exception& recovery_exception) {
                                throw std::runtime_error(
                                    std::string{"active monitor MAC assignment and recovery "
                                                "failed: "} +
                                    exception.what() + "; recovery: " +
                                    recovery_exception.what());
                            }
                            LOG_WARNING(Service_NWM,
                                        "UDS Real: late active monitor MAC assignment failed; "
                                        "continuing with passive-ACK behavior: {}",
                                        exception.what());
                        }
                    }
                    latest_physical_beacon = std::move(*pending_beacon);
                    if (access_point_started) {
                        if (latest_physical_beacon->body != applied_access_point_beacon_body) {
                            try {
                                SetAccessPointBeacon(connection, generic_socket_id, port_id,
                                                     family_id, access_point_ifindex,
                                                     *latest_physical_beacon,
                                                     static_cast<u8>(current_channel), sequence);
                                applied_access_point_beacon_body = latest_physical_beacon->body;
                                ++access_point_beacon_update_count;
                                LOG_INFO(Service_NWM,
                                         "UDS Real ACK shell: updated kernel Nintendo beacon "
                                         "#{}, channel={}, beaconBodyBytes={}",
                                         access_point_beacon_update_count, current_channel,
                                         latest_physical_beacon->body.size());
                            } catch (const std::exception& exception) {
                                LOG_WARNING(Service_NWM,
                                            "UDS Real ACK shell: kernel beacon update failed; "
                                            "stopping ACK shell and restoring raw beacon TX: {}",
                                            exception.what());
                                try {
                                    StopAccessPoint(connection, generic_socket_id, port_id,
                                                    family_id, access_point_ifindex, sequence);
                                    SetInterfaceDown(connection, access_point_ifindex);
                                } catch (...) {
                                }
                                access_point_started = false;
                                access_point_failed = true;
                                applied_access_point_beacon_body.clear();
                                registered_access_point_stations.clear();
                            }
                        }
                    }
                    if (!access_point_started) {
                        const auto physical_frame = GeneratePhysicalNintendoBeacon(
                            *latest_physical_beacon, transmitted_beacon_sequence++,
                            static_cast<u8>(current_channel));
                        connection.SendTo(packet_socket_id, physical_frame);
                        ++transmitted_beacon_count;
                        if (transmitted_beacon_count <= 5 || transmitted_beacon_count % 100 == 0) {
                            LOG_INFO(Service_NWM,
                                     "UDS Real: transmitted physical Nintendo beacon #{}, "
                                     "source={}, channel={}, beaconBodyBytes={}, frameBytes={}",
                                     transmitted_beacon_count,
                                     FormatMac(latest_physical_beacon->host_address.data()),
                                     current_channel, latest_physical_beacon->body.size(),
                                     physical_frame.size());
                        }
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

            const bool peer_is_recent =
                have_active_peer && now - last_active_peer_frame < DiscoveryChannelHold;
            if (have_active_peer && !peer_is_recent) {
                have_active_peer = false;
                LOG_INFO(Service_NWM,
                         "UDS Real: active peer timed out on channel {}; resuming discovery "
                         "channel hopping",
                         current_channel);
                if (access_point_started) {
                    try {
                        StopAccessPoint(connection, generic_socket_id, port_id, family_id,
                                        access_point_ifindex, sequence);
                        SetInterfaceDown(connection, access_point_ifindex);
                        access_point_started = false;
                        registered_access_point_stations.clear();
                        LOG_INFO(Service_NWM,
                                 "UDS Real AP: stopped after active-peer timeout");
                    } catch (const std::exception& exception) {
                        LOG_WARNING(Service_NWM,
                                    "UDS Real AP: failed to stop after peer timeout: {}",
                                    exception.what());
                    }
                }
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
            if (now < next_channel_hop || beacon_is_recent || peer_is_recent ||
                access_point_started) {
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
                    const std::string_view error{exception.what()};
                    const bool radio_busy = error.find("error -16") != std::string_view::npos;
                    if (!radio_busy) {
                        unavailable_channels[next_channel] = true;
                    }
                    if (radio_busy && next_channel == current_channel) {
                        channel_changed = true;
                        LOG_WARNING(Service_NWM,
                                    "UDS Real: radio temporarily busy during discovery hop; "
                                    "retaining current channel {} instead of stopping monitor",
                                    current_channel);
                        break;
                    }
                    LOG_WARNING(Service_NWM,
                                "UDS Real: channel {} unavailable during discovery scan: {}",
                                next_channel, exception.what());
                }
            }
            if (!channel_changed) {
                LOG_WARNING(Service_NWM,
                            "UDS Real: discovery could not change channels; retaining channel {} "
                            "and retrying later",
                            current_channel);
            }
            next_channel_hop = std::chrono::steady_clock::now() + DiscoveryChannelDwell;
        }

        LOG_INFO(Service_NWM,
                 "UDS Real: stopping physical beacon monitor, packets={}, deliveredBeacons={}, "
                 "transmittedBeacons={}, beaconEchoes={}, transmittedProbes={}, probeFrames={}, "
                 "relevantProbeFrames={}, deliveredFrames={}, retryFrames={}, "
                 "transmittedFrames={}, kernelDataEchoes={}, activeMonitor={}, "
                 "activeAckReady={}, "
                 "completedSweeps={}, finalChannel={}",
                 packet_count, delivered_beacon_count, transmitted_beacon_count,
                 transmitted_beacon_echo_count, transmitted_probe_count, probe_frame_count,
                 relevant_probe_frame_count, delivered_frame_count, retry_frame_count,
                 transmitted_frame_count, kernel_data_echo_count, active_monitor_enabled,
                 active_monitor_mac.has_value(), completed_sweeps, current_channel);

        if (access_point_packet_socket_id != 0) {
            connection.CloseSocket(access_point_packet_socket_id);
            access_point_packet_socket_id = 0;
        }
        connection.CloseSocket(packet_socket_id);
        packet_socket_id = 0;
        if (access_point_ifindex != 0) {
            if (access_point_started) {
                StopAccessPoint(connection, generic_socket_id, port_id, family_id,
                                access_point_ifindex, sequence);
            }
            DeleteInterface(connection, generic_socket_id, port_id, family_id,
                            access_point_ifindex, sequence);
            access_point_ifindex = 0;
        }
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
        if (access_point_packet_socket_id != 0) {
            try {
                connection.CloseSocket(access_point_packet_socket_id);
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
        if (access_point_ifindex != 0 && generic_socket_id != 0) {
            try {
                DeleteInterface(connection, generic_socket_id, port_id, family_id,
                                access_point_ifindex, sequence);
            } catch (const std::exception& cleanup_exception) {
                LOG_WARNING(Service_NWM, "UDS Real: AP cleanup failed: {}",
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
    std::atomic<u16> selected_peer_channel{0};
    std::mutex mutex;
    std::thread worker;
    bool have_pending_beacon{};
    PhysicalBeaconSnapshot pending_beacon;
    std::deque<std::vector<u8>> pending_frames;
    std::deque<AccessPointDataFrame> pending_access_point_data;
    AccessPointConfiguration access_point_config;
    bool access_point_activation_requested{};
    std::deque<AccessPointStationRequest> pending_access_point_stations;
};

Nl80211Monitor::Nl80211Monitor() : impl{std::make_unique<Impl>()} {}

Nl80211Monitor::~Nl80211Monitor() {
    Stop();
}

void Nl80211Monitor::Start(u16 channel, const std::array<u8, 6>& local_address,
                           BeaconCallback beacon_callback,
                           FrameCallback frame_callback) {
    Stop();
    if (!beacon_callback || !frame_callback) {
        throw std::invalid_argument("UDS Real monitor requires beacon and frame callbacks");
    }

    std::scoped_lock lock{impl->mutex};
    impl->stop_requested.store(false, std::memory_order_relaxed);
    impl->running.store(true, std::memory_order_relaxed);
    impl->selected_peer_channel.store(0, std::memory_order_relaxed);
    impl->have_pending_beacon = false;
    impl->pending_beacon = {};
    impl->pending_frames.clear();
    impl->pending_access_point_data.clear();
    ++impl->access_point_config.generation;
    impl->access_point_config.enabled = false;
    impl->access_point_activation_requested = false;
    impl->pending_access_point_stations.clear();
    LOG_INFO(Service_NWM,
             "UDS Real: isolated ACK-shell test enabled; software CCMP and raw data TX remain "
             "authoritative; kernel keys, authorization, and AP data carrier are disabled");
    impl->worker = std::thread{[this, channel, local_address,
                                beacon_callback = std::move(beacon_callback),
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
        const AccessPointConfigurationProvider access_point_config_provider = [this]() {
            std::scoped_lock lock{impl->mutex};
            return impl->access_point_config;
        };
        const AccessPointActivationProvider access_point_activation_provider = [this]() {
            std::scoped_lock lock{impl->mutex};
            const bool requested = impl->access_point_activation_requested;
            impl->access_point_activation_requested = false;
            return requested;
        };
        const AccessPointStationProvider access_point_station_provider = [this]() {
            std::scoped_lock lock{impl->mutex};
            if (impl->pending_access_point_stations.empty()) {
                return std::optional<AccessPointStationRequest>{};
            }
            auto request = std::move(impl->pending_access_point_stations.front());
            impl->pending_access_point_stations.pop_front();
            return std::optional<AccessPointStationRequest>{std::move(request)};
        };
        const AccessPointDataProvider access_point_data_provider = [this]() {
            std::scoped_lock lock{impl->mutex};
            if (impl->pending_access_point_data.empty()) {
                return std::optional<AccessPointDataFrame>{};
            }
            auto frame = std::move(impl->pending_access_point_data.front());
            impl->pending_access_point_data.pop_front();
            return std::optional<AccessPointDataFrame>{std::move(frame)};
        };
        RunMonitorBody(impl->stop_requested, impl->selected_peer_channel, channel,
                       local_address, beacon_callback,
                       frame_callback,
                       physical_beacon_provider, physical_frame_provider,
                       access_point_config_provider, access_point_activation_provider,
                       access_point_station_provider, access_point_data_provider);
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

void Nl80211Monitor::SelectPeerChannel(u16 channel) {
    if (channel < 1 || channel > 13) {
        LOG_WARNING(Service_NWM,
                    "UDS Real: ignored invalid selected peer channel {}", channel);
        return;
    }
    impl->selected_peer_channel.store(channel, std::memory_order_release);
}

void Nl80211Monitor::SubmitAccessPointData(
    std::span<const u8> payload, const std::array<u8, 6>& transmitter_address,
    const std::array<u8, 6>& destination_address) {
    if (payload.empty()) {
        return;
    }

    AccessPointDataFrame frame;
    frame.payload.assign(payload.begin(), payload.end());
    frame.transmitter_address = transmitter_address;
    frame.destination_address = destination_address;

    std::scoped_lock lock{impl->mutex};
    constexpr std::size_t MaxPendingDataFrames = 256;
    if (impl->pending_access_point_data.size() >= MaxPendingDataFrames) {
        impl->pending_access_point_data.pop_front();
        LOG_WARNING(Service_NWM, "UDS Real AP: data queue full; dropped oldest frame");
    }
    impl->pending_access_point_data.push_back(std::move(frame));
}

void Nl80211Monitor::ConfigureAccessPoint(const std::array<u8, 6>& host_address,
                                          const std::array<u8, 16>& ccmp_key, u32 network_id,
                                          u8 max_stations) {
    std::scoped_lock lock{impl->mutex};
    impl->access_point_config.host_address = host_address;
    // Intentionally do not retain or install this key. Azahar's proven software CCMP path is the
    // sole encryption/packet-number owner during this ACK-shell experiment.
    (void)ccmp_key;
    constexpr std::array<char, 16> HexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                                                '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    for (std::size_t index = 0; index < impl->access_point_config.ssid.size(); ++index) {
        const std::size_t shift = (impl->access_point_config.ssid.size() - index - 1) * 4;
        impl->access_point_config.ssid[index] =
            static_cast<u8>(HexDigits[(network_id >> shift) & 0xF]);
    }
    impl->access_point_config.max_stations = std::max<u8>(max_stations, 1);
    impl->access_point_config.enabled = true;
    ++impl->access_point_config.generation;
}

void Nl80211Monitor::ActivateAccessPoint() {
    std::scoped_lock lock{impl->mutex};
    if (impl->access_point_config.enabled) {
        impl->access_point_activation_requested = true;
    }
}

void Nl80211Monitor::RegisterAccessPointStation(
    const std::array<u8, 6>& station_address, std::span<const u8> association_body) {
    AccessPointStationRequest request;
    request.station_address = station_address;
    request.association_body.assign(association_body.begin(), association_body.end());
    std::scoped_lock lock{impl->mutex};
    if (impl->access_point_config.enabled) {
        impl->pending_access_point_stations.push_back(std::move(request));
    }
}

void Nl80211Monitor::RemoveAccessPointStation(
    const std::array<u8, 6>& station_address) {
    AccessPointStationRequest request;
    request.station_address = station_address;
    request.remove = true;
    std::scoped_lock lock{impl->mutex};
    if (impl->access_point_config.enabled) {
        impl->pending_access_point_stations.push_back(std::move(request));
    }
}

void Nl80211Monitor::ResetAccessPoint() {
    std::scoped_lock lock{impl->mutex};
    impl->access_point_config.enabled = false;
    ++impl->access_point_config.generation;
    impl->access_point_activation_requested = false;
    impl->pending_access_point_stations.clear();
    impl->pending_access_point_data.clear();
    // The monitor now outlives UDS sessions, so the finished session's beacon must not linger.
    impl->have_pending_beacon = false;
    impl->pending_beacon = {};
}

void Nl80211Monitor::SubmitBeacon(std::span<const u8> beacon_body,
                                  const std::array<u8, 6>& host_address) {
    if (beacon_body.empty()) {
        return;
    }

    std::scoped_lock lock{impl->mutex};
    impl->pending_beacon.body.assign(beacon_body.begin(), beacon_body.end());
    impl->pending_beacon.host_address = host_address;
    impl->pending_beacon.ack_shell_only = false;
    impl->have_pending_beacon = true;
}

void Nl80211Monitor::ConfigureClientAckShell(const std::array<u8, 6>& own_address,
                                             const std::array<u8, 6>& host_address,
                                             u32 network_id,
                                             std::span<const u8> association_body) {
    std::scoped_lock lock{impl->mutex};

    // Same companion interface as the host role, but adopting our own address.
    impl->access_point_config.host_address = own_address;
    constexpr std::array<char, 16> HexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                                                '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    for (std::size_t index = 0; index < impl->access_point_config.ssid.size(); ++index) {
        const std::size_t shift = (impl->access_point_config.ssid.size() - index - 1) * 4;
        impl->access_point_config.ssid[index] =
            static_cast<u8>(HexDigits[(network_id >> shift) & 0xF]);
    }
    impl->access_point_config.max_stations = 1;
    impl->access_point_config.enabled = true;
    ++impl->access_point_config.generation;

    // Minimal hidden-network beacon: fixed parameters, the (hidden) SSID and basic rates. It has
    // no Nintendo vendor elements, so no console can mistake it for a UDS network. The DS
    // parameter set is added for the current channel when the AP starts.
    std::vector<u8> body(8, 0); // Timestamp.
    body.push_back(100);        // Beacon interval: 100 TU.
    body.push_back(0);
    body.push_back(0x31); // Capability: ESS, privacy, short preamble, short slot time.
    body.push_back(0x04);
    body.push_back(0); // SSID.
    body.push_back(static_cast<u8>(impl->access_point_config.ssid.size()));
    body.insert(body.end(), impl->access_point_config.ssid.begin(),
                impl->access_point_config.ssid.end());
    constexpr std::array<u8, 8> SupportedRates{0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
    body.push_back(1);
    body.push_back(static_cast<u8>(SupportedRates.size()));
    body.insert(body.end(), SupportedRates.begin(), SupportedRates.end());

    impl->pending_beacon.body = std::move(body);
    impl->pending_beacon.host_address = own_address;
    impl->pending_beacon.ack_shell_only = true;
    impl->have_pending_beacon = true;

    // Bring the shell up now and register the retail host so it is acknowledged from its first
    // frame. The worker starts the AP and registers the station before it transmits anything
    // queued afterwards, including our authentication request.
    impl->access_point_activation_requested = true;
    AccessPointStationRequest request;
    request.station_address = host_address;
    request.association_body.assign(association_body.begin(), association_body.end());
    impl->pending_access_point_stations.push_back(std::move(request));
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
