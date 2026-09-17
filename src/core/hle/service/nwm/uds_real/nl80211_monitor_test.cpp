// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#include "core/hle/service/nwm/uds_real/nl80211_monitor_test.h"

#include <algorithm>
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
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
constexpr u16 TestChannel = 11;
constexpr u32 TestFrequency = 2462;
constexpr auto CaptureDuration = std::chrono::seconds{45};
constexpr char MonitorName[] = "udsmon0";

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

u16 ReadU16(const u8* input) {
    return static_cast<u16>(input[0]) | static_cast<u16>(input[1] << 8);
}

u32 ReadU32(const u8* input) {
    return static_cast<u32>(input[0]) | (static_cast<u32>(input[1]) << 8) |
           (static_cast<u32>(input[2]) << 16) | (static_cast<u32>(input[3]) << 24);
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
                u32 ifindex, u32& sequence) {
    std::vector<u8> attributes;
    AppendU32Attribute(attributes, Nl80211AttrIfIndex, ifindex);
    AppendU32Attribute(attributes, Nl80211AttrWiphyFreq, TestFrequency);
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

struct BeaconInfo {
    std::string source_mac;
    std::vector<u8> nintendo_tag_types;
};

std::optional<BeaconInfo> ParseBeacon(const std::vector<u8>& packet) {
    if (packet.size() < 24) {
        return std::nullopt;
    }

    std::size_t frame_offset = 0;
    if (packet.size() >= 8 && packet[0] == 0) {
        const std::size_t radiotap_length = ReadU16(packet.data() + 2);
        if (radiotap_length >= 8 && radiotap_length + 24 <= packet.size()) {
            frame_offset = radiotap_length;
        }
    }

    if (frame_offset + 36 > packet.size()) {
        return std::nullopt;
    }
    const u16 frame_control = ReadU16(packet.data() + frame_offset);
    const u8 type = static_cast<u8>((frame_control >> 2) & 0x3);
    const u8 subtype = static_cast<u8>((frame_control >> 4) & 0xF);
    if (type != 0 || subtype != 8) {
        return std::nullopt;
    }

    BeaconInfo result{FormatMac(packet.data() + frame_offset + 10), {}};
    std::size_t offset = frame_offset + 36;
    while (offset + 2 <= packet.size()) {
        const u8 tag = packet[offset];
        const u8 length = packet[offset + 1];
        offset += 2;
        if (offset + length > packet.size()) {
            break;
        }
        if (tag == 221 && length >= 4 && packet[offset] == 0x00 &&
            packet[offset + 1] == 0x1F && packet[offset + 2] == 0x32) {
            result.nintendo_tag_types.push_back(packet[offset + 3]);
        }
        offset += length;
    }
    return result;
}

std::string FormatTagTypes(const std::vector<u8>& tag_types) {
    if (tag_types.empty()) {
        return "none";
    }
    std::string result;
    for (std::size_t index = 0; index < tag_types.size(); ++index) {
        if (index != 0) {
            result += ',';
        }
        result += std::to_string(tag_types[index]);
    }
    return result;
}

void RunTestBody() {
    LdndConnection connection;
    u32 generic_socket_id = 0;
    u32 packet_socket_id = 0;
    u32 monitor_ifindex = 0;
    u16 family_id = 0;
    u32 port_id = 0;
    u32 sequence = 0;

    try {
        LOG_INFO(Service_NWM, "UDS Real MONITOR: stage=connect, state=begin");
        connection.Connect();
        generic_socket_id = connection.Socket(AfNetlink, SockDgram, NetlinkGeneric);
        connection.Bind(generic_socket_id, PackSockaddrNl());
        port_id = ParseSockaddrNlPort(connection.GetSockName(generic_socket_id));
        connection.Start(generic_socket_id);
        family_id = ResolveNl80211Family(connection, generic_socket_id, port_id, sequence);
        LOG_INFO(Service_NWM, "UDS Real MONITOR: stage=connect, state=complete, familyId={}",
                 family_id);

        auto interfaces = EnumerateInterfaces(connection, generic_socket_id, port_id, family_id,
                                              sequence);
        if (const auto old = std::find_if(interfaces.begin(), interfaces.end(),
                                          [](const InterfaceInfo& item) {
                                              return item.name == MonitorName;
                                          });
            old != interfaces.end()) {
            LOG_INFO(Service_NWM, "UDS Real MONITOR: removing stale {} ifindex={}", MonitorName,
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

        LOG_INFO(Service_NWM, "UDS Real MONITOR: stage=create, state=begin, wiphy={}",
                 physical->wiphy);
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
        LOG_INFO(Service_NWM,
                 "UDS Real MONITOR: stage=create, state=complete, interface={}, ifindex={}, "
                 "iftype={}",
                 monitor->name, monitor->ifindex, monitor->iftype);

        SetInterfaceUp(connection, monitor_ifindex);
        SetChannel(connection, generic_socket_id, port_id, family_id, monitor_ifindex, sequence);
        LOG_INFO(Service_NWM,
                 "UDS Real MONITOR: stage=radio, state=complete, channel={}, frequency={}",
                 TestChannel, TestFrequency);

        // socket(2) receives the protocol argument in host byte order, while Linux expects
        // htons(ETH_P_ALL), hence 0x0300 here.
        packet_socket_id = connection.Socket(AfPacket, SockRaw, 0x0300);
        connection.Bind(packet_socket_id, PackSockaddrLl(monitor_ifindex));
        connection.Start(packet_socket_id);
        LOG_INFO(Service_NWM,
                 "UDS Real MONITOR: capture started for 45 seconds. Put Pokemon X on the "
                 "physical 3DS into a local-wireless trade/search screen now.");

        std::size_t packet_count = 0;
        std::size_t beacon_count = 0;
        std::size_t nintendo_beacon_count = 0;
        const auto deadline = std::chrono::steady_clock::now() + CaptureDuration;
        while (std::chrono::steady_clock::now() < deadline) {
            std::vector<u8> packet;
            if (!connection.TryReceiveData(packet_socket_id, packet, 250)) {
                continue;
            }
            ++packet_count;
            const auto beacon = ParseBeacon(packet);
            if (!beacon) {
                continue;
            }
            ++beacon_count;
            const bool nintendo = !beacon->nintendo_tag_types.empty();
            if (nintendo) {
                ++nintendo_beacon_count;
            }
            if (beacon_count <= 10 || nintendo) {
                LOG_INFO(Service_NWM,
                         "UDS Real MONITOR: beacon={}, source={}, nintendo={}, tagTypes={}",
                         beacon_count, beacon->source_mac, nintendo,
                         FormatTagTypes(beacon->nintendo_tag_types));
            }
        }

        LOG_INFO(Service_NWM,
                 "UDS Real MONITOR: capture complete, packets={}, beacons={}, "
                 "nintendoBeacons={}",
                 packet_count, beacon_count, nintendo_beacon_count);

        connection.CloseSocket(packet_socket_id);
        packet_socket_id = 0;
        DeleteInterface(connection, generic_socket_id, port_id, family_id, monitor_ifindex,
                        sequence);
        monitor_ifindex = 0;
        connection.CloseSocket(generic_socket_id);
        generic_socket_id = 0;
        LOG_INFO(Service_NWM, "UDS Real MONITOR: test completed and udsmon0 was removed");
    } catch (const std::exception& exception) {
        LOG_ERROR(Service_NWM, "UDS Real MONITOR: test failed: {}", exception.what());
        if (packet_socket_id != 0) {
            connection.CloseSocket(packet_socket_id);
        }
        if (monitor_ifindex != 0 && generic_socket_id != 0) {
            try {
                DeleteInterface(connection, generic_socket_id, port_id, family_id,
                                monitor_ifindex, sequence);
            } catch (const std::exception& cleanup_exception) {
                LOG_WARNING(Service_NWM, "UDS Real MONITOR: cleanup failed: {}",
                            cleanup_exception.what());
            }
        }
        if (generic_socket_id != 0) {
            connection.CloseSocket(generic_socket_id);
        }
    }
}

} // namespace

void RunNl80211MonitorTest() {
#ifdef _WIN32
    std::thread{RunTestBody}.detach();
#else
    LOG_WARNING(Service_NWM, "UDS Real MONITOR: test skipped on non-Windows platform");
#endif
}

} // namespace Service::NWM::UdsReal
