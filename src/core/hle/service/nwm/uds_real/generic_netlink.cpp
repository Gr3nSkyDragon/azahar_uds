// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#include "core/hle/service/nwm/uds_real/generic_netlink.h"

#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "common/common_types.h"
#include "common/logging/log.h"
#include "core/hle/service/nwm/uds_real/ldnd_connection.h"

namespace Service::NWM::UdsReal {
namespace {

constexpr int AfNetlink = 16;
constexpr int SockDgram = 2;
constexpr int NetlinkGeneric = 16;

constexpr u16 GenlIdCtrl = 0x10;
constexpr u8 CtrlCmdGetFamily = 3;
constexpr u16 CtrlAttrFamilyId = 1;
constexpr u16 CtrlAttrFamilyName = 2;

constexpr u8 Nl80211CmdGetInterface = 5;
constexpr u16 Nl80211AttrWiphy = 1;
constexpr u16 Nl80211AttrIfIndex = 3;
constexpr u16 Nl80211AttrIfName = 4;
constexpr u16 Nl80211AttrIfType = 5;
constexpr u16 Nl80211AttrMac = 6;

constexpr u16 NlmFRequest = 0x0001;
constexpr u16 NlmFMulti = 0x0002;
constexpr u16 NlmFRoot = 0x0100;
constexpr u16 NlmFMatch = 0x0200;
constexpr u16 NlmFDump = NlmFRoot | NlmFMatch;
constexpr u16 NlmsgError = 2;
constexpr u16 NlmsgDone = 3;
constexpr u16 NlaTypeMask = 0x3FFF;

constexpr std::size_t NetlinkHeaderLength = 16;
constexpr std::size_t GenericHeaderLength = 4;

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

std::vector<u8> PackSockaddrNl() {
    std::vector<u8> address;
    address.reserve(12);
    AppendU16(address, AfNetlink);
    AppendU16(address, 0);
    AppendU32(address, 0);
    AppendU32(address, 0);
    return address;
}

u32 ParseSockaddrNlPort(const std::vector<u8>& address) {
    if (address.size() < 12 || ReadU16(address.data()) != AfNetlink) {
        throw std::runtime_error("ldnd returned an invalid sockaddr_nl");
    }
    return ReadU32(address.data() + 4);
}

void AppendAttribute(std::vector<u8>& output, u16 type, const u8* data, std::size_t size) {
    const std::size_t length = 4 + size;
    AppendU16(output, static_cast<u16>(length));
    AppendU16(output, type);
    output.insert(output.end(), data, data + size);
    output.resize(Align4(output.size()), 0);
}

std::vector<u8> PackRequest(u16 family, u16 flags, u32 sequence, u32 port_id, u8 command,
                            const std::vector<u8>& attributes = {}) {
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
    output.push_back(1); // Generic-netlink version.
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

void ThrowNetlinkError(const NetlinkMessageView& message) {
    if (message.payload_size < 4) {
        throw std::runtime_error("received a truncated NLMSG_ERROR");
    }
    const s32 error = static_cast<s32>(ReadU32(message.payload));
    if (error != 0) {
        throw std::runtime_error("netlink request failed with error " + std::to_string(error));
    }
}

u16 ResolveNl80211Family(LdndConnection& connection, u32 socket_id, u32 port_id) {
    std::vector<u8> attributes;
    constexpr char FamilyName[] = "nl80211";
    AppendAttribute(attributes, CtrlAttrFamilyName,
                    reinterpret_cast<const u8*>(FamilyName), sizeof(FamilyName));

    constexpr u32 Sequence = 1;
    const std::vector<u8> request =
        PackRequest(GenlIdCtrl, NlmFRequest, Sequence, port_id, CtrlCmdGetFamily, attributes);
    connection.SendTo(socket_id, request);

    for (;;) {
        const auto messages = ParseMessages(connection.ReceiveData(socket_id));
        for (const auto& message : messages) {
            if (message.sequence != Sequence) {
                continue;
            }
            if (message.type == NlmsgError) {
                ThrowNetlinkError(message);
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

std::string FormatMac(const u8* mac, std::size_t size) {
    if (size < 6) {
        return "unavailable";
    }
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

void EnumerateInterfaces(LdndConnection& connection, u32 socket_id, u32 port_id, u16 family_id) {
    constexpr u32 Sequence = 2;
    const std::vector<u8> request = PackRequest(
        family_id, static_cast<u16>(NlmFRequest | NlmFDump), Sequence, port_id,
        Nl80211CmdGetInterface);
    connection.SendTo(socket_id, request);

    std::size_t interface_count = 0;
    for (;;) {
        const auto messages = ParseMessages(connection.ReceiveData(socket_id));
        for (const auto& message : messages) {
            if (message.sequence != Sequence) {
                continue;
            }
            if (message.type == NlmsgError) {
                ThrowNetlinkError(message);
                continue;
            }
            if (message.type == NlmsgDone) {
                LOG_INFO(Service_NWM, "UDS Real NL80211: interface enumeration complete, count={}",
                         interface_count);
                return;
            }

            u32 wiphy = 0;
            u32 ifindex = 0;
            u32 iftype = 0;
            std::string ifname;
            std::string mac = "unavailable";
            ForEachAttribute(message, [&](u16 type, const u8* value, std::size_t size) {
                if (type == Nl80211AttrWiphy && size >= 4) {
                    wiphy = ReadU32(value);
                } else if (type == Nl80211AttrIfIndex && size >= 4) {
                    ifindex = ReadU32(value);
                } else if (type == Nl80211AttrIfType && size >= 4) {
                    iftype = ReadU32(value);
                } else if (type == Nl80211AttrIfName && size != 0) {
                    const std::size_t length = value[size - 1] == 0 ? size - 1 : size;
                    ifname.assign(reinterpret_cast<const char*>(value), length);
                } else if (type == Nl80211AttrMac) {
                    mac = FormatMac(value, size);
                }
            });
            ++interface_count;
            LOG_INFO(Service_NWM,
                     "UDS Real NL80211: interface={}, ifindex={}, wiphy={}, iftype={}, mac={}",
                     ifname, ifindex, wiphy, iftype, mac);

            if ((message.flags & NlmFMulti) == 0) {
                LOG_INFO(Service_NWM, "UDS Real NL80211: interface enumeration complete, count={}",
                         interface_count);
                return;
            }
        }
    }
}

void RunTestBody() {
    try {
        LOG_INFO(Service_NWM, "UDS Real NL80211: connecting to ldnd");
        LdndConnection connection;
        connection.Connect();

        const u32 socket_id = connection.Socket(AfNetlink, SockDgram, NetlinkGeneric);
        connection.Bind(socket_id, PackSockaddrNl());
        const u32 port_id = ParseSockaddrNlPort(connection.GetSockName(socket_id));
        connection.Start(socket_id);
        LOG_INFO(Service_NWM, "UDS Real NL80211: netlink socket ready, SID={}, portId={}",
                 socket_id, port_id);

        const u16 family_id = ResolveNl80211Family(connection, socket_id, port_id);
        LOG_INFO(Service_NWM, "UDS Real NL80211: resolved family id={}", family_id);
        EnumerateInterfaces(connection, socket_id, port_id, family_id);

        connection.CloseSocket(socket_id);
        LOG_INFO(Service_NWM, "UDS Real NL80211: test completed successfully");
    } catch (const std::exception& exception) {
        LOG_ERROR(Service_NWM, "UDS Real NL80211: test failed: {}", exception.what());
    }
}

} // namespace

void RunNl80211StartupTest() {
#ifdef _WIN32
    // Keep a delayed driver/netlink response from blocking Azahar's UI thread.
    std::thread{RunTestBody}.detach();
#else
    LOG_WARNING(Service_NWM, "UDS Real NL80211: startup test skipped on non-Windows platform");
#endif
}

} // namespace Service::NWM::UdsReal
