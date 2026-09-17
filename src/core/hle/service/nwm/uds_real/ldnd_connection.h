// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#pragma once

#include <memory>
#include <span>
#include <string>
#include <vector>

#include "common/common_types.h"
#include "core/hle/service/nwm/uds_real/ldnd_protocol.h"

namespace Service::NWM::UdsReal {

class LdndConnection {
public:
    LdndConnection();
    ~LdndConnection();

    LdndConnection(const LdndConnection&) = delete;
    LdndConnection& operator=(const LdndConnection&) = delete;

    void Connect(const std::wstring& pipe_path = LR"(\\.\pipe\ldnd)");
    void Disconnect();
    [[nodiscard]] bool IsConnected() const;

    u32 Socket(int domain, int type, int protocol);
    void Bind(u32 socket_id, std::span<const u8> sockaddr);
    void SetSockOpt(u32 socket_id, int level, int option_name, std::span<const u8> value);
    std::vector<u8> GetSockName(u32 socket_id);
    void Start(u32 socket_id);
    void SendTo(u32 socket_id, std::span<const u8> data, int flags = 0);
    std::vector<u8> ReceiveData(u32 socket_id);
    bool TryReceiveData(u32 socket_id, std::vector<u8>& data, u32 timeout_ms);
    void CloseSocket(u32 socket_id);

private:
    struct Impl;
    std::unique_ptr<Impl> impl;

    u32 AllocateSocketId();
    void WriteFrame(const LdndFrame& frame);
    LdndFrame ReadFrame();
    LdndFrame SendRequest(const LdndFrame& frame);
    static void ThrowIfDaemonError(const LdndFrame& reply, const char* operation);
};

// Temporary no-game startup diagnostic. Remove the call from citra_qt.cpp after the
// named-pipe and generic-netlink socket test has passed.
void RunLdndStartupTest();

} // namespace Service::NWM::UdsReal
