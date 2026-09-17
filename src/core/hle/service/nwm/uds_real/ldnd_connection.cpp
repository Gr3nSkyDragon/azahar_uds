// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#include "core/hle/service/nwm/uds_real/ldnd_connection.h"

#include <stdexcept>
#include <string>
#include <utility>

#include "common/logging/log.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace Service::NWM::UdsReal {

struct LdndConnection::Impl {
#ifdef _WIN32
    HANDLE pipe = INVALID_HANDLE_VALUE;
#endif
    u32 next_socket_id = 0;
};

namespace {

#ifdef _WIN32
[[noreturn]] void ThrowWindowsError(const char* operation) {
    throw std::runtime_error(std::string{operation} + " failed with Windows error " +
                             std::to_string(GetLastError()));
}

void WriteExactly(HANDLE pipe, const u8* data, std::size_t length) {
    while (length != 0) {
        const DWORD chunk = static_cast<DWORD>(
            length > static_cast<std::size_t>(MAXDWORD) ? MAXDWORD : length);
        DWORD written = 0;
        if (!WriteFile(pipe, data, chunk, &written, nullptr) || written == 0) {
            ThrowWindowsError("WriteFile(ldnd)");
        }
        data += written;
        length -= written;
    }
}

void ReadExactly(HANDLE pipe, u8* data, std::size_t length) {
    while (length != 0) {
        const DWORD chunk = static_cast<DWORD>(
            length > static_cast<std::size_t>(MAXDWORD) ? MAXDWORD : length);
        DWORD received = 0;
        if (!ReadFile(pipe, data, chunk, &received, nullptr) || received == 0) {
            ThrowWindowsError("ReadFile(ldnd)");
        }
        data += received;
        length -= received;
    }
}
#endif

} // namespace

LdndConnection::LdndConnection() : impl{std::make_unique<Impl>()} {}

LdndConnection::~LdndConnection() {
    Disconnect();
}

void LdndConnection::Connect(const std::wstring& pipe_path) {
#ifdef _WIN32
    if (IsConnected()) {
        return;
    }

    impl->pipe = CreateFileW(pipe_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (impl->pipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY) {
        if (WaitNamedPipeW(pipe_path.c_str(), 2000)) {
            impl->pipe = CreateFileW(pipe_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        }
    }
    if (impl->pipe == INVALID_HANDLE_VALUE) {
        ThrowWindowsError("CreateFileW(\\\\.\\pipe\\ldnd)");
    }

    DWORD mode = PIPE_READMODE_BYTE;
    if (!SetNamedPipeHandleState(impl->pipe, &mode, nullptr, nullptr)) {
        const DWORD error = GetLastError();
        CloseHandle(impl->pipe);
        impl->pipe = INVALID_HANDLE_VALUE;
        SetLastError(error);
        ThrowWindowsError("SetNamedPipeHandleState(ldnd)");
    }
#else
    (void)pipe_path;
    throw std::runtime_error("UDS Real ldnd transport is currently implemented only on Windows");
#endif
}

void LdndConnection::Disconnect() {
#ifdef _WIN32
    if (impl && impl->pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(impl->pipe);
        impl->pipe = INVALID_HANDLE_VALUE;
    }
#endif
}

bool LdndConnection::IsConnected() const {
#ifdef _WIN32
    return impl && impl->pipe != INVALID_HANDLE_VALUE;
#else
    return false;
#endif
}

u32 LdndConnection::AllocateSocketId() {
    ++impl->next_socket_id;
    if (impl->next_socket_id == 0) {
        ++impl->next_socket_id;
    }
    return impl->next_socket_id;
}

void LdndConnection::WriteFrame(const LdndFrame& frame) {
#ifdef _WIN32
    if (!IsConnected()) {
        throw std::runtime_error("ldnd is not connected");
    }
    const auto header = LdndProtocol::SerializeHeader(frame);
    WriteExactly(impl->pipe, header.data(), header.size());
    if (!frame.blob.empty()) {
        WriteExactly(impl->pipe, frame.blob.data(), frame.blob.size());
    }
#else
    (void)frame;
    throw std::runtime_error("ldnd is unavailable on this platform");
#endif
}

LdndFrame LdndConnection::ReadFrame() {
#ifdef _WIN32
    LdndProtocol::Header header{};
    ReadExactly(impl->pipe, header.data(), header.size());
    LdndFrame frame = LdndProtocol::DeserializeHeader(header);
    const u32 blob_length = LdndProtocol::GetBlobLength(header);
    frame.blob.resize(blob_length);
    if (blob_length != 0) {
        ReadExactly(impl->pipe, frame.blob.data(), frame.blob.size());
    }
    return frame;
#else
    throw std::runtime_error("ldnd is unavailable on this platform");
#endif
}

LdndFrame LdndConnection::SendRequest(const LdndFrame& frame) {
    WriteFrame(frame);
    LdndFrame reply = ReadFrame();
    if (reply.socket_id != frame.socket_id) {
        throw std::runtime_error("ldnd reply SID mismatch: expected " +
                                 std::to_string(frame.socket_id) + ", received " +
                                 std::to_string(reply.socket_id));
    }
    return reply;
}

void LdndConnection::ThrowIfDaemonError(const LdndFrame& reply, const char* operation) {
    if (reply.op != LdndOp::Reply) {
        throw std::runtime_error(std::string{"expected ldnd reply after "} + operation +
                                 ", received opcode " +
                                 std::to_string(static_cast<u32>(reply.op)));
    }
    const auto error = static_cast<LdndError>(reply.arg0);
    if (error != LdndError::None) {
        throw std::runtime_error(std::string{"ldnd "} + operation + " failed for SID " +
                                 std::to_string(reply.socket_id) + ": error " +
                                 std::to_string(static_cast<u32>(error)));
    }
}

u32 LdndConnection::Socket(int domain, int type, int protocol) {
    const u32 sid = AllocateSocketId();
    LdndFrame request{LdndOp::Socket, sid, static_cast<u32>(domain), static_cast<u32>(type),
                      static_cast<u32>(protocol), {}};
    const LdndFrame reply = SendRequest(request);
    ThrowIfDaemonError(reply, "socket");
    return sid;
}

void LdndConnection::Bind(u32 socket_id, std::span<const u8> sockaddr) {
    LdndFrame request{LdndOp::Bind, socket_id, 0, 0, 0,
                      std::vector<u8>{sockaddr.begin(), sockaddr.end()}};
    const LdndFrame reply = SendRequest(request);
    ThrowIfDaemonError(reply, "bind");
}

void LdndConnection::SetSockOpt(u32 socket_id, int level, int option_name,
                                std::span<const u8> value) {
    LdndFrame request{LdndOp::SetSockOpt, socket_id, static_cast<u32>(level),
                      static_cast<u32>(option_name), 0,
                      std::vector<u8>{value.begin(), value.end()}};
    const LdndFrame reply = SendRequest(request);
    ThrowIfDaemonError(reply, "setsockopt");
}

std::vector<u8> LdndConnection::GetSockName(u32 socket_id) {
    const LdndFrame reply =
        SendRequest(LdndFrame{LdndOp::GetSockName, socket_id, 0, 0, 0, {}});
    ThrowIfDaemonError(reply, "getsockname");
    return reply.blob;
}

void LdndConnection::Start(u32 socket_id) {
    const LdndFrame reply = SendRequest(LdndFrame{LdndOp::Start, socket_id, 0, 0, 0, {}});
    ThrowIfDaemonError(reply, "start");
}

void LdndConnection::SendTo(u32 socket_id, std::span<const u8> data, int flags) {
    WriteFrame(LdndFrame{LdndOp::SendTo, socket_id, static_cast<u32>(flags), 0, 0,
                         std::vector<u8>{data.begin(), data.end()}});
}

std::vector<u8> LdndConnection::ReceiveData(u32 socket_id) {
    for (;;) {
        LdndFrame frame = ReadFrame();
        if (frame.op == LdndOp::Data && frame.socket_id == socket_id) {
            return std::move(frame.blob);
        }
        if (frame.op == LdndOp::Reply) {
            throw std::runtime_error("unexpected ldnd reply while waiting for socket data");
        }
    }
}

bool LdndConnection::TryReceiveData(u32 socket_id, std::vector<u8>& data, u32 timeout_ms) {
#ifdef _WIN32
    if (!IsConnected()) {
        throw std::runtime_error("ldnd is not connected");
    }

    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(impl->pipe, nullptr, 0, nullptr, &available, nullptr)) {
            ThrowWindowsError("PeekNamedPipe(ldnd)");
        }

        if (available >= LdndProtocol::HeaderLength) {
            LdndFrame frame = ReadFrame();
            if (frame.op == LdndOp::Data && frame.socket_id == socket_id) {
                data = std::move(frame.blob);
                return true;
            }
            if (frame.op == LdndOp::Reply) {
                throw std::runtime_error("unexpected ldnd reply while waiting for socket data");
            }
        }

        if (GetTickCount64() >= deadline) {
            return false;
        }
        Sleep(5);
    }
#else
    (void)socket_id;
    (void)data;
    (void)timeout_ms;
    return false;
#endif
}

void LdndConnection::CloseSocket(u32 socket_id) {
    // daemon.c intentionally sends no reply for LDND_OP_CLOSE.
    WriteFrame(LdndFrame{LdndOp::Close, socket_id, 0, 0, 0, {}});
}

void RunLdndStartupTest() {
#ifdef _WIN32
    try {
        LOG_INFO(Service_NWM, "UDS Real: connecting to \\\\.\\pipe\\ldnd");
        LdndConnection connection;
        connection.Connect();
        LOG_INFO(Service_NWM, "UDS Real: connected to ldnd");

        // Linux constants: AF_NETLINK=16, SOCK_RAW=3, NETLINK_GENERIC=16.
        const u32 socket_id = connection.Socket(16, 3, 16);
        LOG_INFO(Service_NWM, "UDS Real: generic-netlink socket created, SID={}", socket_id);

        connection.CloseSocket(socket_id);
        LOG_INFO(Service_NWM, "UDS Real: handshake succeeded; test socket closed");
    } catch (const std::exception& exception) {
        LOG_ERROR(Service_NWM, "UDS Real: startup handshake failed: {}", exception.what());
    }
#else
    LOG_WARNING(Service_NWM, "UDS Real: ldnd startup test skipped on non-Windows platform");
#endif
}

} // namespace Service::NWM::UdsReal
