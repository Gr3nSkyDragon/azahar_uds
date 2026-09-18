// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#include "core/hle/service/nwm/uds_real/ldnd_connection.h"

#include <deque>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
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
    std::unordered_map<u32, std::deque<std::vector<u8>>> pending_data;
    std::size_t deferred_data_count{};
    std::size_t raw_tx_pipe_trace_count{};

    void QueueData(LdndFrame frame) {
        pending_data[frame.socket_id].push_back(std::move(frame.blob));
        ++deferred_data_count;
    }

    std::optional<std::vector<u8>> TakeData(u32 socket_id) {
        const auto iterator = pending_data.find(socket_id);
        if (iterator == pending_data.end() || iterator->second.empty()) {
            return std::nullopt;
        }
        std::vector<u8> data = std::move(iterator->second.front());
        iterator->second.pop_front();
        if (iterator->second.empty()) {
            pending_data.erase(iterator);
        }
        return data;
    }
};

namespace {

u16 ReadU16LittleEndian(const u8* input) {
    return static_cast<u16>(input[0]) | (static_cast<u16>(input[1]) << 8);
}

u32 ReadU32LittleEndian(const u8* input) {
    return static_cast<u32>(input[0]) | (static_cast<u32>(input[1]) << 8) |
           (static_cast<u32>(input[2]) << 16) | (static_cast<u32>(input[3]) << 24);
}

u32 FingerprintBytes(std::span<const u8> bytes) {
    u32 fingerprint = 2166136261U;
    for (const u8 byte : bytes) {
        fingerprint ^= byte;
        fingerprint *= 16777619U;
    }
    return fingerprint;
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
        output.push_back(Hex[byte & 0xF]);
    }
    return output.empty() ? "<none>" : output;
}

void TraceProtectedSendToFrame(std::size_t& trace_count, const LdndFrame& frame,
                               const LdndProtocol::Header& header) {
    if (frame.op != LdndOp::SendTo || frame.blob.size() < 8 || frame.blob[0] != 0 ||
        frame.blob[1] != 0) {
        return;
    }

    const u16 radiotap_length = ReadU16LittleEndian(frame.blob.data() + 2);
    if (radiotap_length < 8 ||
        frame.blob.size() < static_cast<std::size_t>(radiotap_length) + 32) {
        return;
    }

    const u8* mpdu = frame.blob.data() + radiotap_length;
    const std::size_t mpdu_size = frame.blob.size() - radiotap_length;
    const u16 frame_control = ReadU16LittleEndian(mpdu);
    const u8 frame_type = static_cast<u8>((frame_control >> 2) & 0x3);
    if (frame_type != 2 || (frame_control & 0x4000) == 0) {
        return;
    }

    ++trace_count;
    std::vector<u8> pipe_frame;
    pipe_frame.reserve(header.size() + frame.blob.size());
    pipe_frame.insert(pipe_frame.end(), header.begin(), header.end());
    pipe_frame.insert(pipe_frame.end(), frame.blob.begin(), frame.blob.end());

    const u32 radiotap_present = ReadU32LittleEndian(frame.blob.data() + 4);
    const u16 radiotap_tx_flags =
        radiotap_length >= 10 ? ReadU16LittleEndian(frame.blob.data() + 8) : 0;
    const bool protocol_length_valid =
        static_cast<std::size_t>(ReadU32LittleEndian(header.data() + 17)) == frame.blob.size();
    const bool radiotap_length_valid =
        radiotap_length == ((radiotap_tx_flags & 0x0008) != 0 ? 10 : 8);
    const bool packet_length_valid = frame.blob.size() == radiotap_length + mpdu_size;
    LOG_INFO(
        Service_NWM,
        "UDS LDND RAW TX PIPE #{}: writeSucceeded=true, protocolHeaderBytes={}, "
        "protocolOp={}, socketIdLE={}, arg0FlagsLE={}, arg1LE={}, arg2LE={}, "
        "blobLengthLE={}, blobLengthRaw={:02X}:{:02X}:{:02X}:{:02X}, "
        "radiotapLengthLE={}, radiotapPresentLE=0x{:08X}, "
        "radiotapTxFlagsLE=0x{:04X}, radiotapNoAck={}, mpduOffset={}, "
        "mpduBytes={}, frameControlLE=0x{:04X}, "
        "checks={{protocolLength:{},radiotapLength:{},packetLength:{}}}, "
        "blobFingerprint=0x{:08X}, mpduFingerprint=0x{:08X}, "
        "pipeFrameFingerprint=0x{:08X}, protocolHeader={}, blob={}, pipeFrame={}",
        trace_count, header.size(), static_cast<u32>(frame.op),
        ReadU32LittleEndian(header.data() + 1), ReadU32LittleEndian(header.data() + 5),
        ReadU32LittleEndian(header.data() + 9), ReadU32LittleEndian(header.data() + 13),
        ReadU32LittleEndian(header.data() + 17), header[17], header[18], header[19], header[20],
        radiotap_length, radiotap_present, radiotap_tx_flags,
        (radiotap_tx_flags & 0x0008) != 0, radiotap_length, mpdu_size, frame_control,
        protocol_length_valid, radiotap_length_valid, packet_length_valid,
        FingerprintBytes(frame.blob), FingerprintBytes(std::span<const u8>{mpdu, mpdu_size}),
        FingerprintBytes(pipe_frame), FormatHexBytes(header), FormatHexBytes(frame.blob),
        FormatHexBytes(pipe_frame));
}

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
    impl->next_socket_id = 0;
    impl->pending_data.clear();
    impl->deferred_data_count = 0;
    impl->raw_tx_pipe_trace_count = 0;
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
    if (impl) {
        impl->pending_data.clear();
    }
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

    // Trace after both writes have succeeded. The helper is platform-neutral so its byte parsing
    // and compile-time format checks can also be validated by non-Windows development builds.
    TraceProtectedSendToFrame(impl->raw_tx_pipe_trace_count, frame, header);
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
    for (;;) {
        LdndFrame reply = ReadFrame();
        if (reply.op == LdndOp::Data) {
            const u32 data_socket_id = reply.socket_id;
            impl->QueueData(std::move(reply));
            if (impl->deferred_data_count <= 5 || impl->deferred_data_count % 100 == 0) {
                LOG_INFO(Service_NWM,
                         "UDS Real: ldnd deferred interleaved DATA #{} for SID={} while "
                         "waiting for reply SID={}",
                         impl->deferred_data_count, data_socket_id, frame.socket_id);
            }
            continue;
        }
        if (reply.socket_id != frame.socket_id) {
            throw std::runtime_error("ldnd reply SID mismatch: expected " +
                                     std::to_string(frame.socket_id) + ", received " +
                                     std::to_string(reply.socket_id));
        }
        return reply;
    }
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
    if (auto pending = impl->TakeData(socket_id)) {
        return std::move(*pending);
    }
    for (;;) {
        LdndFrame frame = ReadFrame();
        if (frame.op == LdndOp::Data) {
            if (frame.socket_id == socket_id) {
                return std::move(frame.blob);
            }
            impl->QueueData(std::move(frame));
            continue;
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

    if (auto pending = impl->TakeData(socket_id)) {
        data = std::move(*pending);
        return true;
    }

    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(impl->pipe, nullptr, 0, nullptr, &available, nullptr)) {
            ThrowWindowsError("PeekNamedPipe(ldnd)");
        }

        if (available >= LdndProtocol::HeaderLength) {
            LdndFrame frame = ReadFrame();
            if (frame.op == LdndOp::Data) {
                if (frame.socket_id == socket_id) {
                    data = std::move(frame.blob);
                    return true;
                }
                impl->QueueData(std::move(frame));
                continue;
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
    impl->pending_data.erase(socket_id);
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
