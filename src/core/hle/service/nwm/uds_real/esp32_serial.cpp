// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#include <mutex>

#include "core/hle/service/nwm/uds_real/esp32_serial.h"

#ifdef _WIN32
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>
#include <windows.h>
#include <setupapi.h>

#include "common/logging/log.h"
#endif

namespace Service::NWM::UdsReal::Esp32 {
namespace {
std::mutex factory_mutex;
SerialFactory serial_factory;

#ifdef _WIN32
// Espressif USB Serial/JTAG: the native USB port of an ESP32-S3.
constexpr const char* DeviceHardwareId = "VID_303A&PID_1001";

class WindowsSerialPort final : public SerialPort {
public:
    explicit WindowsSerialPort(HANDLE handle) : handle{handle} {}

    ~WindowsSerialPort() override {
        CloseHandle(handle);
    }

    int Read(std::span<u8> buffer, int timeout_ms) override {
        if (timeout_ms != applied_timeout_ms) {
            // MAXDWORD interval + MAXDWORD multiplier + constant: return at once if bytes are
            // waiting, otherwise wait up to the constant for the first byte.
            COMMTIMEOUTS timeouts{};
            timeouts.ReadIntervalTimeout = MAXDWORD;
            timeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
            timeouts.ReadTotalTimeoutConstant = static_cast<DWORD>(std::max(timeout_ms, 1));
            timeouts.WriteTotalTimeoutConstant = 2000;
            if (!SetCommTimeouts(handle, &timeouts)) {
                return -1;
            }
            applied_timeout_ms = timeout_ms;
        }
        DWORD read = 0;
        if (!ReadFile(handle, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            return -1; // Unplugged or closed.
        }
        return static_cast<int>(read);
    }

    bool Write(std::span<const u8> data) override {
        std::size_t sent = 0;
        while (sent < data.size()) {
            DWORD written = 0;
            if (!WriteFile(handle, data.data() + sent, static_cast<DWORD>(data.size() - sent),
                           &written, nullptr) ||
                written == 0) {
                return false;
            }
            sent += written;
        }
        return true;
    }

private:
    HANDLE handle;
    int applied_timeout_ms{-1};
};

bool ContainsIgnoreCase(const std::string& haystack, const std::string& needle) {
    const auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                                [](char a, char b) {
                                    return std::toupper(static_cast<unsigned char>(a)) ==
                                           std::toupper(static_cast<unsigned char>(b));
                                });
    return it != haystack.end();
}

std::unique_ptr<SerialPort> OpenWindowsSerialPort() {
    const std::optional<std::string> port_name = FindDevicePort();
    if (!port_name) {
        return nullptr;
    }
    const std::string path = R"(\\.\)" + *port_name;
    const HANDLE handle = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                      OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        LOG_WARNING(Service_NWM, "UDS Real ESP32: cannot open {} (error {}); is another program "
                                 "using it?",
                    *port_name, GetLastError());
        return nullptr;
    }
    SetupComm(handle, 65536, 65536);
    DCB dcb{};
    dcb.DCBlength = sizeof(dcb);
    if (GetCommState(handle, &dcb)) {
        dcb.BaudRate = 921600;
        dcb.ByteSize = 8;
        dcb.Parity = NOPARITY;
        dcb.StopBits = ONESTOPBIT;
        dcb.fBinary = TRUE;
        dcb.fParity = FALSE;
        dcb.fOutxCtsFlow = FALSE;
        dcb.fOutxDsrFlow = FALSE;
        dcb.fDsrSensitivity = FALSE;
        dcb.fOutX = FALSE;
        dcb.fInX = FALSE;
        dcb.fDtrControl = DTR_CONTROL_ENABLE;  // DTR on, RTS off: the chip's normal run state.
        dcb.fRtsControl = RTS_CONTROL_DISABLE;
        SetCommState(handle, &dcb);
    }
    EscapeCommFunction(handle, SETDTR);
    EscapeCommFunction(handle, CLRRTS);
    PurgeComm(handle, PURGE_RXCLEAR | PURGE_TXCLEAR);
    return std::make_unique<WindowsSerialPort>(handle);
}
#endif // _WIN32

} // namespace

void SetSerialFactory(SerialFactory factory) {
    std::scoped_lock lock{factory_mutex};
    serial_factory = std::move(factory);
}

std::unique_ptr<SerialPort> OpenSerialPort() {
    SerialFactory factory;
    {
        std::scoped_lock lock{factory_mutex};
        factory = serial_factory;
    }
    if (factory) {
        return factory();
    }
#ifdef _WIN32
    return OpenWindowsSerialPort();
#else
    return nullptr;
#endif
}

std::optional<std::string> FindDevicePort() {
#ifdef _WIN32
    GUID ports_class{};
    DWORD class_count = 0;
    if (!SetupDiClassGuidsFromNameA("Ports", &ports_class, 1, &class_count) || class_count == 0) {
        return std::nullopt;
    }
    const HDEVINFO devices = SetupDiGetClassDevsA(&ports_class, nullptr, nullptr, DIGCF_PRESENT);
    if (devices == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    std::optional<std::string> result;
    for (DWORD index = 0; !result; ++index) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!SetupDiEnumDeviceInfo(devices, index, &info)) {
            break;
        }
        // The hardware IDs are a REG_MULTI_SZ, e.g. "USB\VID_303A&PID_1001&MI_00".
        std::vector<char> ids(1024, 0);
        if (!SetupDiGetDeviceRegistryPropertyA(devices, &info, SPDRP_HARDWAREID, nullptr,
                                               reinterpret_cast<PBYTE>(ids.data()),
                                               static_cast<DWORD>(ids.size() - 2), nullptr)) {
            continue;
        }
        bool matches = false;
        for (const char* id = ids.data(); *id != '\0'; id += std::strlen(id) + 1) {
            if (ContainsIgnoreCase(id, DeviceHardwareId)) {
                matches = true;
                break;
            }
        }
        if (!matches) {
            continue;
        }
        const HKEY key = SetupDiOpenDevRegKey(devices, &info, DICS_FLAG_GLOBAL, 0, DIREG_DEV,
                                              KEY_READ);
        if (key == INVALID_HANDLE_VALUE) {
            continue;
        }
        char name[64]{};
        DWORD size = sizeof(name) - 1;
        DWORD type = 0;
        if (RegQueryValueExA(key, "PortName", nullptr, &type, reinterpret_cast<LPBYTE>(name),
                             &size) == ERROR_SUCCESS &&
            type == REG_SZ && std::strncmp(name, "COM", 3) == 0) {
            result = std::string{name};
        }
        RegCloseKey(key);
    }
    SetupDiDestroyDeviceInfoList(devices);
    return result;
#else
    return std::nullopt;
#endif
}

} // namespace Service::NWM::UdsReal::Esp32
