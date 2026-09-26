// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include "common/common_types.h"

namespace Service::NWM::UdsReal::Esp32 {

// The byte pipe to the ESP32 (a USB CDC-ACM serial port). The core never opens USB itself: the
// host application installs a factory, which on Android is backed by the Kotlin UsbLink through
// JNI. All calls are made from the monitor's worker thread, never from the emulation thread.
class SerialPort {
public:
    virtual ~SerialPort() = default;

    // Reads up to buffer.size() bytes, waiting at most timeout_ms for the first one. Returns the
    // byte count, 0 on timeout, or -1 if the link failed (unplugged, closed).
    virtual int Read(std::span<u8> buffer, int timeout_ms) = 0;
    virtual bool Write(std::span<const u8> data) = 0;
};

using SerialFactory = std::function<std::unique_ptr<SerialPort>()>;

// Installs (or clears, with an empty function) the factory used to open the ESP32. The factory
// returns null when no board is attached or USB permission is missing. Without a factory, Windows
// finds the board by its USB ID and opens its COM port; other platforms have no built-in port.
void SetSerialFactory(SerialFactory factory);
std::unique_ptr<SerialPort> OpenSerialPort();

// Windows only: the COM port of an attached ESP32-S3 (Espressif USB Serial/JTAG, 303A:1001),
// e.g. "COM4", found without opening it. nullopt if none is attached (always so elsewhere).
std::optional<std::string> FindDevicePort();

} // namespace Service::NWM::UdsReal::Esp32
