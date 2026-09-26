// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#pragma once

#include <string>

namespace Service::NWM::UdsReal::Esp32 {

struct DeviceStatus {
    bool attached{};   // A board with the right USB ID is present.
    bool responding{}; // It answered the HELLO handshake (only set by Probe).
    std::string port;  // e.g. "COM4"; empty where the platform does not name ports.
    std::string message; // One line for the user.
};

// Looks for the board without opening it.
DeviceStatus FindDevice();

// Opens the board and performs the HELLO handshake, so the user knows it is running the
// esp32-uds-bridge firmware. Takes up to about ten seconds; call it off the UI thread. It cannot
// succeed while an emulated game is using the port.
DeviceStatus Probe();

} // namespace Service::NWM::UdsReal::Esp32
