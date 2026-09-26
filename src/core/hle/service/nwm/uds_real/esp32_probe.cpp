// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#include <array>
#include <chrono>
#include <optional>

#include "core/hle/service/nwm/uds_real/esp32_probe.h"
#include "core/hle/service/nwm/uds_real/esp32_serial.h"
#include "core/hle/service/nwm/uds_real/esp32_wire.h"

namespace Service::NWM::UdsReal::Esp32 {

DeviceStatus FindDevice() {
    DeviceStatus status;
    if (const auto port = FindDevicePort()) {
        status.attached = true;
        status.port = *port;
        status.message = "ESP32 detected on " + *port + ".";
    } else {
        status.message =
            "No ESP32 found. Connect the board's native USB port (the one that appears as "
            "an Espressif USB Serial/JTAG device).";
    }
    return status;
}

DeviceStatus Probe() {
    DeviceStatus status = FindDevice();
    if (!status.attached) {
        return status;
    }
    auto port = OpenSerialPort();
    if (!port) {
        status.message = "ESP32 detected on " + status.port +
                         " but it could not be opened. Is Azahar (or another program) already "
                         "using it?";
        return status;
    }

    // Opening the port can reset the chip, so keep asking until it answers.
    Decoder decoder;
    std::optional<Frame> ack;
    u8 sequence = 1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!ack && std::chrono::steady_clock::now() < deadline) {
        const std::vector<u8> hello = Encode(Type::Hello, sequence++, 0, {});
        if (!port->Write(hello)) {
            status.message = "Lost the connection to the ESP32 while talking to it.";
            return status;
        }
        const auto attempt_end = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (!ack && std::chrono::steady_clock::now() < attempt_end) {
            std::array<u8, 512> buffer;
            const int count = port->Read(buffer, 50);
            if (count < 0) {
                status.message = "Lost the connection to the ESP32 while talking to it.";
                return status;
            }
            if (count > 0) {
                decoder.Feed(std::span<const u8>{buffer.data(), static_cast<std::size_t>(count)},
                             [&](Frame&& frame) {
                                 if (frame.type == Type::HelloAck) {
                                     ack = std::move(frame);
                                 }
                             });
            }
        }
    }
    if (!ack || ack->payload.size() < 3) {
        status.message = "Something is on " + status.port +
                         " but it did not answer. Is the esp32-uds-bridge firmware flashed?";
        return status;
    }
    status.responding = true;
    status.message = "Connected: ESP32 on " + status.port + ", firmware " +
                     std::to_string(ack->payload[1]) + "." + std::to_string(ack->payload[2]) + ".";
    return status;
}

} // namespace Service::NWM::UdsReal::Esp32
