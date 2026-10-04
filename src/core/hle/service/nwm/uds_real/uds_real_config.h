// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#pragma once

#include "common/settings.h"

// The "UDS Real" physical backend bridges nwm::UDS to a real 802.11 radio. Two radios exist:
//  - a USB Wi-Fi adapter driven through ldnd.exe (Windows only, the default there), and
//  - an ESP32-S3 running firmware/esp32-uds-bridge over USB, selected by the use_esp32_uds setting.
// Android has only the ESP32. On Windows the ESP32 is chosen in Configure > General > Network.
// Other platforms have no backend.
#if defined(_WIN32) || defined(ANDROID)
#define UDS_REAL_BACKEND 1
#else
#define UDS_REAL_BACKEND 0
#endif

namespace Service::NWM::UdsReal {

inline bool IsPhysicalBackendEnabled() {
#if defined(ANDROID)
    return Settings::values.use_esp32_uds.GetValue();
#else
    return true;
#endif
}

} // namespace Service::NWM::UdsReal
