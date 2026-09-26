// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#pragma once

#include "common/settings.h"

// The "UDS Real" physical backend bridges nwm::UDS to a real 802.11 radio. On Windows the radio is
// a USB Wi-Fi adapter driven through ldnd.exe. On Android it is an ESP32-S3 running
// firmware/esp32-uds-bridge over USB, enabled by a setting. Other platforms have no backend.
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
