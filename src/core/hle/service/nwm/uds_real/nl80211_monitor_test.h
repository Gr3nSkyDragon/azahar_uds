// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#pragma once

namespace Service::NWM::UdsReal {

// Temporary physical-radio diagnostic. Creates an nl80211 monitor interface on
// channel 11 and records 802.11 beacon frames for 45 seconds.
void RunNl80211MonitorTest();

} // namespace Service::NWM::UdsReal
