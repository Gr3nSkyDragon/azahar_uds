// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version

#pragma once

namespace Service::NWM::UdsReal {

// Temporary no-game diagnostic: resolves the nl80211 generic-netlink family and
// enumerates the interfaces currently exposed by ldnd's Linux kernel.
void RunNl80211StartupTest();

} // namespace Service::NWM::UdsReal
