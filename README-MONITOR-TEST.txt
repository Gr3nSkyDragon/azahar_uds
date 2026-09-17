AZAHAR UDS REAL - PHYSICAL MONITOR TEST
=======================================

Purpose
-------
This diagnostic creates an nl80211 monitor interface named udsmon0 on wiphy 0,
brings it up, tunes it to 2.4 GHz channel 11 (2462 MHz), opens an AF_PACKET raw
socket through ldnd, and captures frames for 45 seconds. It logs ordinary
802.11 beacons and flags Nintendo vendor information elements with OUI
00:1F:32. It removes udsmon0 when the test ends.

Files in this archive
---------------------
Copy the archive's src directory over the repository's src directory. This:

1. Adds:
   src/core/hle/service/nwm/uds_real/nl80211_monitor_test.h
   src/core/hle/service/nwm/uds_real/nl80211_monitor_test.cpp

2. Replaces the previously-created transport files with versions that add a
   bounded TryReceiveData method:
   src/core/hle/service/nwm/uds_real/ldnd_connection.h
   src/core/hle/service/nwm/uds_real/ldnd_connection.cpp

Required edit 1: src/core/CMakeLists.txt
----------------------------------------
In the nwm source list, immediately after these existing lines:

    hle/service/nwm/uds_real/ldnd_connection.h
    hle/service/nwm/uds_real/ldnd_protocol.h

add:

    hle/service/nwm/uds_real/nl80211_monitor_test.cpp
    hle/service/nwm/uds_real/nl80211_monitor_test.h

Keep generic_netlink.cpp and generic_netlink.h in the list. They are not being
removed yet.

Required edit 2: src/citra_qt/citra_qt.cpp
-------------------------------------------
Replace:

    #include "core/hle/service/nwm/uds_real/generic_netlink.h"

with:

    #include "core/hle/service/nwm/uds_real/nl80211_monitor_test.h"

Then replace:

    Service::NWM::UdsReal::RunNl80211StartupTest();

with:

    Service::NWM::UdsReal::RunNl80211MonitorTest();

Build
-----
Open build/citra.slnx, select Release and x64, then use Build > Build Solution.
Visual Studio's ZERO_CHECK project should notice the CMakeLists.txt change and
regenerate the project before compiling. This is an incremental build; it does
not need to recompile all of Azahar.

If Visual Studio does not regenerate, close Visual Studio and run the same
CMake configure command used to create build/citra.slnx, then reopen the .slnx.
Do not delete the build directory.

Real-radio test
---------------
1. Completely close any previous Azahar instance.
2. Start ldnd.exe and leave it running.
3. On the physical 3DS, enable wireless, start Pokemon X, remain disconnected
   from the Internet in PSS, and open or initiate a nearby/local trade.
4. Start the rebuilt Azahar. No game is needed in Azahar for this diagnostic.
5. Leave both devices running for at least 45 seconds.
6. Close Azahar only after the log says "capture complete" and
   "test completed and udsmon0 was removed".

Expected log milestones
-----------------------
Success through monitor creation:

    UDS Real MONITOR: stage=create, state=complete, interface=udsmon0, ... iftype=6
    UDS Real MONITOR: stage=radio, state=complete, channel=11, frequency=2462
    UDS Real MONITOR: capture started for 45 seconds

Proof raw capture works:

    UDS Real MONITOR: beacon=..., source=..., nintendo=false, tagTypes=none

Proof a 3DS UDS advertisement was observed:

    UDS Real MONITOR: beacon=..., source=..., nintendo=true, tagTypes=20,21,24

The tag list can vary; any nintendo=true is the important result. The final
summary reports packets, beacons, and nintendoBeacons.

Interpreting failure
--------------------
- Failure before stage=create completes: monitor-mode/interface creation issue.
- stage=radio fails: channel-setting or adapter/driver issue.
- packets=0: AF_PACKET capture/binding issue.
- packets>0 but beacons=0: radiotap/frame-format assumption needs inspection.
- beacons>0 but nintendoBeacons=0: transport works, but the 3DS may be using a
  different channel or may not be advertising. The next step is channel hopping
  across channels 1, 6, and 11.
