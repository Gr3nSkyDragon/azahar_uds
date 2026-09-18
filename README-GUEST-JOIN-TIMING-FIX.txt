Azahar UDS Real - guest join timing and retry fix
================================================

Purpose
-------
The 2026-09-18 10:02:33 Pokemon X test proved that the new physical association
request was valid. The retail host answered it in about 6 ms and Azahar completed
EAPOL, but ConnectToNetwork had already returned Timeout roughly 31 ms earlier.
Pokemon therefore tore down a physically successful join.

This incremental patch:

1. Uses the selected retail beacon's advertised channel immediately when
   ConnectToNetwork begins. A channel request made while udsmon0 is starting is
   retained and applied before queued authentication frames are transmitted.
2. Updates nwm::UDS network_channel to the selected network's actual channel.
3. Extends the IPC connection timeout from 5 seconds to 15 seconds, providing
   margin for ldnd/monitor-interface startup.
4. Handles only the first association response for each connection. Retry copies
   no longer generate a burst of duplicate EAPOL-START packets.

Prerequisite
------------
The previous physical-guest-association patch must already be installed.

Files
-----
  src/core/hle/service/nwm/nwm_uds.cpp
  src/core/hle/service/nwm/nwm_uds.h
  src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp
  src/core/hle/service/nwm/uds_real/nl80211_monitor.h

Installation
------------
1. Close Azahar and Visual Studio.
2. Extract this archive into the Azahar repository root (the directory containing
   CMakeLists.txt), preserving folders and replacing all four files.
3. Reopen build/citra.slnx.
4. Build the azahar target in Release | x64.

No CMake regeneration is required.

Next test
---------
Have the retail 3DS request the trade again.

Expected order:

  UDS Real: tuned directly to selected peer channel 6 ...
  UDS MANAGEMENT TRACE TX ... subtype=11 ... channel=6
  UDS JOIN TRACE TX ASSOCIATION REQUEST ... channel=6
  one UDS JOIN TRACE TX EAPOL MPDU
  UDS STATE TRACE ... status=9, reason=1
  connection sequence finished

There must be no "timed out when trying to connect to UDS server" before status=9.
After status=9, Pokemon should remain on the trade-initialization screen and begin
normal channel 3/243 application traffic instead of immediately returning to the
field.

Provide the complete Azahar log after the run and note which device reports the
first visible failure, its exact wording/code, and the approximate timestamp.
