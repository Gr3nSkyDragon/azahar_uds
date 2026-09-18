Azahar UDS Real - physical guest association request
====================================================

Purpose
-------
This incremental patch fixes the retail-3DS-host direction of the physical UDS join.
After Azahar sends authentication SEQ1 and receives the retail host's SEQ2 response,
Azahar now transmits the 802.11 association request that was previously missing.

The request is based directly on the association request captured from a retail 3DS
joining an Azahar-hosted Pokemon X network. Its body contains:

  capability:       0x0431 (little-endian 31 04)
  listen interval:  1      (little-endian 01 00)
  SSID:             network_id formatted as eight uppercase hexadecimal characters
  supported rates:  82 84 8B 0C 12 96 18 24
  extended rates:   30 48 60 6C

This patch is incremental and expects the previous guest-RX-filter patch to already be
installed.

Files
-----
  src/core/hle/service/nwm/nwm_uds.cpp
  src/core/hle/service/nwm/nwm_uds.h

Installation
------------
1. Close Azahar and Visual Studio.
2. Extract this archive into the Azahar repository root (the folder containing
   CMakeLists.txt), preserving folders and replacing the two existing files.
3. Reopen the already-generated build/citra.slnx in Visual Studio.
4. Build the azahar target in Release | x64. No CMake regeneration is required.

Next test
---------
Have the retail 3DS request the trade so Azahar must join the retail-hosted UDS network.

Expected new log marker:

  UDS JOIN TRACE TX ASSOCIATION REQUEST

The body logged on that line must be exactly 30 bytes and should have this structure:

  31:04:01:00:00:08:<8 ASCII SSID bytes>:
  01:08:82:84:8B:0C:12:96:18:24:32:04:30:48:60:6C

After that marker, success at this layer is indicated by a captured physical association
response followed by TX EAPOL-START and RX EAPOL-LOGOFF/data traffic.

If it still fails, provide the complete Azahar log and note exactly which console displayed
the first error and its wording/code.
