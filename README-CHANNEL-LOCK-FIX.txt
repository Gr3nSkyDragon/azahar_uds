Azahar UDS active-peer channel lock fix
=======================================

What this fixes
---------------
After a retail 3DS authenticated on channel 6, the monitor continued hopping
between channels 1, 6, and 11. Azahar therefore missed most of the client's
protected traffic and transmitted host beacons on the wrong channels until the
retail console deauthenticated.

File to replace
---------------
Copy this package into the root of the Azahar source tree and allow Windows to
merge the src directory and replace this existing file:

  src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp

Build
-----
Do not rerun CMake. Close Azahar, select Release and x64 in Visual Studio, and
use Build > Build Solution. Run the rebuilt azahar.exe under the debugger.

Expected next-run evidence
--------------------------
After the first authentication or other relevant peer frame, the log should
contain:

  UDS Real: active peer traffic found; locking radio to channel 6 while the peer remains active

There should be no further "discovery sweep" messages during that connection,
and subsequent physical RX, physical TX, and transmitted beacon messages should
all remain on channel 6.
