Azahar UDS retail no-DS broadcast crash fix
============================================

What this fixes
---------------
The retail 3DS joins Azahar successfully, then sends a protected broadcast data
frame with both 802.11 ToDS and FromDS cleared. Azahar previously asserted in
GenerateCCMPAAD because it only accepted infrastructure-style data frames.

Files to replace
----------------
Copy this package into the root of the Azahar source tree and allow Windows to
merge the src directory and replace these existing files:

  src/core/hle/service/nwm/uds_data.cpp
  src/core/hle/service/nwm/nwm_uds.cpp
  src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp

Build
-----
The files are already part of the generated Visual Studio project. Do not rerun
CMake. Close Azahar, select the Release and x64 configuration in Visual Studio,
then use Build > Build Solution. Run the newly built azahar.exe under the
debugger for the next test.

Expected next-run evidence
--------------------------
The physical RX log for a broadcast data frame should show:

  protected=true, toDS=false, fromDS=false

It should no longer be followed by the GenerateCCMPAAD assertion. A successful
decrypt will be followed by "delivering physical frame". If authentication is
still wrong, Azahar will log "CCMP authentication failed" without crashing.
