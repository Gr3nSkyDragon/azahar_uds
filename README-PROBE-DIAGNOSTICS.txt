Azahar UDS Real - Pokemon X probe diagnostics
================================================

Purpose
-------
The retail 3DS -> Azahar receive path is now working. This overlay diagnoses the
missing reverse direction used by Pokemon X's PSS discovery/trade-request flow.
It does not transmit the emulator's PSS presence yet.

Files replaced
--------------
src/core/hle/service/nwm/nwm_uds.cpp
src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp

Installation
------------
1. Close Visual Studio and Azahar.
2. Extract this ZIP directly into the Azahar repository root:
   E:\DS Emu\3DS\Azahar-UDS\azahar
3. Windows should ask to merge the src folder and replace the two files above.
4. Reopen build\citra.slnx in Visual Studio.
5. Select Release and x64, then build citra_meta.

No CMake regeneration is required because this overlay only replaces source
files that are already in the generated Visual Studio project.

Test procedure
--------------
1. Start ldnd.exe.
2. Start Pokemon X in the newly built Azahar.
3. Keep the retail 3DS running Pokemon X with PSS active.
4. Wait for the retail trainer to appear in Azahar.
5. Select the retail trainer and request a trade, then leave the request active
   for roughly 15 seconds.
6. Close Azahar cleanly and provide azahar_log.txt.

Useful new log lines
--------------------
UDS Real: captured relevant probe request ...
UDS Real: captured relevant probe response ...
UDS Real: SetProbeResponseParam ... (bytes=...)
UDS Real: stopping physical beacon monitor ... probeFrames=... relevantProbeFrames=...

These lines will reveal whether the retail unit sends a Nintendo vendor-specific
probe request, a probe response, or another probe frame from the same MAC as its
working UDS beacon. That determines the exact management frame Azahar must inject
through ldnd in the next implementation step.
