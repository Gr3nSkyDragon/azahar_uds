Azahar UDS Real - active probe request test
===========================================

Result that led to this test
----------------------------
The previous run captured 187 ordinary probe frames, but zero Nintendo probe
frames and zero probe frames from the retail beacon's MAC address. Pokemon X
continued changing SetProbeResponseParam between Nintendo vendor payload values
02:00 and 04:00. This indicates the retail system is waiting for Azahar to
advertise rather than initiating the exchange through a detectable probe frame.

Purpose
-------
This build transmits a standard wildcard 802.11 probe request once per second
after the scanner has found the retail Nintendo beacon and locked onto its
channel. The expected result is a real probe response from the retail 3DS. The
existing diagnostics will log its MAC addresses, SSID, Nintendo OUI type, and
Nintendo vendor data so the next implementation can reproduce the exact frame.

This is still a diagnostic test. It does not yet advertise Azahar's trainer to
the retail 3DS.

File replaced
-------------
src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp

Installation
------------
1. Close Visual Studio and Azahar.
2. Extract this ZIP directly into the Azahar repository root:
   E:\DS Emu\3DS\Azahar-UDS\azahar
3. Windows should merge the src folder and replace the one file above.
4. Reopen build\citra.slnx in Visual Studio.
5. Select Release and x64, then build citra_meta.

No CMake regeneration is required.

Test procedure
--------------
1. Start ldnd.exe.
2. Start Pokemon X in Azahar and on the retail 3DS, with PSS active.
3. Wait until Azahar displays the retail trainer.
4. Leave both systems on PSS for at least 10 seconds.
5. Select the retail trainer in Azahar and request a trade.
6. Leave the request active for another 15 seconds.
7. Close Azahar cleanly and provide azahar_log.txt.

Important log lines
-------------------
UDS Real: transmitted active probe request ...
UDS Real: captured relevant probe response ...
UDS Real: captured relevant probe request ...
UDS Real: stopping physical beacon monitor ... transmittedProbes=...

If transmittedProbes is nonzero but no relevant response appears, the Wi-Fi
driver may require a different radiotap transmit header or the retail 3DS may
only answer a Nintendo-specific probe request. Either outcome narrows the next
change substantially.
