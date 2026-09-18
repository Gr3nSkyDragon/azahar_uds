Azahar UDS Real - active monitor hardware-ACK test
==================================================

Purpose
-------
This test keeps the known-working monitor-only UDS/CCMP transport and adds only the Linux
active-monitor behavior needed for hardware 802.11 acknowledgements. It does not re-enable
udsap0, the kernel AP data carrier, or kernel CCMP.

Changed file
------------
src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp

Installation
------------
Extract this ZIP directly into the main Azahar repository folder: the folder that already
contains CMakeLists.txt and src. Windows should ask to merge src and replace one existing file.

No CMake regeneration is required because this patch replaces an existing source file and adds
no build targets. Open the existing build/citra.slnx in Visual Studio and build the same Release
x64 azahar project/configuration used for the previous successful test.

Test procedure
--------------
1. Start ldnd.exe with the RTL8822BU adapter available.
2. Start the newly built Azahar executable.
3. Load Pokemon X and wait for the retail trainer to appear.
4. Request and accept a trade exactly as in the successful monitor-only baseline.
5. Let the test continue until either the trade advances, communication fails, or at least
   45 seconds have passed after the retail console accepts.
6. Save the complete Azahar log. Also copy any rtw88/ldnd warnings shown during the attempt.

Required startup markers
------------------------
The log must contain:

  UDS Real: active-monitor ACK test enabled; kernel AP creation and data carrier remain disabled

The preferred success path also contains:

  UDS Real: NL80211_MNTR_FLAG_ACTIVE accepted; hardware ACK mode requested
  UDS Real: active monitor MAC configured before interface start
  activeMonitor=true, activeAckReady=true

If the adapter/driver rejects active monitor mode, the log instead contains:

  UDS Real: active monitor creation failed; falling back to passive monitor mode

That fallback is intentional and preserves the previous monitor-only behavior.

What to compare
---------------
Physical RX lines now include retry, sequence, and fragment fields. In the previous baseline,
the retail 3DS repeated authentication/association frames and many protected management frames
several times because it did not receive a timely 802.11 ACK.

The important questions for this test are:

* Are activeMonitor and activeAckReady both true?
* Do repeated frames with the same sequence number disappear or drop sharply?
* Does retryFrames remain low relative to deliveredFrames in the shutdown summary?
* Does the session remain connected beyond the previous approximately 23.8-second lifetime?
* Does ldnd.exe still print "failed to get tx report from firmware"?

Rollback
--------
Re-extract azahar-uds-monitor-only-rollback.zip into the main Azahar repository folder and
rebuild in Visual Studio. That restores the exact source used for the successful communication-
failure baseline.
