Azahar UDS Real - retail-host guest receive-filter fix
=====================================================

Purpose
-------
This test fixes a directional receive bug exposed when the retail 3DS requests the trade and
therefore hosts the subsequent UDS network.

Previously, nl80211_monitor.cpp delivered non-beacon frames only while Azahar had generated a
physical beacon of its own. Azahar does not generate a beacon while joining a retail-hosted
network, so every possible retail authentication response was discarded before nwm::UDS could
process it. The failed run therefore showed five transmitted authentication requests,
deliveredFrames=0, no association/EAPOL/data traffic, and a connection timeout.

Changes
-------
* Pass Azahar's local console MAC to the physical monitor when it starts.
* Accept non-beacon traffic addressed to the local MAC, using the local MAC as BSSID, or using
  the discovered Nintendo host as BSSID.
* Continue suppressing Azahar's own transmitted echoes.
* Preserve the complete received MPDU in CapturedFrame.
* Log complete management TX MPDUs and complete relevant RX MPDUs, including addresses,
  sequence control, length, fingerprint, and raw bytes.

Files
-----
src/core/hle/service/nwm/nwm_uds.cpp
src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp
src/core/hle/service/nwm/uds_real/nl80211_monitor.h

Build
-----
These files do not add or remove CMake sources. If the current Visual Studio solution already
contains the UDS Real transport, replace the files and build the existing azahar project in the
Release configuration. Do not rerun CMake solely for this patch.

Test direction
--------------
1. Start ldnd.exe and the newly built Azahar.
2. Let the retail 3DS request the trade.
3. Accept once in Azahar and save once.
4. Do not click either trainer again while the connection initializes.
5. Wait for both sides to succeed or report failure, then close Azahar and provide azahar_log.txt.

Important log markers
---------------------
UDS MANAGEMENT TRACE TX
UDS Real: physical RX
subtype=11 (authentication)
subtype=1  (association response)
UDS JOIN TRACE
UDS DATA TRACE

Expected immediate improvement
------------------------------
The next run should no longer end with deliveredFrames=0 merely because Azahar is the guest.
At minimum, a retail authentication response addressed to Azahar should be logged and delivered.
The response may expose a separate missing association-request step; the raw trace is included so
that step can be implemented from observed protocol data instead of guessed fields.
