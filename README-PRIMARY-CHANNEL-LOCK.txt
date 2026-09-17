AZAHAR UDS REAL - PRIMARY CHANNEL SCAN AND STABLE LOCK
======================================================

What the previous run proved
----------------------------

Pokemon X's retail beacon was found on channel 1:

  source=B8:AE:6E:A8:D0:10
  channel=1
  wlanCommId=0x00055D10
  id=2
  frameBytes=406

Azahar also returned that frame to the game several times with
queuedReplyCount=1. The scanner nevertheless left channel 1 whenever it saw a
1.5-second gap between accepted Nintendo beacons. Pokemon X broadcasts these
discovery beacons in bursts, so that timeout was too short.

Channel-set conclusion
----------------------

The 3DS radio and public scanning interfaces cover the wider 2.4 GHz channel
range, but the available public UDS documentation does not prove that retail
UDS host auto-selection uses every channel in that range. Our Pokemon X
captures have so far used channel 11 and channel 1. For this implementation we
therefore use the established primary Nintendo channels 1, 6, and 11 until a
real UDS capture demonstrates another host channel.

What this update changes
------------------------

* Discovery scans only channels 1, 6, and 11.
* Channel dwell remains 250 ms.
* A complete scan now takes about 750 ms instead of about 3.25 seconds.
* After finding a Nintendo beacon, the scanner stays on that channel until no
  accepted Nintendo beacon has arrived for 30 seconds.
* Every additional accepted beacon restarts that 30-second timer.
* Sweep packet-count logs now report channels 1, 6, and 11 only.

The 30-second fallback is only for discovery recovery. Once physical UDS
association is implemented, connection state will explicitly pin the radio to
the selected network's channel.

Install
-------

1. Close Azahar and Visual Studio.
2. Extract this ZIP directly into:

   E:\DS Emu\3DS\Azahar-UDS\azahar

3. Replace exactly:

   src\core\hle\service\nwm\uds_real\nl80211_monitor.cpp
   src\core\hle\service\nwm\uds_real\nl80211_monitor.h

4. Do NOT rerun CMake.
5. Open build\citra.slnx and build citra_meta in Release/x64.

Expected log
------------

  UDS Real: discovery channel hopping active, primaryChannels=1,6,11,
            dwellMs=250, foundChannelIdleTimeoutMs=30000, startingChannel=11

After discovery:

  UDS Real: Nintendo beacon found; locking discovery scanner to channel 1
            with a 30000 ms idle timeout

There should be no further sweep lines while Pokemon X continues producing at
least one accepted beacon in each 30-second window.

Test
----

Run the same retail Pokemon X Passerby test for at least 45 seconds. Please
report whether the retail trainer appears in Azahar and provide the new log.
The key result is whether queuedReplyCount=1 remains available often enough
while the scanner stays on channel 1.

