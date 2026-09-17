AZAHAR UDS REAL - DISCOVERY CHANNEL HOPPING
===========================================

Why this update is needed
-------------------------

The previous Pokemon X run proved that the game requested the correct network:

  filterMac=FF:FF:FF:FF:FF:FF
  wlanCommId=0x00055D10
  id=255 (wildcard)

However, the monitor stopped with:

  packets=31878, deliveredBeacons=0

This means queuedReplyCount=0 was correct: no Nintendo beacon reached the
Azahar queue. The adapter was receiving ordinary Wi-Fi traffic on channel 11,
but the retail 3DS was not broadcasting its Pokemon beacon there during this
run.

What this update changes
------------------------

* Starts discovery on Azahar's requested channel (currently channel 11).
* Scans 2.4 GHz channels 1 through 13 with a 250 ms dwell per channel.
* Skips a channel if the adapter/regulatory domain rejects it, rather than
  stopping the monitor.
* When a Nintendo beacon is found, holds the adapter on that channel while the
  beacon remains active.
* Resumes scanning if Nintendo beacons disappear for 1.5 seconds.
* Logs completed sweeps and cumulative raw packet counts by channel.

This is discovery behavior only. When physical association is implemented,
the radio will need to remain locked to the selected host's channel for the
active connection.

Install
-------

1. Close Azahar and Visual Studio.
2. Extract this ZIP directly into:

   E:\DS Emu\3DS\Azahar-UDS\azahar

3. Confirm replacement of exactly these two existing files:

   src\core\hle\service\nwm\uds_real\nl80211_monitor.cpp
   src\core\hle\service\nwm\uds_real\nl80211_monitor.h

4. Accept both replacements.

Build
-----

Do NOT rerun CMake. These files are already part of the generated Visual
Studio solution.

1. Open build\citra.slnx.
2. Select Release and x64.
3. Build citra_meta.
4. Run Azahar from Visual Studio as before.

Test
----

1. Start ldnd.exe with administrator privileges using the same setup as the
   previous tests.
2. Start Pokemon X on the retail 3DS and leave it on the active PSS screen.
3. Start Pokemon X in Azahar and open Passerby.
4. Wait at least 30 seconds. One complete 13-channel sweep takes roughly
   3.25 seconds, excluding small channel-change overhead.
5. Close emulation cleanly and send the new azahar_log.txt.

Expected logs
-------------

At startup:

  UDS Real: discovery channel hopping active, channels=1-13, dwellMs=250 ...

While no Nintendo beacon is found:

  UDS Real: discovery sweep #... complete, rawPacketsByChannel=[...]

On success:

  UDS Real: Nintendo beacon found; holding discovery scanner on channel ...
  UDS Real: delivered Nintendo beacon #1 ... wlanCommId=0x00055D10, id=2 ...
  UDS Real: game beacon scan #... queuedReplyCount=1, firstFrameBytes=406 ...

If deliveredBeacons remains zero after multiple completed sweeps, channel
selection has been ruled out and the next diagnostic should count frame
subtypes and Nintendo OUI tags before the strict beacon parser.

