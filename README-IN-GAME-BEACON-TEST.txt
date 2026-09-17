AZAHAR UDS REAL - IN-GAME BEACON DISCOVERY TEST
===============================================

What this batch does
--------------------
- Replaces the temporary 45-second GUI-startup diagnostic with a persistent
  monitor owned by nwm::UDS.
- Starts the monitor when a game initializes the 3DS UDS service.
- Listens on the game's current UDS channel (channel 11 initially).
- Accepts only beacon frames containing Nintendo NetworkInfo tag 21.
- Removes radiotap and an indicated trailing FCS before giving the frame to
  Azahar.
- Places the physical beacon in Azahar's existing received_beacons queue so the
  guest receives it through RecvBeaconBroadcastData.
- Stops the worker and removes udsmon0 when nwm::UDS shuts down.

Install
-------
1. Close Azahar and Visual Studio.
2. Extract this archive into the main Azahar repository folder, for example:

       E:\DS Emu\3DS\Azahar-UDS\azahar

3. Merge the src folder and approve replacement of:

       src\core\CMakeLists.txt
       src\core\hle\service\nwm\nwm_uds.cpp
       src\core\hle\service\nwm\nwm_uds.h
       src\citra_qt\citra_qt.cpp

   These are the two new files and should not prompt for replacement:

       src\core\hle\service\nwm\uds_real\nl80211_monitor.cpp
       src\core\hle\service\nwm\uds_real\nl80211_monitor.h

4. The old nl80211_monitor_test.cpp and nl80211_monitor_test.h files may remain
   in uds_real, but CMake no longer compiles them.

5. Regenerate the Visual Studio projects:

       cmake -S . -B build

6. Reopen build\citra.slnx, select Release and x64, and build. This should be an
   incremental build.

Test
----
1. Start ldnd.exe.
2. On the physical 3DS, enable wireless, start Pokemon X, remain disconnected
   from the Internet in PSS, and leave the PSS visible in the overworld.
3. Start the rebuilt Azahar and boot Pokemon X.
4. Watch the Azahar log. The monitor now starts when Pokemon X initializes
   nwm::UDS, not when the Azahar window opens.

Expected transport log
----------------------

    UDS Real: physical beacon monitor requested by nwm::UDS
    UDS Real: starting physical beacon monitor, channel=11, frequency=2462
    UDS Real: physical beacon monitor ready, interface=udsmon0, ... channel=11
    UDS Real: delivered Nintendo beacon #1, source=B8:AE:6E:A8:D0:10, ...

The delivered-beacon line also prints wlanCommId and id parsed from the Nintendo
NetworkInfo tag. These values will help verify that the beacon belongs to the
Pokemon X discovery session.

Expected in-game result
-----------------------
The physical 3DS should appear in Pokemon X running in Azahar as a nearby PSS
Passerby. This batch implements receive-side beacon discovery only. The physical
3DS is not expected to see the Azahar trainer yet, and selecting Trade is not
expected to complete a connection yet.

If transport logs show delivered beacons but the trainer does not appear, send
the complete Azahar log. The next diagnostic will compare Pokemon X's requested
wlan_comm_id/id with the values extracted from the physical beacon and verify
the exact frame length returned through RecvBeaconBroadcastData.

Channel hopping later
---------------------
The monitor takes a channel argument and supports 2.4 GHz channels 1-14. A later
scan coordinator can hop channels while disconnected. Once a host is selected,
the radio must stay locked to that host's channel during authentication and data
exchange.
