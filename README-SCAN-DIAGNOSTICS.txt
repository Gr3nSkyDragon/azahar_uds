AZAHAR UDS REAL - POKEMON X SCAN DIAGNOSTICS
=============================================

What this update changes
------------------------

1. Implements NWM command 0x21 (SetProbeResponseParam) as an explicit
   success handler and records the values supplied by Pokemon X.
2. Implements the still-undocumented, zero-argument NWM command 0x23 as an
   explicit success handler. This preserves Azahar's previous fallback
   behavior while removing the misleading unimplemented-function error.
3. Adds Info-level logging to RecvBeaconBroadcastData. The log now shows the
   scan filter requested by Pokemon X and whether Azahar actually returned a
   captured retail beacon to the game.

Important: Azahar's generic unimplemented-function fallback already returned
success. These handlers clean up and identify the calls, but the new scan log
is the part that will locate the actual discovery failure.

Install
-------

1. Close Azahar and Visual Studio.
2. Extract this ZIP directly into:

   E:\DS Emu\3DS\Azahar-UDS\azahar

3. Windows should ask to replace exactly these two existing files:

   src\core\hle\service\nwm\nwm_uds.cpp
   src\core\hle\service\nwm\nwm_uds.h

4. Accept both replacements.

Build
-----

Do NOT rerun CMake for this update. No source files were added and no CMake
list changed.

1. Open build\citra.slnx in Visual Studio.
2. Select Release and x64.
3. Build the citra_meta project (Build > Build citra_meta).
4. Run Azahar from Visual Studio as before.

Test
----

1. Start ldnd.exe with the same administrator setup that passed the monitor
   test.
2. Put the retail 3DS and Pokemon X on the PSS screen with wireless enabled.
3. Start Pokemon X in the rebuilt Azahar.
4. Open Passerby and leave both systems there for at least 30 seconds.
5. Close the emulation cleanly and send the new azahar_log.txt.

Expected new log lines
----------------------

UDS Real: SetProbeResponseParam accepted ...
UDS Real: undocumented nwm::UDS command 0x23 accepted
UDS Real: game beacon scan #..., filterMac=..., wlanCommId=..., id=...,
          queuedReplyCount=..., firstFrameBytes=..., outputCapacity=...

The old red errors for SetProbeResponseParam and command 0x23 should be gone.

How to read the result
----------------------

* If the monitor reports "delivered Nintendo beacon" but every later game
  scan has queuedReplyCount=0, the problem is the scan/MAC selection path.
* If a game scan has queuedReplyCount=1 and firstFrameBytes=406, Azahar passed
  the retail beacon into Pokemon X. If the trainer is still absent, the next
  fix belongs in beacon validation/normalization or the PSS-specific payload
  path.
* The captured retail beacon in the prior test used wlanCommId=0x00055D10 and
  id=2. The new game-scan lines will show whether Pokemon X requests the same
  pair.

