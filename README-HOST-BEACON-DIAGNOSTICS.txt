Azahar UDS Real - Pokemon X host/beacon diagnostics
====================================================

What this package changes
-------------------------
This package replaces exactly two existing Azahar source files:

  src\core\hle\service\nwm\nwm_uds.cpp
  src\core\hle\service\nwm\nwm_uds.h

It does not add a new compilation unit, so you do NOT need to rerun CMake.
The existing directed-probe experiment is left enabled and unchanged.

Install
-------
1. Close Azahar and stop debugging in Visual Studio.
2. Extract this ZIP into the root of your Azahar checkout, for example:

     E:\DS Emu\3DS\Azahar-UDS\azahar

3. Windows should ask to replace two files. Approve both replacements.
4. In Visual Studio select Release and x64.
5. Build the citra_meta project (or Build Solution), then run azahar.exe.

Test
----
1. Start ldnd.exe as before.
2. Start Pokemon X in Azahar and on the retail 3DS.
3. Leave both systems on the PSS screen for at least 20 seconds.
4. Record whether the retail trainer appears in Azahar.
5. If it appears, select it and request a trade. Wait another 15 seconds.
6. Close Azahar normally and send the complete azahar_log.txt.

Important new log messages
--------------------------
  UDS Real: retail beacon payload ...

    Fingerprints the retail 3DS application data and decoded node data. This lets
    us compare a successful-visibility run with a failed-visibility run without
    dumping trainer names or the complete Pokemon payload into the log.

  UDS Real: BeginHostingNetwork ...

    Confirms Pokemon X asked Azahar to create its own UDS network/presence.

  UDS Real: internal beacon generation ...

    Confirms Azahar is generating its own Nintendo beacon body internally. The
    message explicitly notes that physical transmission is not implemented yet.

How to interpret the next run
-----------------------------
* If BeginHostingNetwork and internal beacon generation appear, the next change
  should transmit those generated beacons through the physical wireless adapter.
* If neither appears, Pokemon's outgoing PSS presence uses another command/path,
  so we should instrument that path before writing a transmitter.
* If retail beacon fingerprints differ between visible and invisible runs, PSS
  is likely classifying application payload state. If they remain the same, the
  intermittent visibility is more likely timing or game-side caching.

Scope
-----
This build adds diagnostics only. It does not claim to make the Azahar trainer
or trade request visible on the retail 3DS yet.
