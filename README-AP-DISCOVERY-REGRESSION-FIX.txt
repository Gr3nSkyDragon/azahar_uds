Azahar UDS AP discovery regression fix
=======================================

Cause confirmed by the failed run
---------------------------------
The AP test created udsap0 and immediately brought it UP while Pokemon's PSS
was still doing discovery. On this adapter/driver, an UP AP interface reserves
the shared radio even before START_AP. Every subsequent monitor channel change
failed with Linux error -16 (EBUSY), and the discovery worker incorrectly
treated all channels as permanently unavailable and stopped:

  UDS Real AP: prepared interface=udsap0 ...
  channel 1 unavailable ... error -16
  channel 6 unavailable ... error -16
  channel 11 unavailable ... error -16
  physical beacon monitor failed: no usable channel remained

That is why the emulator remained visible to retail briefly while the retail
trainer disappeared from Azahar: Azahar's physical receive monitor had exited.

What this fix changes
---------------------
* Creates udsap0 early but deliberately leaves it DOWN during PSS discovery.
* Brings udsap0 UP only after a retail authentication frame is received.
* Brings udsap0 DOWN again whenever START_AP is stopped.
* Deletes the partial AP interface if activation fails, restoring discovery.
* Treats transient nl80211 -16/EBUSY during a channel hop as nonfatal and keeps
  the known current channel instead of terminating the monitor.
* Does not change beacon parsing, CCMP, SecureData, or Pokemon packet handling.

File to replace
---------------
Extract this ZIP directly into the root of the Azahar source tree and allow
Windows to merge src and replace this one existing file:

  src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp

Build
-----
Do not rerun CMake. Close Azahar, select Release and x64 in Visual Studio, then
use Build > Build Solution.

Test order and expected evidence
--------------------------------
1. Load Pokemon X and remain on the normal PSS screen first.
2. Confirm the retail trainer appears in Azahar again before entering trade.
3. The log should show:

     UDS Real AP: prepared DOWN interface=udsap0 ...
     discovery radio remains unlocked

4. It must continue showing discovery sweeps and/or delivered retail Nintendo
   beacons. It must not report that the physical beacon monitor failed.
5. Only after requesting/accepting the trade should it show:

     UDS Real AP: START_AP accepted ...
     UDS Real AP: retail station registered and authorized ...

Preserve the complete log even if the AP activation or trade still fails. The
first result we need is restoration of the previously working PSS discovery.
