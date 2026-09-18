Azahar UDS Real - isolated hardware ACK-shell test
==================================================

Changed source files
--------------------
src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp
src/core/hle/service/nwm/uds_real/nl80211_monitor.h

What this test is checking
--------------------------
The active-monitor test was rejected by the RTL8822BU/rtw88 driver with
netlink error -95 (EOPNOTSUPP). The fallback run still exchanged valid UDS and
Pokemon packets, but 100 of 122 captured retail frames had the 802.11 Retry
bit set. That strongly suggests that passive monitor injection/receive works
while immediate hardware MAC acknowledgements do not.

Raw frame injection and hardware acknowledgement are separate adapter paths.
Azahar can build and inject complete Nintendo frames in userspace, but an ACK
must be emitted by the radio firmware only microseconds after receiving a
unicast frame. Userspace and ldnd cannot synthesize that response in time.

This patch therefore enables only an nl80211 AP "ACK shell":

* udsap0 adopts Azahar's advertised host MAC/BSSID.
* The AP starts only when retail authentication begins.
* The retail association request is registered in the kernel station table.
* No group or pairwise CCMP key is installed in the kernel.
* The station is not marked authorized.
* No EAPoL or Pokemon data is submitted through the AP Ethernet interface.
* Azahar remains the sole CCMP packet-number/encryption owner and all data
  frames continue through the proven monitor-injection path.
* Once the ACK shell starts, its firmware beacon uses Azahar's actual Nintendo
  beacon body. Azahar updates it when node data changes, avoiding the generic
  WPA beacon used by the earlier full-AP experiments.

Installation
------------
Extract this ZIP into the root of the Azahar source checkout and allow Windows
to merge src and replace the two files listed above.

No CMake regeneration is required. Close Azahar, select Release and x64 in
Visual Studio, then use Build > Build Solution.

Test procedure
--------------
1. Start ldnd.exe.
2. Start the rebuilt Azahar and load Pokemon X.
3. Confirm the retail trainer appears normally on the PSS screen.
4. Request a trade from Azahar and accept it on the retail 3DS.
5. Let both systems run until the trade succeeds or either side reports an
   error. Preserve the complete Azahar log.

Expected proof that the experiment engaged
------------------------------------------
Look for all of these lines:

  UDS Real: isolated ACK-shell test enabled
  UDS Real AP: prepared DOWN interface=udsap0
  UDS Real ACK shell: START_AP accepted
  UDS Real ACK shell: retail station registered for hardware ACKs

The START_AP line must also say:

  kernelKeys=false, stationAuthorized=false, kernelDataCarrier=false

The decisive result is the Retry field on subsequent "physical RX" lines.
If the shell is supplying MAC ACKs, each new sequence should normally appear
once with retry=false instead of being repeated several times with retry=true.
The final retryFrames/deliveredFrames ratio should fall sharply from the prior
100/122 result.

It is possible for ldnd.exe to continue printing:

  rtw88_8822bu ... failed to get tx report from firmware

That warning concerns firmware TX-status reporting and is not, by itself, a
failure of this incoming-ACK experiment. The retail retry pattern and how far
the trade advances are the important results.

Automatic fallback
------------------
If AP preparation, activation, or Nintendo beacon updating fails, the log
records the exact netlink error. Beacon-update failure stops the ACK shell and
restores raw monitor beacon transmission so discovery is not silently lost.

Rollback
--------
Re-extract azahar-uds-active-monitor-ack-test.zip into the Azahar source root
to return to the immediately preceding monitor-only baseline.
