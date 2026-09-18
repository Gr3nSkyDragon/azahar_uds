Azahar UDS Real: role-aware host broadcast test
================================================

Purpose
-------
This patch changes only the 802.11 DS/address layout used for protected data frames.

Previously, every link-layer broadcast used the no-DS layout observed on retail
client-to-host Pokemon packets. This patch makes the layout role-aware:

* Azahar host -> retail client broadcast: FromDS
* Azahar client -> retail host broadcast: NoDS (unchanged)
* Azahar host -> retail client unicast: FromDS (unchanged)
* Azahar client -> retail host unicast: ToDS (unchanged)

The Pokemon payload, UDS SecureData header, CCMP key, packet number, sequence number,
management-reply behavior, EAPOL behavior, and channel selection are not changed.

Installation
------------
Extract the zip into the Azahar repository root. Windows should ask to merge with src
and replace this file:

  src/core/hle/service/nwm/nwm_uds.cpp

No CMake regeneration is needed. Open the existing generated solution and build the
same Release target in Visual Studio.

Test
----
Use the direction that exercised host broadcasts:

1. Start ldnd.exe and the rebuilt Azahar.
2. Let the retail trainer appear in Pokemon X on Azahar.
3. Request the trade from Azahar.
4. Accept both retail prompts if the duplicate prompt still occurs.
5. Continue until the trade succeeds or either side reports a communication failure.
6. Save azahar_log.txt and the relevant ldnd.exe output.

What to check
-------------
Channel-243 transmit entries should now say:

  broadcast=true, fromDS=true, dsMode=FromDS

The raw MPDU should begin with frame-control bytes 08:42 rather than 08:40.

The monitor previously observed local TX echoes only for the EAPOL frame and the
unicast channel-3 control replies. The most useful result is whether it now also logs
kernel data TX echoes for the channel-243 packet numbers. Also note whether the count
of rtw88 "failed to get tx report from firmware" messages still matches the number of
Pokemon broadcast packets.

This patch intentionally does not implement physical PSS probe responses. That should
remain a separate follow-up change after this test so the two results are not mixed.
