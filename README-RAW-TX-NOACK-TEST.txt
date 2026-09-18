Azahar UDS Real: raw TX verification and broadcast NO_ACK test
================================================================

Purpose
-------
This test keeps the investigation at the raw transport layer.

It makes three controlled changes:

1. Rolls back the unsuccessful host-broadcast FromDS experiment. Protected group data uses the
   previous NoDS address layout again (frame-control bytes 08:40).
2. Adds radiotap TX_FLAGS=NO_ACK to group-addressed frames. A broadcast has no receiver capable
   of returning an 802.11 ACK, so this explicitly tells mac80211/rtw88 not to await one.
3. Records the complete bytes at two independent Azahar boundaries:
   * UDS RAW TX BOUNDARY: bare 802.11 MPDU and radiotap-wrapped packet immediately before SendTo.
   * UDS LDND RAW TX PIPE: ldnd's 21-byte protocol header and identical packet after both Windows
     named-pipe WriteFile operations have succeeded.

No Pokemon payload, UDS SecureData layout, CCMP algorithm/key, PSS probe behavior, channel
selection, or management handshake behavior is changed by this patch.

Files
-----
Extract this archive into the Azahar repository root. Windows should merge with src and replace:

  src/core/hle/service/nwm/nwm_uds.cpp
  src/core/hle/service/nwm/uds_real/ldnd_connection.cpp
  src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp

No CMake regeneration is needed because all three files are already members of the generated
project. Build the same Release target in the existing Visual Studio solution.

Test
----
1. Start ldnd.exe and the rebuilt Azahar.
2. Load Pokemon X and wait for the retail trainer to appear.
3. Request the trade from Azahar and accept it on the retail 3DS.
4. Continue until the trade succeeds or either device reports a failure.
5. Save azahar_log.txt and copy all rtw88 messages from ldnd.exe.

Expected raw format for a protected Pokemon broadcast
-----------------------------------------------------
The same packet should appear in three logs:

  UDS DATA TRACE TX MPDU
  UDS RAW TX BOUNDARY
  UDS LDND RAW TX PIPE

For a broadcast application frame, verify:

  802.11 frame-control value:       0x4008 little-endian
  802.11 frame-control raw bytes:   08:40
  Address 1:                        FF:FF:FF:FF:FF:FF
  ToDS / FromDS:                    false / false
  CCMP header offset:               24 bytes from MPDU start
  Encrypted body+MIC offset:        32 bytes from MPDU start
  CCMP reserved byte:               00
  CCMP ExtIV bit:                   set
  CCMP key index:                   0

The broadcast radiotap prefix must be exactly:

  00:00:0A:00:00:80:00:00:08:00

Decoded in little-endian order, that is:

  version/pad:                      00:00
  radiotap length:                  0A:00 = 10
  present bitmap:                   00:80:00:00 = TX_FLAGS (bit 15)
  TX_FLAGS:                         08:00 = NO_ACK

The complete packet must therefore equal that ten-byte prefix followed byte-for-byte by the MPDU.

Expected ldnd framing
---------------------
The named-pipe frame consists of a 21-byte header followed by the complete radiotap packet:

  byte 0:                           06 (LdndOp::SendTo)
  bytes 1..4:                       socket id, little-endian
  bytes 5..8:                       send flags, little-endian (normally zero)
  bytes 9..12:                      zero
  bytes 13..16:                     zero
  bytes 17..20:                     packet/blob length, little-endian
  byte 21 onward:                   radiotap packet

Every checks={...} value in both raw trace lines should be true.

Cross-boundary identity checks
------------------------------
For each protected frame:

* DATA TRACE TX MPDU mpduFingerprint must equal RAW TX BOUNDARY mpduFingerprint.
* RAW TX BOUNDARY mpduFingerprint must equal LDND RAW TX PIPE mpduFingerprint.
* RAW TX BOUNDARY packetFingerprint must equal LDND RAW TX PIPE blobFingerprint.
* RAW TX BOUNDARY packet= must be byte-for-byte identical to LDND RAW TX PIPE blob=.
* The four blobLengthRaw bytes must decode little-endian to blobLengthLE and packetBytes.

These checks catch changed byte order, an incorrect address, omitted/extra bytes, a bad offset,
and mutation between the 802.11 generator and ldnd's named pipe.

Interpretation
--------------
If the fingerprints or checks disagree, stop at that exact boundary and fix the serialization.

If all values agree but the trade still fails, the Azahar-owned byte path is proven intact through
the successful named-pipe writes. The next raw-data step is a daemon-side AF_PACKET trace or an
independent monitor capture to verify what Linux/mac80211 actually accepts and puts on the air.
That is distinct from assuming the higher-level Pokemon payload is correct.

Also compare the number and timing of rtw88 "failed to get tx report from firmware" messages.
If they were caused by the driver waiting for an impossible ACK to a broadcast, they should cease
or decrease specifically for the NO_ACK group packets.
