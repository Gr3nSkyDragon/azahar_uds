Azahar UDS Real - Pokemon application-data verification trace
==============================================================

Changed source file
-------------------
src/core/hle/service/nwm/nwm_uds.cpp

Purpose
-------
The isolated ACK-shell test reduced received retail retry frames from 100/122
to 7/33. After station registration, only 2 of 28 frames were retries. The
retail 3DS nevertheless stopped exchanging Pokemon channel-243 data, continued
valid channel-3 management traffic for roughly eight seconds, and then sent a
reason-3 deauthentication frame.

This patch makes no networking or protocol behavior changes. It does not add
retransmission, delays, AP changes, packet filtering, or data conversion. It
only records the bytes at every application-data boundary so the first point
of divergence can be identified.

Trace stages
------------
UDS DATA TRACE TX GAME
    Exact application buffer supplied by Pokemon to nwm::UDS.

UDS DATA TRACE TX SECUREDATA
    LLC/SNAP plus Nintendo SecureData header and Pokemon payload before CCMP.

UDS DATA TRACE TX MPDU
    Final encrypted 802.11 MPDU submitted to the monitor transport, including
    destination MAC, broadcast status, 802.11 sequence and CCMP packet number.

UDS DATA TRACE RX MPDU
    Raw retail CCMP body and its radio/header metadata before decryption.

UDS DATA TRACE RX SECUREDATA
    Complete LLC/SNAP plus SecureData plaintext after successful decryption.

UDS DATA TRACE RX QUEUE
    Pokemon payload accepted into the bound nwm::UDS receive queue.

UDS DATA TRACE RX GAME
    Exact application bytes returned to Pokemon by PullPacket.

Each stage logs the complete byte sequence and an FNV-1a fingerprint. The
fingerprints let us verify these invariants directly:

1. TX GAME payload equals the payload suffix inside TX SECUREDATA.
2. TX SECUREDATA plaintext exactly matches the plaintext encrypted into the
   corresponding TX MPDU.
3. RX MPDU decrypts to the corresponding RX SECUREDATA record.
4. RX SECUREDATA payload equals RX QUEUE and RX GAME without mutation.
5. Nintendo header size, sequence, channel, source-node and destination-node
   fields remain internally consistent in both directions.

Installation
------------
Extract this ZIP into the root of the existing ACK-shell Azahar checkout and
replace src/core/hle/service/nwm/nwm_uds.cpp.

No CMake regeneration is required. Close Azahar, select Release and x64 in
Visual Studio, then use Build > Build Solution.

Test procedure
--------------
1. Start ldnd.exe.
2. Start the rebuilt Azahar and load Pokemon X.
3. Confirm the retail trainer appears on PSS.
4. Request and accept a trade exactly as in the successful ACK-shell test.
5. Wait for success or failure, then provide the complete Azahar log.

Do not omit the beginning of the connection. The EAPoL acceptance and the
first channel-243 packet establish the sequence/packet-number baseline needed
to compare later payloads.

Expected ACK-shell lines
------------------------
The run must still contain:

  UDS Real ACK shell: START_AP accepted
  UDS Real ACK shell: retail station registered for hardware ACKs

If either is absent, the data trace may still be readable, but it will not be
directly comparable with the successful 7/33 ACK-shell transport run.
