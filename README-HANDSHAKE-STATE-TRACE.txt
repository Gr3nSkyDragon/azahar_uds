Azahar UDS Real: handshake/state trace test
===========================================

Purpose
-------
This is a trace-only patch. It does not change packet construction, encryption,
timing, channel selection, ACK behavior, or management replies.

It records the data immediately before the Pokemon channel-243 exchange:

* the retail EAPOL-Start join record;
* Azahar's EAPOL-Logoff/node-map reply;
* the encrypted MPDU boundaries for both EAPOL directions;
* every channel-3 UDS management request and reply;
* the NodeInfo supplied by Pokemon when nwm::UDS is initialized;
* connection status and NodeInfo values returned to Pokemon.

Installation
------------
Extract the zip into the Azahar repository root. Windows should ask to merge
with src and replace these two files:

  src/core/hle/service/nwm/nwm_uds.cpp
  src/core/hle/service/nwm/nwm_uds.h

No CMake regeneration is needed because this patch adds no source files and
does not edit a CMakeLists.txt. Open the existing generated solution and build
the same Release target in Visual Studio.

Test A: reproduce the current direction
---------------------------------------
1. Start ldnd.exe and the rebuilt Azahar.
2. Let the retail trainer appear in Pokemon X on Azahar.
3. Request the trade from Azahar, accept it on the retail 3DS, and wait for the
   communication failure.
4. Save azahar_log.txt.

Test B: obtain the retail-host reference (most valuable)
--------------------------------------------------------
1. Restart both sides for a clean log.
2. Let the Azahar trainer appear on the retail 3DS.
3. Request the trade from the retail 3DS and accept it in Azahar.
4. Continue as far as possible, even if Azahar cannot complete the client-side
   join, then save azahar_log.txt.

The second direction lets us compare a retail-generated host EAPOL-Logoff and
host channel-243 record against Azahar's generated equivalents instead of
guessing which fields are role-dependent.

Expected log markers
--------------------

  UDS JOIN TRACE
  UDS STATE TRACE
  UDS CONTROL TRACE
  UDS DATA TRACE

Privacy note
------------
The summary fields use fingerprints, but the full EAPOL plaintext contains raw
NodeInfo data, including the configured console name and friend-code seed. Keep
the complete log private rather than posting it publicly without redaction.
