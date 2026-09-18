Azahar UDS Real - controlled monitor-only rollback
==================================================

Changed source files
--------------------
src/core/hle/service/nwm/nwm_uds.cpp
src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp

Why this rollback is necessary
------------------------------
The 2026-09-17 10:43 and 11:20 tests completed Nintendo EAPoL admission and
exchanged bidirectional Pokemon SecureData on channel 243 for about 23 seconds.
Those tests used software CCMP encryption and monitor-mode injection.

The 11:20 run attempted to activate the companion kernel AP, encountered an
ldnd SID mismatch, and fell back to monitor-only operation. Fixing that SID
demultiplexing error made the AP activate, but every later AP-based build
regressed to an earlier failure stage: association ordering errors, an EAPoL
response that received no follow-up, or retail error 018-0000.

The latest AP Ethernet test failed even earlier. The retail console
reassociated, its protected EAPoL-Start failed CCMP authentication, and the
intended Ethernet EAPoL transmit path was never reached. The AP interface also
emitted unrelated IPv6 multicast traffic to 33:33:* destinations.

What this changes
-----------------
* Prevents creation, activation, station registration, and key ownership by
  the experimental udsap0 companion interface.
* Restores every host-originated EAPoL and SecureData packet to the proven
  software CCMP plus monitor-injection path.
* Restores the FromDS address layout used by the successful host-side tests.
* Keeps the ldnd demultiplexing fix, discovery fixes, retail connection-type
  handling, management replies, shared SecureData sequence counter, and all
  useful diagnostics.
* Does not change packet contents or Pokemon's application protocol.

Installation
------------
Extract this ZIP into the root of the Azahar source checkout and allow Windows
to merge src and replace the two existing files listed above.

No CMake regeneration is required. Close Azahar, select Release and x64 in
Visual Studio, then use Build > Build Solution.

Test
----
1. Start ldnd.exe.
2. Start the rebuilt Azahar and load Pokemon X.
3. Verify the retail trainer appears on the normal PSS screen.
4. Request a trade from Azahar and accept it on the retail 3DS.
5. Leave both systems running until the session completes or fails.

Expected rollback evidence
--------------------------
The log must contain:

  UDS Real: monitor-only rollback active; kernel AP creation and data carrier disabled

It must not contain:

  UDS Real AP: prepared DOWN
  UDS Real AP: START_AP accepted
  UDS Real AP: kernel control-port TX
  UDS Real AP: kernel data TX
  UDS Real AP: captured kernel data TX

The recovered baseline should then show, in order:

  UDS Real: accepting retail EAPoL client connection type 0x0
  UDS Real: accepted client ... assignedNodeId=2
  UDS Real: physical TX ... type=2 ... frameBytes=712
  UDS Real: queued application SecureData, channel=243 ... payloadBytes=73
  UDS Real: delivered application SecureData to game, channel=243
  UDS Real: sending application SecureData, channel=243 ... payloadBytes=73

Management channel-3 replies should continue with increasing host reply
sequence numbers. Preserve the complete Azahar log even if the retail console
eventually reports Communication failed. The next development step depends on
whether this exact bidirectional SecureData baseline is restored.
