Azahar UDS Real - kernel AP data carrier
========================================

Changed source files
--------------------
src/core/hle/service/nwm/nwm_uds.cpp
src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp
src/core/hle/service/nwm/uds_real/nl80211_monitor.h

Why this patch is needed
------------------------
The association-order test succeeded.  The retail 3DS associated, transmitted
a protected EAPoL-Start frame, and Azahar decrypted and accepted it.  Azahar
then sent its 712-byte EAPoL-Logoff/node-map response as a software-encrypted
monitor-mode frame.  No further retail frames arrived.

That transmit path bypassed the kernel AP's acknowledgement/retry machinery and
created a second pairwise CCMP packet-number owner.  The kernel had already
installed the same key on udsap0, so both the software injector and mac80211
could begin at PN 1.

This patch keeps udsmon0 for discovery and management diagnostics, but routes
host-originated protected traffic through udsap0:

* Nintendo EAPoL (EtherType 0x888E) uses NL80211_CMD_CONTROL_PORT_FRAME.
* Nintendo SecureData (EtherType 0x876D) uses an Ethernet AF_PACKET socket
  bound to udsap0.
* mac80211 therefore owns CCMP packet numbers, encryption, ACK handling, and
  retransmission for AP-originated data.

Installation
------------
Extract this ZIP into the root of the Azahar source checkout and merge the src
directory.  Confirm that all three source files listed above are replaced.

No CMake regeneration is required because this package adds no compiled source
file and does not modify CMakeLists.txt.  Build the existing Release x64 target
in Visual Studio.

Expected log evidence
---------------------
After the retail EAPoL-Start is accepted, the old line:

  physical TX ..., type=2, protected=true, frameBytes=712

should be replaced by:

  UDS Real AP: kernel control-port TX, ... ethertype=0x888E, payloadBytes=664

If that succeeds, look for additional protected physical RX frames from the
retail 3DS.  Later Azahar SecureData replies should log:

  UDS Real AP: kernel data TX, ... ethertype=0x876D, ...

Any "UDS Real AP: data TX failed" line is decisive and should be included with
the next full Azahar log.
