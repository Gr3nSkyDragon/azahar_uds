Azahar UDS Real - AP Ethernet EAPoL test
========================================

Changed source files
--------------------
src/core/hle/service/nwm/nwm_uds.cpp
src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp
src/core/hle/service/nwm/uds_real/nl80211_monitor.h

Result that motivated this test
-------------------------------
The previous build successfully registered the retail station, decrypted its
protected EAPoL-Start, assigned node 2, and received a successful netlink ACK
for NL80211_CMD_CONTROL_PORT_FRAME.  The retail 3DS nevertheless sent no
further frame and reported 018-0000.

A netlink ACK proves that the kernel accepted the command, but not that the
wireless peer acknowledged or accepted the resulting frame.  Nintendo's custom
0x888E packet is therefore moved out of nl80211 control-port mode and sent as
an ordinary Ethernet frame through the authorized udsap0 data interface.  The
payload bytes are unchanged.  mac80211 still owns encryption, CCMP packet
numbers, hardware ACK handling, and retransmission.

The monitor also logs any host-originated protected data frame it can observe
over the air.  This separates "AF_PACKET submission succeeded" from "the
driver actually emitted a protected frame."

Installation
------------
Extract this ZIP into the root of the Azahar source checkout and merge the src
directory.  Confirm that the three source files listed above are replaced.

No CMake regeneration is required.  Build the existing Release x64 target in
Visual Studio.

Expected log evidence
---------------------
After Azahar accepts the retail EAPoL client, expect:

  UDS Real AP: kernel data TX, ... ethertype=0x888E, ethernetBytes=678

If the adapter exposes its own AP transmission to the monitor interface, also
expect:

  UDS Real AP: captured kernel data TX #1, ... protected=true, fromDS=true ...

The strongest success indicator is another protected "physical RX" frame from
the retail 3DS after those lines.  Please provide the full Azahar log whether
the result is success, a communication failure, or error 018-0000.
