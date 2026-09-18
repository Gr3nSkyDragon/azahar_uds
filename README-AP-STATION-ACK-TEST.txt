Azahar UDS hardware-ACK/AP station test
========================================

What the latest run proved
--------------------------
The SecureData sequence fix worked. Pokemon delivered retail application
packets to the emulated game and sent increasing host sequences back. Traffic
continued in both directions until the retail 3DS deauthenticated about 23.8
seconds after association.

The retail unit transmitted the same management and deauthentication MPDUs
many times in rapid succession. Those are 802.11 retransmissions: monitor-mode
injection can exchange the frame contents, but it does not make the adapter
send the immediate MAC acknowledgement expected by the retail radio. A
userspace ACK routed through Windows, ldnd and USB would be far too late.

What this patch changes
-----------------------
* Retains udsmon0 for the working Nintendo beacon, CCMP and UDS frame path.
* Creates a companion udsap0 interface with Azahar's advertised host MAC.
* Prepares the AP asynchronously when Pokemon begins hosting a UDS network.
* Starts the AP on the monitor's locked channel when retail authentication
  begins.
* Configures hidden-SSID WPA2/CCMP state with the same derived UDS key.
* Parses the retail association request and registers, keys and authorizes the
  station with nl80211.
* Lets the Linux Wi-Fi driver/hardware generate timing-critical 802.11 ACKs.
* Stops and removes the AP cleanly on departure, network reset or shutdown.
* Falls back to the existing monitor-only transport with a precise log message
  if the adapter/driver rejects an AP operation.

Files to replace
----------------
Copy this package into the root of the Azahar source tree and allow Windows to
merge the src directory and replace these three existing files:

  src/core/hle/service/nwm/nwm_uds.cpp
  src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp
  src/core/hle/service/nwm/uds_real/nl80211_monitor.h

Build
-----
These files are already part of the generated Visual Studio project. Do not
rerun CMake. Close Azahar, select Release and x64 in Visual Studio, then use
Build > Build Solution. Run the rebuilt azahar.exe under the debugger.

Test
----
Use the same successful path as the prior run: load Pokemon X, find the retail
trainer, request a trade, accept it on retail, and allow the initialization to
continue. Preserve the complete Azahar log whether it succeeds or fails.

Expected AP evidence
--------------------
Before retail authentication:

  UDS Real AP: prepared interface=udsap0, ifindex=..., hostMac=..., ssid=...

When authentication begins:

  UDS Real AP: START_AP accepted, ... hardware MAC acknowledgements enabled

After the association request:

  UDS Real AP: retail station registered and authorized, station=..., aid=1,
                pairwiseKeyIndex=0

The decisive result is whether the session passes the previous approximately
24-second boundary. If an operation is rejected, the log will instead contain
one of these with the exact netlink error number:

  UDS Real AP: preparation failed; continuing with monitor-only transport: ...
  UDS Real AP: activation failed; continuing with monitor-only transport: ...
  UDS Real AP: station operation failed for ...: ...

No CMake regeneration or new Visual Studio project file is required.
