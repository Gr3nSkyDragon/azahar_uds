Azahar UDS retail management-reply test
========================================

What this tests
---------------
The retail 3DS now completes association with Azahar, but then sends a valid
one-byte UDS management payload (00) repeatedly until it deauthenticates about
20 seconds later. Azahar previously consumed that packet without replying.

This patch makes an Azahar UDS host mirror each new channel-3 management
request back to the retail client. It preserves the incoming UDS sequence and
payload and suppresses duplicate 802.11 retransmissions.

Files to replace
----------------
Copy this package into the root of the Azahar source tree and allow Windows to
merge the src directory and replace these four existing files:

  src/core/hle/service/nwm/nwm_uds.cpp
  src/core/hle/service/nwm/nwm_uds.h
  src/core/hle/service/nwm/uds_data.cpp
  src/core/hle/service/nwm/uds_data.h

Build
-----
These files are already part of the generated Visual Studio project. Do not
rerun CMake. Close Azahar, select Release and x64 in Visual Studio, then use
Build > Build Solution. Run the rebuilt azahar.exe under the debugger.

Expected next-run evidence
--------------------------
For every new retail management sequence, the log should show exactly one:

  UDS Real: replied to management SecureData request, channel=3, ... payload=00

The normal physical-TX diagnostic should immediately follow it with a protected
unicast data frame to the retail MAC address. Duplicate captures of the same
sequence are deliberately suppressed and only logged at Trace level.

The important outcome is whether the retail console remains connected beyond
the previous approximately 20-second boundary and whether normal game-channel
SecureData begins flowing. If it still deauthenticates despite these replies,
preserve the complete Azahar log: repeated encrypted frames indicate that the
next likely blocker is missing hardware-timed 802.11 ACK handling in the
monitor-mode transport, rather than another nwm::UDS payload stub.
