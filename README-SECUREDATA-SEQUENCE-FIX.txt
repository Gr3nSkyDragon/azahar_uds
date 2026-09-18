Azahar UDS SecureData sequence fix and delivery diagnostics
===========================================================

What the latest run proved
--------------------------
The management replies were generated and physically transmitted. The retail
3DS remained associated longer than in the preceding run and was still sending
valid encrypted traffic when Pokemon/Azahar ended the session. This was not a
channel-hop, CCMP-authentication, or malformed-frame failure.

The next protocol defect was in SendToHLE: every normal game SecureData packet
used sequence number 0. Retail traffic shows that SecureData sequence numbers
advance across both management and game packets. Reusing zero can therefore
make the retail game discard every Azahar game packet after the first one as a
duplicate.

What this patch changes
-----------------------
* Adds one host-side SecureData sequence counter.
* Shares it across management replies and normal game SendTo traffic.
* Resets it whenever a host or client network session begins.
* Logs application packets when sent, queued, delivered to the game, or
  discarded because no compatible Bind exists.
* Retains management-request deduplication and the reply that extended the
  physical session in the latest test.

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
Do not rerun CMake. Close Azahar, select Release and x64 in Visual Studio, then
use Build > Build Solution. Run the rebuilt azahar.exe under the debugger.

Expected next-run evidence
--------------------------
Management replies should contain distinct request and host reply sequences:

  UDS Real: replied to management SecureData request, channel=3,
            requestSequence=..., replySequence=...

Normal game sends should use increasing sequence values instead of always 0:

  UDS Real: sending application SecureData, channel=..., sequence=...

Inbound game packets will produce one of these decisive paths:

  UDS Real: queued application SecureData
  UDS Real: delivered application SecureData to game
  UDS Real: discarded application SecureData for unbound channel
  UDS Real: discarded application SecureData for filtered source

Preserve the complete log even if the trade still fails. If packets are sent
with increasing sequences and received packets are delivered to Pokemon, the
next remaining transport target is hardware-backed AP/station registration so
the Wi-Fi adapter can generate time-critical 802.11 ACKs automatically.
