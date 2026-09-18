Azahar UDS ldnd interleaved-data demultiplexing fix
===================================================

What the latest run proved
--------------------------
The PSS discovery regression is fixed. The retail beacon was delivered to
Azahar, the trade network moved to channel 6, and bidirectional Pokemon
SecureData worked again.

The AP itself did not start. Its first activation attempt failed with:

  ldnd reply SID mismatch: expected 4, received 3

SID 3 is the active monitor packet socket. SID 4 is the temporary route socket
used to bring udsap0 UP. A normal asynchronous Wi-Fi DATA frame for SID 3
arrived while the C++ transport was waiting for SID 4's command reply. The old
transport assumed the next incoming frame must always belong to the request
that was just sent, so it aborted AP activation. The trade then continued in
monitor-only mode and hit the same approximately 23-second retail timeout.

What this fix changes
---------------------
* Queues asynchronous ldnd DATA frames by virtual socket ID.
* Allows DATA for the monitor socket to interleave with route/generic-netlink
  command replies without being mistaken for a corrupt reply.
* Makes ReceiveData and TryReceiveData consume their socket's queued frames
  before reading additional named-pipe data.
* Preserves strict checking for an actual REPLY carrying the wrong SID.
* Clears queued frames when a socket or the connection closes.
* Adds a low-volume diagnostic when interleaved DATA is deferred.

File to replace
---------------
Extract this ZIP directly into the root of the Azahar source tree and allow
Windows to merge src and replace this one existing file:

  src/core/hle/service/nwm/uds_real/ldnd_connection.cpp

Build
-----
Do not rerun CMake. Close Azahar, select Release and x64 in Visual Studio, then
use Build > Build Solution.

Expected next-run evidence
--------------------------
At authentication, an interleaved monitor packet may now produce:

  UDS Real: ldnd deferred interleaved DATA #1 for SID=3 while waiting for
            reply SID=4

That must be followed by:

  UDS Real AP: START_AP accepted ...
  UDS Real AP: retail station registered and authorized ...

The old message below must not recur:

  UDS Real AP: activation failed ... ldnd reply SID mismatch ...

Preserve the complete log. If START_AP reaches a different nl80211 error, that
new error is the next AP integration target.
