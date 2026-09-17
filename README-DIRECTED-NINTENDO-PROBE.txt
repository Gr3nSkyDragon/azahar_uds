Azahar UDS Real - directed Nintendo scan probe test
===================================================

Previous result
---------------
The wildcard active-probe build submitted 53 probe requests and continued to
receive valid retail Pokemon X beacons, but it captured no Nintendo probe
response. The monitor counted 513 probe frames overall. A wildcard SSID is
therefore not sufficient to make the retail 3DS respond.

Purpose
-------
This build changes the active request to the full 32-byte SSID used by the 3DS
continuous scanner:

Nintendo_3DS_continuous_scan_000

It also treats any request or response containing that SSID as relevant even if
its transmitter MAC differs from the UDS beacon MAC. Finally, it recognizes
frames using our own probe source MAC, which tells us whether the monitor sees a
transmit echo from the adapter/driver.

This remains a diagnostic test. It does not yet advertise the Azahar trainer.

File replaced
-------------
src/core/hle/service/nwm/uds_real/nl80211_monitor.cpp

Installation
------------
1. Close Visual Studio and Azahar.
2. Extract this ZIP directly into the Azahar repository root:
   E:\DS Emu\3DS\Azahar-UDS\azahar
3. Windows should merge src and replace the one file above.
4. Reopen build\citra.slnx.
5. Build citra_meta using Release and x64.

No CMake regeneration is required.

Test procedure
--------------
1. Start ldnd.exe.
2. Start Pokemon X on Azahar and the retail 3DS with PSS active.
3. Wait for the retail trainer to appear in Azahar.
4. Leave both systems on PSS for at least 10 seconds.
5. Request a trade from Azahar.
6. Leave the request active for another 15 seconds.
7. Close Azahar cleanly and provide azahar_log.txt.

Important log lines
-------------------
UDS Real: transmitted directed Nintendo scan probe request ...
UDS Real: captured relevant probe ...

Relevant probe lines now include:

fromBeaconSource=
fromOurProbeSource=
nintendoScanSsid=
nintendoIe=

Interpretation
--------------
fromOurProbeSource=true confirms the monitor received an echo of the injected
request. A response with nintendoIe=true gives us the retail response template.
A request with nintendoScanSsid=true but a different source MAC identifies the
retail continuous scanner even when it does not reuse its UDS beacon MAC.
