AZAHAR UDS REAL - PHYSICAL TRADE TRANSPORT TEST
================================================

Purpose
-------
This overlay extends the already-working Pokemon X beacon/PSS path into the dedicated UDS
trade network created after the retail player accepts a trade request.

It adds:
  * Capture and classification of physical authentication, association, deauthentication,
    and data frames addressed to Azahar's emulated host MAC.
  * Physical authentication and association-response transmission.
  * Idempotent handling of a retail console retrying its authentication request.
  * Physical EAPOL and SecureData transmission/reception.
  * Activation of Azahar's existing UDS CCMP key derivation using the game's passphrase.
  * CCMP encryption, authentication, and decryption for retail 802.11 data frames.
  * Focused RX/TX logs that identify the first remaining failure without dumping payloads or keys.

Files replaced
--------------
Extract this ZIP into the main Azahar source folder (the folder containing CMakeLists.txt) and
allow Windows to merge "src" and replace these six files:

  src\core\hle\service\nwm\nwm_uds.cpp
  src\core\hle\service\nwm\nwm_uds.h
  src\core\hle\service\nwm\uds_data.cpp
  src\core\hle\service\nwm\uds_data.h
  src\core\hle\service\nwm\uds_real\nl80211_monitor.cpp
  src\core\hle\service\nwm\uds_real\nl80211_monitor.h

Build
-----
No CMake regeneration is required: every file already exists in the generated Visual Studio
solution. Close a running Azahar instance, select Release and x64, then use Build > Build Solution.
Run build\bin\Release\azahar.exe after the build succeeds.

Test
----
  1. Start ldnd.exe.
  2. Start this Azahar build and Pokemon X.
  3. Wait for the retail trainer to appear in Passersby/Acquaintances.
  4. Request a trade from Azahar and accept it on the retail 3DS.
  5. Continue as far as either game permits. If the Pokemon-selection screen appears, attempt a
     small test trade.
  6. Close Azahar normally and provide the complete azahar_log.txt.

Important log markers
---------------------
The first successful join should contain a sequence similar to:

  UDS Real: physical RX ... type=0, subtype=11 ...
  UDS Real: delivering physical frame ... packetType=2 ...
  UDS Real: physical TX ... type=0, subtype=11 ...
  UDS Real: physical TX ... type=0, subtype=1 ...
  UDS Real: physical RX ... type=2 ... protected=true ...
  UDS Real: delivering physical frame ... packetType=1 ...

PacketType values in the delivery log follow Network::WifiPacket:
  0 = Beacon
  1 = Data
  2 = Authentication
  3 = AssociationResponse
  4 = Deauthentication

If the next barrier is cryptographic, the log will say:
  UDS Real: CCMP authentication failed ...

If authentication/association succeeds, the host connection status should gain a second node and
Pokemon should leave DllCommWait. The log intentionally does not print the passphrase, CCMP key,
decrypted trade payload, or Pokemon data.

Notes
-----
This is the first physical data-plane implementation. The common non-QoS UDS data format is
implemented. If the retail 3DS uses a QoS data subtype, a different CCMP key index, or an
adapter-specific radiotap requirement, the focused logs should expose that immediately and the
next adjustment can be limited to the frame wrapper rather than the Pokemon/PSS code.
