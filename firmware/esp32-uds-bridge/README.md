# esp32-uds-bridge

Firmware for an **ESP32-S3** that acts as the 802.11 radio for Azahar's local wireless (UDS) on
Android, in place of the USB Wi-Fi adapter and `ldnd.exe` used on Windows. The phone talks to the
board over USB-C; the board captures and injects raw Wi-Fi frames so the emulator can trade with a
retail 3DS.

It is deliberately dumb. It has no LDN/PIA logic (unlike GB-Link-Switch-LDN): CCMP encryption, the
authentication/association handshake, beacons' contents and everything else stay in Azahar's
`nwm::UDS`. The board only does what a phone cannot:

| Job | How |
| --- | --- |
| Receiving unicast frames sent to the emulated 3DS | The hardware is started with a *twin* of the emulated MAC (first octet XOR 0x02), not the MAC itself. The chip does not hand unicast data frames addressed to its own address to the capture path, which broke the join handshake; with a twin address those frames are ordinary sniffed traffic. The consequence is that the hardware does not ACK them and the peer retransmits a few frames. The peer does ACK every unicast frame the board sends (`txUnicast == acksRx` in the stats). |
| Capture | Promiscuous mode (management + data). Only frames that matter are forwarded: beacons carrying a Nintendo (00:1F:32) vendor element, and any frame touching the emulated MAC or the "watched" peer MAC. |
| Inject | `esp_wifi_80211_tx` with the sequence control field left alone. `ieee80211_raw_frame_sanity_check` is overridden (see `main/CMakeLists.txt`, `-zmuldefs`) so authentication/association/beacon frames are allowed. |
| Beacon cadence | Azahar hands over a beacon template; the board sends it every 102.4 ms with a fresh timestamp and sequence number, so USB jitter never shows up as a missing beacon. |
| Channel | Azahar drives discovery hopping (1, 6, 11) and channel selection with `SET_CHANNEL`, exactly like the desktop monitor. |

## Hardware

Any ESP32-S3 board. **Use the chip's native USB port** (the one wired to GPIO19/20, usually labelled
"USB" rather than "UART"/"COM"); it enumerates as Espressif USB Serial/JTAG (`303A:1001`), which is
what the app looks for. Connect it to the phone with a USB-C cable (a USB-C to USB-C cable, or an OTG
adapter). The board is powered from the phone; 2.4 GHz radio TX draws a few hundred mA.

## Flashing a pre-built firmware (no ESP-IDF needed)

Each release ships one file, `esp32-uds-bridge-fw<version>-esp32s3.bin` (bootloader, partition table
and app merged). It is written at **offset `0x0`**, gaps included, so it also **erases the stored 3DS key**:
store the key again after flashing. Plug the board in through its **native USB port** (the one that
shows up as an Espressif USB Serial/JTAG device) and use one of these:

**With uds-esp32-setup (Windows).** `uds-esp32-setup.exe` ships next to the `.bin`. It
flashes the firmware and then stores the 3DS key from your `aes_keys.txt` in one go (either step can
be done on its own): pick the firmware (the newest `.bin` beside it is filled in), your `aes_keys.txt`
and the board, and press Start. Only the one 16-byte key the board needs (slot 0x2D) is sent to it,
and it is never shown or logged. It is built from mGBA-LDN's sources (`src/gb/sio/uds-esp32-setup.c`,
target `uds-esp32-setup`) and needs nothing else installed.

**In the browser (nothing to install).** Open Espressif's [esptool-js](https://espressif.github.io/esptool-js/)
in Chrome or Edge (it needs Web Serial). Connect, pick the board's port, add the `.bin` at address
`0x0`, and Program.

**With esptool.**

```
pip install esptool
esptool --chip esp32s3 -p COM4 write_flash 0x0 esp32-uds-bridge-fw1.4-esp32s3.bin
```

(replace `COM4` with the board's port; on older esptool versions the command is `esptool.py`).

If the board is not detected, hold **BOOT** while plugging it in, then release it. The firmware prints
nothing after flashing; in Azahar's Network settings, **Connect** should report the firmware version.
The merged file was verified by flashing it to a real ESP32-S3 with esptool and with esptool-js.

To produce the merged file for a new release, run `package-release-bin.ps1` from an ESP-IDF PowerShell.

## Build and flash

Requires ESP-IDF 5.2 or newer (`idf.py`).

```
cd firmware/esp32-uds-bridge
idf.py set-target esp32s3
idf.py build
idf.py -p COMx flash        # COMx = the board's port on your PC
```

Flash it over the same native USB port (hold BOOT while plugging in if the port is not detected).
The firmware prints nothing: the USB port carries the binary protocol below, and `sdkconfig.defaults`
turns the console off.

## Host tests

The framing is shared with the emulator (`src/core/hle/service/nwm/uds_real/esp32_wire.*`) and both
sides are tested against the same golden vectors:

```
cd test
gcc -I../main wire_test.c ../main/uds_wire.c -o wire_test && ./wire_test
```

The emulator's copy is the Catch2 case `ESP32 wire` in `src/tests/core/hle/service/nwm/esp32_wire.cpp`.

## Protocol

Frame: `| version=1 | type | seq | flags | length:u16 LE | payload | crc32:u32 LE |`, CRC-32/ISO-HDLC over
everything before it, COBS encoded, terminated by `0x00`. A leading `0x00` at boot lets the host
discard the ROM boot banner. Maximum payload 2432 bytes.

Host to device:

| Type | Payload | Reply |
| --- | --- | --- |
| `0x01` HELLO | none | HELLO_ACK |
| `0x02` START | `channel:u8, mac[6]` (radio up with this MAC) | STATUS |
| `0x03` STOP | none | STATUS |
| `0x04` SET_CHANNEL | `channel:u8` | STATUS |
| `0x06` TX_FRAME | `tx_flags:u8, rate500k:u8, mpdu` (no FCS; rate 0 = 1 Mbit/s, 22 = 11 Mbit/s) | none (see `tx_failed` in STATS) |
| `0x07` SET_BEACON | beacon MPDU template; empty clears | STATUS |
| `0x08` SET_WATCH | `mac[6]`; all zero clears | STATUS |
| `0x09` PING | `token:u32` | PONG |

Firmware 1.4 adds a second job, the **Game Boy wrapper** (`main/gbwrap.c`, see `main/gbwrap/README.md`): the board itself joins a
3DS running a Virtual Console Pokemon game (Red, Blue, Yellow, Gold, Silver, Crystal) and stands in for a link-cable partner, so the
host only carries a cartridge's serial transfers. Azahar never sends these commands and keeps the raw radio above; while the wrapper
runs, the raw radio commands are refused (`ESP_ERR_INVALID_STATE`) and received frames stay on the board.

| Type | Payload | Reply |
| --- | --- | --- |
| `0x0A` SET_KEY | `slot:u8 (0x2D), key[16]` | STATUS. Stored in flash (NVS), never sent back. `idf.py flash` leaves it; a release image written at 0x0 erases it |
| `0x0B` KEY_STATUS | none | `0x88` KEY_INFO `{slot, present}` |
| `0x0C` ERASE_KEYS | none | STATUS |
| `0x10` GB_START | `flags:u8 (bit 0: log), title[16] (cartridge header at 0x134), name[20] (UTF-16LE)` | STATUS: 0, `0x105` no key stored, `0x106` unknown game |
| `0x11` GB_XFER | `master:u8`, the byte the cartridge clocked out | `0x91` GB_REPLY `{slave:u8, wire phase:u8}`, the byte shifted back in the same transfer |
| `0x12` GB_STOP | none | STATUS (STOP does the same while the wrapper runs) |

While the wrapper runs the board also sends `0x90` GB_STATE `{room, session, wire phase, generation, channel}` on every change,
`0x92` GB_STATS (10 × u32: beacons, frames sent and received, frames dropped for decryption, replay and other reasons, tx failures,
units sent and received, transfers) every 5 s, and, with the log flag, LOG lines. The key is the 3DS UDS data key, AES key slot `0x2D`
KeyN (the line `slot0x2DKeyN=` of Azahar's `aes_keys.txt`). mGBA stores it from its key file the first time it needs it, or by hand:
mGBA's probe tool (in mGBA's build folder; in PowerShell the quoted path needs `&` in front):

```
& "<mGBA build folder>\uds-esp32-probe.exe" COMx --store-key "<path>\aes_keys.txt"
```

and `--key-status` or `--erase-keys` in place of `--store-key <file>`.

Device to host: `0x81` HELLO_ACK `{proto, fw_major, fw_minor, factory_mac[6]}`, `0x82` STATUS
`{request_type:u8, result:s32}` (echoes the request's `seq`), `0x83` RX `{channel, rssi, flags, mpdu}`,
`0x85` STATS every 5 s (`rx_seen, rx_forwarded, rx_dropped, tx_ok, tx_failed, beacons_sent,
usb_dropped`), `0x86` PONG.

## Status: what has and has not been verified

Verified on the development PC: the framing (C and C++ agree with an independent Python reference),
and the emulator-side code compiles for both Windows and Android (arm64, NDK 26).

**Not verified: this firmware has not been built with ESP-IDF or run on a board.** The parts most
likely to need a first-hardware fix are the ones that depend on the Wi-Fi driver's behaviour:

Update: the board has since been run against a retail 3DS on a PC (ESP-IDF 5.2.8): discovery, both
join directions (Azahar hosting and Azahar joining) and trading data work. That run found that
hardware ACK generation and delivery of frames addressed to the board's own MAC are mutually
exclusive on this chip, hence the twin-MAC design above. Still untested: Android (USB permission,
the app's JNI link), and long sessions.

Things to look at first if something misbehaves:

1. **Peer retransmissions.** Without hardware ACKs the peer resends frames it thinks were lost; a
   lot of `retry=true` in the log means the join is slow.
2. **The raw-frame sanity-check override.** `-zmuldefs` and the symbol name are driver-version
   specific; a link error or `ESP_ERR_INVALID_ARG` from `esp_wifi_80211_tx` for authentication frames
   points here.
3. **Per-frame rate.** `esp_wifi_config_80211_tx_rate` needs ESP-IDF 5.1 or newer; older versions
   transmit at the default rate.
