# The Game Boy wrapper's shared files

`uds-*.c` here and `include/mgba/internal/gb/sio/uds-*.h` are copied **unchanged** from mGBA's Virtual Console wrapper
(github.com/Gr3nSkyDragon/mgba_LDN, branch `mgba-ldn`, `src/gb/sio` and `include/mgba/internal/gb/sio`; commit `af8515454`), where
their unit tests live (`uds-wire-test`, `uds-cable-test`, `uds-test`, `uds-ccmp-test`). They are MPL-2.0, which permits this
combination with the GPLv2+ firmware.

| File | What it is |
| --- | --- |
| `uds-wire.c` | the permanent slave on the link cable: role, syncs, menus, block alignment, mail |
| `uds-cable.c` | the sync and menu translation it uses |
| `uds-session.c`, `uds-pia.c` | the Pia session: setup, reliable unit stream, HMAC |
| `uds-room.c` | the join: beacon, authentication, EAPoL, node id |
| `uds-ccmp.c` | AES, CCMP and the data key |

`include/mgba-util/` stands in for the two mGBA utility headers they include (`common.h`, `md5.h` on top of the ESP32 ROM's MD5).
What took the PC's place (the join on this board's radio instead of over USB, and the task that runs it) is `../gbwrap.c`.

To update: copy the six files and their headers again from mGBA, rebuild, and note the commit above.
