/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
 *
 * The 3DS key the Game Boy wrapper needs, stored on the board (NVS) so that a cartridge, which cannot supply one, can trade: the UDS
 * data key, AES key slot 0x2D (KeyN, the "normal" key Azahar reads from aes_keys.txt). It is written once by the host
 * (UDS_CMD_SET_KEY) and never sent back: the host can only ask whether it is there (UDS_CMD_KEY_STATUS). It survives reflashing the
 * firmware, but not a full erase of the flash.
 */
#ifndef UDS_KEYS_H
#define UDS_KEYS_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#define UDS_KEY_SLOT_DATA 0x2D

esp_err_t keys_init(void);
esp_err_t keys_store(uint8_t slot, const uint8_t key[16]);
bool keys_load(uint8_t slot, uint8_t key[16]);
bool keys_present(uint8_t slot);
esp_err_t keys_erase(void);

#endif
