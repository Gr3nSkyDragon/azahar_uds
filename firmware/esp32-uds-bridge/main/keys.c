/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version. */
#include "keys.h"

#include <string.h>

#include "nvs.h"
#include "nvs_flash.h"

#define KEY_NAMESPACE "uds_keys"

static const char *slot_name(uint8_t slot)
{
    return slot == UDS_KEY_SLOT_DATA ? "slot2d" : NULL;
}

esp_err_t keys_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* The partition cannot be used as it is (full, or written by another NVS version): it has to be erased, keys included. */
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    return err;
}

esp_err_t keys_store(uint8_t slot, const uint8_t key[16])
{
    const char *name = slot_name(slot);
    if (!name) return ESP_ERR_NOT_SUPPORTED;
    nvs_handle_t handle;
    esp_err_t err = nvs_open(KEY_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(handle, name, key, 16);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err;
}

bool keys_load(uint8_t slot, uint8_t key[16])
{
    const char *name = slot_name(slot);
    if (!name) return false;
    nvs_handle_t handle;
    if (nvs_open(KEY_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) return false;
    size_t length = 16;
    bool ok = nvs_get_blob(handle, name, key, &length) == ESP_OK && length == 16;
    nvs_close(handle);
    if (!ok) memset(key, 0, 16);
    return ok;
}

bool keys_present(uint8_t slot)
{
    uint8_t key[16];
    bool present = keys_load(slot, key);
    memset(key, 0, sizeof(key));
    return present;
}

esp_err_t keys_erase(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(KEY_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_erase_all(handle);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err;
}
