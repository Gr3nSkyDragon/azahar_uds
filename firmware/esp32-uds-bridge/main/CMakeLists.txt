idf_component_register(
    SRCS "main.c" "radio.c" "uds_wire.c" "keys.c" "gbwrap.c" "display.c" "scene.c" "screen.c"
         # The Game Boy wrapper, copied unchanged from mGBA (mgba_LDN, src/gb/sio): see gbwrap/README.md.
         "gbwrap/uds-wire.c" "gbwrap/uds-cable.c" "gbwrap/uds-session.c" "gbwrap/uds-pia.c" "gbwrap/uds-room.c"
         "gbwrap/uds-ccmp.c"
    INCLUDE_DIRS "." "gbwrap/include"
    REQUIRES esp_wifi esp_event esp_netif esp_timer nvs_flash driver
             esp_hw_support esp_system esp_rom
)

# radio.c overrides ieee80211_raw_frame_sanity_check (defined in the Wi-Fi driver library) so that
# authentication, association and beacon frames can be injected. Allow the duplicate definition.
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,-zmuldefs")
