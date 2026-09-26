idf_component_register(
    SRCS "main.c" "radio.c" "uds_wire.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi esp_event esp_netif esp_timer nvs_flash driver
             esp_hw_support esp_system
)

# radio.c overrides ieee80211_raw_frame_sanity_check (defined in the Wi-Fi driver library) so that
# authentication, association and beacon frames can be injected. Allow the duplicate definition.
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,-zmuldefs")
