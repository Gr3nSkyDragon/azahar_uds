/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version. */
#include "radio.h"

#include <string.h>

#include "esp_event.h"
#include "esp_private/wifi.h"
#include "esp_idf_version.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs_flash.h"
#include "uds_wire.h"

#define BEACON_INTERVAL_US 102400 /* 100 TU */
#define MAX_MPDU 2346
#define RX_HEADER 3               /* channel, rssi, flags */
#define NINTENDO_OUI_0 0x00
#define NINTENDO_OUI_1 0x1F
#define NINTENDO_OUI_2 0x32

/* The Wi-Fi driver refuses to transmit some management frame types (authentication, association,
 * beacons ...) through esp_wifi_80211_tx. The UDS handshake needs all of them, so the check is
 * overridden - see the -zmuldefs link option in main/CMakeLists.txt. */
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3)
{
    (void)arg;
    (void)arg2;
    (void)arg3;
    return 0;
}

static uds_event_sink_t s_sink;
static uint32_t s_txdone_data_reports;
static bool s_wifi_initialized;
static bool s_running;
static uint8_t s_channel = 1;
static uint8_t s_own_mac[6];
static uint8_t s_watch_mac[6];
static bool s_watch_set;
static uds_stats_t s_stats;

static SemaphoreHandle_t s_tx_lock;
static esp_timer_handle_t s_beacon_timer;
static uint8_t s_beacon[MAX_MPDU];
static size_t s_beacon_length;
static uint16_t s_beacon_sequence;
static wifi_phy_rate_t s_current_rate = (wifi_phy_rate_t)-1;

static wifi_phy_rate_t map_rate(uint8_t rate500k)
{
    switch (rate500k) {
    case 2: return WIFI_PHY_RATE_1M_L;
    case 4: return WIFI_PHY_RATE_2M_L;
    case 11: return WIFI_PHY_RATE_5M_L;
    case 22: return WIFI_PHY_RATE_11M_L;
    case 12: return WIFI_PHY_RATE_6M;
    case 18: return WIFI_PHY_RATE_9M;
    case 24: return WIFI_PHY_RATE_12M;
    case 36: return WIFI_PHY_RATE_18M;
    case 48: return WIFI_PHY_RATE_24M;
    case 72: return WIFI_PHY_RATE_36M;
    case 96: return WIFI_PHY_RATE_48M;
    case 108: return WIFI_PHY_RATE_54M;
    default: return WIFI_PHY_RATE_1M_L;
    }
}

static void set_tx_rate(wifi_phy_rate_t rate)
{
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 1, 0)
    if (rate != s_current_rate) {
        if (esp_wifi_config_80211_tx_rate(WIFI_IF_STA, rate) == ESP_OK) s_current_rate = rate;
    }
#else
    (void)rate;
#endif
}

static bool mac_equal(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) == 0; }

/* True if the beacon body carries a Nintendo (00:1F:32) vendor element. */
static bool has_nintendo_element(const uint8_t *frame, size_t length)
{
    size_t offset = 24 + 12; /* management header + beacon fixed fields */
    while (offset + 2 <= length) {
        uint8_t tag = frame[offset];
        uint8_t len = frame[offset + 1];
        offset += 2;
        if (offset + len > length) return false;
        if (tag == 221 && len >= 4 && frame[offset] == NINTENDO_OUI_0 &&
            frame[offset + 1] == NINTENDO_OUI_1 && frame[offset + 2] == NINTENDO_OUI_2)
            return true;
        offset += len;
    }
    return false;
}

/* Which captured frames are worth the USB bandwidth. Azahar makes the final decision; this only
 * drops the neighbourhood's traffic. */
static bool wanted(const uint8_t *frame, size_t length, int type, int subtype)
{
    if (type == 0 && subtype == 8) return has_nintendo_element(frame, length); /* beacon */
    if (type == 0 && (subtype == 4 || subtype == 5)) return false;             /* probes */
    if (type == 1) return false;                                               /* control */
    const uint8_t *a1 = frame + 4, *a2 = frame + 10, *a3 = frame + 16;
    if (mac_equal(a1, s_own_mac) || mac_equal(a2, s_own_mac) || mac_equal(a3, s_own_mac))
        return true;
    if (s_watch_set &&
        (mac_equal(a1, s_watch_mac) || mac_equal(a2, s_watch_mac) || mac_equal(a3, s_watch_mac)))
        return true;
    return false;
}

static void promiscuous_rx(void *buffer, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *packet = buffer;
    if (type == WIFI_PKT_CTRL) {
        /* Only ACKs pass the control filter. One addressed to us means the peer received a
         * unicast frame we sent, which says whether our transmissions are being heard. */
        if (packet->rx_ctrl.sig_len >= 10 && (packet->payload[0] & 0xFC) == 0xD4 &&
            mac_equal(packet->payload + 4, s_own_mac))
            ++s_stats.acks_rx;
        return;
    }
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    ++s_stats.rx_seen;

    /* sig_len counts the trailing 4-byte FCS; the host wants the MPDU without it. */
    size_t length = packet->rx_ctrl.sig_len;
    if (length < 4 + 24) return;
    length -= 4;
    if (length > MAX_MPDU) length = MAX_MPDU;

    const uint8_t *frame = packet->payload;
    const uint16_t frame_control = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
    const int frame_type = (frame_control >> 2) & 3;
    const int subtype = (frame_control >> 4) & 0xF;
    if (!wanted(frame, length, frame_type, subtype)) return;

    static uint8_t event[RX_HEADER + MAX_MPDU];
    event[0] = (uint8_t)packet->rx_ctrl.channel;
    event[1] = (uint8_t)(int8_t)packet->rx_ctrl.rssi;
    event[2] = 0;
    memcpy(event + RX_HEADER, frame, length);
    if (s_sink && s_sink(UDS_EVT_RX, event, RX_HEADER + length)) {
        ++s_stats.rx_forwarded;
    } else {
        ++s_stats.rx_dropped;
    }
}

static esp_err_t transmit_locked(const uint8_t *mpdu, size_t length)
{
    /* en_sys_seq = false: the sequence control field is Azahar's (or the beacon's own). */
    esp_err_t result = esp_wifi_80211_tx(WIFI_IF_STA, mpdu, (int)length, false);
    if (result == ESP_OK) ++s_stats.tx_ok; else ++s_stats.tx_failed;
    if (result == ESP_OK && length >= 10 && !(mpdu[4] & 1)) ++s_stats.tx_unicast;
    return result;
}

static void beacon_tick(void *unused)
{
    (void)unused;
    if (xSemaphoreTake(s_tx_lock, 0) != pdTRUE) return; /* a frame is going out; next tick */
    if (s_running && s_beacon_length >= 36) {
        const uint64_t timestamp = (uint64_t)esp_timer_get_time();
        for (int i = 0; i < 8; ++i) s_beacon[24 + i] = (uint8_t)(timestamp >> (8 * i));
        const uint16_t sequence_control = (uint16_t)((s_beacon_sequence++ & 0x0FFF) << 4);
        s_beacon[22] = (uint8_t)sequence_control;
        s_beacon[23] = (uint8_t)(sequence_control >> 8);
        set_tx_rate(WIFI_PHY_RATE_1M_L);
        if (transmit_locked(s_beacon, s_beacon_length) == ESP_OK) ++s_stats.beacons_sent;
    }
    xSemaphoreGive(s_tx_lock);
}

/* Reports what the radio did with each unicast frame we sent: whether the peer ACKed it, and the
 * first bytes as actually handed to the hardware. Management frames always; data frames only for
 * the first few (the join handshake), so game traffic does not flood the link. */
#define TXDONE_BYTES 48
static void tx_done(uint8_t ifidx, uint8_t *data, uint16_t *length, bool success)
{
    if (ifidx != WIFI_IF_STA || !s_sink || !data || !length || *length < 24) return;
    const uint8_t frame_type = (data[0] >> 2) & 3;
    if (data[4] & 1) return; /* group addressed: no ACK to report */
    if (frame_type == 2 && s_txdone_data_reports >= 30) return;
    if (frame_type == 2) ++s_txdone_data_reports;
    else if (frame_type != 0) return;
    uint8_t event[3 + TXDONE_BYTES];
    const size_t copy = *length < TXDONE_BYTES ? *length : TXDONE_BYTES;
    event[0] = success ? 1 : 0;
    event[1] = (uint8_t)*length;
    event[2] = (uint8_t)(*length >> 8);
    memcpy(event + 3, data, copy);
    s_sink(UDS_EVT_TXDONE, event, 3 + copy);
}

esp_err_t radio_init(uds_event_sink_t sink)
{
    s_sink = sink;
    s_tx_lock = xSemaphoreCreateMutex();
    if (!s_tx_lock) return ESP_ERR_NO_MEM;
    const esp_timer_create_args_t timer_args = {.callback = beacon_tick, .name = "beacon"};
    return esp_timer_create(&timer_args, &s_beacon_timer);
}

static esp_err_t init_wifi_once(void)
{
    if (s_wifi_initialized) return ESP_OK;
    esp_err_t result = nvs_flash_init();
    if (result == ESP_ERR_NVS_NO_FREE_PAGES || result == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        result = nvs_flash_init();
    }
    if (result != ESP_OK) return result;
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_init());
    esp_event_loop_create_default(); /* may already exist */
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    if ((result = esp_wifi_init(&config)) != ESP_OK) return result;
    if ((result = esp_wifi_set_storage(WIFI_STORAGE_RAM)) != ESP_OK) return result;
    if ((result = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK) return result;
    /* 802.11b/g only: the 3DS speaks nothing newer, and it keeps ACK rates plain. */
    if ((result = esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G)) !=
        ESP_OK)
        return result;
    s_wifi_initialized = true;
    return ESP_OK;
}

esp_err_t radio_start(uint8_t channel, const uint8_t mac[6], bool decoy_hw_mac)
{
    if (channel < 1 || channel > 13) return ESP_ERR_INVALID_ARG;
    if (mac[0] & 1) return ESP_ERR_INVALID_ARG; /* the hardware needs an individual address */
    esp_err_t result = init_wifi_once();
    if (result != ESP_OK) return result;

    xSemaphoreTake(s_tx_lock, portMAX_DELAY);
    if (s_running) {
        esp_wifi_set_promiscuous(false);
        esp_wifi_stop();
        s_running = false;
    }
    memcpy(s_own_mac, mac, 6);
    memset(&s_stats, 0, sizeof(s_stats));
    s_txdone_data_reports = 0;
    s_current_rate = (wifi_phy_rate_t)-1;

    /* The MAC can only change while the interface is stopped. This is what makes the hardware
     * acknowledge unicast frames sent to the emulated 3DS. */
    uint8_t hw_mac[6];
    memcpy(hw_mac, mac, 6);
    if (decoy_hw_mac) hw_mac[0] ^= 0x02; /* locally administered twin: still an individual address */
    if ((result = esp_wifi_set_mac(WIFI_IF_STA, hw_mac)) == ESP_OK &&
        (result = esp_wifi_start()) == ESP_OK) {
        esp_wifi_set_ps(WIFI_PS_NONE);
        esp_wifi_set_tx_done_cb(tx_done);
        const wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                                                                 WIFI_PROMIS_FILTER_MASK_DATA |
                                                                 WIFI_PROMIS_FILTER_MASK_CTRL};
        esp_wifi_set_promiscuous_filter(&filter);
        const wifi_promiscuous_filter_t control = {.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ACK};
        esp_wifi_set_promiscuous_ctrl_filter(&control);
        esp_wifi_set_promiscuous_rx_cb(promiscuous_rx);
        if ((result = esp_wifi_set_promiscuous(true)) == ESP_OK &&
            (result = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE)) == ESP_OK) {
            s_channel = channel;
            s_running = true;
            set_tx_rate(WIFI_PHY_RATE_1M_L);
            esp_timer_stop(s_beacon_timer);
            esp_timer_start_periodic(s_beacon_timer, BEACON_INTERVAL_US);
        }
    }
    xSemaphoreGive(s_tx_lock);
    return result;
}

esp_err_t radio_stop(void)
{
    xSemaphoreTake(s_tx_lock, portMAX_DELAY);
    esp_timer_stop(s_beacon_timer);
    s_beacon_length = 0;
    if (s_running) {
        esp_wifi_set_promiscuous(false);
        esp_wifi_stop();
        s_running = false;
    }
    xSemaphoreGive(s_tx_lock);
    return ESP_OK;
}

esp_err_t radio_set_channel(uint8_t channel)
{
    if (!s_running) return ESP_ERR_INVALID_STATE;
    if (channel < 1 || channel > 13) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(s_tx_lock, portMAX_DELAY);
    esp_err_t result = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (result == ESP_OK) s_channel = channel;
    xSemaphoreGive(s_tx_lock);
    return result;
}

esp_err_t radio_tx(const uint8_t *mpdu, size_t length, uint8_t rate500k)
{
    if (!s_running) return ESP_ERR_INVALID_STATE;
    if (length < 10 || length > MAX_MPDU) return ESP_ERR_INVALID_SIZE;
    xSemaphoreTake(s_tx_lock, portMAX_DELAY);
    set_tx_rate(rate500k ? map_rate(rate500k) : WIFI_PHY_RATE_1M_L);
    esp_err_t result = transmit_locked(mpdu, length);
    xSemaphoreGive(s_tx_lock);
    return result;
}

esp_err_t radio_set_beacon(const uint8_t *mpdu, size_t length)
{
    if (length > MAX_MPDU || (length != 0 && length < 36)) return ESP_ERR_INVALID_SIZE;
    xSemaphoreTake(s_tx_lock, portMAX_DELAY);
    if (length) memcpy(s_beacon, mpdu, length);
    s_beacon_length = length;
    xSemaphoreGive(s_tx_lock);
    return ESP_OK;
}

void radio_set_watch(const uint8_t mac[6])
{
    static const uint8_t zero[6] = {0};
    s_watch_set = !mac_equal(mac, zero);
    memcpy(s_watch_mac, mac, 6);
}

void radio_get_stats(uds_stats_t *stats) { *stats = s_stats; }
void radio_note_usb_dropped(void) { ++s_stats.usb_dropped; }
