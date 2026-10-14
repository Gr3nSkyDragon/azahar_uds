/* Copyright 2026 Azahar Emulator Project. Licensed under GPLv2 or any later version.
 *
 * The Game Boy wrapper mode (see gbwrap.h). The join on the air below is mGBA's uds-air-radio.c and uds-joiner.c with this board's
 * radio (radio.h) in place of the USB link to it: the same scan, host choice, authentication, association, CCMP and replay check.
 */
#include "gbwrap.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/uart.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/ringbuf.h"
#include "freertos/task.h"
#include "keys.h"
#include "radio.h"
#include "uds_wire.h"

#include <mgba/internal/gb/sio/uds-ccmp.h>
#include <mgba/internal/gb/sio/uds-clock.h>
#include <mgba/internal/gb/sio/uds-room.h>
#include <mgba/internal/gb/sio/uds-session.h>
#include <mgba/internal/gb/sio/uds-wire.h>

#define TASK_STACK (32 * 1024) /* the join keeps 4 KB datagrams on the stack, a few deep */
#define TASK_PRIORITY 7
#define QUEUE_LENGTH 64
#define RX_RING_BYTES (32 * 1024)
#define STATS_MS 5000

/* The game: the first 11 characters of the cartridge header's title (0x134), as mGBA's game table keys them. */
#define TITLE_KEY 11
struct gb_game {
    const char *title;
    bool gen2;
    const char *name; /* on the board's screen */
};
static const struct gb_game kGames[] = {
    {"POKEMON RED", false, "PKMN RED"},  {"POKEMON BLU", false, "PKMN BLUE"},  {"POKEMON YEL", false, "PKMN YELLOW"},
    {"POKEMON_GLD", true, "PKMN GOLD"},  {"POKEMON_SLV", true, "PKMN SILVER"}, {"PM_CRYSTAL", true, "PKMN CRYSTAL"},
};
/* A cartridge whose header nobody can read (behind a real GB-Link, or GB_START's detect flag): the wire takes its generation from
 * its first sync (udsWireSetGeneration 0). */
static const struct gb_game kCartridge = {"", false, "GB CARTRIDGE"};
/* The name the 3DS is shown when no host gave one (the board on its own with a GB-Link). */
static const uint16_t kStandaloneName[UDS_NAME_WORDS] = {'G', 'B', '-', 'L', 'i', 'n', 'k'};

/* Every Game Boy Virtual Console Pokemon network: the comm id is the title id plus 0x10 (Red 00171010, Gold 00172610, Silver
 * 00172710), so the Gen 1 titles share 00171xxx and the Gen 2 ones 00172xxx. Both are accepted whatever the cartridge is: a Gen 2
 * cartridge trades with a Gen 1 host through the Time Capsule. */
#define COMM_ID 0x00170000u
#define COMM_MASK 0xFFFFC000u

/* The air, as mGBA's uds-air-radio.c. */
#define HOP_MS 400
#define HOST_SILENT_MS 6000
#define CLIENT_DATA_RATE 22 /* 11 Mbit/s, in 500 kbit/s units: the rate that worked for Azahar as a client */
#define MAX_HOSTS 8

/* The leave, as mGBA's uds-joiner.h. */
#define LEAVE_RESEND_MS 150
#define LEAVE_DELAY_MS 400
#define REJOIN_HOLD_MS 6000

static const uint8_t kChannels[3] = {1, 6, 11};
static const uint8_t kPassphrase[12] = {'T', 'R', 'L', '_', 'N', 'E', 'T', 'W', 'O', 'R', 'K', 0};

struct air_host {
    bool valid;
    uint8_t mac[6];
    uint8_t channel;
    uint32_t comm_id;
    uint32_t network_id;
    uint8_t id;
};

struct request {
    uint8_t type;
    uint8_t seq;
    uint8_t length;
    uint8_t data[72]; /* GB_START's 37, or a Pico frame (5 + up to 64) */
};
/* Requests of the board's own, beside the host's commands (uds_wire.h). */
#define GBWRAP_REQ_UART 0xF0 /* bytes the Pico sent on the UART */
#define GBWRAP_REQ_HOST 0xF1 /* a host said HELLO */

static gbwrap_send_t s_send;
static QueueHandle_t s_queue;
static RingbufHandle_t s_rx_ring;
static volatile bool s_active;

/* Everything below is owned by the wrapper task. */
static const struct gb_game *s_game;
static bool s_host;        /* started by a host's GB_START: it gets the state, the stats and (with the log flag) the log */
static bool s_host_claimed; /* a host has said HELLO since boot: the board no longer starts on its own */
static bool s_trace;
static uint32_t s_start_ms;
static uint32_t s_now;
static uint8_t s_mac[6];
static uint16_t s_name[UDS_NAME_WORDS];

static struct {
    uint8_t slot_key[16];
    struct air_host hosts[MAX_HOSTS];
    bool have_host;
    struct air_host host;
    uint8_t data_key[16];
    bool assoc_sent;
    uint64_t tx_packet_number;
    uint16_t tx_sequence;
    uint64_t last_rx_packet_number;
    bool have_rx_packet_number;
    uint32_t last_host_frame_ms;
    uint8_t channel;
    unsigned hop_index;
    uint32_t last_hop_ms;
    unsigned beacons_seen, frames_sent, frames_received, dropped_decrypt, dropped_replay, dropped_other, tx_failed;
} s_air;

static struct UDSRoom s_room;
static struct UDSSession s_session;
static bool s_session_active;
static uint32_t s_leave_start_ms;
static bool s_leave_resent;
static struct UDSWire s_wire;
static unsigned s_exchanges;

/* Who is on the other end of the cartridge's cable (GB_START flag bit 1, see uds_wire.h). XFER: the cartridge is the master and the
 * host sends each transfer it clocked. PICO: the cartridge sits behind a GB-Link Pico in Game Boy mode, which only clocks, so this
 * board drives the clock (uds-clock.c) and the Pico shifts each byte; the Pico is a real one or mGBA standing in for one, and either
 * way speaks the Pico's own frames (GB-Link GBLink-Firmware 2.2.7: serialLayer, gb.cpp, control.hpp). */
enum front { FRONT_XFER, FRONT_PICO };
static uint8_t s_front;
static struct UDSClock s_clock;

/* Where the Pico is. USB: the host stands in for it (mGBA), its frames inside GB_PICO. UART: a GB-Link wired to this board, as
 * GB-Link's own ESP32 firmware has it (firmware/common/pico_link.c: UART 1 at 921600, its S3 build on GPIO2 to the Pico's GP9 and
 * GPIO1 from its GP8; the Pico's bridge UART is uart1, GP8 TX, GP9 RX). With nothing on USB the board starts on its own: it asks
 * the UART for Game Boy mode now and then, and a Pico that answers starts the wrapper (start_standalone). A host's HELLO ends that
 * and stops a wrapper running so, so that the host has the board. */
#define PICO_UART UART_NUM_1
#define PICO_UART_BAUD 921600
#define PICO_PROBE_US 1000000
static bool s_pico_uart;     /* the running wrapper's Pico is on the UART */
static bool s_uart_ok;       /* the UART is set up (CONFIG_UDS_PICO_LINK) */
static bool s_feeding_uart;  /* pico_frame: the frame came from the UART */
static int64_t s_probe_us;

#define PICO_SYNC0 0x47 /* 'G' */
#define PICO_SYNC1 0x42 /* 'B' */
#define PICO_CHANNEL_COMMAND 0x00
#define PICO_CHANNEL_DATA 0x01
#define PICO_CHANNEL_STATUS 0x02
#define PICO_MAX_PAYLOAD 64
#define PICO_CMD_SET_MODE 0x00 /* {mode} */
#define PICO_CMD_CANCEL 0x01
#define PICO_MODE_GB_LINK 0x02
#define PICO_CMD_SET_TIMING 0x30 /* {us between transfers:u24 LE, bytes per transfer:u8} */
#define PICO_STATUS_GB_MODE_ACTIVE 0xFF0A
#define PICO_STATUS_GB_SESSION_FINISHED 0xFF0C
#define PICO_SETUP_RESEND_US 500000
#define PICO_REPLY_TIMEOUT_US 250000
/* The waits after an exchange (uds-clock.h), in real time. mGBA's Local mode, where these were tested, counts them in emulated
 * cycles (105336, 8389 and 4194 at 8388608 a second: 12.6 ms, 1 ms, 0.5 ms) and adds 75 us for the UART; here the round trip to the
 * Pico comes on top, and it differs by transport: microseconds on a UART, a few milliseconds through a PC that relays both USB ports
 * (uds-gblink-relay), where each byte crosses USB four times. In idle, sync and menu the clock must reach the cartridge in every frame
 * (16.7 ms): a Gen 1 sync's last loop is ten frames of one 00 each that do not wait for the clock, and the wire counts all ten. So the
 * loop gap is what is left of Local's period after the measured round trip (its running average), never below the floor. */
#define PICO_LOOP_PERIOD_US 12557
#define PICO_GAP_LOOP_MIN_US 2000
#define PICO_GAP_ROLE_US 1000
#define PICO_CMD_SET_VOLTAGE_5V 0x41 /* a hardware command: an official GB-Link sets its link port's voltage in software (the DIY
                                        board's SW1 does it by hand); 5 V for a Game Boy, as GB-Link's web page sends for Gen 1 and 2 */
#define PICO_GAP_BYTE_US 500

static struct {
    bool running;           /* the Pico is in Game Boy mode: clock */
    bool awaiting;          /* a byte is out, its reply not back */
    enum UDSClockGap gap;   /* the wait after the byte that is out */
    int64_t setup_us;       /* when the mode was last asked for */
    int64_t sent_us;
    int64_t next_us;        /* when the next byte may go */
    unsigned timeouts, stray_replies, setups;
    uint32_t round_trips, round_trip_max_us; /* since the last report */
    uint32_t round_trip_avg_us;               /* running average, for the loop gap */
    uint64_t round_trip_sum_us;
    /* The frame being received (the Pico's serialLayer parser). */
    uint8_t rx_state, rx_channel;
    uint16_t rx_length, rx_pos;
    uint8_t rx[PICO_MAX_PAYLOAD];
} s_pico;

static uint8_t s_reported[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint32_t s_last_stats_ms;

/* The screen's copy (gbwrap_get_status), written by the wrapper task. */
static portMUX_TYPE s_status_lock = portMUX_INITIALIZER_UNLOCKED;
static gbwrap_status_t s_status;

#define RX_PER_PASS 4
#define SLOW_PASS_US 100000
static struct {
    uint32_t max_pass_us;
    uint32_t max_frame_us;
    uint32_t frames;
    uint32_t last_report_ms;
} s_timing;
static volatile uint32_t s_rx_dropped; /* frames the radio delivered while the queue was full */

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000) - s_start_ms;
}

static void logf_host(const char *format, ...)
{
    if (!s_trace || !s_host) return;
    char line[256];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (length < 0) return;
    if ((size_t)length >= sizeof(line)) length = sizeof(line) - 1;
    s_send(UDS_EVT_LOG, 0, (const uint8_t *)line, (size_t)length);
}

static void send_status(uint8_t request_type, uint8_t seq, int32_t result)
{
    uint8_t payload[5] = {request_type};
    for (int i = 0; i < 4; ++i) payload[1 + i] = (uint8_t)((uint32_t)result >> (8 * i));
    s_send(UDS_EVT_STATUS, seq, payload, sizeof(payload));
}

/* The air ------------------------------------------------------------------------------------------------------------------ */

static bool group_address(const uint8_t *mac)
{
    return mac[0] & 1;
}

static void room_receive(const uint8_t *datagram, size_t size);

static void air_deliver(uint8_t type, uint8_t channel, const uint8_t *transmitter, const uint8_t *destination,
                        const uint8_t *data, size_t size)
{
    struct UDSRoomPacket packet;
    memset(&packet, 0, sizeof(packet));
    packet.type = type;
    packet.channel = channel;
    memcpy(packet.transmitter, transmitter, 6);
    memcpy(packet.destination, destination, 6);
    packet.data = data;
    packet.size = size;
    static uint8_t datagram[UDS_BRIDGE_MAX_DATAGRAM]; /* only the wrapper task delivers, and never re-entrantly */
    size_t length = udsRoomEncode(datagram, sizeof(datagram), &packet);
    if (length) {
        ++s_air.frames_received;
        room_receive(datagram, length);
    }
}

static void air_transmit(const uint8_t *frame, size_t size, uint8_t rate)
{
    if (radio_tx(frame, size, rate) == ESP_OK) {
        ++s_air.frames_sent;
    } else {
        ++s_air.tx_failed;
    }
}

static struct air_host *air_find_host(const uint8_t *mac)
{
    for (unsigned i = 0; i < MAX_HOSTS; ++i) {
        if (s_air.hosts[i].valid && !memcmp(s_air.hosts[i].mac, mac, 6)) return &s_air.hosts[i];
    }
    return NULL;
}

static void air_remember_host(const uint8_t *mac, uint8_t channel, const struct UDSRoomHost *info)
{
    struct air_host *host = air_find_host(mac);
    if (!host) {
        unsigned i;
        for (i = 0; i < MAX_HOSTS && s_air.hosts[i].valid; ++i) {
        }
        if (i == MAX_HOSTS) i = 0; /* the table is full of other hosts: replace the oldest slot */
        host = &s_air.hosts[i];
        memset(host, 0, sizeof(*host));
        host->valid = true;
        memcpy(host->mac, mac, 6);
    }
    host->channel = channel;
    host->comm_id = info->commId;
    host->network_id = info->networkId;
    host->id = info->id;
}

/* The room has sent its first frame to a host: tune to its channel, watch its address and make the data key. */
static bool air_choose_host(const uint8_t *mac)
{
    struct air_host *known = air_find_host(mac);
    if (!known) return false;
    s_air.host = *known;
    s_air.have_host = true;
    s_air.assoc_sent = false;
    s_air.tx_packet_number = 1;
    s_air.tx_sequence = 0;
    s_air.have_rx_packet_number = false;
    s_air.last_host_frame_ms = s_now;
    udsCcmpDeriveKey(s_air.slot_key, kPassphrase, sizeof(kPassphrase), known->comm_id, known->network_id, known->mac, known->id,
                     s_air.data_key);
    if (s_air.channel != known->channel) {
        radio_set_channel(known->channel);
        s_air.channel = known->channel;
    }
    radio_set_watch(known->mac);
    logf_host("joining %02x:%02x:%02x:%02x:%02x:%02x on channel %u, comm id %08lx", known->mac[0], known->mac[1], known->mac[2],
              known->mac[3], known->mac[4], known->mac[5], known->channel, (unsigned long)known->comm_id);
    return true;
}

static void air_send_assoc_request(void)
{
    uint8_t body[30], frame[UDS_80211_HEADER + 30];
    udsBuildAssocRequestBody(body, s_air.host.network_id);
    size_t size = udsBuildMgmtFrame(frame, sizeof(frame), UDS_FC_ASSOC_REQUEST, s_mac, s_air.host.mac, s_air.host.mac,
                                    s_air.tx_sequence++, body, sizeof(body));
    if (size) air_transmit(frame, size, 0);
}

/* A frame from the radio: {channel, rssi, flags, mpdu}. */
static void air_rx(const uint8_t *event, size_t event_length)
{
    if (event_length < 3 + UDS_80211_HEADER) return;
    const uint8_t channel = event[0];
    const uint8_t *m = event + 3;
    const size_t length = event_length - 3;
    uint16_t frame_control = (uint16_t)(m[0] | (m[1] << 8));
    unsigned type = (frame_control >> 2) & 3, subtype = (frame_control >> 4) & 0xF;
    const uint8_t *a1 = &m[4], *a2 = &m[10];

    if (type == 0 && subtype == 8) { /* beacon */
        struct UDSRoomHost info;
        memset(&info, 0, sizeof(info));
        if (length >= UDS_80211_HEADER + 12 && udsRoomParseBeacon(m + UDS_80211_HEADER, length - UDS_80211_HEADER, &info)) {
            ++s_air.beacons_seen;
            air_remember_host(a2, channel, &info);
            if (s_air.have_host && !memcmp(a2, s_air.host.mac, 6)) s_air.last_host_frame_ms = s_now;
            air_deliver(UDS_PACKET_BEACON, channel, a2, a1, m + UDS_80211_HEADER, length - UDS_80211_HEADER);
        }
        return;
    }
    if (!s_air.have_host || memcmp(a2, s_air.host.mac, 6)) return; /* not from the host we are joining */
    if (memcmp(a1, s_mac, 6) && !group_address(a1)) return;         /* for someone else */
    s_air.last_host_frame_ms = s_now;
    const uint8_t *body = m + UDS_80211_HEADER;
    size_t body_length = length - UDS_80211_HEADER;

    if (type == 0) {
        if (subtype == 0xB && body_length >= 6) { /* authentication */
            air_deliver(UDS_PACKET_AUTH, channel, a2, a1, body, body_length);
            if (body[2] == 2 && !s_air.assoc_sent) { /* SEQ2: now the association request, which the room does not know about */
                s_air.assoc_sent = true;
                air_send_assoc_request();
            }
        } else if (subtype == 1 && body_length >= 6) { /* association response */
            air_deliver(UDS_PACKET_ASSOC_RESPONSE, channel, a2, a1, body, body_length);
        } else if (subtype == 0xC) { /* deauthentication */
            s_air.assoc_sent = false;
            air_deliver(UDS_PACKET_DEAUTH, channel, a2, a1, body, body_length);
        }
        return;
    }
    if (type == 2 && (frame_control & 0x4000)) { /* protected data */
        static uint8_t plain[UDS_BRIDGE_MAX_DATAGRAM];
        size_t plain_length = 0;
        struct UDSDataFrameInfo info;
        if (length > sizeof(plain) + UDS_DATA_OVERHEAD) {
            ++s_air.dropped_other;
            return;
        }
        if (!udsOpenDataFrame(s_air.data_key, m, length, plain, &plain_length, &info)) {
            ++s_air.dropped_decrypt;
            return;
        }
        /* The host retransmits what the board did not acknowledge: the retries repeat the packet number. */
        if (s_air.have_rx_packet_number && info.packetNumber <= s_air.last_rx_packet_number) {
            ++s_air.dropped_replay;
            return;
        }
        s_air.have_rx_packet_number = true;
        s_air.last_rx_packet_number = info.packetNumber;
        air_deliver(UDS_PACKET_DATA, channel, a2, a1, plain, plain_length);
        return;
    }
    ++s_air.dropped_other;
}

static void air_poll(void)
{
    if (s_air.have_host) {
        if (s_now - s_air.last_host_frame_ms > HOST_SILENT_MS) {
            s_air.have_host = false; /* the host is gone: scan again */
            radio_set_watch((const uint8_t[6]){0, 0, 0, 0, 0, 0});
            logf_host("the host went silent: scanning");
        }
    } else if (s_now - s_air.last_hop_ms >= HOP_MS) {
        s_air.hop_index = (s_air.hop_index + 1) % 3;
        s_air.channel = kChannels[s_air.hop_index];
        radio_set_channel(s_air.channel);
        s_air.last_hop_ms = s_now;
    }
}

/* A datagram from the room (uds-room.h form) goes out on the air. */
static void air_send(const uint8_t *datagram, size_t size)
{
    struct UDSRoomPacket packet;
    if (!udsRoomDecode(datagram, size, &packet)) return;
    if (packet.type == UDS_PACKET_AUTH) {
        if (!s_air.have_host || memcmp(s_air.host.mac, packet.destination, 6)) {
            if (!air_choose_host(packet.destination)) {
                ++s_air.dropped_other;
                return;
            }
        }
        uint8_t frame[UDS_80211_HEADER + 16];
        size_t length = udsBuildMgmtFrame(frame, sizeof(frame), UDS_FC_AUTH, s_mac, s_air.host.mac, s_air.host.mac,
                                          s_air.tx_sequence++, packet.data, packet.size > 16 ? 16 : packet.size);
        if (length) air_transmit(frame, length, 0);
        return;
    }
    if (packet.type == UDS_PACKET_DEAUTH) {
        /* Leaving the host, as a 3DS joiner does when its game leaves the room. */
        if (s_air.have_host) {
            uint8_t frame[UDS_80211_HEADER + 4];
            size_t length = udsBuildMgmtFrame(frame, sizeof(frame), UDS_FC_DEAUTH, s_mac, s_air.host.mac, s_air.host.mac,
                                              s_air.tx_sequence++, packet.data, packet.size > 2 ? 2 : packet.size);
            if (length) air_transmit(frame, length, 0);
        }
        return;
    }
    if (packet.type == UDS_PACKET_DATA && s_air.have_host) {
        static uint8_t frame[UDS_BRIDGE_MAX_DATAGRAM + UDS_DATA_OVERHEAD];
        size_t length = udsBuildDataFrame(frame, sizeof(frame), s_air.data_key, packet.data, packet.size, s_mac, s_air.host.mac,
                                          s_air.host.mac, UDS_DS_TO, s_air.tx_packet_number++, s_air.tx_sequence++);
        if (length) air_transmit(frame, length, CLIENT_DATA_RATE);
    }
}

/* The joiner, as mGBA's uds-joiner.c ---------------------------------------------------------------------------------------- */

static void room_send(void *context, const uint8_t *datagram, size_t size)
{
    (void)context;
    air_send(datagram, size);
}

static void session_send(void *context, const uint8_t *frame, size_t size)
{
    (void)context;
    udsRoomSendPia(&s_room, frame, size);
}

static void room_pia(void *context, const uint8_t *payload, size_t size)
{
    (void)context;
    if (s_session_active) udsSessionReceive(&s_session, s_now, payload, size);
}

static void room_joined(void *context, const struct UDSRoomHost *host)
{
    (void)context;
    struct UDSSessionConfig config;
    memset(&config, 0, sizeof(config));
    /* The Pia connection id is random per session (2..255). The setup sequence values count from the low 32 bits of the 3DS
     * tick clock, which only has to look like one. */
    config.connectionId = 2 + rand() % 254;
    config.tickBase = 0x25C3B5D2F0ULL + ((uint64_t)(rand() & 0xFFFF) << 16);
    config.sequenceBase = (uint32_t)config.tickBase;
    memcpy(config.appData, host->appData, sizeof(config.appData));
    memcpy(config.name, s_name, sizeof(config.name));
    config.profileRole = 0x06;
    config.gameRoleFlags[0] = 0x01;
    config.gameRoleFlags[1] = 0x01;
    udsSessionInit(&s_session, &config, session_send, NULL);
    udsSessionStart(&s_session, s_now);
    s_session_active = true;
    logf_host("joined: node %u", (unsigned)host->nodeId);
}

static void room_receive(const uint8_t *datagram, size_t size)
{
    udsRoomReceive(&s_room, s_now, datagram, size);
}

static void joiner_poll(void)
{
    udsRoomPoll(&s_room, s_now);
    if (udsWireGeneration(&s_wire) == 2 && s_session_active && s_session.hostLeaving) {
        /* The host's game is leaving the room. Its VC waits about five seconds for its partner's end-of-session record and then
         * closes the network: answer with ours (once more a moment later, in case the first is lost), then leave the network as a
         * 3DS joiner does. */
        if (!s_leave_start_ms) {
            s_leave_start_ms = s_now ? s_now : 1;
            udsSessionSendLeave(&s_session, s_now);
        } else if (s_now - s_leave_start_ms >= LEAVE_RESEND_MS && !s_leave_resent) {
            s_leave_resent = true;
            udsSessionSendLeave(&s_session, s_now);
        } else if (s_now - s_leave_start_ms >= LEAVE_DELAY_MS) {
            s_session_active = false;
            s_leave_start_ms = 0;
            s_leave_resent = false;
            udsRoomLeave(&s_room, s_now, REJOIN_HOLD_MS);
        }
    }
    if (s_session_active) {
        udsSessionPoll(&s_session, s_now);
        if (s_session.state == UDS_STATE_CLOSED) {
            s_session_active = false;
            s_room.state = UDS_ROOM_SCAN; /* the host is gone: wait for the next beacon */
            logf_host("the session closed: scanning");
        }
    }
}

/* The cartridge side: the permanent slave's unit port is the session ------------------------------------------------------ */

static bool port_ready(void *context)
{
    (void)context;
    return s_session_active && s_session.state == UDS_STATE_JOINED;
}

static bool port_queue(void *context, uint8_t byte)
{
    (void)context;
    return udsSessionQueueUnit(&s_session, byte);
}

static void port_flush(void *context)
{
    (void)context;
    udsSessionFlush(&s_session, s_now);
}

static bool port_pop(void *context, uint8_t *byte)
{
    (void)context;
    return udsSessionPopUnit(&s_session, byte);
}

static bool port_peek(void *context, uint8_t *byte)
{
    (void)context;
    return udsSessionPeekUnit(&s_session, byte);
}

static size_t port_waiting(void *context)
{
    (void)context;
    return udsSessionUnitsWaiting(&s_session);
}

static void port_trace(void *context, const char *line)
{
    (void)context;
    logf_host("%s", line);
}

/* The cartridge behind a Pico: this board drives the clock (uds-clock.c) ----------------------------------------------------- */

static void clock_trace(void *context, const char *line)
{
    (void)context;
    logf_host("%s", line);
}

/* One frame to the Pico: on the UART, or to the host (mGBA standing in for a Pico) inside GB_PICO. */
static void pico_send_to(bool uart, uint8_t channel, const uint8_t *payload, size_t length)
{
    uint8_t frame[5 + PICO_MAX_PAYLOAD];
    if (length > PICO_MAX_PAYLOAD) return;
    frame[0] = PICO_SYNC0;
    frame[1] = PICO_SYNC1;
    frame[2] = channel;
    frame[3] = (uint8_t)length;
    frame[4] = (uint8_t)(length >> 8);
    if (length) memcpy(frame + 5, payload, length);
    if (uart) {
        if (s_uart_ok) uart_write_bytes(PICO_UART, frame, 5 + length);
    } else {
        s_send(UDS_EVT_GB_PICO, 0, frame, 5 + length);
    }
}

static void pico_send(uint8_t channel, const uint8_t *payload, size_t length)
{
    pico_send_to(s_pico_uart, channel, payload, length);
}

static int32_t start_standalone(void);

/* The board may start on its own: the UART is set up, no host has claimed the board and the 3DS key is stored. */
static bool standalone_allowed(void)
{
    return s_uart_ok && !s_host_claimed && keys_present(UDS_KEY_SLOT_DATA);
}

static int64_t gap_us(enum UDSClockGap gap)
{
    switch (gap) {
    case UDS_CLOCK_GAP_ROLE: return PICO_GAP_ROLE_US;
    case UDS_CLOCK_GAP_BYTE: return PICO_GAP_BYTE_US;
    case UDS_CLOCK_GAP_LOOP:
    default: {
        const int64_t gap = PICO_LOOP_PERIOD_US - (int64_t)s_pico.round_trip_avg_us;
        return gap < PICO_GAP_LOOP_MIN_US ? PICO_GAP_LOOP_MIN_US : gap;
    }
    }
}

/* The byte that was out came back (or was given up on): the clock's rules take it, and the next waits its gap. */
static void pico_exchanged(uint8_t reply)
{
    const uint32_t round_trip_us = (uint32_t)(esp_timer_get_time() - s_pico.sent_us);
    ++s_pico.round_trips;
    s_pico.round_trip_sum_us += round_trip_us;
    if (round_trip_us > s_pico.round_trip_max_us) s_pico.round_trip_max_us = round_trip_us;
    if (round_trip_us < PICO_REPLY_TIMEOUT_US) { /* a byte given up on is not a round trip */
        s_pico.round_trip_avg_us = s_pico.round_trip_avg_us ? (s_pico.round_trip_avg_us * 7 + round_trip_us) / 8 : round_trip_us;
    }
    s_pico.awaiting = false;
    udsClockExchanged(&s_clock, s_now, reply);
    ++s_exchanges;
    s_pico.next_us = esp_timer_get_time() + gap_us(s_pico.gap);
}

static void pico_frame(uint8_t channel, const uint8_t *payload, size_t length)
{
    if (!s_active) {
        /* Nothing runs: only a Pico on the UART answering the board's own SetMode starts the wrapper. */
        const bool mode_active = channel == PICO_CHANNEL_STATUS && length >= 2 &&
                                 (uint16_t)(payload[0] | (payload[1] << 8)) == PICO_STATUS_GB_MODE_ACTIVE;
        if (!s_feeding_uart || !mode_active || !standalone_allowed() || start_standalone() != ESP_OK) return;
    } else if (s_front != FRONT_PICO || s_feeding_uart != s_pico_uart) {
        return; /* a frame from the other transport than the running wrapper's Pico */
    }
    if (channel == PICO_CHANNEL_STATUS && length >= 2) {
        const uint16_t status = (uint16_t)(payload[0] | (payload[1] << 8));
        if (status == PICO_STATUS_GB_MODE_ACTIVE && !s_pico.running) {
            /* The Pico waits 1 ms after each byte before it answers unless told otherwise: the gaps are this board's (uds-clock.h). */
            const uint8_t timing[5] = {PICO_CMD_SET_TIMING, 0, 0, 0, 1};
            pico_send(PICO_CHANNEL_COMMAND, timing, sizeof(timing));
            s_pico.running = true;
            s_pico.awaiting = false;
            s_pico.next_us = esp_timer_get_time();
            logf_host("pico: Game Boy mode active; clocking");
        } else if (status == PICO_STATUS_GB_SESSION_FINISHED && s_pico.running) {
            s_pico.running = false;
            s_pico.setup_us = 0;
            logf_host("pico: it left Game Boy mode; asking again");
        }
        return;
    }
    if (channel == PICO_CHANNEL_DATA && length >= 1) {
        if (s_pico.awaiting) {
            pico_exchanged(payload[0]); /* one byte goes out at a time */
        } else {
            ++s_pico.stray_replies;
        }
    }
}

/* The Pico's frames, byte by byte as its own serialLayer parses them, so that a stream from a UART can be fed in the same way. */
static void pico_feed(uint8_t b)
{
    switch (s_pico.rx_state) {
    case 0:
        if (b == PICO_SYNC0) s_pico.rx_state = 1;
        break;
    case 1:
        if (b == PICO_SYNC1) s_pico.rx_state = 2;
        else if (b != PICO_SYNC0) s_pico.rx_state = 0;
        break;
    case 2:
        s_pico.rx_channel = b;
        s_pico.rx_state = 3;
        break;
    case 3:
        s_pico.rx_length = b;
        s_pico.rx_state = 4;
        break;
    case 4:
        s_pico.rx_length |= (uint16_t)(b << 8);
        s_pico.rx_pos = 0;
        if (s_pico.rx_length > PICO_MAX_PAYLOAD) {
            s_pico.rx_state = 0; /* oversized: resynchronize */
        } else if (!s_pico.rx_length) {
            pico_frame(s_pico.rx_channel, s_pico.rx, 0);
            s_pico.rx_state = 0;
        } else {
            s_pico.rx_state = 5;
        }
        break;
    default:
        s_pico.rx[s_pico.rx_pos++] = b;
        if (s_pico.rx_pos >= s_pico.rx_length) {
            pico_frame(s_pico.rx_channel, s_pico.rx, s_pico.rx_length);
            s_pico.rx_state = 0;
        }
        break;
    }
}

/* GB_PICO {Pico frame} from the host, or bytes from the UART. Each transport has its frames checked against the running wrapper's in
 * pico_frame. */
static void pico_receive(const struct request *request, bool uart)
{
    if (!s_active && !uart) return;
    s_feeding_uart = uart;
    for (uint8_t i = 0; i < request->length; ++i) pico_feed(request->data[i]);
}

/* With nothing running and the board free to start on its own: ask a Pico on the UART for Game Boy mode now and then. */
static void probe_pico(void)
{
    const int64_t now_us = esp_timer_get_time();
    if (s_probe_us && now_us - s_probe_us < PICO_PROBE_US) return;
    s_probe_us = now_us;
    const uint8_t mode[2] = {PICO_CMD_SET_MODE, PICO_MODE_GB_LINK};
    pico_send_to(true, PICO_CHANNEL_COMMAND, mode, sizeof(mode));
}

/* Each pass: until the Pico is in Game Boy mode ask for it; then one byte at a time, each after the gap the last one chose. */
static void pico_poll(void)
{
    const int64_t now_us = esp_timer_get_time();
    if (!s_pico.running) {
        if (!s_pico.setup_us || now_us - s_pico.setup_us >= PICO_SETUP_RESEND_US) {
            const uint8_t voltage[1] = {PICO_CMD_SET_VOLTAGE_5V};
            const uint8_t mode[2] = {PICO_CMD_SET_MODE, PICO_MODE_GB_LINK};
            pico_send(PICO_CHANNEL_COMMAND, voltage, sizeof(voltage));
            pico_send(PICO_CHANNEL_COMMAND, mode, sizeof(mode));
            s_pico.setup_us = now_us;
            if (++s_pico.setups == 1) logf_host("pico: asking for Game Boy mode");
        }
        return;
    }
    if (s_pico.awaiting) {
        if (now_us - s_pico.sent_us > PICO_REPLY_TIMEOUT_US) {
            ++s_pico.timeouts;
            logf_host("pico: no reply to a byte in %d ms (%u so far): taken as FF, nobody shifted", (int)(PICO_REPLY_TIMEOUT_US / 1000),
                      s_pico.timeouts);
            pico_exchanged(0xFF);
        }
        return;
    }
    if (s_wire.phase == UDS_WIRE_DOWN || now_us < s_pico.next_us) return;
    s_pico.gap = udsClockGap(&s_clock);
    uint8_t byte;
    if (!udsClockPrepare(&s_clock, s_now, &byte)) return; /* the mail hold: look again on the next pass */
    pico_send(PICO_CHANNEL_DATA, &byte, 1);
    s_pico.awaiting = true;
    s_pico.sent_us = now_us;
}

/* The task --------------------------------------------------------------------------------------------------------------- */

static uint8_t stage(void)
{
    switch (s_room.state) {
    case UDS_ROOM_SCAN: return GBWRAP_SCANNING;
    case UDS_ROOM_AUTH:
    case UDS_ROOM_EAPOL: return GBWRAP_JOINING;
    case UDS_ROOM_JOINED: break;
    }
    if (!s_session_active) return GBWRAP_JOINED;
    switch (s_session.state) {
    case UDS_STATE_IDLE:
    case UDS_STATE_SETUP: return GBWRAP_SETUP;
    case UDS_STATE_CLOSED: return GBWRAP_CLOSED;
    case UDS_STATE_JOINED: break;
    }
    switch (s_wire.phase) {
    case UDS_WIRE_DOWN: return GBWRAP_CABLE_DOWN;
    case UDS_WIRE_ROLE: return GBWRAP_ROLES;
    case UDS_WIRE_IDLE: return GBWRAP_LINKED;
    case UDS_WIRE_SYNC: return GBWRAP_SYNC;
    case UDS_WIRE_MENU: return GBWRAP_MENU;
    case UDS_WIRE_PASS: return GBWRAP_DATA;
    }
    return GBWRAP_CABLE_DOWN;
}

static void publish_status(bool active)
{
    gbwrap_status_t status = {.active = active};
    if (active) {
        status.gen = (uint8_t)udsWireGeneration(&s_wire); /* 0 until a cartridge whose generation was not given has told it */
        status.channel = s_air.channel;
        status.stage = stage();
        status.frames_sent = s_air.frames_sent;
        status.frames_received = s_air.frames_received;
        if (s_game) strncpy(status.title, s_game->name, sizeof(status.title) - 1);
    }
    portENTER_CRITICAL(&s_status_lock);
    s_status = status;
    portEXIT_CRITICAL(&s_status_lock);
}

static void report_state(void)
{
    publish_status(true);
    if (!s_host) return; /* on its own the board has nobody to tell (a write with no host reading would hold the task) */
    uint8_t state[5] = {(uint8_t)s_room.state, s_session_active ? (uint8_t)s_session.state : 0xFF, (uint8_t)s_wire.phase,
                        (uint8_t)udsWireGeneration(&s_wire), s_air.channel};
    if (memcmp(state, s_reported, sizeof(state))) {
        memcpy(s_reported, state, sizeof(state));
        s_send(UDS_EVT_GB_STATE, 0, state, sizeof(state));
    }
    if (s_now - s_last_stats_ms >= STATS_MS) {
        s_last_stats_ms = s_now;
        const uint32_t values[10] = {s_air.beacons_seen,    s_air.frames_sent,     s_air.frames_received, s_air.dropped_decrypt,
                                     s_air.dropped_replay,  s_air.dropped_other,   s_air.tx_failed,       s_wire.sentUnits,
                                     s_wire.recvUnits,      s_exchanges};
        uint8_t payload[40];
        for (int i = 0; i < 10; ++i)
            for (int b = 0; b < 4; ++b) payload[i * 4 + b] = (uint8_t)(values[i] >> (8 * b));
        s_send(UDS_EVT_GB_STATS, 0, payload, sizeof(payload));
        if (s_front == FRONT_PICO) {
            logf_host("clock (Pico): %u exchanges to the wire, %u kept from it; %u bytes with no reply, %u replies with no byte out; "
                      "%lu bytes in 5 s, round trip %lu us on average, %lu at most",
                      s_clock.exchanges, s_clock.quiet, s_pico.timeouts, s_pico.stray_replies, (unsigned long)s_pico.round_trips,
                      (unsigned long)(s_pico.round_trips ? s_pico.round_trip_sum_us / s_pico.round_trips : 0),
                      (unsigned long)s_pico.round_trip_max_us);
            s_pico.round_trips = 0;
            s_pico.round_trip_sum_us = 0;
            s_pico.round_trip_max_us = 0;
        }
    }
}

/* Brings everything up to date: frames the radio received, then the timers of the join, the session and the slave. */
/* Frames are taken a few at a time, so that a transfer request never waits behind a long queue of them. Returns true when more are
 * waiting. Each pass is timed; a slow one is reported with what it did, and the worst figures go out every few seconds. */
static bool service(void)
{
    const int64_t start = esp_timer_get_time();
    s_now = now_ms();
    size_t length;
    uint8_t *item;
    unsigned frames = 0;
    bool more = false;
    while ((item = xRingbufferReceive(s_rx_ring, &length, 0)) != NULL) {
        const int64_t frame_start = esp_timer_get_time();
        air_rx(item, length);
        vRingbufferReturnItem(s_rx_ring, item);
        const uint32_t frame_us = (uint32_t)(esp_timer_get_time() - frame_start);
        if (frame_us > s_timing.max_frame_us) s_timing.max_frame_us = frame_us;
        ++s_timing.frames;
        if (++frames == RX_PER_PASS) {
            more = true;
            break;
        }
    }
    air_poll();
    joiner_poll();
    udsWirePoll(&s_wire, s_now);
    if (s_front == FRONT_PICO) pico_poll();
    report_state();
    const uint32_t pass_us = (uint32_t)(esp_timer_get_time() - start);
    if (pass_us > s_timing.max_pass_us) s_timing.max_pass_us = pass_us;
    if (pass_us > SLOW_PASS_US) {
        logf_host("slow pass: %lu ms (%u frames, room %d, session %d, wire phase %d)", (unsigned long)(pass_us / 1000), frames,
                  (int)s_room.state, s_session_active ? (int)s_session.state : -1, (int)s_wire.phase);
    }
    if (s_now - s_timing.last_report_ms >= STATS_MS) {
        s_timing.last_report_ms = s_now;
        logf_host("timing: worst pass %lu us, worst frame %lu us, frames %lu, frames dropped (queue full) %lu, stack free %u bytes",
                  (unsigned long)s_timing.max_pass_us, (unsigned long)s_timing.max_frame_us, (unsigned long)s_timing.frames,
                  (unsigned long)s_rx_dropped, (unsigned)uxTaskGetStackHighWaterMark(NULL));
        s_timing.max_pass_us = s_timing.max_frame_us = 0;
    }
    return more;
}

static void stop_wrapper(void)
{
    if (!s_active) return;
    if (s_front == FRONT_PICO && s_pico.running) {
        const uint8_t cancel[1] = {PICO_CMD_CANCEL};
        pico_send(PICO_CHANNEL_COMMAND, cancel, sizeof(cancel));
    }
    s_active = false;
    publish_status(false);
    radio_stop();
    memset(s_air.slot_key, 0, sizeof(s_air.slot_key));
    memset(s_air.data_key, 0, sizeof(s_air.data_key));
    s_session_active = false;
    /* Drop frames still queued from the radio. */
    size_t length;
    uint8_t *item;
    while ((item = xRingbufferReceive(s_rx_ring, &length, 0)) != NULL) vRingbufferReturnItem(s_rx_ring, item);
}

/* Starts the wrapper for `game` (kCartridge: the generation is detected). `host`: started by a host's GB_START, which gets the state
 * and stats. `pico`: the cartridge is behind a Pico and this board clocks it, on the UART (`uart`) or through the host. */
static int32_t begin_wrapper(const struct gb_game *game, bool host, bool trace, bool pico, bool uart, const uint16_t name[UDS_NAME_WORDS])
{
    s_game = game;
    memset(&s_air, 0, sizeof(s_air));
    if (!keys_load(UDS_KEY_SLOT_DATA, s_air.slot_key)) return ESP_ERR_NOT_FOUND;

    s_host = host;
    s_trace = trace;
    memcpy(s_name, name, sizeof(s_name));
    s_start_ms = (uint32_t)(esp_timer_get_time() / 1000);
    s_now = 0;
    srand(esp_random());
    /* A locally administered unicast address, as mGBA's joiner. */
    s_mac[0] = 0x02;
    s_mac[1] = 0x47;
    s_mac[2] = 0x42;
    for (int i = 3; i < 6; ++i) s_mac[i] = (uint8_t)esp_random();

    s_air.channel = kChannels[0];
    esp_err_t err = radio_start(s_air.channel, s_mac, true);
    if (err != ESP_OK) {
        memset(s_air.slot_key, 0, sizeof(s_air.slot_key));
        return err;
    }
    s_air.last_hop_ms = 0;

    udsRoomInit(&s_room, s_mac, s_name, room_send, room_joined, room_pia, NULL);
    s_room.wantCommId = COMM_ID;
    s_room.wantCommMask = COMM_MASK;
    memset(&s_session, 0, sizeof(s_session));
    s_session_active = false;
    s_leave_start_ms = 0;
    s_leave_resent = false;
    udsWireInit(&s_wire, &(struct UDSUnitPort){
                             .context = NULL,
                             .ready = port_ready,
                             .queue = port_queue,
                             .flush = port_flush,
                             .pop = port_pop,
                             .peek = port_peek,
                             .waiting = port_waiting,
                             .trace = port_trace,
                         });
    udsWireSetGeneration(&s_wire, game == &kCartridge ? 0 : game->gen2 ? 2 : 1);
    udsWireSetCartEcho(&s_wire, true); /* a menu the cartridge chose first reaches the 3DS (uds-wire.h) */
    s_front = pico ? FRONT_PICO : FRONT_XFER;
    s_pico_uart = pico && uart;
    memset(&s_pico, 0, sizeof(s_pico));
    udsClockInit(&s_clock, &s_wire, true, UDS_CLOCK_MAIL_HOLD_AHEAD);
    if (s_trace) udsClockSetTrace(&s_clock, clock_trace, NULL);
    s_exchanges = 0;
    memset(&s_timing, 0, sizeof(s_timing));
    s_rx_dropped = 0;
    memset(s_reported, 0xFF, sizeof(s_reported));
    s_last_stats_ms = 0;
    s_active = true;
    if (game == &kCartridge) {
        logf_host("wrapper started for a cartridge whose generation its first sync will tell%s",
                  s_front == FRONT_PICO ? ", behind a Pico: this board drives the clock" : "");
    } else {
        logf_host("wrapper started for %s (Gen %d)%s", game->title, game->gen2 ? 2 : 1,
                  s_front == FRONT_PICO ? ", the cartridge behind a Pico: this board drives the clock" : "");
    }
    return ESP_OK;
}

/* GB_START {flags:u8 (bit 0: send the wrapper's log, bit 1: Pico, bit 2: detect the generation), title[16] (the cartridge header's,
 * 0x134), name[20] (UTF-16LE, 10 words)}. A wrapper the board started on its own gives way. */
static int32_t start_wrapper(const struct request *request)
{
    stop_wrapper();
    if (request->length < 1 + 16) return ESP_ERR_INVALID_SIZE;
    const uint8_t flags = request->data[0];
    const struct gb_game *game = NULL;
    if ((flags & UDS_GB_START_PICO) && (flags & UDS_GB_START_DETECT)) {
        game = &kCartridge;
    } else {
        char title[TITLE_KEY + 1] = {0};
        for (int i = 0; i < TITLE_KEY; ++i) {
            uint8_t ch = request->data[1 + i];
            if (ch < 0x20 || ch >= 0x7F) break;
            title[i] = (char)ch;
        }
        for (size_t i = 0; i < sizeof(kGames) / sizeof(kGames[0]); ++i) {
            if (!strncmp(title, kGames[i].title, TITLE_KEY)) game = &kGames[i];
        }
    }
    if (!game) return ESP_ERR_NOT_SUPPORTED;
    uint16_t name[UDS_NAME_WORDS] = {'G', 'B'};
    if (request->length >= 1 + 16 + 20) {
        for (int i = 0; i < UDS_NAME_WORDS; ++i) name[i] = (uint16_t)(request->data[17 + 2 * i] | (request->data[18 + 2 * i] << 8));
    }
    s_host_claimed = true;
    return begin_wrapper(game, true, flags & UDS_GB_START_LOG, flags & UDS_GB_START_PICO, false, name);
}

/* A Pico on the UART answered the board's SetMode, with no host: the wrapper runs on its own, for a cartridge whose generation its
 * first sync will tell. Nothing is logged or reported (nobody is listening); the screen shows where it is. */
static int32_t start_standalone(void)
{
    return begin_wrapper(&kCartridge, false, false, true, true, kStandaloneName);
}

/* GB_XFER {master:u8}: the cartridge clocked a transfer out. The answer is the byte the slave shifts back in that same transfer. */
static void transfer(const struct request *request)
{
    uint8_t payload[2] = {UDS_WIRE_IDLE_LINE, 0xFF};
    if (s_active && s_front == FRONT_XFER && request->length >= 1) {
        service();
        payload[0] = udsWirePreload(&s_wire);
        udsWireExchanged(&s_wire, s_now, request->data[0]);
        payload[1] = (uint8_t)s_wire.phase;
        ++s_exchanges;
    }
    s_send(UDS_EVT_GB_REPLY, request->seq, payload, sizeof(payload));
}

static void handle(const struct request *request)
{
    switch (request->type) {
    case UDS_CMD_GB_START:
        send_status(request->type, request->seq, start_wrapper(request));
        break;
    case UDS_CMD_GB_XFER:
        transfer(request);
        break;
    case UDS_CMD_GB_PICO:
        pico_receive(request, false);
        break;
    case GBWRAP_REQ_UART:
        pico_receive(request, true);
        break;
    case GBWRAP_REQ_HOST:
        /* A host has the board from now on: a wrapper running on its own stops (its Pico leaves Game Boy mode), and none starts. */
        s_host_claimed = true;
        if (s_active && !s_host) stop_wrapper();
        break;
    case UDS_CMD_GB_STOP:
    case UDS_CMD_STOP:
        stop_wrapper();
        send_status(request->type, request->seq, ESP_OK);
        break;
    default:
        send_status(request->type, request->seq, ESP_ERR_NOT_SUPPORTED);
        break;
    }
}

static void gbwrap_task(void *arg)
{
    (void)arg;
    struct request request;
    bool more = false;
    for (;;) {
        /* With frames still waiting, look for a request and go straight on; otherwise wait a millisecond (or for the next start, and
         * while the board may start on its own, for the next look for a Pico on the UART). */
        const bool may_start = !s_active && standalone_allowed();
        const TickType_t wait = s_active ? (more ? 0 : 1) : may_start ? pdMS_TO_TICKS(100) : portMAX_DELAY;
        bool got = xQueueReceive(s_queue, &request, wait) == pdTRUE;
        more = s_active && service();
        if (got) handle(&request);
        if (may_start && !s_active) probe_pico();
    }
}

#if CONFIG_UDS_PICO_LINK
/* The Pico's bytes, as they come, to the wrapper task. */
static void uart_task(void *arg)
{
    (void)arg;
    uint8_t buffer[64];
    for (;;) {
        const int count = uart_read_bytes(PICO_UART, buffer, sizeof(buffer), pdMS_TO_TICKS(20));
        if (count > 0) gbwrap_request(GBWRAP_REQ_UART, 0, buffer, (size_t)count);
    }
}

#endif

static void uart_init(void)
{
#if CONFIG_UDS_PICO_LINK
    const uart_config_t config = {
        .baud_rate = PICO_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    if (uart_driver_install(PICO_UART, 1024, 1024, 0, NULL, 0) != ESP_OK) return;
    if (uart_param_config(PICO_UART, &config) != ESP_OK ||
        uart_set_pin(PICO_UART, CONFIG_UDS_PICO_LINK_TX_GPIO, CONFIG_UDS_PICO_LINK_RX_GPIO, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE) != ESP_OK) {
        uart_driver_delete(PICO_UART);
        return;
    }
    s_uart_ok = true;
    xTaskCreate(uart_task, "pico_uart", 3072, NULL, TASK_PRIORITY, NULL);
#endif
}

void gbwrap_init(gbwrap_send_t send)
{
    s_send = send;
    s_queue = xQueueCreate(QUEUE_LENGTH, sizeof(struct request));
    s_rx_ring = xRingbufferCreate(RX_RING_BYTES, RINGBUF_TYPE_NOSPLIT);
    uart_init();
    xTaskCreate(gbwrap_task, "gbwrap", TASK_STACK, NULL, TASK_PRIORITY, NULL);
}

void gbwrap_host_hello(void)
{
    gbwrap_request(GBWRAP_REQ_HOST, 0, NULL, 0);
}

void gbwrap_request(uint8_t type, uint8_t seq, const uint8_t *payload, size_t length)
{
    struct request request = {.type = type, .seq = seq};
    if (length > sizeof(request.data)) length = sizeof(request.data);
    request.length = (uint8_t)length;
    if (length) memcpy(request.data, payload, length);
    xQueueSend(s_queue, &request, portMAX_DELAY);
}

bool gbwrap_active(void)
{
    return s_active;
}

void gbwrap_get_status(gbwrap_status_t *status)
{
    portENTER_CRITICAL(&s_status_lock);
    *status = s_status;
    portEXIT_CRITICAL(&s_status_lock);
}

bool gbwrap_sink_rx(const uint8_t *payload, size_t length)
{
    if (xRingbufferSend(s_rx_ring, payload, length, 0) == pdTRUE) return true;
    ++s_rx_dropped;
    return false;
}
