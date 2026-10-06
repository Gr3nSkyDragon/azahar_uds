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
};
static const struct gb_game kGames[] = {
    {"POKEMON RED", false}, {"POKEMON BLU", false}, {"POKEMON YEL", false},
    {"POKEMON_GLD", true},  {"POKEMON_SLV", true},  {"PM_CRYSTAL", true},
};

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
    uint8_t data[40];
};

static gbwrap_send_t s_send;
static QueueHandle_t s_queue;
static RingbufHandle_t s_rx_ring;
static volatile bool s_active;

/* Everything below is owned by the wrapper task. */
static const struct gb_game *s_game;
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
static bool s_leave_with_host;
static uint32_t s_leave_start_ms;
static bool s_leave_resent;
static struct UDSWire s_wire;
static unsigned s_exchanges;

static uint8_t s_reported[4] = {0xFF, 0xFF, 0xFF, 0xFF};
static uint32_t s_last_stats_ms;

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
    if (!s_trace) return;
    char line[160];
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
    if (s_leave_with_host && s_session_active && s_session.hostLeaving) {
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

/* The task --------------------------------------------------------------------------------------------------------------- */

static void report_state(void)
{
    uint8_t state[4] = {(uint8_t)s_room.state, s_session_active ? (uint8_t)s_session.state : 0xFF, (uint8_t)s_wire.phase,
                        s_air.channel};
    if (memcmp(state, s_reported, sizeof(state))) {
        memcpy(s_reported, state, sizeof(state));
        uint8_t payload[5] = {state[0], state[1], state[2], (uint8_t)(s_game && s_game->gen2 ? 2 : 1), state[3]};
        s_send(UDS_EVT_GB_STATE, 0, payload, sizeof(payload));
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
    s_active = false;
    radio_stop();
    memset(s_air.slot_key, 0, sizeof(s_air.slot_key));
    memset(s_air.data_key, 0, sizeof(s_air.data_key));
    s_session_active = false;
    /* Drop frames still queued from the radio. */
    size_t length;
    uint8_t *item;
    while ((item = xRingbufferReceive(s_rx_ring, &length, 0)) != NULL) vRingbufferReturnItem(s_rx_ring, item);
}

/* GB_START {flags:u8 (bit 0: send the wrapper's log), title[16] (the cartridge header's, 0x134), name[20] (UTF-16LE, 10 words)}. */
static int32_t start_wrapper(const struct request *request)
{
    stop_wrapper();
    if (request->length < 1 + 16) return ESP_ERR_INVALID_SIZE;
    char title[TITLE_KEY + 1] = {0};
    for (int i = 0; i < TITLE_KEY; ++i) {
        uint8_t ch = request->data[1 + i];
        if (ch < 0x20 || ch >= 0x7F) break;
        title[i] = (char)ch;
    }
    s_game = NULL;
    for (size_t i = 0; i < sizeof(kGames) / sizeof(kGames[0]); ++i) {
        if (!strncmp(title, kGames[i].title, TITLE_KEY)) s_game = &kGames[i];
    }
    if (!s_game) return ESP_ERR_NOT_SUPPORTED;

    memset(&s_air, 0, sizeof(s_air));
    if (!keys_load(UDS_KEY_SLOT_DATA, s_air.slot_key)) return ESP_ERR_NOT_FOUND;

    s_trace = request->data[0] & 1;
    memset(s_name, 0, sizeof(s_name));
    if (request->length >= 1 + 16 + 20) {
        for (int i = 0; i < UDS_NAME_WORDS; ++i) s_name[i] = (uint16_t)(request->data[17 + 2 * i] | (request->data[18 + 2 * i] << 8));
    } else {
        s_name[0] = 'G';
        s_name[1] = 'B';
    }
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
    s_leave_with_host = s_game->gen2;
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
    udsWireSetGeneration(&s_wire, s_game->gen2 ? 2 : 1);
    s_exchanges = 0;
    memset(&s_timing, 0, sizeof(s_timing));
    s_rx_dropped = 0;
    memset(s_reported, 0xFF, sizeof(s_reported));
    s_last_stats_ms = 0;
    s_active = true;
    logf_host("wrapper started for %s (Gen %d)", s_game->title, s_game->gen2 ? 2 : 1);
    return ESP_OK;
}

/* GB_XFER {master:u8}: the cartridge clocked a transfer out. The answer is the byte the slave shifts back in that same transfer. */
static void transfer(const struct request *request)
{
    uint8_t payload[2] = {UDS_WIRE_IDLE_LINE, 0xFF};
    if (s_active && request->length >= 1) {
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
        /* With frames still waiting, look for a request and go straight on; otherwise wait a millisecond (or for the next start). */
        bool got = xQueueReceive(s_queue, &request, !s_active ? portMAX_DELAY : more ? 0 : 1) == pdTRUE;
        more = s_active && service();
        if (got) handle(&request);
    }
}

void gbwrap_init(gbwrap_send_t send)
{
    s_send = send;
    s_queue = xQueueCreate(QUEUE_LENGTH, sizeof(struct request));
    s_rx_ring = xRingbufferCreate(RX_RING_BYTES, RINGBUF_TYPE_NOSPLIT);
    xTaskCreate(gbwrap_task, "gbwrap", TASK_STACK, NULL, TASK_PRIORITY, NULL);
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

bool gbwrap_sink_rx(const uint8_t *payload, size_t length)
{
    if (xRingbufferSend(s_rx_ring, payload, length, 0) == pdTRUE) return true;
    ++s_rx_dropped;
    return false;
}
