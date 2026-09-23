// =============================================================================
// des_transport.h — pluggable, open-standard transports for distributed DES
// =============================================================================
//
// The coordination protocol in des_generic.h never calls a network API
// directly. It goes through this interface:
//
//     begin()   bring the link up
//     send(m)   deliver a fixed-size frame to every other node (best effort)
//     poll(m)   non-blocking receive, false if nothing waiting
//     service() periodic upkeep (keepalives, reconnects)
//
// That is the whole contract. Reliability, ordering and atomicity are provided
// END-TO-END by the protocol itself (sequence numbers, acknowledgement,
// retransmission, two-phase commit), not by the transport — the classic
// end-to-end argument (Saltzer, Reed & Clark 1984). A transport therefore only
// has to be *best effort*, which is why a transport can be swapped without
// touching a line of control logic, and why plain UDP is enough.
//
// ── BINDINGS PROVIDED ───────────────────────────────────────────────────────
//
//   DES_TRANSPORT_UDP   (default)  IP multicast, RFC 1112 / RFC 3376.
//       BSD sockets. No broker, no vendor, no library. Runs on ESP32 (lwIP),
//       Linux, *BSD, macOS, QNX, VxWorks — anything with a socket API. This is
//       the same substrate OPC UA PubSub (IEC 62541-14) and DDS/RTPS use for
//       their UDP mappings, so the protocol maps onto either without redesign.
//
//   DES_TRANSPORT_MQTT             MQTT 3.1.1, ISO/IEC 20922 / OASIS.
//       A complete minimal client written on the same sockets — no external
//       library, so there is nothing proprietary and nothing to install. Use
//       it when the plant already runs a broker (Mosquitto, EMQX, NanoMQ, HiveMQ).
//       Publishes at QoS 0 ON PURPOSE: the end-to-end 2PC above already gives
//       exactly-once *application* semantics, so broker QoS would be redundant
//       work on every frame. Raise DES_MQTT_QOS to 1 if a reviewer expects it.
//
//   DES_TRANSPORT_LOOPBACK         in-process, for single-board testing.
//
// ── ADDING A TRANSPORT ──────────────────────────────────────────────────────
// Implement the four functions and register them. An OPC UA PubSub binding is
// ~100 lines over open62541 (MPL-2.0); a DDS binding is ~80 over Eclipse
// Cyclone DDS (EPL-2.0) or eProsima Fast DDS (Apache-2.0). Both were left out
// only because they pull in a build system this sketch does not assume.
// =============================================================================

#pragma once
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// ── platform socket headers ─────────────────────────────────────────────────
#if defined(ESP_PLATFORM) || defined(ARDUINO_ARCH_ESP32)
#  include <lwip/sockets.h>
#  include <lwip/inet.h>
#  include <lwip/netdb.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
#endif

// ── transport selection ─────────────────────────────────────────────────────
#define DES_TRANSPORT_UDP       0
#define DES_TRANSPORT_MQTT      1
#define DES_TRANSPORT_LOOPBACK  2

#ifndef DES_TRANSPORT
#define DES_TRANSPORT DES_TRANSPORT_UDP
#endif

// ── UDP multicast configuration ─────────────────────────────────────────────
// 239.0.0.0/8 is the administratively-scoped block (RFC 2365) — safe on a
// private plant network and never routed to the public internet.
#ifndef DES_MCAST_GROUP
#define DES_MCAST_GROUP "239.192.7.1"
#endif
#ifndef DES_MCAST_PORT
#define DES_MCAST_PORT 5077
#endif
#ifndef DES_MCAST_TTL
#define DES_MCAST_TTL 1          // 1 = stay on the local subnet
#endif
#ifndef DES_MCAST_LOOP
#define DES_MCAST_LOOP 0         // 1 = several nodes on ONE host (testing)
#endif

// ── MQTT configuration ──────────────────────────────────────────────────────
#ifndef DES_MQTT_HOST
#define DES_MQTT_HOST "192.168.1.10"
#endif
#ifndef DES_MQTT_PORT
#define DES_MQTT_PORT 1883
#endif
#ifndef DES_MQTT_TOPIC
#define DES_MQTT_TOPIC "des/cell0/coord"
#endif
#ifndef DES_MQTT_KEEPALIVE_S
#define DES_MQTT_KEEPALIVE_S 30
#endif
#ifndef DES_MQTT_QOS
#define DES_MQTT_QOS 0
#endif
// This client never sends PUBACK, so at QoS 1 the broker would redeliver every
// frame and eventually stall the subscription. It is not needed: the protocol
// already retransmits end to end until every participant acknowledges, which
// is the guarantee QoS 1 would add per hop (Saltzer, Reed & Clark 1984).
#if DES_MQTT_QOS != 0
#  error "DES_MQTT_QOS must be 0 — reliability is end-to-end in the protocol"
#endif

#ifndef DES_LOG
#  if defined(ARDUINO)
#    define DES_LOG(...) Serial.printf(__VA_ARGS__)
#  else
#    define DES_LOG(...) printf(__VA_ARGS__)
#  endif
#endif

// The protocol's frame. Fixed size on purpose: every frame looks identical on
// the wire, so an observer cannot tell a REQ from a COMMIT by length.
#ifndef DES_FRAME_BYTES
#define DES_FRAME_BYTES 44              // 28 B of header + a 16 B authentication tag
#endif

struct DesTransport {
    const char* name;
    bool (*begin)();
    bool (*send)(const void* frame, int len);
    bool (*poll)(void* frame, int len);
    void (*service)();
};

// =============================================================================
// Helpers shared by the socket-based bindings
// =============================================================================

static inline int des_sock_nonblock(int fd) {
#if defined(ESP_PLATFORM) || defined(ARDUINO_ARCH_ESP32)
    int fl = lwip_fcntl(fd, F_GETFL, 0);
    return lwip_fcntl(fd, F_SETFL, fl | O_NONBLOCK);
#else
    int fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
#endif
}

// Local IPv4 address, needed to pick the multicast interface. Returns 0 if the
// stack has no address yet (not associated / no DHCP lease).
static uint32_t des_local_ipv4();

// =============================================================================
// Binding 1 — UDP/IP multicast   (RFC 1112, RFC 3376)
// =============================================================================
//
// One socket does both directions: it is bound to the group port, joined to the
// group, and sends to the group. Every node is a peer; there is no server, no
// broker and no discovery step — joining the group IS the discovery.

#if DES_TRANSPORT == DES_TRANSPORT_UDP

static int                des_udp_fd = -1;
static struct sockaddr_in des_udp_dst;

static bool des_udp_begin() {
    des_udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (des_udp_fd < 0) { DES_LOG("[net] socket() failed\n"); return false; }

    int yes = 1;
    setsockopt(des_udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family      = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port        = htons(DES_MCAST_PORT);
    if (bind(des_udp_fd, (struct sockaddr*)&local, sizeof(local)) < 0) {
        DES_LOG("[net] bind() failed\n"); return false;
    }

    // Join the group on the interface that owns our address.
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(DES_MCAST_GROUP);
    mreq.imr_interface.s_addr = des_local_ipv4();
    if (setsockopt(des_udp_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        DES_LOG("[net] IP_ADD_MEMBERSHIP failed — is the interface up?\n");
        return false;
    }

    uint8_t ttl = DES_MCAST_TTL;
    setsockopt(des_udp_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    // Normally our own datagrams are not looped back — the protocol filters them
    // by source id and epoch anyway, so this only saves wakeups. Several nodes
    // on one host (a test bench) need the loop, or none of them hears the rest.
    uint8_t loop = DES_MCAST_LOOP;
    setsockopt(des_udp_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

    struct in_addr ifaddr;
    ifaddr.s_addr = des_local_ipv4();
    setsockopt(des_udp_fd, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof(ifaddr));

    des_sock_nonblock(des_udp_fd);

    memset(&des_udp_dst, 0, sizeof(des_udp_dst));
    des_udp_dst.sin_family      = AF_INET;
    des_udp_dst.sin_addr.s_addr = inet_addr(DES_MCAST_GROUP);
    des_udp_dst.sin_port        = htons(DES_MCAST_PORT);

    DES_LOG("[net] UDP multicast %s:%d  ttl=%d  frame=%d B\n",
            DES_MCAST_GROUP, (int)DES_MCAST_PORT, (int)DES_MCAST_TTL,
            (int)DES_FRAME_BYTES);
    return true;
}

static bool des_udp_send(const void* frame, int len) {
    if (des_udp_fd < 0) return false;
    return sendto(des_udp_fd, frame, len, 0,
                  (struct sockaddr*)&des_udp_dst, sizeof(des_udp_dst)) == len;
}

// Returns the next datagram of exactly `len` bytes. Anything else on the port
// is consumed and skipped here: returning false for it would tell the caller
// "nothing waiting" and leave every valid frame behind it in the kernel's
// six-slot mailbox until the next poll.
static bool des_udp_poll(void* frame, int len) {
    if (des_udp_fd < 0) return false;
    for (;;) {
        struct sockaddr_in from; socklen_t flen = sizeof(from);
        int n = recvfrom(des_udp_fd, frame, len, MSG_DONTWAIT,
                         (struct sockaddr*)&from, &flen);
        if (n < 0)    return false;               // nothing waiting
        if (n == len) return true;
    }
}

static void des_udp_service() { }

static DesTransport DES_TRANSPORT_IMPL = {
    "UDP/IP multicast (RFC 1112)",
    des_udp_begin, des_udp_send, des_udp_poll, des_udp_service
};

// =============================================================================
// Binding 2 — MQTT 3.1.1   (ISO/IEC 20922)
// =============================================================================
//
// A complete minimal client: CONNECT, SUBSCRIBE, PUBLISH, PINGREQ. Deliberately
// no external library — nothing to install, nothing proprietary, and the whole
// wire format is visible for a paper. All nodes publish to and subscribe from
// one topic; the protocol filters out its own frames by source id.

#elif DES_TRANSPORT == DES_TRANSPORT_MQTT

static int      des_mq_fd       = -1;
static bool     des_mq_ready    = false;
static uint32_t des_mq_last_tx  = 0;
static uint8_t  des_mq_rx[512];
static int      des_mq_rxn      = 0;
static uint32_t des_millis_fwd();          // provided by des_generic.h

// Encode an MQTT "remaining length" varint. Returns bytes written.
static int des_mq_varint(uint8_t* p, uint32_t v) {
    int n = 0;
    do { uint8_t b = v % 128; v /= 128; if (v) b |= 0x80; p[n++] = b; } while (v);
    return n;
}

static bool des_mq_write(const uint8_t* b, int n) {
    int sent = 0;
    while (sent < n) {
        int w = send(des_mq_fd, (const char*)b + sent, n - sent, 0);
        if (w <= 0) return false;
        sent += w;
    }
    des_mq_last_tx = des_millis_fwd();
    return true;
}

static bool des_mq_connect() {
    des_mq_ready = false;
    if (des_mq_fd >= 0) { close(des_mq_fd); des_mq_fd = -1; }

    des_mq_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (des_mq_fd < 0) return false;

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(DES_MQTT_PORT);
    srv.sin_addr.s_addr = inet_addr(DES_MQTT_HOST);
    if (srv.sin_addr.s_addr == (uint32_t)-1) {          // not a literal IP
        struct hostent* he = gethostbyname(DES_MQTT_HOST);
        if (!he) { close(des_mq_fd); des_mq_fd = -1; return false; }
        memcpy(&srv.sin_addr, he->h_addr_list[0], 4);
    }
    if (connect(des_mq_fd, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        close(des_mq_fd); des_mq_fd = -1; return false;
    }
    int one = 1;
    setsockopt(des_mq_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    // ---- CONNECT ----
    char cid[32];
    snprintf(cid, sizeof(cid), "des-node-%u", (unsigned)DES_NODE_ID);
    int   cidn = (int)strlen(cid);
    uint8_t var[64]; int v = 0;
    var[v++] = 0; var[v++] = 4; memcpy(var + v, "MQTT", 4); v += 4;
    var[v++] = 4;                                   // protocol level 3.1.1
    var[v++] = 0x02;                                // clean session
    var[v++] = (uint8_t)(DES_MQTT_KEEPALIVE_S >> 8);
    var[v++] = (uint8_t)(DES_MQTT_KEEPALIVE_S & 0xFF);
    var[v++] = (uint8_t)(cidn >> 8); var[v++] = (uint8_t)(cidn & 0xFF);
    memcpy(var + v, cid, cidn); v += cidn;

    uint8_t pkt[96]; int n = 0;
    pkt[n++] = 0x10;
    n += des_mq_varint(pkt + n, (uint32_t)v);
    memcpy(pkt + n, var, v); n += v;
    if (!des_mq_write(pkt, n)) return false;

    // Wait (briefly, blocking) for CONNACK before going non-blocking.
    uint8_t ack[4];
    int got = 0;
    uint32_t t0 = des_millis_fwd();
    while (got < 4 && des_millis_fwd() - t0 < 5000) {
        int r = recv(des_mq_fd, (char*)ack + got, 4 - got, 0);
        if (r > 0) got += r; else if (r == 0) break;
    }
    if (got < 4 || ack[0] != 0x20 || ack[3] != 0x00) {
        DES_LOG("[net] MQTT CONNACK refused (rc=%d)\n", got >= 4 ? ack[3] : -1);
        close(des_mq_fd); des_mq_fd = -1; return false;
    }

    // ---- SUBSCRIBE ----
    const char* topic = DES_MQTT_TOPIC;
    int tn = (int)strlen(topic);
    v = 0;
    var[v++] = 0; var[v++] = 1;                     // packet id 1
    var[v++] = (uint8_t)(tn >> 8); var[v++] = (uint8_t)(tn & 0xFF);
    memcpy(var + v, topic, tn); v += tn;
    var[v++] = DES_MQTT_QOS;
    n = 0;
    pkt[n++] = 0x82;
    n += des_mq_varint(pkt + n, (uint32_t)v);
    memcpy(pkt + n, var, v); n += v;
    if (!des_mq_write(pkt, n)) return false;

    des_sock_nonblock(des_mq_fd);
    des_mq_rxn   = 0;
    des_mq_ready = true;
    DES_LOG("[net] MQTT %s:%d topic '%s' qos %d — connected\n",
            DES_MQTT_HOST, (int)DES_MQTT_PORT, DES_MQTT_TOPIC, (int)DES_MQTT_QOS);
    return true;
}

static bool des_mq_begin() { return des_mq_connect(); }

static bool des_mq_send(const void* frame, int len) {
    if (!des_mq_ready) return false;
    const char* topic = DES_MQTT_TOPIC;
    int tn = (int)strlen(topic);
    uint8_t pkt[16 + 64 + DES_FRAME_BYTES]; int n = 0;
    uint32_t rem = 2 + tn + len;
    pkt[n++] = 0x30;                                // PUBLISH, QoS 0
    n += des_mq_varint(pkt + n, rem);
    pkt[n++] = (uint8_t)(tn >> 8); pkt[n++] = (uint8_t)(tn & 0xFF);
    memcpy(pkt + n, topic, tn); n += tn;
    memcpy(pkt + n, frame, len); n += len;
    if (!des_mq_write(pkt, n)) { des_mq_ready = false; return false; }
    return true;
}

// Pull bytes off the socket and extract the first complete PUBLISH payload.
static bool des_mq_poll(void* frame, int len) {
    if (!des_mq_ready) return false;

    int space = (int)sizeof(des_mq_rx) - des_mq_rxn;
    if (space > 0) {
        int r = recv(des_mq_fd, (char*)des_mq_rx + des_mq_rxn, space, MSG_DONTWAIT);
        if (r > 0)      des_mq_rxn += r;
        else if (r == 0) { des_mq_ready = false; return false; }   // broker closed
    }

    while (des_mq_rxn >= 2) {
        uint8_t  type = des_mq_rx[0] & 0xF0;
        uint32_t rem = 0; int mult = 1, i = 1;
        bool ok = false;
        while (i < des_mq_rxn && i <= 4) {
            uint8_t b = des_mq_rx[i++];
            rem += (uint32_t)(b & 0x7F) * mult;
            mult *= 128;
            if (!(b & 0x80)) { ok = true; break; }
        }
        if (!ok) {
            if (i > 4) { des_mq_ready = false; return false; }   // malformed
            return false;                            // length incomplete
        }
        int total = i + (int)rem;
        // A packet larger than the buffer can never complete, and waiting for
        // it would stall this parser for good. Drop the connection instead;
        // service() reconnects.
        if (total > (int)sizeof(des_mq_rx)) { des_mq_ready = false; return false; }
        if (des_mq_rxn < total) return false;        // body incomplete

        bool produced = false;
        if (type == 0x30) {                          // PUBLISH
            int p  = i;
            int tn = (des_mq_rx[p] << 8) | des_mq_rx[p + 1];
            p += 2 + tn;
            if ((des_mq_rx[0] & 0x06) >> 1 > 0) p += 2;          // packet id
            int plen = total - p;
            if (plen == len) { memcpy(frame, des_mq_rx + p, len); produced = true; }
        }
        memmove(des_mq_rx, des_mq_rx + total, des_mq_rxn - total);
        des_mq_rxn -= total;
        if (produced) return true;
    }
    return false;
}

static void des_mq_service() {
    if (!des_mq_ready) { des_mq_connect(); return; }
    if (des_millis_fwd() - des_mq_last_tx > (uint32_t)DES_MQTT_KEEPALIVE_S * 500) {
        uint8_t ping[2] = { 0xC0, 0x00 };
        if (!des_mq_write(ping, 2)) des_mq_ready = false;
    }
}

static DesTransport DES_TRANSPORT_IMPL = {
    "MQTT 3.1.1 (ISO/IEC 20922)",
    des_mq_begin, des_mq_send, des_mq_poll, des_mq_service
};

// =============================================================================
// Binding 3 — loopback (single-board bring-up, no network at all)
// =============================================================================

#else

static uint8_t des_lb_buf[8][DES_FRAME_BYTES];
static int     des_lb_head = 0, des_lb_tail = 0;

static bool des_lb_begin() { DES_LOG("[net] loopback (no network)\n"); return true; }
static bool des_lb_send(const void* f, int len) {
    int nxt = (des_lb_head + 1) % 8;
    if (nxt == des_lb_tail) return false;
    memcpy(des_lb_buf[des_lb_head], f, len < DES_FRAME_BYTES ? len : DES_FRAME_BYTES);
    des_lb_head = nxt; return true;
}
static bool des_lb_poll(void* f, int len) {
    if (des_lb_tail == des_lb_head) return false;
    memcpy(f, des_lb_buf[des_lb_tail], len < DES_FRAME_BYTES ? len : DES_FRAME_BYTES);
    des_lb_tail = (des_lb_tail + 1) % 8; return true;
}
static void des_lb_service() { }

static DesTransport DES_TRANSPORT_IMPL = {
    "loopback", des_lb_begin, des_lb_send, des_lb_poll, des_lb_service
};

#endif
