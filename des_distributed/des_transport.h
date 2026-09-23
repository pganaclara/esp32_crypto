// =============================================================================
// des_transport.h — the transport under the distributed DES protocol
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
// has to be *best effort*, which is why plain UDP is enough, and why another
// transport can be swapped in without touching a line of control logic.
//
// ── THE BINDING: UDP/IP multicast, RFC 1112 / RFC 3376 ──────────────────────
// BSD sockets. No broker, no vendor, no library. Runs on ESP32 (lwIP), Linux,
// *BSD, macOS, QNX, VxWorks — anything with a socket API. It is the same
// substrate OPC UA PubSub (IEC 62541-14) and DDS/RTPS use for their UDP
// mappings, so the protocol maps onto either without redesign.
//
// ── ADDING A TRANSPORT ──────────────────────────────────────────────────────
// Implement the four functions and point DES_TRANSPORT_IMPL at them. An OPC UA
// PubSub binding is ~100 lines over open62541 (MPL-2.0); a DDS binding ~80 over
// Eclipse Cyclone DDS (EPL-2.0) or eProsima Fast DDS (Apache-2.0).
// =============================================================================

#pragma once
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// ── platform socket headers ─────────────────────────────────────────────────
#if defined(ESP_PLATFORM) || defined(ARDUINO_ARCH_ESP32)
#  include <lwip/sockets.h>
#  include <lwip/inet.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <fcntl.h>
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
// stack has no address yet (not associated / no DHCP lease). Provided by the
// platform entry point (des_distributed.ino, host_main.cpp).
static uint32_t des_local_ipv4();

// =============================================================================
// UDP/IP multicast   (RFC 1112, RFC 3376)
// =============================================================================
//
// One socket does both directions: it is bound to the group port, joined to the
// group, and sends to the group. Every node is a peer; there is no server, no
// broker and no discovery step — joining the group IS the discovery.

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
