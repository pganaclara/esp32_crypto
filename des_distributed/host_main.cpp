// =============================================================================
// host_main.cpp — the SAME engine on a POSIX host (Linux / *BSD / macOS)
// =============================================================================
//
// des_generic.h contains no Arduino, FreeRTOS or ESP-IDF code. Running a node
// on an industrial PC, a Raspberry Pi or a Linux gateway needs only this file
// in place of des_distributed.ino. A mixed deployment works too: an ESP32 next
// to a machine and a Linux cell controller are peers in the same multicast
// group, speaking the same 44-byte signed frames.
//
//   build (the cell key comes from secrets.h, the same file the ESP32 reads;
//   -DDES_AUTH_KEY='"..."' overrides it):
//     g++ -std=c++17 -O2 -DDES_NODE_ID=1 -DDES_NUM_NODES=2 -o des_node1
//         host_main.cpp -lmbedcrypto -lmbedx509 -lmbedtls      (one line)
//
//   run (one shell per node, same LAN segment):
//     ./des_node1 1 2           # node 1 of 2
//     ./des_node2 2 2           # node 2 of 2
//
//   Several nodes on ONE host also need -DDES_MCAST_LOOP=1 (and -DDES_MCAST_TTL=0
//   to keep the traffic on that machine).
//
//   Debian/Ubuntu:  sudo apt install libmbedtls-dev
//   Fedora:         sudo dnf install mbedtls-devel
//
// Verified: built with g++ 13 on Ubuntu (WSL) and run as several nodes over
// real UDP multicast — see "Verification status" in README.md.
// =============================================================================

// The Arduino IDE compiles EVERY .cpp in the sketch folder, including this one,
// against the ESP32 toolchain — which has no <ifaddrs.h> and no main(). This
// file is only ever meant for a POSIX build, so on Arduino it compiles to
// nothing at all. Build it for the host with g++ (see the command above), where
// ARDUINO is not defined and the real contents come into view.
#if !defined(ARDUINO)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ── deployment configuration ────────────────────────────────────────────────
// Overridable from the compiler: -DDES_DATA_HEADER='"supervisor_data_fms.h"'
#ifndef DES_DATA_HEADER
#define DES_DATA_HEADER "supervisor_data_extended_small_factory.h"
#endif

// argv overrides these at runtime; they only need to exist at compile time
// because the engine builds its routing tables from macros.
#ifndef DES_NODE_ID
#define DES_NODE_ID 1
#endif
#ifndef DES_NUM_NODES
#define DES_NUM_NODES 2
#endif
#ifndef DES_FAMILY
#define DES_FAMILY DES_FAMILY_LMOD_RED
#endif

// The cell key, from the same unversioned file the ESP32 sketch reads (the
// Wi-Fi settings in it are simply unused here). -DDES_AUTH_KEY=... overrides.
#if __has_include("secrets.h")
#  include "secrets.h"
#endif

#include "des_generic.h"

// The engine asks the platform which interface to join the multicast group on.
// Prefer $DES_IFACE_IP when set, else the first non-loopback IPv4 that is up.
static uint32_t des_local_ipv4() {
    if (const char* env = getenv("DES_IFACE_IP")) return inet_addr(env);

    struct ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) != 0) return htonl(INADDR_ANY);
    uint32_t found = htonl(INADDR_ANY);
    for (struct ifaddrs* p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (!(p->ifa_flags & IFF_UP))        continue;
        if (p->ifa_flags & IFF_LOOPBACK)     continue;
        if (!(p->ifa_flags & IFF_MULTICAST)) continue;
        found = ((struct sockaddr_in*)p->ifa_addr)->sin_addr.s_addr;
        break;
    }
    freeifaddrs(ifa);
    return found;
}

int main(int argc, char** argv) {
    // The node identity is baked in at compile time because the routing tables
    // are macro-driven. Refuse a mismatch loudly rather than run as the wrong
    // node — two boards claiming the same id would corrupt the sequence space.
    if (argc >= 3) {
        int id = atoi(argv[1]), n = atoi(argv[2]);
        if (id != DES_NODE_ID || n != DES_NUM_NODES) {
            fprintf(stderr,
                "This binary was built as node %d of %d, but you asked for %d of %d.\n"
                "Rebuild with:  g++ -std=c++17 -O2 -DDES_NODE_ID=%d -DDES_NUM_NODES=%d \\\n"
                "                   -o des_node%d host_main.cpp -lmbedcrypto -lmbedx509 -lmbedtls\n",
                (int)DES_NODE_ID, (int)DES_NUM_NODES, id, n, id, n, id);
            return 2;
        }
    }
    // Line-buffered even when redirected to a file or a pipe, so a log shows
    // where a node is NOW rather than whenever the libc buffer happens to fill.
    setvbuf(stdout, nullptr, _IOLBF, 0);
    printf("des_node: node %d of %d, %s, data %s\n",
           (int)DES_NODE_ID, (int)DES_NUM_NODES, DES_FAMILY_NAME, DES_DATA_HEADER);

    des_setup();
    for (;;) des_loop();
}

#endif  // !defined(ARDUINO)
