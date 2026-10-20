// =============================================================================
// host_main.cpp — the same two roles on a POSIX host, to test the protocol
// =============================================================================
//
//   g++ -std=c++17 -O2 -DDES_ROLE=DES_PLANT      -DDES_MCAST_LOOP=1 -o plant      host_main.cpp -lmbedcrypto
//   g++ -std=c++17 -O2 -DDES_ROLE=DES_SUPERVISOR -DDES_MCAST_LOOP=1 -o supervisor host_main.cpp -lmbedcrypto
//   ./supervisor & ./plant
//
// The cell key comes from secrets.h, or -DDES_AUTH_KEY='"..."'. Without the
// mbedTLS headers (Debian/Ubuntu: libmbedtls-dev), the build falls back to a
// MOCK group — integers modulo 2^61 - 1, which has the same algebra as the
// curve and no security at all — so the protocol can be tested anywhere.
// -DDES_SIMULATE_LOSS_PCT=20 drops a fifth of the received frames.
//
// The Arduino IDE compiles every .cpp in the sketch folder; on the ESP32 this
// file compiles to nothing.
// =============================================================================

#if !defined(ARDUINO)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef DES_DATA_HEADER
#define DES_DATA_HEADER "supervisor_data_cluster_tool_2.h"
#endif
#if __has_include("secrets.h")
#  include "secrets.h"
#endif
#if !__has_include(<mbedtls/ecp.h>)
#  define DES_SPLIT_MOCK 1
#endif

#include "des_split.h"

#if DES_SPLIT_MOCK
// ── mock group: Z_p, p = 2^61 - 1; the "point" iG is the integer i ───────────
#include <random>
static const uint64_t MP = (1ULL << 61) - 1;
static std::mt19937_64 g_rng;
static uint64_t g_mY = 0, g_mnegk = 0;

static uint64_t mmul(uint64_t a, uint64_t b) { return (uint64_t)((unsigned __int128)a * b % MP); }
static uint64_t madd(uint64_t a, uint64_t b) { return (a + b) % MP; }
static uint64_t mrand() { return 1 + g_rng() % (MP - 1); }
static void put(uint64_t v, uint8_t raw[PT_RAW]) {      // in the x coordinate
    memset(raw, 0, PT_RAW);
    for (int i = 0; i < 8; ++i) raw[23 - i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get_raw(const uint8_t raw[PT_RAW]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)raw[23 - i] << (8 * i);
    return v;
}
static uint64_t get_cmp(const uint8_t cmp[PT_CMP]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)cmp[24 - i] << (8 * i);
    return v;
}

static void cr_init(const char*) {
    std::random_device rd; g_rng.seed(((uint64_t)rd() << 32) ^ rd());
}
static uint32_t cr_random32() { return (uint32_t)g_rng(); }
static void cr_hmac(const uint8_t* msg, size_t len, uint8_t tag[DES_TAG_BYTES]) {
    uint64_t h1 = 1469598103934665603ULL, h2 = 1099511628211ULL;  // not a MAC
    for (size_t i = 0; i < sizeof(DES_AUTH_KEY) - 1; ++i) { h1 = (h1 ^ DES_AUTH_KEY[i]) * 1099511628211ULL; }
    for (size_t i = 0; i < len; ++i) { h1 = (h1 ^ msg[i]) * 1099511628211ULL; h2 = (h2 ^ msg[i]) * 16777619ULL + h1; }
    memcpy(tag, &h1, 8); memcpy(tag + 8, &h2, 8);
}
static int cr_keygen(uint8_t Y[PT_CMP]) {
    uint64_t k = mrand(); g_mY = k; g_mnegk = MP - k;
    uint8_t raw[PT_RAW]; put(g_mY, raw); memset(Y, 0, PT_CMP); Y[0] = 0x02; memcpy(Y + 1, raw, 24);
    return 0;
}
static int cr_set_pub(const uint8_t Y[PT_CMP]) { g_mY = get_cmp(Y); return g_mY ? 0 : -1; }
static int cr_enc(int m, uint8_t cell[CELL_RAW]) {
    uint64_t r = mrand();
    put(r, cell); put(madd((uint64_t)m, mmul(r, g_mY)), cell + PT_RAW);
    return 0;
}
static int cr_sum(const uint8_t* const* cells, int cnt, uint8_t out[CELL_RAW]) {
    uint64_t u = 0, v = 0;
    for (int i = 0; i < cnt; ++i) { u = madd(u, get_raw(cells[i])); v = madd(v, get_raw(cells[i] + PT_RAW)); }
    put(u, out); put(v, out + PT_RAW);
    return 0;
}
static int cr_rerandomize(const uint8_t* cell_cmp, uint8_t out[CELL_RAW], uint64_t* gen_us) {
    uint64_t t0 = des_micros();
    uint64_t s = mrand(), zu = s, zv = mmul(s, g_mY);
    *gen_us = des_micros() - t0;
    uint64_t u = cell_cmp ? get_cmp(cell_cmp) : 0, v = cell_cmp ? get_cmp(cell_cmp + PT_CMP) : 0;
    put(madd(u, zu), out); put(madd(v, zv), out + PT_RAW);
    return 0;
}
static int cr_zero_test(const uint8_t cell[CELL_RAW]) {
    return madd(get_raw(cell + PT_RAW), mmul(g_mnegk, get_raw(cell))) ? 1 : 0;
}
#endif  // DES_SPLIT_MOCK

// The interface for the multicast group: $DES_IFACE_IP, else the first
// non-loopback IPv4 that is up and does multicast.
static uint32_t des_local_ipv4() {
    if (const char* env = getenv("DES_IFACE_IP")) return inet_addr(env);
    struct ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) != 0) return htonl(INADDR_ANY);
    uint32_t found = htonl(INADDR_ANY);
    for (struct ifaddrs* p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
        if (!(p->ifa_flags & IFF_MULTICAST)) continue;
        found = ((struct sockaddr_in*)p->ifa_addr)->sin_addr.s_addr;
        break;
    }
    freeifaddrs(ifa);
    return found;
}

int main() {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    printf("des_split: %s, data %s%s\n", DES_ROLE == DES_PLANT ? "PLANT" : "SUPERVISOR",
           DES_DATA_HEADER, DES_SPLIT_MOCK ? ", MOCK crypto (test only, insecure)" : "");
    split_setup();
    while (!g_done && !g_halt) split_loop();
    return g_halt ? 1 : 0;
}

#endif  // !defined(ARDUINO)
