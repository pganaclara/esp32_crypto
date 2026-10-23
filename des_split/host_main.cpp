// =============================================================================
// host_main.cpp — the same two roles on a POSIX host, to test the protocol
// =============================================================================
//
//   g++ -std=c++17 -O2 -DDES_ROLE=DES_PLANT      -DDES_MCAST_LOOP=1 -o plant      host_main.cpp -lmbedcrypto
//   g++ -std=c++17 -O2 -DDES_ROLE=DES_SUPERVISOR -DDES_MCAST_LOOP=1 -o supervisor host_main.cpp -lmbedcrypto
//   ./supervisor & ./plant
//
// The identity keys come from secrets.h (make_keys.py), or -DDES_ID_PLANT=...
// and the three others. Without the
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
#if __has_include("secrets.h") && !defined(DES_ID_PLANT)   // keys on the command line win
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
static uint64_t g_mY = 0, g_mnegk = 0, g_mYj = 0, g_mid = 0, g_mpeer = 0;
static uint64_t g_mmac[2];

static uint64_t mmul(uint64_t a, uint64_t b) { return (uint64_t)((unsigned __int128)a * b % MP); }
static uint64_t madd(uint64_t a, uint64_t b) { return (a + b) % MP; }
static uint64_t mrand() { return 1 + g_rng() % (MP - 1); }
static void put(uint64_t v, uint8_t raw[PT_RAW]) {      // in the x coordinate
    memset(raw, 0, PT_RAW);
    for (int i = 0; i < 8; ++i) raw[SC_BYTES - 1 - i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get_raw(const uint8_t raw[PT_RAW]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)raw[SC_BYTES - 1 - i] << (8 * i);
    return v;
}
static void put_sc(uint64_t v, uint8_t sc[SC_BYTES]) {
    memset(sc, 0, SC_BYTES);
    for (int i = 0; i < 8; ++i) sc[SC_BYTES - 1 - i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get_sc(const uint8_t sc[SC_BYTES]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)sc[SC_BYTES - 1 - i] << (8 * i);
    return v;
}
static uint64_t mhash(const uint8_t* m, size_t n, uint64_t h = 1469598103934665603ULL) {  // not a hash
    for (size_t i = 0; i < n; ++i) h = (h ^ m[i]) * 1099511628211ULL;
    return h;
}
// Schnorr as in des_split.h: sig = R || z, c = H(pre || R).
static void msign(uint64_t x, const uint8_t* pre, size_t n, uint8_t sig[SIG_BYTES]) {
    uint64_t t = mrand(); put(t, sig);
    uint64_t c = mhash(sig, PT_RAW, mhash(pre, n)) % MP;
    put_sc(madd(t, mmul(c, x)), sig + PT_RAW);
}
static int mcheck(uint64_t X, const uint8_t* pre, size_t n, const uint8_t sig[SIG_BYTES]) {
    uint64_t c = mhash(sig, PT_RAW, mhash(pre, n)) % MP;
    return get_sc(sig + PT_RAW) == madd(get_raw(sig), mmul(c, X)) ? 0 : -1;
}
static uint64_t mhex(const char* hex, size_t n) {       // the last 8 of the first n bytes
    if (strlen(hex) < 2 * n) return 0;
    uint64_t v = 0;
    for (size_t i = 2 * n - 16; i < 2 * n; ++i) {
        char ch = hex[i];
        v = v * 16 + (uint64_t)(ch <= '9' ? ch - '0' : (ch | 32) - 'a' + 10);
    }
    return v;
}

static void cr_init(const char*) {
    std::random_device rd; g_rng.seed(((uint64_t)rd() << 32) ^ rd());
}
static uint32_t cr_random32() { return (uint32_t)g_rng(); }
static int cr_identity(const char* my_priv, const char* my_pub, const char* peer_pub) {
    g_mid = mhex(my_priv, SC_BYTES) % MP; g_mpeer = mhex(peer_pub, SC_BYTES);
    return g_mid && g_mid == mhex(my_pub, SC_BYTES) && g_mpeer ? 0 : -1;   // here xG = x
}
static int cr_sign(const uint8_t* msg, size_t len, uint8_t sig[SIG_BYTES]) {
    msign(g_mid, msg, len, sig); return 0;
}
static int cr_verify(const uint8_t* msg, size_t len, const uint8_t sig[SIG_BYTES]) {
    return mcheck(g_mpeer, msg, len, sig);
}
static uint64_t mdet(const uint8_t seed[32], const char* tag, uint32_t a, uint32_t b) {
    uint64_t h = mhash(seed, 32);
    h = mhash((const uint8_t*)tag, strlen(tag), h);
    h = mhash((const uint8_t*)&a, 4, h);
    return mhash((const uint8_t*)&b, 4, h);
}
static void cr_sha256(const uint8_t* m, size_t n, uint8_t out[32]) {    // not SHA-256
    for (int i = 0; i < 4; ++i) { uint64_t h = mhash(m, n, 1469598103934665603ULL + i); memcpy(out + 8 * i, &h, 8); }
}
static void cr_random_bytes(uint8_t* out, size_t n) { for (size_t i = 0; i < n; ++i) out[i] = (uint8_t)g_rng(); }
static int cr_enc_det(int m, const uint8_t seed[32], const char* tag, uint32_t a, uint32_t b,
                      uint8_t cell[CELL_RAW]) {
    uint64_t r = mdet(seed, tag, a, b) % (MP - 1) + 1;
    put(r, cell); put(madd((uint64_t)m, mmul(r, g_mY)), cell + PT_RAW);
    return 0;
}
static uint32_t cr_det_u32(const uint8_t seed[32], const char* tag, uint32_t a, uint32_t b) {
    return (uint32_t)mdet(seed, tag, a, b);
}
static int cr_keygen(uint8_t role, const uint8_t* seed, uint8_t msg[KEY_MSG]) {
    uint64_t k = seed ? mdet(seed, "share", 0, 0) % (MP - 1) + 1 : mrand(); g_mY = k; g_mnegk = MP - k;
    put(k, msg);
    uint8_t pre[1 + PT_RAW]; pre[0] = role; memcpy(pre + 1, msg, PT_RAW);
    msign(k, pre, sizeof(pre), msg + PT_RAW);
    return 0;
}
static int cr_join(uint8_t role, const uint8_t msg[KEY_MSG]) {
    uint8_t pre[1 + PT_RAW]; pre[0] = role; memcpy(pre + 1, msg, PT_RAW);
    g_mYj = get_raw(msg);
    if (!g_mYj || mcheck(g_mYj, pre, sizeof(pre), msg + PT_RAW)) return -1;
    g_mY = madd(g_mY, g_mYj);
    return g_mY ? 0 : -1;
}
static int cr_session(uint32_t epoch_plant, uint32_t epoch_supervisor) {
    uint64_t w = mmul(g_mnegk, g_mYj);              // -k_i k_j: the same on both boards
    for (int d = 0; d < 2; ++d) {
        uint8_t m[17];
        memcpy(m, &w, 8); m[8] = (uint8_t)(d + 1);
        memcpy(m + 9, &epoch_plant, 4); memcpy(m + 13, &epoch_supervisor, 4);
        g_mmac[d] = mhash(m, sizeof(m));
    }
    return 0;
}
static void cr_mac(bool mine, const uint8_t* msg, size_t len, uint8_t tag[DES_TAG_BYTES]) {
    int d = (mine ? DES_ROLE : 3 - DES_ROLE) - 1;
    uint64_t h1 = mhash(msg, len, g_mmac[d]), h2 = mhash(msg, len, g_mmac[d] ^ 0x5bd1e995ULL);
    memcpy(tag, &h1, 8); memcpy(tag + 8, &h2, 8);
}
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
static int cr_rerandomize(const uint8_t* cell, const uint8_t z[CELL_RAW], uint8_t out[CELL_RAW]) {
    uint64_t u = madd(cell ? get_raw(cell) : 0, get_raw(z));
    uint64_t v = madd(cell ? get_raw(cell + PT_RAW) : 0, get_raw(z + PT_RAW));
    put(u, out); put(v, out + PT_RAW);
    return 0;
}
static int cr_partial(const uint8_t cell[CELL_RAW], uint8_t D[PT_RAW]) {
    put(mmul(g_mnegk, get_raw(cell)), D);
    return 0;
}
static int cr_zero_test(const uint8_t cell[CELL_RAW], const uint8_t D[PT_RAW]) {
    return madd(madd(get_raw(cell + PT_RAW), get_raw(D)), mmul(g_mnegk, get_raw(cell))) ? 1 : 0;
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
