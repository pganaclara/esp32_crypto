// =============================================================================
// des_split.h — the supervisor and the plant on two boards
// =============================================================================
//
// The supervisor board holds the supervisor (its tables and its encrypted
// state); the plant board emulates the plant. The private key k = k_P + k_S is
// SPLIT between them: each board draws its own share at boot and nobody ever
// holds k, so neither board can decrypt anything alone. Both encrypt under
// Y = k_P G + k_S G. The supervisor adds its part of the decryption to the
// decision sums only, never to the state.
//
// The plant sends the event to the supervisor, encrypted, and the supervisor
// computes the next encrypted state for that event only, as a supervisor of
// the supervisory control theory does: the cells MOVE. The cell of q' is the
// cell of the state that the event leads to q' (the sum of their cells if it
// leads several there); the cells left over all encrypt 0 (the current state
// is one that the event leaves) and go to the states that the event leads
// nothing into, so that no cell is (O, O). The state is never decrypted, and
// the plant never receives it.
//
// One step (k), after the plant fired event σ:
//
//   plant (share k_P)                         supervisor (share k_S)
//                                              before the event: a fresh
//                                              Enc_Y(0) per decision row
//     ◀──────────────────────────── READY(k)
//     STEP(k, σ encrypted) ─────────────────▶  c'[q'] = c[q] for the q that σ
//                                              leads to q'; the other cells to
//                                              the states σ leads nothing into;
//                                              then, row by row: the sum of its
//                                              cells ⊞ Enc_Y(0), D = -k_S U
//     ◀──────────────────────────── DECS(k) ×rows
//   zero test V + D - k_P U of each row
//   as it arrives → decisions
//
// What the supervisor learns: the events, and so, from its tables, the state
// (it is not decrypted, but the supervisor can follow it). What the plant
// learns about the supervisor: the decisions. It never receives a cell of the
// state, and every decision sum carries its own fresh Enc_Y(0), so the rows of
// R do not show either (without it, a row that is the union of two others
// would have U equal to the sum of theirs). The network sees neither the
// events nor the state: the event travels encrypted, with a symmetric cipher
// apart from the ElGamal of the state, under a key that only the two boards
// hold. Whoever reads the supervisor's memory once finds ciphertexts that it
// cannot relate to anything: the seed of the initial encryption is erased once
// it is done, and the keys of the event's encryption and of the encryptions of
// zero move on at every step (a hash ratchet), so none of an earlier step is
// left. Whoever reads it twice sees where each cell moved
// between the two reads, and so the events in between; if it knows the state
// at the first read (at boot, for instance), it knows it at the second.
//
// The supervisor draws the encryptions of zero of a step (one per decision
// row) BEFORE the event, while it is idle, and keeps them in RAM only; each is
// used once and then erased (a step that comes before they are ready finishes
// them on the spot). So the step itself has no scalar multiplication but the
// one of D per row: the new state is cells moved, and a sum is kept in
// Jacobian coordinates, with one field inversion at the end. Cells are stored
// uncompressed, so no square root is computed to read a point. The supervisor
// sends each row as soon as it is made, and the plant tests it while the
// supervisor makes the next.
//
// Each board has its own identity key (secrets.h, made by make_keys.py) and
// knows the other's public key. The KEY frames are signed with it; every
// other frame is signed with HMAC-SHA256/128 under a session key, one per
// direction, that only the two boards can derive. A copy of one board's flash
// lets no one pass for the other board. Frames are 1400 bytes and carry a
// per-boot epoch and a configuration fingerprint; a lost frame is asked for
// again (NACK) by the receiver. Only the monolithic supervisor is used (one
// supervisor, MONO_SUP of the header).
//
// Both boards are assumed to follow the protocol and to learn what they can
// from what they see (honest-but-curious).
//
// Integrity is not checked in real time: a supervisor board that deviates from
// the protocol can send wrong sums and so wrong decisions. It is accountable
// instead. At boot it commits to its tables and to a secret seed from which it
// draws all its randomness (its share, the initial encryption, the encryptions
// of zero), and after every step it signs a chain of SHA-256 over the step's
// encrypted event and decisions, which the plant board checks against what it
// sent and received. An auditor given the seed and the tables redoes every
// step from a recording of the network (audit.py) and finds any deviation,
// which the supervisor's signature makes undeniable.
//
// The plant board also runs the supervisor in clear, as an oracle that checks
// every decision; a deployment would omit it, and the plant would then not
// need the supervisor's tables at all.
// =============================================================================

#pragma once

#ifndef DES_SPLIT_MOCK
#define DES_SPLIT_MOCK 0        // 1 only in the host test build without mbedTLS
#endif

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>

#define DES_PLANT      1
#define DES_SUPERVISOR 2
#ifndef DES_ROLE
#  error "Set DES_ROLE to DES_PLANT or DES_SUPERVISOR"
#endif

// ── platform ─────────────────────────────────────────────────────────────────
#if defined(ARDUINO)
#  include <Arduino.h>
#  include <esp_timer.h>
#  ifndef DES_LOG
#    define DES_LOG(...) Serial.printf(__VA_ARGS__)
#  endif
#  define DES_YIELD() yield()
static uint32_t des_millis()            { return (uint32_t)millis(); }
static uint64_t des_micros()            { return (uint64_t)esp_timer_get_time(); }
static void     des_sleep_ms(uint32_t ms) { delay(ms); }
#else
#  include <time.h>
#  include <sched.h>
#  ifndef DES_LOG
#    define DES_LOG(...) printf(__VA_ARGS__)
#  endif
#  define DES_YIELD() sched_yield()
#  ifndef PROGMEM
#    define PROGMEM
#  endif
#  ifndef pgm_read_byte
#    define pgm_read_byte(a) (*(const uint8_t*)(a))
#  endif
#  ifndef pgm_read_word
#    define pgm_read_word(a) (*(const uint16_t*)(a))
#  endif
#  ifndef pgm_read_ptr
#    define pgm_read_ptr(a)  (*(void* const*)(a))
#  endif
#  ifndef strncpy_P
#    define strncpy_P strncpy
#  endif
static uint64_t des_micros() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}
static uint32_t des_millis() { return (uint32_t)(des_micros() / 1000ULL); }
static void des_sleep_ms(uint32_t ms) {
    struct timespec ts; ts.tv_sec = ms / 1000; ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, nullptr);
}
#endif

#include DES_DATA_HEADER

#if !HAS_MONO
#  error "des_split needs the monolithic supervisor: the header has HAS_MONO 0"
#endif
static_assert(EVENT_COUNT <= 64, "the decision groups use a 64-bit event mask");

#ifndef DES_MCAST_PORT
#define DES_MCAST_PORT 5078         // not des_distributed's 5077
#endif
#ifndef DES_FRAME_BYTES
#define DES_FRAME_BYTES 1400        // one UDP datagram, below the Ethernet MTU
#endif
#include "des_transport.h"

// This board's identity: its private and public key, and the other board's
// public key, from secrets.h (make_keys.py writes them). The other board's
// private key is never compiled in.
#if DES_ROLE == DES_PLANT
#  define DES_MY_ID    DES_ID_PLANT
#  define DES_MY_PUB   DES_PUB_PLANT
#  define DES_PEER_PUB DES_PUB_SUPERVISOR
#else
#  define DES_MY_ID    DES_ID_SUPERVISOR
#  define DES_MY_PUB   DES_PUB_SUPERVISOR
#  define DES_PEER_PUB DES_PUB_PLANT
#endif
#if DES_ROLE == DES_PLANT && !defined(DES_ID_PLANT) || \
    DES_ROLE == DES_SUPERVISOR && !defined(DES_ID_SUPERVISOR) || \
    !defined(DES_PUB_PLANT) || !defined(DES_PUB_SUPERVISOR)
#  error "secrets.h needs the identity keys: python make_keys.py >> secrets.h"
#endif

// =============================================================================
// 1. Cells and the crypto they need
// =============================================================================
//
// The curve is NIST P-192, P-224 or P-256 (DES_CURVE). A point travels raw,
// x || y (all zero = the point at infinity): 48, 56 or 64 bytes; a cell (a
// ciphertext (U, V)) twice that. Nothing travels compressed: decompressing
// costs a square root, and mbedTLS cannot decompress a P-224 point. A raw
// point is refused when read if it is not on the curve.

#ifndef DES_CURVE
#define DES_CURVE 256
#endif
#if DES_CURVE != 192 && DES_CURVE != 224 && DES_CURVE != 256
#  error "DES_CURVE must be 192, 224 or 256 (NIST P-192, P-224, P-256)"
#endif
#define SC_BYTES (DES_CURVE / 8)                    // a coordinate, a scalar mod N
#define PT_RAW   (2 * SC_BYTES)
#define CELL_RAW (2 * PT_RAW)
#define SIG_BYTES (PT_RAW + SC_BYTES)               // a Schnorr signature or proof: R, z
#define KEY_MSG  (PT_RAW + SIG_BYTES)               // Y_i, then the proof that k_i is known
static_assert(sizeof(DES_MY_ID) - 1 == 2 * SC_BYTES && sizeof(DES_MY_PUB) - 1 == 4 * SC_BYTES &&
              sizeof(DES_PEER_PUB) - 1 == 4 * SC_BYTES,
              "the identity keys of secrets.h are not keys of DES_CURVE: run make_keys.py again");
#define DES_TAG_BYTES 16

// Implemented below with mbedTLS, or by a host test build (DES_SPLIT_MOCK).
#define CR_FN static __attribute__((unused))   // each role uses only some of them
// Erases a buffer (volatile writes, which the compiler keeps).
static void wipe(void* p, size_t n) { volatile uint8_t* v = (volatile uint8_t*)p; while (n--) *v++ = 0; }
CR_FN void cr_init(const char* pers);
CR_FN uint32_t cr_random32();
// This board's identity key and the other board's public key (hex; a public
// key is x || y). Fails unless my_pub is my_priv's.
CR_FN int  cr_identity(const char* my_priv, const char* my_pub, const char* peer_pub);
CR_FN int  cr_sign(const uint8_t* msg, size_t len, uint8_t sig[SIG_BYTES]);          // as this board
CR_FN int  cr_verify(const uint8_t* msg, size_t len, const uint8_t sig[SIG_BYTES]);  // the other's
// After cr_join: one MAC key per direction and the key of the event's
// encryption (g_evk), HMAC-SHA256 under the x of the shares' Diffie–Hellman k_P k_S G
// (only the two boards can compute it) of "des_split" || 1, 2 or 3 || both
// epochs. cr_mac signs as this board (mine) or checks the other's.
static uint8_t g_evk[32];
CR_FN int  cr_session(uint32_t epoch_plant, uint32_t epoch_supervisor);
CR_FN void cr_mac(bool mine, const uint8_t* msg, size_t len, uint8_t tag[DES_TAG_BYTES]);
// out = HMAC-SHA256(key, label) (out may be key).
CR_FN void cr_kdf(const uint8_t key[32], const char* label, uint8_t out[32]);
// This board's share k_i: msg = Y_i = k_i G and a proof that the board knows
// k_i (a Schnorr signature of role || Y_i under k_i). Without the proof, a
// board that saw the other's share Y_j first could send aG - Y_j, and the
// joint key would be aG: it alone would hold the whole key. role names the
// prover, so a proof cannot be passed off as the other board's. k_i is random,
// or derived from seed (the supervisor's, for the audit). Until cr_join, Y is
// the share alone.
CR_FN int  cr_keygen(uint8_t role, const uint8_t* seed, uint8_t msg[KEY_MSG]);
CR_FN int  cr_join(uint8_t role, const uint8_t msg[KEY_MSG]);  // checks it; Y = Y_i + Y_j
CR_FN int  cr_enc(int m, uint8_t cell[CELL_RAW]);        // fresh encryption of m
// The same with the random number derived from a secret seed, so that an
// auditor given the seed can redo it: s = (HMAC-SHA256(seed, tag || a || b || 1)
// || HMAC-SHA256(seed, tag || a || b || 2)) mod (N - 1) + 1, a and b little-endian.
CR_FN int  cr_enc_det(int m, const uint8_t seed[32], const char* tag, uint32_t a, uint32_t b,
                      uint8_t cell[CELL_RAW]);
CR_FN uint32_t cr_det_u32(const uint8_t seed[32], const char* tag, uint32_t a, uint32_t b);
CR_FN void cr_sha256(const uint8_t* m, size_t n, uint8_t out[32]);
CR_FN void cr_random_bytes(uint8_t* out, size_t n);
// out = the homomorphic sum of the cells (out may be one of them).
CR_FN int  cr_sum(const uint8_t* const* cells, int cnt, uint8_t out[CELL_RAW]);
// D = -k_i U, this board's part of the decryption of the cell (U, V).
CR_FN int  cr_partial(const uint8_t cell[CELL_RAW], uint8_t D[PT_RAW]);
// V + D - k_i U, which is mG with D from the other board: 0 if m = 0, 1 if
// not, or < 0 on error.
CR_FN int  cr_zero_test(const uint8_t cell[CELL_RAW], const uint8_t D[PT_RAW]);

#if !DES_SPLIT_MOCK
#define MBEDTLS_ALLOW_PRIVATE_ACCESS   // the curve's fast reduction and an mpi's sign, in f_red() and f_sub()
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>

#if DES_CURVE == 192
#  define DES_ECP_ID MBEDTLS_ECP_DP_SECP192R1
#elif DES_CURVE == 224
#  define DES_ECP_ID MBEDTLS_ECP_DP_SECP224R1
#else
#  define DES_ECP_ID MBEDTLS_ECP_DP_SECP256R1
#endif

static mbedtls_ecp_group        g_grp;
static mbedtls_ecp_point        g_Y;                // joint public key
static mbedtls_mpi              g_one, g_neg_k;     // N - k_i: this board's share
static mbedtls_ecp_point        g_Yj, g_peer_id;    // the other's share, its identity key
static mbedtls_mpi              g_id;               // this board's identity key
static uint8_t                  g_mac[2][32];       // the session's MAC keys: plant's, supervisor's
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_entropy_context  g_entropy;

static inline void swap_pt(mbedtls_ecp_point* a, mbedtls_ecp_point* b) {
    mbedtls_ecp_point t = *a; *a = *b; *b = t;
}
static bool pt_raw_is_inf(const uint8_t* p) {
    uint8_t acc = 0;
    for (int i = 0; i < PT_RAW; ++i) acc |= p[i];
    return acc == 0;
}
static int pt_from_raw(const uint8_t raw[PT_RAW], mbedtls_ecp_point* P) {
    if (pt_raw_is_inf(raw)) return mbedtls_ecp_set_zero(P);
    uint8_t b[1 + PT_RAW]; b[0] = 0x04; memcpy(b + 1, raw, PT_RAW);
    int ret = mbedtls_ecp_point_read_binary(&g_grp, P, b, sizeof(b));
    if (ret == 0) ret = mbedtls_ecp_check_pubkey(&g_grp, P);  // on the curve
    return ret;
}
static int pt_to_raw(mbedtls_ecp_point* P, uint8_t raw[PT_RAW]) {
    if (mbedtls_ecp_is_zero(P)) { memset(raw, 0, PT_RAW); return 0; }
    uint8_t b[1 + PT_RAW]; size_t len = 0;
    int ret = mbedtls_ecp_point_write_binary(&g_grp, P, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &len, b, sizeof(b));
    if (ret == 0) memcpy(raw, b + 1, PT_RAW);
    return ret;
}
// R = A + B. mbedtls_ecp_muladd refuses the point at infinity as an input.
static int pt_add(mbedtls_ecp_point* R, mbedtls_ecp_point* A, mbedtls_ecp_point* B) {
    if (mbedtls_ecp_is_zero(A)) return mbedtls_ecp_copy(R, B);
    if (mbedtls_ecp_is_zero(B)) return mbedtls_ecp_copy(R, A);
    return mbedtls_ecp_muladd(&g_grp, R, &g_one, A, &g_one, B);
}
// (U, V) = (sG, sY), the encryption of zero with the random number s.
static int enc_with(mbedtls_mpi* s, mbedtls_ecp_point* U, mbedtls_ecp_point* V) {
    int ret = mbedtls_ecp_mul(&g_grp, U, s, &g_grp.G, mbedtls_ctr_drbg_random, &g_drbg);
    if (ret == 0) ret = mbedtls_ecp_mul(&g_grp, V, s, &g_Y,     mbedtls_ctr_drbg_random, &g_drbg);
    return ret;
}
// A fresh encryption of zero.
static int enc0(mbedtls_ecp_point* U, mbedtls_ecp_point* V) {
    mbedtls_mpi s; mbedtls_mpi_init(&s);
    int ret = mbedtls_ecp_gen_privkey(&g_grp, &s, mbedtls_ctr_drbg_random, &g_drbg);
    if (ret == 0) ret = enc_with(&s, U, V);
    mbedtls_mpi_free(&s);
    return ret;
}
// HMAC-SHA256(seed, tag || a || b || ctr): randomness derived from a seed.
static void det_bytes(const uint8_t seed[32], const char* tag, uint32_t a, uint32_t b, uint8_t ctr,
                      uint8_t out[32]) {
    uint8_t m[32];
    size_t n = strlen(tag);                                 // a few letters
    memcpy(m, tag, n); memcpy(m + n, &a, 4); memcpy(m + n + 4, &b, 4); m[n + 8] = ctr;
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), seed, 32, m, n + 9, out);
}
static int det_scalar(const uint8_t seed[32], const char* tag, uint32_t a, uint32_t b, mbedtls_mpi* s) {
    uint8_t h[64];
    det_bytes(seed, tag, a, b, 1, h); det_bytes(seed, tag, a, b, 2, h + 32);
    mbedtls_mpi x, n1, r; mbedtls_mpi_init(&x); mbedtls_mpi_init(&n1); mbedtls_mpi_init(&r);
    int ret = mbedtls_mpi_read_binary(&x, h, sizeof(h));
    if (ret == 0) ret = mbedtls_mpi_sub_mpi(&n1, &g_grp.N, &g_one);
    if (ret == 0) ret = mbedtls_mpi_mod_mpi(&r, &x, &n1);
    if (ret == 0) ret = mbedtls_mpi_add_mpi(s, &r, &g_one);            // 1 .. N - 1
    wipe(h, sizeof(h));
    mbedtls_mpi_free(&x); mbedtls_mpi_free(&n1); mbedtls_mpi_free(&r);
    return ret;
}
// W = (N - k_i) U = -k_i U, the point at infinity if U is. The scalar
// multiplication is blinded (a DRBG callback), against timing and power analysis.
static int neg_share_times(mbedtls_ecp_point* U, mbedtls_ecp_point* W) {
    if (mbedtls_ecp_is_zero(U)) return mbedtls_ecp_set_zero(W);
    return mbedtls_ecp_mul(&g_grp, W, &g_neg_k, U, mbedtls_ctr_drbg_random, &g_drbg);
}
// Schnorr with the key x over the bytes pre: R = tG for a random t,
// c = SHA-256(pre || R) mod N, z = t + c x mod N; sig = R || z. It holds iff
// zG - cX = R.
static int schnorr_c(const uint8_t* pre, size_t n, const uint8_t R[PT_RAW], mbedtls_mpi* c) {
    std::vector<uint8_t> m(pre, pre + n);
    m.insert(m.end(), R, R + PT_RAW);
    uint8_t h[32];
    mbedtls_mpi x; mbedtls_mpi_init(&x);
    int ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), m.data(), m.size(), h);
    if (ret == 0) ret = mbedtls_mpi_read_binary(&x, h, sizeof(h));
    if (ret == 0) ret = mbedtls_mpi_mod_mpi(c, &x, &g_grp.N);
    mbedtls_mpi_free(&x);
    return ret;
}
static int schnorr_sign(const mbedtls_mpi* x, const uint8_t* pre, size_t n, uint8_t sig[SIG_BYTES]) {
    mbedtls_mpi t, c, cx, z;
    mbedtls_mpi_init(&t); mbedtls_mpi_init(&c); mbedtls_mpi_init(&cx); mbedtls_mpi_init(&z);
    mbedtls_ecp_point R; mbedtls_ecp_point_init(&R);
    int ret = mbedtls_ecp_gen_keypair(&g_grp, &t, &R, mbedtls_ctr_drbg_random, &g_drbg);
    if (ret == 0) ret = pt_to_raw(&R, sig);
    if (ret == 0) ret = schnorr_c(pre, n, sig, &c);
    if (ret == 0) ret = mbedtls_mpi_mul_mpi(&cx, &c, x);
    if (ret == 0) ret = mbedtls_mpi_add_mpi(&z, &cx, &t);
    if (ret == 0) ret = mbedtls_mpi_mod_mpi(&cx, &z, &g_grp.N);
    if (ret == 0) ret = mbedtls_mpi_write_binary(&cx, sig + PT_RAW, SC_BYTES);
    mbedtls_mpi_free(&t); mbedtls_mpi_free(&c); mbedtls_mpi_free(&cx); mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&R);
    return ret;
}
static int schnorr_check(mbedtls_ecp_point* X, const uint8_t* pre, size_t n, const uint8_t sig[SIG_BYTES]) {
    mbedtls_ecp_point R, T; mbedtls_ecp_point_init(&R); mbedtls_ecp_point_init(&T);
    mbedtls_mpi c, nc, z; mbedtls_mpi_init(&c); mbedtls_mpi_init(&nc); mbedtls_mpi_init(&z);
    int ret = pt_from_raw(sig, &R);
    if (ret == 0) ret = mbedtls_mpi_read_binary(&z, sig + PT_RAW, SC_BYTES);
    if (ret == 0) ret = schnorr_c(pre, n, sig, &c);
    if (ret == 0) ret = mbedtls_mpi_sub_mpi(&nc, &g_grp.N, &c);
    if (ret == 0) ret = mbedtls_ecp_muladd(&g_grp, &T, &z, &g_grp.G, &nc, X);
    if (ret == 0 && mbedtls_ecp_point_cmp(&T, &R) != 0) ret = -1;
    mbedtls_ecp_point_free(&R); mbedtls_ecp_point_free(&T);
    mbedtls_mpi_free(&c); mbedtls_mpi_free(&nc); mbedtls_mpi_free(&z);
    return ret;
}
static int hex_in(const char* hex, uint8_t* out, size_t n) {
    if (strlen(hex) != 2 * n) return -1;
    for (size_t i = 0; i < n; ++i) {
        unsigned v = 0;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static void cr_init(const char* pers) {
    mbedtls_ecp_group_init(&g_grp); mbedtls_ecp_point_init(&g_Y);
    mbedtls_mpi_init(&g_one); mbedtls_mpi_init(&g_neg_k); mbedtls_mpi_init(&g_id);
    mbedtls_ecp_point_init(&g_Yj); mbedtls_ecp_point_init(&g_peer_id);
    mbedtls_ctr_drbg_init(&g_drbg); mbedtls_entropy_init(&g_entropy);
    mbedtls_mpi_lset(&g_one, 1);
    mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                          (const uint8_t*)pers, strlen(pers));
    mbedtls_ecp_group_load(&g_grp, DES_ECP_ID);
}
static uint32_t cr_random32() {
    uint32_t r = 0;
    mbedtls_ctr_drbg_random(&g_drbg, (unsigned char*)&r, sizeof(r));
    return r;
}
static int cr_identity(const char* my_priv, const char* my_pub, const char* peer_pub) {
    uint8_t b[PT_RAW];
    mbedtls_ecp_point Q, P; mbedtls_ecp_point_init(&Q); mbedtls_ecp_point_init(&P);
    int ret = hex_in(my_priv, b, SC_BYTES);
    if (ret == 0) ret = mbedtls_mpi_read_binary(&g_id, b, SC_BYTES);
    if (ret == 0) ret = mbedtls_ecp_check_privkey(&g_grp, &g_id);
    if (ret == 0) ret = mbedtls_ecp_mul(&g_grp, &Q, &g_id, &g_grp.G, mbedtls_ctr_drbg_random, &g_drbg);
    if (ret == 0) ret = hex_in(my_pub, b, PT_RAW);
    if (ret == 0) ret = pt_from_raw(b, &P);
    if (ret == 0 && mbedtls_ecp_point_cmp(&Q, &P) != 0) ret = -1;
    if (ret == 0) ret = hex_in(peer_pub, b, PT_RAW);
    if (ret == 0) ret = pt_from_raw(b, &g_peer_id);
    if (ret == 0) ret = mbedtls_ecp_check_pubkey(&g_grp, &g_peer_id);  // not the point at infinity
    memset(b, 0, sizeof(b));
    mbedtls_ecp_point_free(&Q); mbedtls_ecp_point_free(&P);
    return ret;
}
static int cr_sign(const uint8_t* msg, size_t len, uint8_t sig[SIG_BYTES]) {
    return schnorr_sign(&g_id, msg, len, sig);
}
static int cr_verify(const uint8_t* msg, size_t len, const uint8_t sig[SIG_BYTES]) {
    return schnorr_check(&g_peer_id, msg, len, sig);
}
static int cr_session(uint32_t epoch_plant, uint32_t epoch_supervisor) {
    mbedtls_ecp_point W; mbedtls_ecp_point_init(&W);
    uint8_t w[PT_RAW];
    int ret = neg_share_times(&g_Yj, &W);        // -k_i k_j G: the same x on both boards
    if (ret == 0) ret = pt_to_raw(&W, w);
    uint8_t* key[3] = {g_mac[0], g_mac[1], g_evk};
    for (int d = 0; d < 3 && ret == 0; ++d) {
        uint8_t m[18];
        memcpy(m, "des_split", 9); m[9] = (uint8_t)(d + 1);
        memcpy(m + 10, &epoch_plant, 4); memcpy(m + 14, &epoch_supervisor, 4);
        ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), w, SC_BYTES,
                              m, sizeof(m), key[d]);
    }
    memset(w, 0, sizeof(w));
    mbedtls_ecp_point_free(&W);
    return ret;
}
static void cr_mac(bool mine, const uint8_t* msg, size_t len, uint8_t tag[DES_TAG_BYTES]) {
    int d = (mine ? DES_ROLE : (DES_ROLE == DES_PLANT ? DES_SUPERVISOR : DES_PLANT)) - 1;
    uint8_t full[32];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), g_mac[d], sizeof(g_mac[d]),
                    msg, len, full);
    memcpy(tag, full, DES_TAG_BYTES);
}
static void cr_kdf(const uint8_t key[32], const char* label, uint8_t out[32]) {
    uint8_t h[32];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32,
                    (const uint8_t*)label, strlen(label), h);
    memcpy(out, h, 32);
    wipe(h, sizeof(h));
}
static int cr_keygen(uint8_t role, const uint8_t* seed, uint8_t msg[KEY_MSG]) {
    mbedtls_mpi k; mbedtls_mpi_init(&k);
    uint8_t pre[1 + PT_RAW];
    int ret = seed ? det_scalar(seed, "share", 0, 0, &k)
                   : mbedtls_ecp_gen_privkey(&g_grp, &k, mbedtls_ctr_drbg_random, &g_drbg);
    if (ret == 0) ret = mbedtls_ecp_mul(&g_grp, &g_Y, &k, &g_grp.G, mbedtls_ctr_drbg_random, &g_drbg);
    if (ret == 0) ret = mbedtls_mpi_sub_mpi(&g_neg_k, &g_grp.N, &k);
    if (ret == 0) ret = pt_to_raw(&g_Y, msg);
    pre[0] = role; memcpy(pre + 1, msg, PT_RAW);
    if (ret == 0) ret = schnorr_sign(&k, pre, sizeof(pre), msg + PT_RAW);
    mbedtls_mpi_free(&k);                               // only N - k_i is kept
    return ret;
}
static int cr_join(uint8_t role, const uint8_t msg[KEY_MSG]) {
    mbedtls_ecp_point T; mbedtls_ecp_point_init(&T);
    uint8_t pre[1 + PT_RAW];
    pre[0] = role; memcpy(pre + 1, msg, PT_RAW);
    int ret = pt_from_raw(msg, &g_Yj);
    if (ret == 0) ret = mbedtls_ecp_check_pubkey(&g_grp, &g_Yj);     // not the point at infinity
    if (ret == 0) ret = schnorr_check(&g_Yj, pre, sizeof(pre), msg + PT_RAW);
    if (ret == 0) ret = pt_add(&T, &g_Y, &g_Yj);
    if (ret == 0) ret = mbedtls_ecp_check_pubkey(&g_grp, &T);        // not the point at infinity
    if (ret == 0) swap_pt(&g_Y, &T);
    mbedtls_ecp_point_free(&T);
    return ret;
}
static int cr_enc(int m, uint8_t cell[CELL_RAW]) {
    mbedtls_ecp_point U, V, W;
    mbedtls_ecp_point_init(&U); mbedtls_ecp_point_init(&V); mbedtls_ecp_point_init(&W);
    int ret = enc0(&U, &V);
    if (ret == 0 && m) { ret = pt_add(&W, &V, &g_grp.G); if (ret == 0) swap_pt(&V, &W); }
    if (ret == 0) ret = pt_to_raw(&U, cell);
    if (ret == 0) ret = pt_to_raw(&V, cell + PT_RAW);
    mbedtls_ecp_point_free(&U); mbedtls_ecp_point_free(&V); mbedtls_ecp_point_free(&W);
    return ret;
}
static int cr_enc_det(int m, const uint8_t seed[32], const char* tag, uint32_t a, uint32_t b,
                      uint8_t cell[CELL_RAW]) {
    mbedtls_mpi s; mbedtls_mpi_init(&s);
    mbedtls_ecp_point U, V, W;
    mbedtls_ecp_point_init(&U); mbedtls_ecp_point_init(&V); mbedtls_ecp_point_init(&W);
    int ret = det_scalar(seed, tag, a, b, &s);
    if (ret == 0) ret = enc_with(&s, &U, &V);
    if (ret == 0 && m) { ret = pt_add(&W, &V, &g_grp.G); if (ret == 0) swap_pt(&V, &W); }
    if (ret == 0) ret = pt_to_raw(&U, cell);
    if (ret == 0) ret = pt_to_raw(&V, cell + PT_RAW);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&U); mbedtls_ecp_point_free(&V); mbedtls_ecp_point_free(&W);
    return ret;
}
static uint32_t cr_det_u32(const uint8_t seed[32], const char* tag, uint32_t a, uint32_t b) {
    uint8_t h[32];
    det_bytes(seed, tag, a, b, 1, h);
    uint32_t v; memcpy(&v, h, 4);
    return v;
}
static void cr_sha256(const uint8_t* m, size_t n, uint8_t out[32]) {
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), m, n, out);
}
static void cr_random_bytes(uint8_t* out, size_t n) {
    mbedtls_ctr_drbg_random(&g_drbg, out, n);
}
// ── Sums without an inversion per addition ──────────────────────────────────
// mbedtls_ecp_muladd gives every sum in affine coordinates, at the price of a
// field inversion per addition, which is almost all of it. A sum is kept here
// in Jacobian coordinates instead, (X, Y, Z) for the affine point
// (X/Z^2, Y/Z^3): an affine point is added with 3 squarings and 8
// multiplications, and the sum is brought back to affine with one inversion.
// The points are the same, and so are the bytes. Every point read is checked
// to be on the curve, as pt_from_raw does. (From docker_des, engine 0783b03.)
struct Jac { mbedtls_mpi X, Y, Z; };       // Z = 0: the point at infinity
static mbedtls_mpi f_t[4], f_x, f_y;       // scratch
static void jac_init(Jac& J) { mbedtls_mpi_init(&J.X); mbedtls_mpi_init(&J.Y); mbedtls_mpi_init(&J.Z); }
static void f_setup() {
    static bool done = false;
    if (done) return;
    for (mbedtls_mpi& t : f_t) mbedtls_mpi_init(&t);
    mbedtls_mpi_init(&f_x); mbedtls_mpi_init(&f_y);
    done = true;
}
// x mod p, for 0 <= x < p^2: mbedTLS's fast reduction of the NIST primes.
static int f_red(mbedtls_mpi* x) {
    int ret = g_grp.modp ? g_grp.modp(x) : mbedtls_mpi_mod_mpi(x, x, &g_grp.P);
    while (ret == 0 && x->s < 0 && mbedtls_mpi_cmp_int(x, 0) != 0) ret = mbedtls_mpi_add_mpi(x, x, &g_grp.P);
    while (ret == 0 && mbedtls_mpi_cmp_mpi(x, &g_grp.P) >= 0) ret = mbedtls_mpi_sub_abs(x, x, &g_grp.P);
    return ret;
}
static int f_mul(mbedtls_mpi* r, const mbedtls_mpi* a, const mbedtls_mpi* b) {
    int ret = mbedtls_mpi_mul_mpi(r, a, b);
    return ret ? ret : f_red(r);
}
static int f_sub(mbedtls_mpi* r, const mbedtls_mpi* a, const mbedtls_mpi* b) {
    int ret = mbedtls_mpi_sub_mpi(r, a, b);
    while (ret == 0 && r->s < 0 && mbedtls_mpi_cmp_int(r, 0) != 0) ret = mbedtls_mpi_add_mpi(r, r, &g_grp.P);
    return ret;
}
static int f_add(mbedtls_mpi* r, const mbedtls_mpi* a, const mbedtls_mpi* b) {
    int ret = mbedtls_mpi_add_mpi(r, a, b);
    while (ret == 0 && mbedtls_mpi_cmp_mpi(r, &g_grp.P) >= 0) ret = mbedtls_mpi_sub_abs(r, r, &g_grp.P);
    return ret;
}
// The affine point x || y of raw, checked to be on the curve y^2 = x^3 - 3x + b
// (every curve here has a = -3); *inf for the point at infinity (all zero).
static int f_read(const uint8_t raw[PT_RAW], mbedtls_mpi* x, mbedtls_mpi* y, bool* inf) {
    *inf = pt_raw_is_inf(raw);
    if (*inf) return 0;
    int ret = mbedtls_mpi_read_binary(x, raw, SC_BYTES);
    if (ret == 0) ret = mbedtls_mpi_read_binary(y, raw + SC_BYTES, SC_BYTES);
    if (ret) return ret;
    if (mbedtls_mpi_cmp_mpi(x, &g_grp.P) >= 0 || mbedtls_mpi_cmp_mpi(y, &g_grp.P) >= 0) return MBEDTLS_ERR_ECP_INVALID_KEY;
    mbedtls_mpi *l = &f_t[0], *r = &f_t[1], *t = &f_t[2];
    ret = f_mul(l, y, y);
    if (ret == 0) ret = f_mul(r, x, x);
    if (ret == 0) ret = f_mul(r, r, x);
    if (ret == 0) ret = f_add(t, x, x);
    if (ret == 0) ret = f_add(t, t, x);
    if (ret == 0) ret = f_sub(r, r, t);
    if (ret == 0) ret = f_add(r, r, &g_grp.B);
    if (ret == 0 && mbedtls_mpi_cmp_mpi(l, r) != 0) ret = MBEDTLS_ERR_ECP_INVALID_KEY;
    return ret;
}
// J = 2J, through mbedTLS: an addition of a point to itself, which happens
// with probability about 1/N.
static int jac_double_slow(Jac& J) {
    mbedtls_ecp_point P, R; mbedtls_ecp_point_init(&P); mbedtls_ecp_point_init(&R);
    mbedtls_mpi zi, z2; mbedtls_mpi_init(&zi); mbedtls_mpi_init(&z2);
    int ret = mbedtls_mpi_inv_mod(&zi, &J.Z, &g_grp.P);
    if (ret == 0) ret = f_mul(&z2, &zi, &zi);
    if (ret == 0) ret = f_mul(&P.X, &J.X, &z2);
    if (ret == 0) ret = f_mul(&z2, &z2, &zi);
    if (ret == 0) ret = f_mul(&P.Y, &J.Y, &z2);
    if (ret == 0) ret = mbedtls_mpi_lset(&P.Z, 1);
    if (ret == 0) ret = mbedtls_ecp_muladd(&g_grp, &R, &g_one, &P, &g_one, &P);
    if (ret == 0) ret = mbedtls_mpi_copy(&J.X, &R.X);
    if (ret == 0) ret = mbedtls_mpi_copy(&J.Y, &R.Y);
    if (ret == 0) ret = mbedtls_mpi_copy(&J.Z, &R.Z);   // 1, or 0 if 2J is the point at infinity
    mbedtls_ecp_point_free(&P); mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&zi); mbedtls_mpi_free(&z2);
    return ret;
}
// J += (x, y), an affine point (mixed addition, a = -3).
static int jac_add(Jac& J, const mbedtls_mpi* x, const mbedtls_mpi* y) {
    int ret;
    if (mbedtls_mpi_cmp_int(&J.Z, 0) == 0) {
        ret = mbedtls_mpi_copy(&J.X, x);
        if (ret == 0) ret = mbedtls_mpi_copy(&J.Y, y);
        return ret ? ret : mbedtls_mpi_lset(&J.Z, 1);
    }
    mbedtls_mpi *t1 = &f_t[0], *t2 = &f_t[1], *t3 = &f_t[2], *t4 = &f_t[3];
    ret = f_mul(t1, &J.Z, &J.Z);
    if (ret == 0) ret = f_mul(t2, t1, &J.Z);
    if (ret == 0) ret = f_mul(t1, t1, x);                    // U2 = x Z^2
    if (ret == 0) ret = f_mul(t2, t2, y);                    // S2 = y Z^3
    if (ret == 0) ret = f_sub(t1, t1, &J.X);                 // H
    if (ret == 0) ret = f_sub(t2, t2, &J.Y);                 // R
    if (ret) return ret;
    if (mbedtls_mpi_cmp_int(t1, 0) == 0)
        return mbedtls_mpi_cmp_int(t2, 0) ? mbedtls_mpi_lset(&J.Z, 0) : jac_double_slow(J);
    ret = f_mul(&J.Z, &J.Z, t1);                             // Z3 = Z H
    if (ret == 0) ret = f_mul(t3, t1, t1);                   // H^2
    if (ret == 0) ret = f_mul(t4, t3, t1);                   // H^3
    if (ret == 0) ret = f_mul(t3, t3, &J.X);                 // X H^2
    if (ret == 0) ret = f_mul(&J.X, t2, t2);
    if (ret == 0) ret = f_sub(&J.X, &J.X, t4);
    if (ret == 0) ret = f_sub(&J.X, &J.X, t3);
    if (ret == 0) ret = f_sub(&J.X, &J.X, t3);               // X3 = R^2 - H^3 - 2 X H^2
    if (ret == 0) ret = f_sub(t3, t3, &J.X);
    if (ret == 0) ret = f_mul(t3, t3, t2);
    if (ret == 0) ret = f_mul(t4, t4, &J.Y);
    if (ret == 0) ret = f_sub(&J.Y, t3, t4);                 // Y3 = R (X H^2 - X3) - Y H^3
    return ret;
}
// J to affine raw x || y (all zero for the point at infinity).
static int jac_out(Jac& J, uint8_t out[PT_RAW]) {
    if (mbedtls_mpi_cmp_int(&J.Z, 0) == 0) { memset(out, 0, PT_RAW); return 0; }
    mbedtls_mpi *zi = &f_t[0], *z2 = &f_t[1], *c = &f_t[2];
    int ret = mbedtls_mpi_inv_mod(zi, &J.Z, &g_grp.P);
    if (ret == 0) ret = f_mul(z2, zi, zi);
    if (ret == 0) ret = f_mul(c, &J.X, z2);
    if (ret == 0) ret = mbedtls_mpi_write_binary(c, out, SC_BYTES);
    if (ret == 0) ret = f_mul(z2, z2, zi);
    if (ret == 0) ret = f_mul(c, &J.Y, z2);
    if (ret == 0) ret = mbedtls_mpi_write_binary(c, out + SC_BYTES, SC_BYTES);
    return ret;
}
static int cr_sum(const uint8_t* const* cells, int cnt, uint8_t out[CELL_RAW]) {
    f_setup();
    static Jac S[2];
    static bool ready = false;
    if (!ready) { jac_init(S[0]); jac_init(S[1]); ready = true; }
    int ret = mbedtls_mpi_lset(&S[0].Z, 0);
    if (ret == 0) ret = mbedtls_mpi_lset(&S[1].Z, 0);
    for (int i = 0; i < cnt && ret == 0; ++i)
        for (int h = 0; h < 2 && ret == 0; ++h) {
            bool inf;
            ret = f_read(cells[i] + h * PT_RAW, &f_x, &f_y, &inf);
            if (ret == 0 && !inf) ret = jac_add(S[h], &f_x, &f_y);
        }
    if (ret == 0) ret = jac_out(S[0], out);
    if (ret == 0) ret = jac_out(S[1], out + PT_RAW);
    return ret;
}
static int cr_partial(const uint8_t cell[CELL_RAW], uint8_t D[PT_RAW]) {
    mbedtls_ecp_point U, W;
    mbedtls_ecp_point_init(&U); mbedtls_ecp_point_init(&W);
    int ret = pt_from_raw(cell, &U);
    if (ret == 0) ret = neg_share_times(&U, &W);
    if (ret == 0) ret = pt_to_raw(&W, D);
    mbedtls_ecp_point_free(&U); mbedtls_ecp_point_free(&W);
    return ret;
}
static int cr_zero_test(const uint8_t cell[CELL_RAW], const uint8_t D[PT_RAW]) {
    mbedtls_ecp_point U, V, P, W, R;
    mbedtls_ecp_point_init(&U); mbedtls_ecp_point_init(&V); mbedtls_ecp_point_init(&P);
    mbedtls_ecp_point_init(&W); mbedtls_ecp_point_init(&R);
    int ret = pt_from_raw(cell, &U);
    if (ret == 0) ret = pt_from_raw(cell + PT_RAW, &V);
    if (ret == 0) ret = pt_from_raw(D, &P);
    if (ret == 0) ret = neg_share_times(&U, &W);
    if (ret == 0) ret = pt_add(&R, &V, &W);
    if (ret == 0) ret = pt_add(&W, &R, &P);
    int bit = (ret == 0) ? (mbedtls_ecp_is_zero(&W) ? 0 : 1) : ret;
    mbedtls_ecp_point_free(&U); mbedtls_ecp_point_free(&V); mbedtls_ecp_point_free(&P);
    mbedtls_ecp_point_free(&W); mbedtls_ecp_point_free(&R);
    return bit;
}
#endif  // !DES_SPLIT_MOCK

// =============================================================================
// 2. The supervisor's tables
// =============================================================================

static const int NS = MONO_NUM_STATES;
static int g_toff[EVENT_COUNT];                     // offset of e's pairs in trans
static uint64_t g_ctrl = 0;                         // bit e: e is controllable

static inline int8_t   pm_i8 (const int8_t*   a, int i) { return (int8_t) pgm_read_byte(a + i); }
static inline int16_t  pm_i16(const int16_t*  a, int i) { return (int16_t)pgm_read_word(a + i); }
static inline uint16_t pm_u16(const uint16_t* a, int i) { return (uint16_t)pgm_read_word(a + i); }
static int  tcnt(int e)          { return pm_u16(MONO_SUP.tcnt, e); }
static int  tfrom(int e, int p)  { return pm_i16(MONO_SUP.trans, (g_toff[e] + p) * 2); }
static int  tto(int e, int p)    { return pm_i16(MONO_SUP.trans, (g_toff[e] + p) * 2 + 1); }
static bool enabled(int e, int q) { return pm_i8(MONO_SUP.enable, e * NS + q) != 0; }

static const char* ev_name(int e, char* buf) {
    strncpy_P(buf, (const char*)pgm_read_ptr(&EVENT_NAMES[e]), 15);
    buf[15] = 0; return buf;
}
// Same convention as des_generic.h: 'a…' controllable, 'b…' not, otherwise an
// odd trailing digit is controllable (FMS, cluster tool, small factory).
static bool derive_controllable(int e) {
#ifdef DES_CONTROLLABLE_MASK
    return ((uint64_t)(DES_CONTROLLABLE_MASK) >> e) & 1u;
#else
    char nm[16]; ev_name(e, nm);
    if (nm[0] == 'a') return true;
    if (nm[0] == 'b') return false;
    int last = -1;
    for (int i = 0; nm[i]; ++i) if (nm[i] >= '0' && nm[i] <= '9') last = nm[i] - '0';
    return last >= 0 ? (last & 1) != 0 : true;
#endif
}

// What both boards must agree on: the protocol, the supervisor, the trace.
static uint32_t g_cfg = 0;
static uint32_t config_fingerprint() {
    uint32_t h = 2166136261u;
    auto mix = [&](uint32_t v) { for (int i = 0; i < 4; ++i) { h ^= (v >> (8 * i)) & 0xff; h *= 16777619u; } };
    mix(0x5350u + 7);                               // protocol version 7: the event to the supervisor
    mix(DES_CURVE);
    mix(NS); mix(EVENT_COUNT); mix((uint32_t)g_ctrl); mix((uint32_t)(g_ctrl >> 32));
    for (int q = 0; q < NS; ++q) mix(pm_i8(MONO_SUP.init, q));
    for (int e = 0; e < EVENT_COUNT; ++e) {
        mix(tcnt(e));
        for (int p = 0; p < tcnt(e); ++p) { mix(tfrom(e, p)); mix(tto(e, p)); }
        for (int q = 0; q < NS; ++q) mix(enabled(e, q));
    }
    for (int i = 0; i < SIM_SEQ_LEN; ++i) mix(pm_u16(SIM_SEQ, i));
    return h;
}

// Moves: one entry per event e and per state q' that e leads into; the new
// cell of q' is the sum of c[q] over the states q that e leads to q' (in these
// supervisors always a single cell). Entries are ordered by event; the moves
// of e are g_move[g_moff[e] .. g_moff[e + 1]).
struct Move { uint16_t to; uint16_t src0, nsrc; };
static std::vector<Move>     g_move;
static std::vector<uint16_t> g_move_src;
static int g_moff[EVENT_COUNT + 1];

// Decisions: one sum per DISTINCT row of R among the controllable events;
// events with equal rows share it (optimization O2 of the paper).
struct RowGroup { uint64_t evmask; std::vector<uint16_t> cells; };
static std::vector<RowGroup> g_rows;

static void build_tables() {
    int off = 0;
    for (int e = 0; e < EVENT_COUNT; ++e) {
        g_toff[e] = off; off += tcnt(e);
        if (derive_controllable(e)) g_ctrl |= 1ULL << e;
    }
    for (int e = 0; e < EVENT_COUNT; ++e) {
        g_moff[e] = (int)g_move.size();
        std::vector<std::vector<uint16_t>> into(NS);
        for (int p = 0; p < tcnt(e); ++p) into[tto(e, p)].push_back((uint16_t)tfrom(e, p));
        for (int q = 0; q < NS; ++q) {
            if (into[q].empty()) continue;
            g_move.push_back({(uint16_t)q, (uint16_t)g_move_src.size(), (uint16_t)into[q].size()});
            for (uint16_t s : into[q]) g_move_src.push_back(s);
        }
    }
    g_moff[EVENT_COUNT] = (int)g_move.size();
    for (int e = 0; e < EVENT_COUNT; ++e) {
        if (!((g_ctrl >> e) & 1)) continue;         // uncontrollable: never disabled
        bool merged = false;
        for (auto& g : g_rows) {
            bool same = true;
            for (int q = 0; q < NS && same; ++q) {
                bool in = false;
                for (uint16_t c : g.cells) if (c == q) { in = true; break; }
                same = (in == enabled(e, q));
            }
            if (same) { g.evmask |= 1ULL << e; merged = true; break; }
        }
        if (merged) continue;
        RowGroup g; g.evmask = 1ULL << e;
        for (int q = 0; q < NS; ++q) if (enabled(e, q)) g.cells.push_back((uint16_t)q);
        g_rows.push_back(g);
    }
    g_cfg = config_fingerprint();
}

// =============================================================================
// 3. Frames
// =============================================================================

enum : uint8_t { T_KEY = 1, T_READY = 2, T_STEP = 3, T_DECS = 6, T_NACK = 7, T_FIN = 8, T_SIGN = 9 };
#define NO_EVENT 0xFFFFu                            // the event of the boot "step"

struct __attribute__((packed)) SplitHdr {
    uint32_t magic;      // 'DSPL'
    uint8_t  type;
    uint8_t  role;       // sender: DES_PLANT or DES_SUPERVISOR
    uint16_t chunk;      // this frame's index within its message
    uint16_t nchunks;    // frames in the message
    uint16_t count;      // items in this frame
    uint32_t epoch;      // sender's, random per boot
    uint32_t peer;       // receiver's epoch as the sender knows it (0: none yet)
    uint32_t cfg;        // configuration fingerprint
    uint32_t seq;        // step (0 = boot)
};
#define SPLIT_MAGIC   0x4C505344u
#define SPLIT_PAYLOAD (DES_FRAME_BYTES - (int)sizeof(SplitHdr) - DES_TAG_BYTES)
#define DECS_ITEM     (8 + CELL_RAW + PT_RAW)       // event mask, sum, D = -k_S U: one per frame
#define KEY_PAY       (KEY_MSG + 32)                // share, proof, the supervisor's commitment
#define SIGN_PAY      (32 + SIG_BYTES)              // h_k and the supervisor's signature of it

struct Frame {
    uint8_t b[DES_FRAME_BYTES];
    SplitHdr*      h()       { return (SplitHdr*)b; }
    const SplitHdr* h() const { return (const SplitHdr*)b; }
    uint8_t*       p()       { return b + sizeof(SplitHdr); }
    const uint8_t* p() const { return b + sizeof(SplitHdr); }
};

static uint32_t g_epoch = 0, g_peer_epoch = 0;
static uint8_t  g_mykey[KEY_MSG];                  // this board's KEY: share and proof
static uint8_t  g_commit[32];                      // the supervisor's commitment; the plant's is 0
static uint32_t g_tx = 0, g_rx = 0, g_resent = 0, g_nacks = 0, g_auth_bad = 0, g_cfg_bad = 0;
static bool     g_halt = false, g_done = false;
static bool     g_session = false;                 // the MAC keys are set (after KEY)

static Frame g_txf;                                // the frame being built and sent
static void frame_init(Frame& f, uint8_t type, uint32_t seq, uint16_t chunk, uint16_t nchunks,
                       uint16_t count) {
    memset(f.b, 0, sizeof(f.b));
    SplitHdr* h = f.h();
    h->magic = SPLIT_MAGIC; h->type = type; h->role = DES_ROLE;
    h->chunk = chunk; h->nchunks = nchunks; h->count = count;
    h->epoch = g_epoch; h->peer = g_peer_epoch; h->cfg = g_cfg; h->seq = seq;
}
// KEY carries a signature instead (send_key); every other frame a MAC.
static void frame_send(Frame& f) {
    if (f.h()->type != T_KEY)
        cr_mac(true, f.b, DES_FRAME_BYTES - DES_TAG_BYTES, f.b + DES_FRAME_BYTES - DES_TAG_BYTES);
    for (int tries = 0; tries < 20; ++tries) {             // the TX queue may be full
        if (DES_TRANSPORT_IMPL.send(f.b, DES_FRAME_BYTES)) { ++g_tx; break; }
        des_sleep_ms(2);
    }
    des_sleep_ms(1);                                       // pace: the receiver's
}                                                          // mailbox is small
static void send_simple(uint8_t type, uint32_t seq, const void* pl = nullptr, int len = 0) {
    Frame& f = g_txf; frame_init(f, type, seq, 0, 1, 0);
    if (pl) memcpy(f.p(), pl, len);
    frame_send(f);
}
static bool frame_ok(const Frame& f) {
    if (f.h()->type == T_KEY) return true;                 // checked by its signature
    if (!g_session) return false;
    uint8_t t[DES_TAG_BYTES];
    cr_mac(false, f.b, DES_FRAME_BYTES - DES_TAG_BYTES, t);
    uint8_t d = 0;                                         // constant time
    for (int i = 0; i < DES_TAG_BYTES; ++i) d |= (uint8_t)(t[i] ^ f.b[DES_FRAME_BYTES - DES_TAG_BYTES + i]);
    return d == 0;
}

// Which frames of a multi-frame message have arrived.
struct RxSet {
    uint32_t seq = 0; uint8_t type = 0; int n = 0, have = 0;
    std::vector<uint8_t> got; uint32_t t_last = 0;
    void reset(uint8_t ty, uint32_t s) { type = ty; seq = s; n = 0; have = 0; got.clear(); t_last = des_millis(); }
    bool mark(const SplitHdr* h) {                         // true if new
        if (n == 0) { n = h->nchunks; got.assign(n, 0); }
        if (h->chunk >= n || got[h->chunk]) return false;
        got[h->chunk] = 1; ++have; t_last = des_millis(); return true;
    }
    bool complete() const { return n > 0 && have == n; }
};
// A message of `items` items, `per` to a frame: is this frame one of its
// frames, with the right count? Checked before anything is read from it.
static bool shape_ok(const SplitHdr* h, int items, int per) {
    int n = (items + per - 1) / per, c = h->chunk;
    return h->nchunks == n && c < n && h->count == (items - c * per < per ? items - c * per : per);
}

// NACK: the type and step of the message, and a bitmap of the frames missing
// (an empty bitmap means "all of them").
static void send_nack(const RxSet& r) {
    Frame& f = g_txf; frame_init(f, T_NACK, r.seq, 0, 1, 0);
    uint8_t* p = f.p(); p[0] = r.type;
    int n = r.n; memcpy(p + 2, &n, 2);
    for (int i = 0; i < n && 4 + i / 8 < SPLIT_PAYLOAD; ++i)
        if (!r.got[i]) p[4 + i / 8] |= (uint8_t)(1u << (i % 8));
    ++g_nacks;
    frame_send(f);
}
static bool nack_wants(const Frame& f, int chunk) {
    const uint8_t* p = f.p(); uint16_t n; memcpy(&n, p + 2, 2);
    if (n == 0) return true;
    return chunk < n && (p[4 + chunk / 8] >> (chunk % 8)) & 1;
}

// Receive every waiting frame that is ours, authentic and for this cell.
static void handle(const Frame& f);
static void drain() {
    static Frame f;
    while (DES_TRANSPORT_IMPL.poll(f.b, DES_FRAME_BYTES)) {
        const SplitHdr* h = f.h();
        if (h->magic != SPLIT_MAGIC || h->role == DES_ROLE) continue;  // our echo
#ifdef DES_SIMULATE_LOSS_PCT
        if ((int)(cr_random32() % 100) < DES_SIMULATE_LOSS_PCT) continue;
#endif
        if (!frame_ok(f)) { if (g_session) ++g_auth_bad; continue; }
        if (h->cfg != g_cfg) {
            if (g_cfg_bad++ == 0)
                DES_LOG("[!!] a board with a different configuration (%08x, mine %08x): "
                        "both must be built from the same header\n", (unsigned)h->cfg, (unsigned)g_cfg);
            continue;
        }
        ++g_rx;
        handle(f);
    }
}

static void halt(const char* why) {
    if (g_halt) return;
    g_halt = true;
    DES_LOG("\n[HALT] %s\n", why);
}

// KEY: this board's share and its proof, and the supervisor's commitment for
// the audit, signed with this board's identity key together with the header
// (epochs, configuration).
static void send_key() {
    Frame& f = g_txf; frame_init(f, T_KEY, 0, 0, 1, 0);
    memcpy(f.p(), g_mykey, KEY_MSG);
    memcpy(f.p() + KEY_MSG, g_commit, 32);
    if (cr_sign(f.b, sizeof(SplitHdr) + KEY_PAY, f.p() + KEY_PAY)) { halt("signing failed"); return; }
    frame_send(f);
}
static bool key_signed(const Frame& f) {
    return cr_verify(f.b, sizeof(SplitHdr) + KEY_PAY, f.p() + KEY_PAY) == 0;
}
static void my_key_pay(uint8_t out[KEY_PAY]) {
    memcpy(out, g_mykey, KEY_MSG); memcpy(out + KEY_MSG, g_commit, 32);
}

// The record of the run, for the audit. Both boards chain a SHA-256 over every
// step's event and decisions, h_k = SHA-256(h_{k-1} || k || x_k || H(DECS)),
// where x_k is the event encrypted as the STEP carried it (16 bits; NO_EVENT for
// the boot) and H(DECS) the SHA-256 of the SHA-256 of each row, in row order,
// from h_init = SHA-256("des_split record" || the plant's KEY || the
// supervisor's KEY || both epochs). The supervisor signs every h_k (SIGN); the
// plant checks that it is what it sent and received. With the event in the
// clear, whoever records the network could find it by trying every event
// against the signed h_k.
static uint8_t g_chain[32];
static void chain_start(const uint8_t* key_plant, const uint8_t* key_sup, uint32_t ep, uint32_t es) {
    const uint8_t* tag = (const uint8_t*)"des_split record";
    std::vector<uint8_t> m(tag, tag + 16);
    m.insert(m.end(), key_plant, key_plant + KEY_PAY);
    m.insert(m.end(), key_sup, key_sup + KEY_PAY);
    m.insert(m.end(), (const uint8_t*)&ep, (const uint8_t*)&ep + 4);
    m.insert(m.end(), (const uint8_t*)&es, (const uint8_t*)&es + 4);
    cr_sha256(m.data(), m.size(), g_chain);
}
static void chain_step(uint32_t k, uint16_t ev, const std::vector<uint8_t>& hd) {
    uint8_t m[32 + 4 + 2 + 32];
    memcpy(m, g_chain, 32); memcpy(m + 32, &k, 4); memcpy(m + 36, &ev, 2);
    cr_sha256(hd.data(), hd.size(), m + 38);
    cr_sha256(m, sizeof(m), g_chain);
}
// A hash ratchet: key = HMAC-SHA256(key, "des_split next"). The key of the
// event's encryption and the supervisor's seed of the encryptions of zero move
// on at every step, so a memory read finds no key of an earlier step.
static void ratchet(uint8_t key[32]) { cr_kdf(key, "des_split next", key); }
// The event of a STEP travels encrypted, with a stream cipher (symmetric, not
// the ElGamal of the state): σ XOR the pad, the first two bytes of
// HMAC-SHA256(K_k, "des_split event"), where K_1 = g_evk of cr_session and
// K_{k+1} = ratchet(K_k). The supervisor decrypts it with the same pad. Each
// board takes the pad of a step once, in step order (the plant when it fires
// the event, the supervisor when its STEP comes), so a STEP sent again carries
// the same encrypted event.
static uint16_t event_pad() {
    uint8_t h[32];
    cr_kdf(g_evk, "des_split event", h);
    uint16_t pad; memcpy(&pad, h, 2);
    wipe(h, sizeof(h));
    ratchet(g_evk);
    return pad;
}
// What the supervisor signs for step k: "des_split signed" || k || h_k.
static void signed_msg(uint32_t k, const uint8_t h[32], uint8_t m[52]) {
    memcpy(m, "des_split signed", 16); memcpy(m + 16, &k, 4); memcpy(m + 20, h, 32);
}
static void hex_out(const uint8_t* b, size_t n, char* out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 15]; }
    out[2 * n] = 0;
}

// =============================================================================
// 4. The plant board: its key share, the events, the decisions
// =============================================================================
#if DES_ROLE == DES_PLANT

enum PPhase { P_KEY, P_DECS, P_WAIT };         // P_WAIT: between events
static PPhase   p_phase = P_KEY;
static uint32_t p_k = 0;                       // step; 0 = boot decisions
static int      p_ev = -1;                     // event of step p_k
static uint16_t p_evx = NO_EVENT;              // the same, encrypted as its STEP carries it
static int8_t   p_dec[EVENT_COUNT];            // 1 enabled, 0 disabled
static RxSet    p_rx;
static uint32_t p_t_send = 0, p_t_progress = 0;
static uint32_t p_min_dec_ms = 0;              // fastest wait for the decisions: the timeout
static uint32_t p_row_ms = 0;                  // fastest mean gap between two rows of a step
static uint32_t p_t_row0 = 0;                  // when the first row of step p_k came
static uint32_t p_s_ready = 0;                 // READY(k): the supervisor is ready for step k
static std::vector<uint8_t> p_hd;              // hashes of this step's DECS frames
static uint8_t  p_sign[SIGN_PAY];              // the supervisor's SIGN of step p_sign_k
static uint32_t p_sign_k = 0xFFFFFFFFu;
static bool     p_recorded = false;            // step p_k is signed and checked
static uint32_t p_records = 0;
static int      p_oracle = 0;                  // the supervisor in clear
static int      p_pass = 0, p_fail = 0;
static uint64_t p_t0 = 0, p_tz = 0;
static uint64_t sum_dec = 0, sum_zt = 0, sum_total = 0;
static uint32_t p_t_boot = 0, p_t_first = 0;   // the wall clock: this board's boot, the first event
static uint32_t p_steps = 0;

static void print_bits(const char* label, const int8_t* d) {
    char nm[16];
    DES_LOG("  %-8s", label);
    for (int e = 0; e < EVENT_COUNT; ++e)
        if ((g_ctrl >> e) & 1) DES_LOG(" %s:%d", ev_name(e, nm), d[e]);
    DES_LOG("\n");
}

static void print_summary() {
    DES_LOG("\n============================================\n");
    DES_LOG("  SPLIT — plant board (its key share, the events, the decisions)\n");
    DES_LOG("============================================\n");
    DES_LOG("  supervisor  : monolithic, %s: %d states, %d events (%d controllable),"
            " %d distinct controllable rows\n", DES_DATA_HEADER, NS,
            EVENT_COUNT, __builtin_popcountll(g_ctrl), (int)g_rows.size());
    DES_LOG("  curve       : NIST P-%d\n", DES_CURVE);
    DES_LOG("  trace       : %d of %d steps; decisions %s (%d steps checked, %d failed)\n",
            (int)p_steps, (int)SIM_SEQ_LEN, p_fail ? "FAIL" : "PASS", p_pass + p_fail, p_fail);
    if (p_steps) {
        double n = (double)p_steps;
        DES_LOG("  per step    : %.1f ms on average, from the event to the decisions\n",
                sum_total / 1000.0 / n);
        DES_LOG("     waiting for the decisions (the supervisor's new state and sums, and the link)"
                " %.1f | zero tests, each as its row arrives, %.1f  (ms)\n",
                sum_dec / 1000.0 / n, sum_zt / 1000.0 / n);
        double run = (des_millis() - p_t_first) / 1000.0;
        DES_LOG("  run         : %.1f s from the first event to the end (%.2f s per event, the"
                " supervisor's preparation included); %.1f s since this board's boot\n",
                run, run / n, (des_millis() - p_t_boot) / 1000.0);
    }
    DES_LOG("  frames      : %u sent, %u received, %u resent, %u NACKs sent, "
            "%u failed authentication\n", (unsigned)g_tx, (unsigned)g_rx,
            (unsigned)g_resent, (unsigned)g_nacks, (unsigned)g_auth_bad);
    DES_LOG("  audit       : %u steps signed by the supervisor and checked (the [audit] lines);\n"
            "                with a recording of the network and the supervisor's seed,\n"
            "                audit.py redoes every step\n", (unsigned)p_records);
    DES_LOG("============================================\n");
}

// The supervisor's SIGN of step p_k: its h_k must be the plant's, and its
// signature valid. The [audit] line is the plant's evidence.
static void check_record() {
    if (p_sign_k != p_k) return;                   // not here yet
    uint8_t m[52];
    signed_msg(p_k, p_sign, m);
    if (memcmp(p_sign, g_chain, 32) != 0) { halt("the supervisor signed a record that differs from what the plant sent and received"); return; }
    if (cr_verify(m, sizeof(m), p_sign + 32)) { halt("the supervisor's signature of the step is wrong"); return; }
    p_recorded = true; ++p_records;
    char h[65], sg[2 * SIG_BYTES + 1];
    hex_out(p_sign, 32, h); hex_out(p_sign + 32, SIG_BYTES, sg);
    DES_LOG("[audit] %u %s %s\n", (unsigned)p_k, h, sg);
}

// The decisions of step p_k come one row per frame; each is tested as it
// arrives, while the supervisor makes the next.
static void begin_decs() {
    p_phase = P_DECS;
    p_rx.reset(T_DECS, p_k);
    p_hd.clear();
    for (int e = 0; e < EVENT_COUNT; ++e) p_dec[e] = 1;  // uncontrollable: never disabled
    p_tz = 0;
    p_t_send = p_t_progress = des_millis();
}
static void send_step() {
    send_simple(T_STEP, p_k, &p_evx, 2);
}

// The next event of the trace, as the plant: a controllable event only if
// the supervisor enables it. The event goes to the supervisor, encrypted.
static void next_step() {
    if (p_k == (uint32_t)SIM_SEQ_LEN) {
        for (int i = 0; i < 3; ++i) send_simple(T_FIN, p_k);
        g_done = true;
        print_summary();
        return;
    }
    int e = pm_u16(SIM_SEQ, p_k);
    char nm[16]; ev_name(e, nm);
    if (((g_ctrl >> e) & 1) && !p_dec[e]) {
        DES_LOG("[!!] the trace fires %s, which the supervisor disables\n", nm);
        halt("trace not admissible");
        return;
    }
    int to = -1;                                   // oracle: move in clear
    for (int p = 0; p < tcnt(e); ++p) if (tfrom(e, p) == p_oracle) { to = tto(e, p); break; }
    if (to < 0) { DES_LOG("[!!] %s is impossible in the supervisor's state\n", nm); halt("trace not admissible"); return; }
    p_oracle = to;

    ++p_k; p_ev = e; p_evx = (uint16_t)(e ^ event_pad());
    if (p_k == 1) p_t_first = des_millis();
    begin_decs();
    p_t0 = des_micros();
    send_step();
}

// Every row of step p_k is tested.
static void decided() {
    uint64_t total = des_micros() - p_t0;
    int8_t oracle[EVENT_COUNT];
    bool ok = true;
    for (int e = 0; e < EVENT_COUNT; ++e) {
        oracle[e] = (int8_t)enabled(e, p_oracle);
        if (((g_ctrl >> e) & 1) && oracle[e] != p_dec[e]) ok = false;
    }
    if (ok) ++p_pass; else ++p_fail;
    char nm[16];
    if (p_k == 0) DES_LOG("\n-- Boot: decisions in the initial state --\n");
    else DES_LOG("\n-- Step %u | Event: %s (sent to the supervisor) --\n", (unsigned)p_k, ev_name(p_ev, nm));
    print_bits("[Oracle]", oracle);
    print_bits("[HE]", p_dec);
    if (p_k > 0) {
        uint64_t td = total - p_tz;                // waiting for the supervisor and the link
        DES_LOG("  Time: %.1f ms  (waiting %.1f | zero tests %.1f)  %s\n", total / 1000.0,
                td / 1000.0, p_tz / 1000.0, ok ? "OK" : "MISMATCH");
        sum_total += total; sum_dec += td; sum_zt += p_tz;
        ++p_steps;
        // The FASTEST time: a slow step (a resend) must not stretch the next wait.
        if (p_min_dec_ms == 0 || td / 1000 < p_min_dec_ms) p_min_dec_ms = (uint32_t)(td / 1000);
        if (g_rows.size() > 1) {
            uint32_t gap = (p_rx.t_last - p_t_row0) / (uint32_t)(g_rows.size() - 1);
            if (p_row_ms == 0 || gap < p_row_ms) p_row_ms = gap;
        }
    } else {
        DES_LOG("  %s\n", ok ? "OK" : "MISMATCH");
    }
    chain_step(p_k, p_k ? p_evx : (uint16_t)NO_EVENT, p_hd);
    p_recorded = false;
    p_phase = P_WAIT;                              // the next event, once signed and READY
}

static void handle(const Frame& f) {
    const SplitHdr* h = f.h();
    if (h->type == T_KEY) {
        if (g_peer_epoch && h->epoch == g_peer_epoch) return;     // a repeat
        if (!key_signed(f)) { ++g_auth_bad; return; }             // not the supervisor board
    }
    if (h->peer != g_epoch) return;                // not (yet) addressed to this boot
    if (g_peer_epoch && h->epoch != g_peer_epoch) { halt("the supervisor board restarted: RESET both boards"); return; }
    if (h->type == T_READY && g_peer_epoch && h->seq > p_s_ready) p_s_ready = h->seq;
    if (p_phase == P_KEY) {
        if (h->type == T_KEY && g_peer_epoch == 0) {
            if (cr_join(DES_SUPERVISOR, f.p())) { halt("the supervisor's key share failed its check"); return; }
            g_peer_epoch = h->epoch;
            if (cr_session(g_epoch, g_peer_epoch)) { halt("no session keys"); return; }
            g_session = true;
            uint8_t mine[KEY_PAY]; my_key_pay(mine);
            chain_start(mine, f.p(), g_epoch, g_peer_epoch);
            DES_LOG("[split] supervisor %08x: identity and key share checked; it encrypts the"
                    " initial state under the joint key\n", (unsigned)g_peer_epoch);
        } else if (h->type == T_READY && g_peer_epoch && h->seq == 0) {
            DES_LOG("[split] supervisor ready; it encrypted the initial state\n");
            p_k = 0;
            begin_decs();
        }
        return;
    }

    switch (h->type) {
    case T_DECS: {
        if (p_phase != P_DECS || h->seq != p_k || !shape_ok(h, (int)g_rows.size(), 1) ||
            !p_rx.mark(h)) return;
        p_t_progress = des_millis();
        if (p_rx.have == 1) p_t_row0 = p_rx.t_last;
        if (p_hd.empty()) p_hd.assign((size_t)32 * h->nchunks, 0);
        cr_sha256(f.p(), DECS_ITEM, &p_hd[(size_t)32 * h->chunk]);
        uint64_t t0 = des_micros();
        uint64_t mask; memcpy(&mask, f.p(), 8);
        int bit = cr_zero_test(f.p() + 8, f.p() + 8 + CELL_RAW);
        if (bit < 0) { halt("zero test failed"); return; }
        for (int e = 0; e < EVENT_COUNT; ++e) if ((mask >> e) & 1) p_dec[e] = (int8_t)bit;
        p_tz += des_micros() - t0;
        if (p_rx.complete()) decided();
        break;
    }
    case T_SIGN:
        if (h->seq == p_k) { memcpy(p_sign, f.p(), SIGN_PAY); p_sign_k = h->seq; }
        break;
    }
}

// The same supervisor unencrypted on this board: its move and its decisions
// along the whole trace, from the tables in flash, repeated so that the
// microseconds of a step can be measured. The baseline of the encrypted step.
static void bench_clear(int q0) {
    const int R = 100;
    uint32_t steps = 0, allowed = 0;               // allowed: keeps every decision computed
    uint64_t t0 = des_micros();
    for (int r = 0; r < R; ++r) {
        int q = q0;
        for (int k = 0; k < SIM_SEQ_LEN; ++k) {
            int e = pm_u16(SIM_SEQ, k), to = -1;
            for (int p = 0; p < tcnt(e); ++p) if (tfrom(e, p) == q) { to = tto(e, p); break; }
            if (to < 0) return;                    // not admissible: next_step() says so
            q = to;
            for (int f = 0; f < EVENT_COUNT; ++f) allowed += enabled(f, q);
            ++steps;
        }
        DES_YIELD();
    }
    uint64_t t = des_micros() - t0;
    volatile uint32_t sink = allowed; (void)sink;
    DES_LOG("[clear] the same supervisor unencrypted on this board: %.2f us per step"
            " (%u steps of the trace)\n", steps ? (double)t / steps : 0.0, (unsigned)steps);
}

static void split_setup() {
    p_t_boot = des_millis();
    build_tables();
    cr_init("des_split_plant");
    g_epoch = cr_random32() | 1;
    if (cr_identity(DES_MY_ID, DES_MY_PUB, DES_PEER_PUB)) {
        halt("the identity keys of secrets.h do not fit together: run make_keys.py again"); return;
    }
    if (cr_keygen(DES_PLANT, nullptr, g_mykey)) { halt("key generation failed"); return; }
    // Self-test of the share and the zero test, under the share alone (D = 0).
    uint8_t c0[CELL_RAW], c1[CELL_RAW], none[PT_RAW] = {0};
    if (cr_enc(0, c0) || cr_enc(1, c1) || cr_zero_test(c0, none) != 0 || cr_zero_test(c1, none) != 1) {
        halt("self-test failed"); return;
    }
    if (!DES_TRANSPORT_IMPL.begin()) { halt("network down"); return; }
    p_oracle = 0;
    for (int q = 0; q < NS; ++q) if (pm_i8(MONO_SUP.init, q)) p_oracle = q;
    bench_clear(p_oracle);
    DES_LOG("[split] PLANT board, epoch %08x, config %08x, P-%d: %d states, %d events, "
            "%d decision sums per step\n", (unsigned)g_epoch, (unsigned)g_cfg, DES_CURVE, NS,
            EVENT_COUNT, (int)g_rows.size());
    DES_LOG("[split] waiting for the supervisor board's key share...\n");
    p_t_send = des_millis();
    send_key();
}

static void split_loop() {
    if (g_halt || g_done) { drain(); return; }
    drain();
    uint32_t now = des_millis();
    if (p_phase == P_DECS && now - p_t_progress > 120000) {
        halt("no progress for 2 minutes"); return;
    }
    switch (p_phase) {
    case P_KEY:
        if (now - p_t_send > 500) { send_key(); p_t_send = now; }
        break;
    case P_DECS:
        if (p_rx.have == 0) {
            if (now - p_t_send > 1000 + 2 * p_min_dec_ms) {
                if (p_k > 0) { send_step(); ++g_resent; }  // the STEP lost?
                else send_nack(p_rx);                      // the boot rows lost?
                p_t_send = now;
            }
        } else {
            // A row lost? The supervisor makes the rows one after another, so
            // they come a gap apart: the larger of the fastest mean gap of the
            // earlier steps and the mean gap of this step's rows so far.
            // Silence for twice the gap (and 300 ms) means a lost row; only
            // rows already made are sent again.
            uint32_t gap = p_row_ms;
            if (p_rx.have > 1) gap = std::max(gap, (p_rx.t_last - p_t_row0) / (uint32_t)(p_rx.have - 1));
            uint32_t wait = 300 + 2 * gap;
            if (now - p_rx.t_last > wait && now - p_t_send > wait) { send_nack(p_rx); p_t_send = now; }
        }
        break;
    case P_WAIT:
        if (!p_recorded) check_record();                           // the supervisor's SIGN
        if (g_halt) break;
        if (p_recorded && p_k == (uint32_t)SIM_SEQ_LEN) next_step();   // the end of the trace
        else if (p_recorded && p_s_ready > p_k) next_step();       // both boards are ready
        break;
    }
}

// =============================================================================
// 5. The supervisor board: tables, encrypted state, its key share
// =============================================================================
#else

enum SPhase { S_KEY, S_IDLE, S_DECS };
static SPhase   s_phase = S_KEY;
static uint32_t s_k = 0;
static uint16_t s_evx = NO_EVENT;              // the event of step s_k, encrypted: for its record
static std::vector<uint8_t> s_c;               // the encrypted state, raw cells
static std::vector<uint8_t> s_new;             // the next one, made at the event
static std::vector<uint8_t> s_mark;            // at the event: the states it leaves and enters, then erased
static std::vector<uint8_t> s_decs;            // DECS(s_k): one item per row, kept for resends
static size_t   s_row_n = 0;                   // rows of s_decs made
static uint32_t s_t_ready = 0;
static uint64_t s_move_us = 0, s_dec_us = 0;
static uint32_t s_steps = 0;

// Prepared while idle, one per pass of the loop, for the next step: a fresh
// Enc_Y(0) per decision row ("dz"). A STEP that comes before they are all
// ready finishes them on the spot. Each is used once and then erased.
static std::vector<uint8_t> s_dz;              // Enc_Y(0) per row
static size_t   s_dz_n = 0;
static uint32_t s_prep_k = 0;                  // the step they are for
// The audit: all of this board's randomness comes from s_seed, committed to
// at boot together with the tables (g_commit). The seed is erased once the
// initial state is encrypted; the encryptions of zero of step k come from
// z_k, with z_0 = HMAC-SHA256(seed, "des_split zeros") and z_{k+1} =
// ratchet(z_k) as soon as step k's new state is made. A memory read finds
// neither the seed nor the z of an earlier step, so it cannot redo the
// encryption of a cell of the state.
static uint8_t  s_seed[32];
static uint8_t  s_zs[32];                      // z of the next step that needs one
static uint8_t  s_sign[SIGN_PAY];              // SIGN of step s_k, kept for resends
static uint32_t s_prep_idle = 0, s_prep_step = 0, s_t_rdy = 0;
static uint64_t s_prep_us = 0;                 // time spent preparing them while idle

static bool prep_done() { return s_dz_n == g_rows.size(); }
static void start_prepare() {
    s_prep_k = s_k + 1;
    s_dz.assign(g_rows.size() * CELL_RAW, 0);
    s_dz_n = 0;
}
static void prepare_one(bool in_step) {
    uint64_t t0 = des_micros();
    int ret = cr_enc_det(0, s_zs, "dz", s_prep_k, (uint32_t)s_dz_n, &s_dz[s_dz_n * CELL_RAW]);
    ++s_dz_n;
    if (ret) { halt("preparation failed"); return; }
    if (in_step) ++s_prep_step;
    else { ++s_prep_idle; s_prep_us += des_micros() - t0; }
}

// The decision of row g: the sum of its cells and of a fresh Enc_Y(0) z, so
// that the rows of R show no relation, and this board's part of its decryption.
static int make_row(size_t g, const uint8_t z[CELL_RAW]) {
    uint8_t* it = &s_decs[g * DECS_ITEM];
    memcpy(it, &g_rows[g].evmask, 8);
    std::vector<const uint8_t*> v;
    for (uint16_t q : g_rows[g].cells) v.push_back(&s_c[(size_t)q * CELL_RAW]);
    v.push_back(z);
    int ret = cr_sum(v.data(), (int)v.size(), it + 8);
    if (ret == 0) ret = cr_partial(it + 8, it + 8 + CELL_RAW);
    return ret;
}
static void send_row(size_t g) {
    Frame& f = g_txf; frame_init(f, T_DECS, s_k, (uint16_t)g, (uint16_t)g_rows.size(), 1);
    memcpy(f.p(), &s_decs[g * DECS_ITEM], DECS_ITEM);
    frame_send(f);
}
static void send_decs(const Frame* nack) {           // the rows made so far
    for (size_t g = 0; g < s_row_n; ++g) {
        if (nack && !nack_wants(*nack, (int)g)) continue;
        send_row(g);
        if (nack) ++g_resent;
    }
}
// The boot decisions, all at once (not timed).
static void boot_decs() {
    s_decs.assign(g_rows.size() * DECS_ITEM, 0);
    for (size_t g = 0; g < g_rows.size(); ++g) {
        uint8_t z[CELL_RAW];
        if (cr_enc_det(0, s_zs, "dz", 0, (uint32_t)g, z) || make_row(g, z)) {
            halt("boot decisions failed"); return;
        }
    }
    s_row_n = g_rows.size();
}
// The record of step s_k (see chain_step), signed and sent.
static void record_step() {
    std::vector<uint8_t> hd(32 * g_rows.size(), 0);
    for (size_t g = 0; g < g_rows.size(); ++g) cr_sha256(&s_decs[g * DECS_ITEM], DECS_ITEM, &hd[32 * g]);
    chain_step(s_k, s_evx, hd);
    uint8_t m[52];
    signed_msg(s_k, g_chain, m);
    memcpy(s_sign, g_chain, 32);
    if (cr_sign(m, sizeof(m), s_sign + 32)) { halt("signing failed"); return; }
    send_simple(T_SIGN, s_k, s_sign, SIGN_PAY);
}
// The tables the supervisor commits to: NS, EVENT_COUNT, the controllable
// events, the initial state, then per event its transitions and its row of
// the enablement matrix, little-endian (audit.py builds the same bytes).
static std::vector<uint8_t> tables_bytes() {
    std::vector<uint8_t> t;
    auto put = [&](const void* p, size_t n) { t.insert(t.end(), (const uint8_t*)p, (const uint8_t*)p + n); };
    uint32_t ns = (uint32_t)NS, ne = EVENT_COUNT;
    put(&ns, 4); put(&ne, 4); put(&g_ctrl, 8);
    for (int q = 0; q < NS; ++q) { int8_t v = pm_i8(MONO_SUP.init, q); put(&v, 1); }
    for (int e = 0; e < EVENT_COUNT; ++e) {
        uint16_t c = (uint16_t)tcnt(e); put(&c, 2);
        for (int p = 0; p < tcnt(e); ++p) { int16_t a = (int16_t)tfrom(e, p), b = (int16_t)tto(e, p); put(&a, 2); put(&b, 2); }
        for (int q = 0; q < NS; ++q) { int8_t v = pm_i8(MONO_SUP.enable, e * NS + q); put(&v, 1); }
    }
    return t;
}
// The new state for the event ev: the cells move. The cell of each state q'
// that ev leads into is the cell of the state that ev leads to q' (in these
// supervisors there is one; if there are several, the sum of their cells).
// The cells of the states that ev does not leave all encrypt 0, since the
// current state is one that ev leaves; they go, in the order of the states,
// to the states that ev leads nothing into. There are as many of them when no
// two states go to the same one; otherwise the states left get fresh Enc_Y(0)
// ("z0"), drawn here. No cell is copied: each is in one place only.
static void move_all(uint16_t ev) {
    int ret = 0;
    for (int m = g_moff[ev]; m < g_moff[ev + 1] && ret == 0; ++m) {
        const Move& mv = g_move[m];
        uint8_t* out = &s_new[(size_t)mv.to * CELL_RAW];
        s_mark[mv.to] |= 2;                            // ev enters it
        for (int j = 0; j < mv.nsrc && ret == 0; ++j) {
            int q = g_move_src[mv.src0 + j];
            s_mark[q] |= 1;                            // ev leaves it
            const uint8_t* v[2] = {out, &s_c[(size_t)q * CELL_RAW]};
            if (j == 0) memcpy(out, v[1], CELL_RAW);
            else ret = cr_sum(v, 2, out);
        }
    }
    int left = 0;                                      // the next cell that ev does not leave
    uint32_t z = 0;
    for (int q = 0; q < NS && ret == 0; ++q) {
        if (s_mark[q] & 2) continue;
        while (left < NS && (s_mark[left] & 1)) ++left;
        uint8_t* out = &s_new[(size_t)q * CELL_RAW];
        if (left < NS) memcpy(out, &s_c[(size_t)left++ * CELL_RAW], CELL_RAW);
        else ret = cr_enc_det(0, s_zs, "z0", s_k, z++, out);
    }
    std::fill(s_mark.begin(), s_mark.end(), 0);        // which states ev left and entered, erased
    if (ret) { halt("new state failed"); return; }
    s_c.swap(s_new);
    std::fill(s_new.begin(), s_new.end(), 0);          // the old state, erased
}
// The next row of the step's decisions, sent at once.
static void row_one() {
    uint64_t t0 = des_micros();
    size_t g = s_row_n;
    uint8_t* z = &s_dz[g * CELL_RAW];
    if (make_row(g, z)) { halt("decision failed"); return; }
    memset(z, 0, CELL_RAW);                            // used once
    ++s_row_n;
    s_dec_us += des_micros() - t0;
    send_row(g);
    if (s_row_n == g_rows.size()) {
        record_step();
        ++s_steps;
        s_phase = S_IDLE;
        start_prepare();
        if (s_steps % 10 == 0) DES_LOG("[split] %u steps\n", (unsigned)s_steps);
    }
}

static void print_summary() {
    DES_LOG("\n============================================\n");
    DES_LOG("  SPLIT — supervisor board (its key share, the events)\n");
    DES_LOG("============================================\n");
    DES_LOG("  supervisor  : monolithic, %d states; %d decision sums per step\n",
            NS, (int)g_rows.size());
    DES_LOG("  curve       : NIST P-%d\n", DES_CURVE);
    DES_LOG("  steps       : %u; received every event, never a decision or the plant's key share\n",
            (unsigned)s_steps);
    if (s_steps)
        DES_LOG("  per step    : new state %.1f ms; decision sums and partial decryptions %.1f ms\n",
                s_move_us / 1000.0 / s_steps, s_dec_us / 1000.0 / s_steps);
    DES_LOG("  audit       : every step signed; the seed, printed at boot, was erased once the"
            " initial state was encrypted\n");
    if (s_prep_idle && s_steps) {
        double item = s_prep_us / 1e6 / s_prep_idle;
        DES_LOG("  prepared    : %u Enc(0) between steps (%.1f ms each), %u during a step: one per"
                " decision row, about %.1f s of preparation between events\n",
                (unsigned)s_prep_idle, item * 1000.0, (unsigned)s_prep_step, g_rows.size() * item);
    }
    DES_LOG("  frames      : %u sent, %u received, %u resent, %u NACKs sent, "
            "%u failed authentication\n", (unsigned)g_tx, (unsigned)g_rx,
            (unsigned)g_resent, (unsigned)g_nacks, (unsigned)g_auth_bad);
    DES_LOG("============================================\n");
}

static void handle(const Frame& f) {
    const SplitHdr* h = f.h();
    if (h->type == T_KEY) {
        bool repeat = g_peer_epoch && h->epoch == g_peer_epoch;
        if (!repeat && !key_signed(f)) { ++g_auth_bad; return; }  // not the plant board
        if (s_phase != S_KEY && !repeat) {
            static bool said = false;
            if (!said) DES_LOG("[!!] the plant board restarted; RESET both boards\n");
            said = true;
            return;
        }
        if (s_phase == S_KEY) {
            if (cr_join(DES_PLANT, f.p())) { halt("the plant's key share failed its check"); return; }
            g_peer_epoch = h->epoch;
            if (cr_session(g_peer_epoch, g_epoch)) { halt("no session keys"); return; }
            g_session = true;
            uint8_t mine[KEY_PAY]; my_key_pay(mine);
            chain_start(f.p(), mine, g_peer_epoch, g_epoch);
            send_key();                                    // the plant learns the joint key
            DES_LOG("[split] plant %08x: identity and key share checked; encrypting the initial"
                    " state under the joint key (%d cells)...\n", (unsigned)g_peer_epoch, NS);
            uint64_t t0 = des_micros();
            s_c.assign((size_t)NS * CELL_RAW, 0);
            for (int q = 0; q < NS; ++q) {
                if (cr_enc_det(pm_i8(MONO_SUP.init, q), s_seed, "init", 0, (uint32_t)q, &s_c[(size_t)q * CELL_RAW])) {
                    halt("encryption failed"); return;
                }
                DES_YIELD();
            }
            wipe(s_seed, sizeof(s_seed));                  // see s_zs
            DES_LOG("[split] encrypted in %.1f ms; boot decisions\n", (des_micros() - t0) / 1000.0);
            s_new.assign((size_t)NS * CELL_RAW, 0);
            s_mark.assign(NS, 0);
            s_k = 0; s_evx = NO_EVENT;
            boot_decs();
            ratchet(s_zs);
            record_step();
            s_phase = S_IDLE;
            start_prepare();
        }
        // Duplicate KEYs pile up while the state is being encrypted: answer
        // at most twice a second, with this board's share again (it may have
        // been lost).
        if (des_millis() - s_t_ready < 500 && s_t_ready) return;
        s_t_ready = des_millis();
        send_key();
        send_simple(T_READY, 0);
        if (s_k == 0) { send_decs(nullptr); send_simple(T_SIGN, 0, s_sign, SIGN_PAY); }
        return;
    }
    if (g_peer_epoch == 0) {
        static bool said = false;
        if (!said) DES_LOG("[!!] the plant board is in the middle of a run; RESET both boards\n");
        said = true;
        return;
    }
    if (h->epoch != g_peer_epoch || h->peer != g_epoch) return;

    switch (h->type) {
    case T_STEP: {
        if (s_phase == S_IDLE && h->seq == s_k + 1) {
            uint64_t t0 = des_micros();
            while (!prep_done() && !g_halt) { prepare_one(true); DES_YIELD(); }   // the event came early
            if (g_halt) return;
            memcpy(&s_evx, f.p(), 2);
            uint16_t ev = s_evx ^ event_pad();         // the event is kept nowhere after the move
            if (ev >= EVENT_COUNT) { halt("the plant sent an unknown event"); return; }
            s_k = h->seq;
            move_all(ev);
            if (g_halt) return;
            ratchet(s_zs);                             // z of this step: used
            s_move_us += des_micros() - t0;
            s_decs.assign(g_rows.size() * DECS_ITEM, 0);
            s_row_n = 0;
            s_phase = S_DECS;
        } else if (h->seq == s_k && s_row_n > 0) {
            send_decs(nullptr);                            // the plant got none of the rows sent
        }
        break;
    }
    case T_NACK:
        if (h->seq == s_k && f.p()[0] == T_DECS) send_decs(&f);
        break;
    case T_FIN:
        if (!g_done) { g_done = true; print_summary(); }
        break;
    }
}

static void split_setup() {
    build_tables();
    cr_init("des_split_supervisor");
    g_epoch = cr_random32() | 1;
    if (cr_identity(DES_MY_ID, DES_MY_PUB, DES_PEER_PUB)) {
        halt("the identity keys of secrets.h do not fit together: run make_keys.py again"); return;
    }
    // The audit: a secret seed for all of this board's randomness, and the
    // commitment SHA-256("des_split commit" || seed || tables), sent in KEY.
    cr_random_bytes(s_seed, sizeof(s_seed));
    {
        std::vector<uint8_t> t = tables_bytes();
        const uint8_t* tag = (const uint8_t*)"des_split commit";
        std::vector<uint8_t> m(tag, tag + 16);
        m.insert(m.end(), s_seed, s_seed + 32);
        m.insert(m.end(), t.begin(), t.end());
        cr_sha256(m.data(), m.size(), g_commit);
        wipe(m.data(), m.size());
    }
    if (cr_keygen(DES_SUPERVISOR, s_seed, g_mykey)) { halt("key generation failed"); return; }
    cr_kdf(s_seed, "des_split zeros", s_zs);           // z_0
    if (!DES_TRANSPORT_IMPL.begin()) { halt("network down"); return; }
    DES_LOG("[split] SUPERVISOR board, epoch %08x, config %08x, P-%d: %d states, %d events, "
            "%d decision sums per step\n", (unsigned)g_epoch, (unsigned)g_cfg,
            DES_CURVE, NS, EVENT_COUNT, (int)g_rows.size());
    // Printed for the prototype: a deployment would hand the seed to the
    // auditor only, who keeps it for as long as a run may be audited.
    char seed[65]; hex_out(s_seed, 32, seed);
    DES_LOG("[split] audit: the opening, for the auditor only: seed %s (erased from RAM once the"
            " initial state is encrypted)\n", seed);
    wipe(seed, sizeof(seed));
    DES_LOG("[split] waiting for the plant board's key share...\n");
}

static void split_loop() {
    drain();
    if (g_halt || g_done) return;
    if (s_phase == S_IDLE && !prep_done()) {
        prepare_one(false);
        if (prep_done()) { send_simple(T_READY, s_k + 1); s_t_rdy = des_millis(); }
    } else if (s_phase == S_IDLE && des_millis() - s_t_rdy > 1000) {
        // READY or the SIGN may have been lost: the plant needs both to go on
        send_simple(T_READY, s_k + 1); send_simple(T_SIGN, s_k, s_sign, SIGN_PAY); s_t_rdy = des_millis();
    } else if (s_phase == S_DECS) {
        row_one();                                     // one row per pass: frames keep coming
    }
}

#endif  // DES_ROLE
