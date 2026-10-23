// =============================================================================
// des_split.h — the supervisor and the plant on two boards
// =============================================================================
//
// The supervisor board holds the supervisor (its tables and its encrypted
// state); the plant board emulates the plant. The private key k = k_P + k_S is
// SPLIT between them: each board draws its own share at boot and nobody ever
// holds k, so neither board can decrypt anything alone. Both encrypt under
// Y = k_P G + k_S G. The supervisor adds its part of the decryption to the
// decision sums only, never to the state. Three things never reach the
// supervisor board:
//
//   • the plant's share of the key;
//   • the event — the supervisor computes the next encrypted state for EVERY
//     event, the plant keeps the one of the event that occurred, re-randomizes
//     it and sends it back, so the supervisor cannot tell which one it was;
//   • the decisions — the supervisor computes the encrypted decisions (the
//     homomorphic sums of the rows of R) and only the plant can finish
//     decrypting them; nothing is cached on the supervisor between steps.
//
// One step (k), after the plant fired event σ:
//
//   plant (share k_P)                         supervisor (share k_S)
//                                              before the event: a fresh
//                                              permutation π of the states;
//                                              for every event e and every
//                                              transition q → q' of e, the
//                                              cell c[q] ⊞ Enc_Y(0) (sum if
//                                              several), tagged (e, π(q'))
//     ◀──────────────────────────── READY(k)
//     STEP(k)  ─────────────────────────────▶
//     ◀──────────────────────────── CAND(k) ×m
//   keep the cells of σ, then for every
//   label l:  c'[l] = cell ⊞ Enc_Y(0),
//   each frame sent as soon as it is made
//     NEWST(k) ×n/10 ───────────────────────▶  c[q] ← c'[π(q)], each cell
//                                              added to the sums of its rows
//                                              as it arrives; then, row by
//                                              row: d ⊞ Enc_Y(0), D = -k_S U
//     ◀──────────────────────────── DECS(k) ×rows
//   zero test V + D - k_P U of each row
//   as it arrives → decisions
//
// What the supervisor learns: that a step happened. Every message of a step
// has the same number of frames whatever σ is, the supervisor's work does not
// depend on σ, and the plant does the same work for every σ (it waits for ALL
// the candidates, re-randomizes ALL the cells and tests ALL the rows).
//
// The two boards work at the same time: the supervisor sums the new state
// while the plant is still re-randomizing it, and makes the next decision
// while the plant tests the last one.
//
// The plant draws the n encryptions of zero of a step BEFORE the event, while
// it is idle, and keeps them in RAM only; each is used for one cell and then
// erased, so none is ever used twice (a step that finds none left draws them
// on the spot). Cells travel uncompressed, so the plant does not compute a
// square root to read each point.
//
// What the plant learns about the supervisor: n, the decisions, and which
// labels each event leads to, that is, for every event the set of states it
// leads into, up to a renaming of the states (states that differ in the events
// leading into them can be told apart at every step). Every candidate carries
// its own fresh Enc_Y(0), so the plant cannot match it to a cell it sent (that
// would take k_S), and is tagged with a label of a permutation drawn afresh
// every step, the candidates of each event in label order, so the number of a
// state never shows; every decision sum also carries its own Enc_Y(0), so the
// plant cannot find which of its cells make it up. The supervisor prepares all
// of them before the event, while idle.
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
// from what they see (honest-but-curious). A plant board that deviated could
// send ciphertexts of its choice as the new state and decrypt them with the
// supervisor's part of the decryption of the sums: that is out of scope.
//
// Integrity is not checked in real time: a supervisor board that deviates from
// the protocol can send wrong sums and so wrong decisions. It is accountable
// instead. At boot it commits to its tables and to a secret seed from which it
// draws all its randomness (its share, the initial encryption, the
// permutations, the encryptions of zero), and after every step it signs a
// chain of SHA-256 over all the step's messages, which the plant board checks
// against what it received. An auditor given the seed and the tables redoes
// every step from a recording of the network (audit.py) and finds any
// deviation, which the supervisor's signature makes undeniable.
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
CR_FN void cr_init(const char* pers);
CR_FN uint32_t cr_random32();
// This board's identity key and the other board's public key (hex; a public
// key is x || y). Fails unless my_pub is my_priv's.
CR_FN int  cr_identity(const char* my_priv, const char* my_pub, const char* peer_pub);
CR_FN int  cr_sign(const uint8_t* msg, size_t len, uint8_t sig[SIG_BYTES]);          // as this board
CR_FN int  cr_verify(const uint8_t* msg, size_t len, const uint8_t sig[SIG_BYTES]);  // the other's
// After cr_join: one MAC key per direction, HMAC-SHA256 of the x of the
// shares' Diffie–Hellman k_P k_S G (only the two boards can compute it) and of
// both epochs. cr_mac signs as this board (mine) or checks the other's.
CR_FN int  cr_session(uint32_t epoch_plant, uint32_t epoch_supervisor);
CR_FN void cr_mac(bool mine, const uint8_t* msg, size_t len, uint8_t tag[DES_TAG_BYTES]);
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
CR_FN int  cr_sum(const uint8_t* const* cells, int cnt, uint8_t out[CELL_RAW]);
// out = cell ⊞ z, z a fresh encryption of zero (cr_enc(0, z)), or out = z
// when cell is null; the same work either way.
CR_FN int  cr_rerandomize(const uint8_t* cell, const uint8_t z[CELL_RAW],
                           uint8_t out[CELL_RAW]);
// D = -k_i U, this board's part of the decryption of the cell (U, V).
CR_FN int  cr_partial(const uint8_t cell[CELL_RAW], uint8_t D[PT_RAW]);
// V + D - k_i U, which is mG with D from the other board: 0 if m = 0, 1 if
// not, or < 0 on error.
CR_FN int  cr_zero_test(const uint8_t cell[CELL_RAW], const uint8_t D[PT_RAW]);

#if !DES_SPLIT_MOCK
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
static uint8_t                  g_dummy[CELL_RAW]; // (G, G), for constant work

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
    memset(h, 0, sizeof(h));
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
    pt_to_raw(&g_grp.G, g_dummy);
    memcpy(g_dummy + PT_RAW, g_dummy, PT_RAW);
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
    for (int d = 0; d < 2 && ret == 0; ++d) {
        uint8_t m[18];
        memcpy(m, "des_split", 9); m[9] = (uint8_t)(d + 1);
        memcpy(m + 10, &epoch_plant, 4); memcpy(m + 14, &epoch_supervisor, 4);
        ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), w, SC_BYTES,
                              m, sizeof(m), g_mac[d]);
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
static int cr_sum(const uint8_t* const* cells, int cnt, uint8_t out[CELL_RAW]) {
    mbedtls_ecp_point S[2], P, T;
    mbedtls_ecp_point_init(&S[0]); mbedtls_ecp_point_init(&S[1]);
    mbedtls_ecp_point_init(&P); mbedtls_ecp_point_init(&T);
    int ret = mbedtls_ecp_set_zero(&S[0]);
    if (ret == 0) ret = mbedtls_ecp_set_zero(&S[1]);
    for (int i = 0; i < cnt && ret == 0; ++i) {
        for (int h = 0; h < 2 && ret == 0; ++h) {
            ret = pt_from_raw(cells[i] + h * PT_RAW, &P);
            if (ret == 0) ret = pt_add(&T, &S[h], &P);
            if (ret == 0) swap_pt(&S[h], &T);
        }
        DES_YIELD();
    }
    if (ret == 0) ret = pt_to_raw(&S[0], out);
    if (ret == 0) ret = pt_to_raw(&S[1], out + PT_RAW);
    mbedtls_ecp_point_free(&S[0]); mbedtls_ecp_point_free(&S[1]);
    mbedtls_ecp_point_free(&P); mbedtls_ecp_point_free(&T);
    return ret;
}
static int cr_rerandomize(const uint8_t* cell, const uint8_t z[CELL_RAW], uint8_t out[CELL_RAW]) {
    mbedtls_ecp_point Z, C, T;
    mbedtls_ecp_point_init(&Z); mbedtls_ecp_point_init(&C); mbedtls_ecp_point_init(&T);
    // An empty cell takes the dummy (G, G) through the same reading and
    // addition, and the result is thrown away: the time does not show which
    // cells were empty, which would hint at the event.
    const uint8_t* in = cell ? cell : g_dummy;
    int ret = 0;
    for (int h = 0; h < 2 && ret == 0; ++h) {
        ret = pt_from_raw(z + h * PT_RAW, &Z);
        if (ret == 0) ret = pt_from_raw(in + h * PT_RAW, &C);
        if (ret == 0) ret = pt_add(&T, &C, &Z);
        if (ret == 0) ret = pt_to_raw(cell ? &T : &Z, out + h * PT_RAW);
    }
    mbedtls_ecp_point_free(&Z); mbedtls_ecp_point_free(&C); mbedtls_ecp_point_free(&T);
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
    mix(0x5350u + 6);                               // protocol version 6
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

// Candidates: one entry per event e and per state q' that e leads into; its
// cell is the sum of c[q] over the states q that e leads to q' (in these
// supervisors always a single cell). Entries are ordered by event.
struct CandEntry { uint8_t ev; uint16_t to; uint16_t src0, nsrc; };
static std::vector<CandEntry> g_cand;
static std::vector<uint16_t>  g_cand_src;

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
        std::vector<std::vector<uint16_t>> into(NS);
        for (int p = 0; p < tcnt(e); ++p) into[tto(e, p)].push_back((uint16_t)tfrom(e, p));
        for (int q = 0; q < NS; ++q) {
            if (into[q].empty()) continue;
            g_cand.push_back({(uint8_t)e, (uint16_t)q, (uint16_t)g_cand_src.size(),
                              (uint16_t)into[q].size()});
            for (uint16_t s : into[q]) g_cand_src.push_back(s);
        }
    }
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

enum : uint8_t { T_KEY = 1, T_READY, T_STEP, T_CAND, T_NEWST, T_DECS, T_NACK, T_FIN, T_SIGN };

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
#define CAND_ITEM     (1 + 2 + CELL_RAW)            // event, state, cell
#define CAND_PER      (SPLIT_PAYLOAD / CAND_ITEM)
#define NEWST_PER     (SPLIT_PAYLOAD / CELL_RAW)
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
// step's messages, h_k = SHA-256(h_{k-1} || k || H(CAND) || H(NEWST) || H(DECS)),
// where H(X) is the SHA-256 of the SHA-256 of the items of each frame of X, in
// frame order (32 zero bytes for a message the step does not have), from
// h_init = SHA-256("des_split record" || the plant's KEY || the supervisor's
// KEY || both epochs). The supervisor signs every h_k (SIGN); the plant checks
// that it is what it received.
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
static void chain_step(uint32_t k, const std::vector<uint8_t>& hc, const std::vector<uint8_t>& hn,
                       const std::vector<uint8_t>& hd) {
    uint8_t m[32 + 4 + 96];
    memcpy(m, g_chain, 32); memcpy(m + 32, &k, 4);
    const std::vector<uint8_t>* hs[3] = {&hc, &hn, &hd};
    for (int i = 0; i < 3; ++i) {
        if (hs[i]->empty()) memset(m + 36 + 32 * i, 0, 32);
        else cr_sha256(hs[i]->data(), hs[i]->size(), m + 36 + 32 * i);
    }
    cr_sha256(m, sizeof(m), g_chain);
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

enum PPhase { P_KEY, P_CAND, P_DECS, P_FILL };   // P_FILL: between events
static PPhase   p_phase = P_KEY;
static uint32_t p_k = 0;                       // step; 0 = boot decisions
static int      p_ev = -1;                     // event of step p_k
static std::vector<uint8_t> p_sel, p_has;      // the candidate of p_ev
static std::vector<uint8_t> p_new;             // c' as sent (NEWST)
static int8_t   p_dec[EVENT_COUNT];            // 1 enabled, 0 disabled
static RxSet    p_rx;
static uint32_t p_t_send = 0, p_t_progress = 0;
static uint32_t p_min_dec_ms = 0;              // fastest wait for the decisions: the timeout
static uint32_t p_s_ready = 0;                 // READY(k): the supervisor's candidates of step k
static std::vector<uint8_t> p_hc, p_hn, p_hd;  // hashes of this step's CAND, NEWST, DECS frames
static uint8_t  p_sign[SIGN_PAY];              // the supervisor's SIGN of step p_sign_k
static uint32_t p_sign_k = 0xFFFFFFFFu;
static bool     p_recorded = false;            // step p_k is signed and checked
static uint32_t p_records = 0;
static int      p_oracle = 0;                  // the supervisor in clear
static int      p_pass = 0, p_fail = 0;
static uint64_t p_t0 = 0, p_tc = 0, p_tr = 0, p_tg = 0, p_td = 0, p_tz = 0;
static uint64_t sum_cand = 0, sum_rr = 0, sum_gen = 0, sum_dec = 0, sum_zt = 0, sum_total = 0;
static uint32_t p_steps = 0;

// Fresh encryptions of zero for the next step, drawn while the plant is idle
// and kept in RAM only. Each is used for one cell and erased: none is ever
// used twice. A step that finds the pool empty draws on the spot (in p_tg).
static std::vector<uint8_t> p_pool;            // NS cells; the first p_pool_n are ready
static int      p_pool_n = 0;
static uint32_t p_drawn_idle = 0, p_drawn_step = 0;
static uint64_t sum_idle = 0;                  // time spent drawing them while idle

static void pool_fill_one() {
    uint64_t t0 = des_micros();
    if (cr_enc(0, &p_pool[(size_t)p_pool_n * CELL_RAW])) { halt("encryption of zero failed"); return; }
    sum_idle += des_micros() - t0;
    ++p_pool_n; ++p_drawn_idle;
}
static int pool_take(uint8_t z[CELL_RAW]) {
    if (p_pool_n == 0) {
        uint64_t t0 = des_micros();
        int ret = cr_enc(0, z);
        p_tg += des_micros() - t0; ++p_drawn_step;
        return ret;
    }
    uint8_t* e = &p_pool[(size_t)--p_pool_n * CELL_RAW];
    memcpy(z, e, CELL_RAW);
    memset(e, 0, CELL_RAW);                    // erased: it cannot be used again
    return 0;
}

static int newst_chunks() { return (NS + NEWST_PER - 1) / NEWST_PER; }
static void send_newst_frame(int c) {
    int first = c * NEWST_PER, cnt = NS - first < NEWST_PER ? NS - first : NEWST_PER;
    Frame& f = g_txf; frame_init(f, T_NEWST, p_k, (uint16_t)c, (uint16_t)newst_chunks(), (uint16_t)cnt);
    memcpy(f.p(), &p_new[(size_t)first * CELL_RAW], (size_t)cnt * CELL_RAW);
    frame_send(f);
}

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
        DES_LOG("     candidates (supervisor + link) %.1f | re-randomize and send %.1f, of it"
                " drawing Enc(0) %.1f | waiting for the decisions (supervisor + link) %.1f |"
                " zero tests, each as its row arrives, %.1f  (ms)\n",
                sum_cand / 1000.0 / n, sum_rr / 1000.0 / n, sum_gen / 1000.0 / n,
                sum_dec / 1000.0 / n, sum_zt / 1000.0 / n);
    }
    if (p_drawn_idle)
        DES_LOG("  Enc(0)      : %u drawn between events (%.1f ms each: %.1f s to refill the"
                " %d of a step), %u during a step; each used once\n", (unsigned)p_drawn_idle,
                sum_idle / 1000.0 / p_drawn_idle, NS * (sum_idle / 1e6 / p_drawn_idle), NS,
                (unsigned)p_drawn_step);
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
    if (memcmp(p_sign, g_chain, 32) != 0) { halt("the supervisor signed a record that differs from what the plant received"); return; }
    if (cr_verify(m, sizeof(m), p_sign + 32)) { halt("the supervisor's signature of the step is wrong"); return; }
    p_recorded = true; ++p_records;
    char h[65], sg[2 * SIG_BYTES + 1];
    hex_out(p_sign, 32, h); hex_out(p_sign + 32, SIG_BYTES, sg);
    DES_LOG("[audit] %u %s %s\n", (unsigned)p_k, h, sg);
}

// The next event of the trace, as the plant: a controllable event only if
// the supervisor enables it.
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

    ++p_k; p_ev = e;
    p_sel.assign((size_t)NS * CELL_RAW, 0); p_has.assign(NS, 0);
    p_hc.clear(); p_hn.clear();
    p_rx.reset(T_CAND, p_k);
    p_phase = P_CAND;
    p_t0 = des_micros();
    send_simple(T_STEP, p_k);
    p_t_send = p_t_progress = des_millis();
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
    p_td = des_micros();
}

// c': the kept cells re-randomized, every label in order. Each frame goes out
// as soon as its cells are done, so that the supervisor sums it meanwhile.
static void rerandomize_and_send() {
    uint64_t t0 = des_micros();
    p_tc = t0 - p_t0;
    p_tg = 0;
    p_new.assign((size_t)NS * CELL_RAW, 0);
    p_hn.assign((size_t)32 * newst_chunks(), 0);
    for (int c = 0; c < newst_chunks(); ++c) {
        int first = c * NEWST_PER, last = first + NEWST_PER < NS ? first + NEWST_PER : NS;
        for (int q = first; q < last; ++q) {
            uint8_t z[CELL_RAW];
            int ret = pool_take(z);
            if (ret == 0) ret = cr_rerandomize(p_has[q] ? &p_sel[(size_t)q * CELL_RAW] : nullptr, z,
                                               &p_new[(size_t)q * CELL_RAW]);
            if (ret) { halt("re-randomization failed"); return; }
            DES_YIELD();
        }
        cr_sha256(&p_new[(size_t)first * CELL_RAW], (size_t)(last - first) * CELL_RAW, &p_hn[(size_t)32 * c]);
        send_newst_frame(c);
    }
    p_tr = des_micros() - t0;
    begin_decs();
}

// Every row of step p_k is tested.
static void decided() {
    p_td = des_micros() - p_td - p_tz;             // waiting for the supervisor, not testing
    int8_t oracle[EVENT_COUNT];
    bool ok = true;
    for (int e = 0; e < EVENT_COUNT; ++e) {
        oracle[e] = (int8_t)enabled(e, p_oracle);
        if (((g_ctrl >> e) & 1) && oracle[e] != p_dec[e]) ok = false;
    }
    if (ok) ++p_pass; else ++p_fail;
    char nm[16];
    if (p_k == 0) DES_LOG("\n-- Boot: decisions in the initial state --\n");
    else DES_LOG("\n-- Step %u | Event: %s (known to the plant only) --\n", (unsigned)p_k, ev_name(p_ev, nm));
    print_bits("[Oracle]", oracle);
    print_bits("[HE]", p_dec);
    if (p_k > 0) {
        uint64_t total = p_tc + p_tr + p_td + p_tz;
        DES_LOG("  Time: %.1f ms  (candidates %.1f | re-randomize and send %.1f, Enc(0) %.1f | "
                "waiting %.1f | zero tests %.1f)  %s\n", total / 1000.0, p_tc / 1000.0,
                p_tr / 1000.0, p_tg / 1000.0, p_td / 1000.0, p_tz / 1000.0, ok ? "OK" : "MISMATCH");
        sum_total += total; sum_cand += p_tc; sum_rr += p_tr; sum_gen += p_tg; sum_dec += p_td; sum_zt += p_tz;
        ++p_steps;
        // The FASTEST time: a slow step (a resend) must not stretch the next wait.
        if (p_min_dec_ms == 0 || p_td / 1000 < p_min_dec_ms) p_min_dec_ms = (uint32_t)(p_td / 1000);
    } else {
        DES_LOG("  %s\n", ok ? "OK" : "MISMATCH");
    }
    chain_step(p_k, p_hc, p_hn, p_hd);
    p_recorded = false;
    p_phase = P_FILL;                              // the next event, once refilled and signed
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
            DES_LOG("[split] supervisor %08x: identity and key share checked; drawing the"
                    " encryptions of zero of the first step under the joint key\n",
                    (unsigned)g_peer_epoch);
        } else if (h->type == T_READY && g_peer_epoch && h->seq == 0) {
            DES_LOG("[split] supervisor ready; it encrypted the initial state\n");
            p_k = 0;
            begin_decs();
        }
        return;
    }

    switch (h->type) {
    case T_CAND:
        if (p_phase != P_CAND || h->seq != p_k || !shape_ok(h, (int)g_cand.size(), CAND_PER) ||
            !p_rx.mark(h)) return;
        p_t_progress = des_millis();
        if (p_hc.empty()) p_hc.assign((size_t)32 * h->nchunks, 0);
        cr_sha256(f.p(), (size_t)h->count * CAND_ITEM, &p_hc[(size_t)32 * h->chunk]);
        // Every candidate is received; only the event's own cells are kept, at
        // the labels the supervisor gave their states this step.
        for (int i = 0; i < h->count; ++i) {
            const uint8_t* it = f.p() + i * CAND_ITEM;
            uint16_t to; memcpy(&to, it + 1, 2);
            if (it[0] == p_ev && to < NS) {
                memcpy(&p_sel[(size_t)to * CELL_RAW], it + 3, CELL_RAW);
                p_has[to] = 1;
            }
        }
        if (p_rx.complete()) rerandomize_and_send();
        break;
    case T_NACK:
        if (f.p()[0] == T_NEWST && h->seq == p_k && p_phase == P_DECS)
            for (int c = 0; c < newst_chunks(); ++c)
                if (nack_wants(f, c)) { send_newst_frame(c); ++g_resent; }
        break;
    case T_DECS: {
        if (p_phase != P_DECS || h->seq != p_k || !shape_ok(h, (int)g_rows.size(), 1) ||
            !p_rx.mark(h)) return;
        p_t_progress = des_millis();
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

static void split_setup() {
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
    p_pool.assign((size_t)NS * CELL_RAW, 0);
    DES_LOG("[split] PLANT board, epoch %08x, config %08x, P-%d: %d states, %d events, "
            "%d candidate cells and %d decision sums per step\n", (unsigned)g_epoch,
            (unsigned)g_cfg, DES_CURVE, NS, EVENT_COUNT, (int)g_cand.size(), (int)g_rows.size());
    DES_LOG("[split] waiting for the supervisor board's key share...\n");
    p_t_send = des_millis();
    send_key();
}

static void split_loop() {
    if (g_halt || g_done) { drain(); return; }
    drain();
    uint32_t now = des_millis();
    if ((p_phase == P_CAND || p_phase == P_DECS) && now - p_t_progress > 120000) {
        halt("no progress for 2 minutes"); return;
    }
    switch (p_phase) {
    case P_KEY:
        if (now - p_t_send > 500) { send_key(); p_t_send = now; }
        else if (g_peer_epoch && p_pool_n < NS) pool_fill_one();     // under the joint key
        break;
    case P_CAND:
        if (p_rx.have == 0 && now - p_t_send > 1000) {            // STEP lost?
            send_simple(T_STEP, p_k); p_t_send = now; ++g_resent;
        } else if (p_rx.have > 0 && now - p_rx.t_last > 300 && now - p_t_send > 300) {
            send_nack(p_rx); p_t_send = now;
        }
        break;
    case P_DECS:
        if (now - p_t_send > 1000 + 2 * p_min_dec_ms && now - p_rx.t_last > 300) {
            send_nack(p_rx); p_t_send = now;
        }
        break;
    case P_FILL:            // one draw per pass, so that frames are still received
        if (!p_recorded) check_record();                           // the supervisor's SIGN
        if (g_halt) break;
        if (p_recorded && p_k == (uint32_t)SIM_SEQ_LEN) next_step();   // the end of the trace
        else if (p_pool_n < NS) pool_fill_one();                   // also while the SIGN is on its way
        else if (p_recorded && p_s_ready > p_k) next_step();       // both boards are ready
        break;
    }
}

// =============================================================================
// 5. The supervisor board: tables, encrypted state, its key share
// =============================================================================
#else

enum SPhase { S_KEY, S_IDLE, S_NEWST, S_DECS };
static SPhase   s_phase = S_KEY;
static uint32_t s_k = 0;
static std::vector<uint8_t> s_c;               // the encrypted state, raw cells
static std::vector<uint8_t> s_acc;             // the decision sums of step s_k, as they grow
static std::vector<uint8_t> s_decs;            // DECS(s_k): one item per row, kept for resends
static size_t   s_row_n = 0;                   // rows of s_decs made
static std::vector<uint16_t> s_pending;        // labels of NEWST cells not yet summed
static std::vector<uint32_t> s_rows_off;       // the rows of state q: s_rows_of[off[q], off[q+1])
static std::vector<uint8_t>  s_rows_of;
static RxSet    s_rx;
static uint32_t s_t_cand = 0, s_t_ready = 0;
static uint64_t s_cand_us = 0, s_dec_us = 0;
static uint32_t s_steps = 0;

static int cand_chunks() { return ((int)g_cand.size() + CAND_PER - 1) / CAND_PER; }

// Prepared while idle, one item per pass of the loop: a fresh permutation π of
// the states first, then, for every transition q → q' of every event e, the
// cell c[q] (the sum if several) plus a fresh Enc_Y(0), tagged (e, π(q')) and
// sent by event and then in label order, and a fresh Enc_Y(0) per decision
// row. A STEP that comes before they are all ready finishes them on the spot.
static std::vector<uint8_t>  s_cand;           // the items of CAND, ready to send
static std::vector<uint8_t>  s_dz;             // Enc_Y(0) per row, each used once
static std::vector<uint16_t> s_label, s_state; // π, and its inverse
static std::vector<uint16_t> s_order;          // g_cand in sending order: by event, then label
static size_t   s_prep_n = 0;                  // items ready: the candidates, then the rows
static uint32_t s_prep_k = 0;                  // the step they are for
// The audit: all of this board's randomness comes from s_seed, committed to
// at boot together with the tables (g_commit).
static uint8_t  s_seed[32];
static std::vector<uint8_t> s_hn;              // hashes of this step's NEWST frames
static uint8_t  s_sign[SIGN_PAY];              // SIGN of step s_k, kept for resends
static uint32_t s_prep_idle = 0, s_prep_step = 0, s_t_rdy = 0;
static uint64_t s_prep_us = 0;                 // time spent preparing them while idle

static size_t prep_total() { return g_cand.size() + g_rows.size(); }

static void start_prepare() {
    s_label.resize(NS); s_state.resize(NS);
    s_prep_k = s_k + 1;
    for (int q = 0; q < NS; ++q) s_label[q] = (uint16_t)q;
    for (int i = NS - 1; i > 0; --i) {                      // Fisher–Yates
        int j = (int)(cr_det_u32(s_seed, "perm", s_prep_k, (uint32_t)i) % (uint32_t)(i + 1));
        uint16_t t = s_label[i]; s_label[i] = s_label[j]; s_label[j] = t;
    }
    for (int q = 0; q < NS; ++q) s_state[s_label[q]] = (uint16_t)q;
    // In the order of the states, the candidates of an event would show how
    // the true numbers of their labels compare.
    s_order.resize(g_cand.size());
    for (size_t i = 0; i < g_cand.size(); ++i) s_order[i] = (uint16_t)i;
    std::sort(s_order.begin(), s_order.end(), [](uint16_t a, uint16_t b) {
        const CandEntry &x = g_cand[a], &y = g_cand[b];
        return x.ev != y.ev ? x.ev < y.ev : s_label[x.to] < s_label[y.to];
    });
    s_cand.assign(g_cand.size() * CAND_ITEM, 0);
    s_dz.assign(g_rows.size() * CELL_RAW, 0);
    s_prep_n = 0;
}
static void prepare_one(bool in_step) {
    uint64_t t0 = des_micros();
    int ret = 0;
    if (s_prep_n < g_cand.size()) {
        const CandEntry& en = g_cand[s_order[s_prep_n]];
        uint8_t* it = &s_cand[s_prep_n * CAND_ITEM];
        it[0] = en.ev; memcpy(it + 1, &s_label[en.to], 2);
        uint8_t sum[CELL_RAW], z[CELL_RAW];
        const uint8_t* cell = &s_c[(size_t)g_cand_src[en.src0] * CELL_RAW];
        if (en.nsrc > 1) {
            std::vector<const uint8_t*> v;
            for (int j = 0; j < en.nsrc; ++j) v.push_back(&s_c[(size_t)g_cand_src[en.src0 + j] * CELL_RAW]);
            ret = cr_sum(v.data(), (int)v.size(), sum);
            cell = sum;
        }
        if (ret == 0) ret = cr_enc_det(0, s_seed, "cand", s_prep_k, (uint32_t)s_prep_n, z);
        if (ret == 0) ret = cr_rerandomize(cell, z, it + 3);
    } else {
        uint32_t g = (uint32_t)(s_prep_n - g_cand.size());
        ret = cr_enc_det(0, s_seed, "dz", s_prep_k, g, &s_dz[g * CELL_RAW]);
    }
    if (ret) { halt("preparation failed"); return; }
    ++s_prep_n;
    if (in_step) ++s_prep_step;
    else { ++s_prep_idle; s_prep_us += des_micros() - t0; }
}

// Sends CAND(s_k) from the prepared candidates; a resend is the same bytes.
static void send_cand(const Frame* nack) {
    int nch = cand_chunks();
    uint64_t t0 = des_micros();
    for (int c = 0; c < nch; ++c) {
        if (nack && !nack_wants(*nack, c)) continue;
        int first = c * CAND_PER, cnt = (int)g_cand.size() - first;
        if (cnt > CAND_PER) cnt = CAND_PER;
        Frame& f = g_txf; frame_init(f, T_CAND, s_k, (uint16_t)c, (uint16_t)nch, (uint16_t)cnt);
        memcpy(f.p(), &s_cand[(size_t)first * CAND_ITEM], (size_t)cnt * CAND_ITEM);
        frame_send(f);
        if (nack) ++g_resent;
    }
    if (!nack) s_cand_us += des_micros() - t0;
}

// The decision of row g: its sum d (all its cells), plus a fresh Enc_Y(0) z so
// that the plant cannot tell which of its cells make it up, and this board's
// part of its decryption.
static int make_row(size_t g, const uint8_t z[CELL_RAW]) {
    uint8_t* it = &s_decs[g * DECS_ITEM];
    memcpy(it, &g_rows[g].evmask, 8);
    int ret = cr_rerandomize(&s_acc[g * CELL_RAW], z, it + 8);
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
    s_acc.assign(g_rows.size() * CELL_RAW, 0);
    s_decs.assign(g_rows.size() * DECS_ITEM, 0);
    for (size_t g = 0; g < g_rows.size(); ++g) {
        std::vector<const uint8_t*> v;
        for (uint16_t q : g_rows[g].cells) v.push_back(&s_c[(size_t)q * CELL_RAW]);
        uint8_t z[CELL_RAW];
        if (cr_sum(v.data(), (int)v.size(), &s_acc[g * CELL_RAW]) ||
            cr_enc_det(0, s_seed, "dz", 0, (uint32_t)g, z) || make_row(g, z)) {
            halt("boot decisions failed"); return;
        }
    }
    s_row_n = g_rows.size();
}
// The record of step s_k (see chain_step), signed and sent.
static void record_step() {
    std::vector<uint8_t> hc, hd;
    if (s_k > 0) {
        int nch = cand_chunks();
        hc.assign((size_t)32 * nch, 0);
        for (int c = 0; c < nch; ++c) {
            int first = c * CAND_PER, cnt = (int)g_cand.size() - first;
            if (cnt > CAND_PER) cnt = CAND_PER;
            cr_sha256(&s_cand[(size_t)first * CAND_ITEM], (size_t)cnt * CAND_ITEM, &hc[(size_t)32 * c]);
        }
    }
    hd.assign(32 * g_rows.size(), 0);
    for (size_t g = 0; g < g_rows.size(); ++g) cr_sha256(&s_decs[g * DECS_ITEM], DECS_ITEM, &hd[32 * g]);
    chain_step(s_k, hc, s_k > 0 ? s_hn : std::vector<uint8_t>(), hd);
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
// One NEWST cell into the sums of the rows of its state.
static void add_one() {
    uint64_t t0 = des_micros();
    uint16_t l = s_pending.back(); s_pending.pop_back();
    int q = s_state[l];
    const uint8_t* cell = &s_c[(size_t)q * CELL_RAW];
    for (uint32_t i = s_rows_off[q]; i < s_rows_off[q + 1]; ++i) {
        uint8_t* acc = &s_acc[(size_t)s_rows_of[i] * CELL_RAW];
        const uint8_t* two[2] = {acc, cell};
        if (cr_sum(two, 2, acc)) { halt("decision sum failed"); return; }
    }
    s_dec_us += des_micros() - t0;
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
    DES_LOG("  SPLIT — supervisor board (its key share, no event)\n");
    DES_LOG("============================================\n");
    DES_LOG("  supervisor  : monolithic, %d states; %d candidate cells (%d frames) and %d"
            " decision sums per step\n", NS, (int)g_cand.size(), cand_chunks(), (int)g_rows.size());
    DES_LOG("  curve       : NIST P-%d\n", DES_CURVE);
    DES_LOG("  steps       : %u; never saw an event, a decision or the plant's key share\n", (unsigned)s_steps);
    if (s_steps)
        DES_LOG("  per step    : candidates %.1f ms; decision sums, their Enc(0) and partial"
                " decryptions %.1f ms\n", s_cand_us / 1000.0 / s_steps, s_dec_us / 1000.0 / s_steps);
    char seed[65]; hex_out(s_seed, 32, seed);
    // Printed for the prototype: in a deployment the seed would be kept for the
    // auditor only, for as long as a run may be audited.
    DES_LOG("  audit       : every step signed; the opening, for the auditor only: seed %s\n", seed);
    if (s_prep_idle)
        DES_LOG("  prepared    : %u items between steps (%.1f ms each: %.1f s for the %d candidates"
                " and %d decision Enc(0) of a step), %u during a step; labels permuted every step\n",
                (unsigned)s_prep_idle, s_prep_us / 1000.0 / s_prep_idle,
                (double)prep_total() * (s_prep_us / 1e6 / s_prep_idle), (int)g_cand.size(),
                (int)g_rows.size(), (unsigned)s_prep_step);
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
            send_key();                                    // the plant can start its pool
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
            DES_LOG("[split] encrypted in %.1f ms; boot decisions\n", (des_micros() - t0) / 1000.0);
            s_k = 0;
            boot_decs();
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
    case T_STEP:
        if (s_phase == S_IDLE && h->seq == s_k + 1) {
            uint64_t t0 = des_micros();                    // the event came early
            while (s_prep_n < prep_total() && !g_halt) { prepare_one(true); DES_YIELD(); }
            if (g_halt) return;
            s_cand_us += des_micros() - t0;
            s_k = h->seq;
            s_acc.assign(g_rows.size() * CELL_RAW, 0);
            s_decs.assign(g_rows.size() * DECS_ITEM, 0);
            s_row_n = 0;
            s_pending.clear();
            s_hn.assign((size_t)32 * ((NS + NEWST_PER - 1) / NEWST_PER), 0);
            s_phase = S_NEWST;
            s_rx.reset(T_NEWST, s_k);
            send_cand(nullptr);
            s_t_cand = des_millis();
        } else if (s_phase == S_NEWST && h->seq == s_k && s_rx.have == 0 &&
                   des_millis() - s_t_cand > 500) {
            send_cand(nullptr);                            // the plant got none
            s_t_cand = des_millis();
        }
        break;
    case T_NACK:
        if (h->seq != s_k) return;
        if (f.p()[0] == T_CAND && s_phase == S_NEWST && s_rx.have == 0) send_cand(&f);
        else if (f.p()[0] == T_DECS && s_phase == S_NEWST && !s_rx.complete()) send_nack(s_rx);
        else if (f.p()[0] == T_DECS) send_decs(&f);
        break;
    case T_NEWST:
        if (s_phase != S_NEWST || h->seq != s_k || !shape_ok(h, NS, NEWST_PER) || !s_rx.mark(h)) return;
        cr_sha256(f.p(), (size_t)h->count * CELL_RAW, &s_hn[(size_t)32 * h->chunk]);
        // The cell of label l goes back to the state it labels: c[q] = c'[π(q)];
        // the loop adds it to the sums of its rows. The old state is no longer
        // needed: this step's candidates are made.
        for (int i = 0; i < h->count; ++i) {
            int l = h->chunk * NEWST_PER + i;
            memcpy(&s_c[(size_t)s_state[l] * CELL_RAW], f.p() + (size_t)i * CELL_RAW, CELL_RAW);
            s_pending.push_back((uint16_t)l);
        }
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
    }
    if (cr_keygen(DES_SUPERVISOR, s_seed, g_mykey)) { halt("key generation failed"); return; }
    s_rows_off.assign((size_t)NS + 1, 0);              // the rows of every state
    for (auto& g : g_rows) for (uint16_t q : g.cells) ++s_rows_off[q + 1];
    for (int q = 0; q < NS; ++q) s_rows_off[q + 1] += s_rows_off[q];
    s_rows_of.assign(s_rows_off[NS], 0);
    std::vector<uint32_t> at(s_rows_off.begin(), s_rows_off.end() - 1);
    for (size_t g = 0; g < g_rows.size(); ++g)
        for (uint16_t q : g_rows[g].cells) s_rows_of[at[q]++] = (uint8_t)g;
    if (!DES_TRANSPORT_IMPL.begin()) { halt("network down"); return; }
    DES_LOG("[split] SUPERVISOR board, epoch %08x, config %08x, P-%d: %d states, %d events, "
            "%d candidate cells and %d decision sums per step\n", (unsigned)g_epoch,
            (unsigned)g_cfg, DES_CURVE, NS, EVENT_COUNT, (int)g_cand.size(), (int)g_rows.size());
    DES_LOG("[split] waiting for the plant board's key share...\n");
}

static void split_loop() {
    drain();
    if (g_halt || g_done) return;
    if (s_phase == S_IDLE && s_prep_n < prep_total()) {
        prepare_one(false);
        if (s_prep_n == prep_total()) { send_simple(T_READY, s_k + 1); s_t_rdy = des_millis(); }
    } else if (s_phase == S_IDLE && des_millis() - s_t_rdy > 1000) {
        // READY or the SIGN may have been lost: the plant needs both to go on
        send_simple(T_READY, s_k + 1); send_simple(T_SIGN, s_k, s_sign, SIGN_PAY); s_t_rdy = des_millis();
    } else if (s_phase == S_NEWST && !s_pending.empty()) {
        add_one();                                     // one cell per pass: frames keep coming
    } else if (s_phase == S_NEWST && s_rx.complete()) {
        s_phase = S_DECS;
    } else if (s_phase == S_DECS) {
        row_one();
    }
    if (s_phase == S_NEWST && s_rx.have > 0 && !s_rx.complete() && des_millis() - s_rx.t_last > 300 &&
        des_millis() - s_t_cand > 300) {
        send_nack(s_rx); s_t_cand = des_millis();
    }
}

#endif  // DES_ROLE
