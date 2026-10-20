// =============================================================================
// des_split.h — the supervisor and the plant on two boards
// =============================================================================
//
// The supervisor board holds the supervisor (its tables and its encrypted
// state) and only the PUBLIC key. The plant board emulates the plant and holds
// the PRIVATE key. Three things never reach the supervisor board:
//
//   • the private key — the supervisor only ever adds ciphertexts;
//   • the event — the supervisor computes the next encrypted state for EVERY
//     event, the plant keeps the one of the event that occurred, re-randomizes
//     it and sends it back, so the supervisor cannot tell which one it was;
//   • the decisions — the supervisor computes the encrypted decisions (the
//     homomorphic sums of the rows of R) and the plant decrypts them; nothing
//     is cached on the supervisor between steps.
//
// One step (k), after the plant fired event σ:
//
//   plant                                     supervisor (public key Y)
//     STEP(k)  ─────────────────────────────▶
//                                              for every event e and every
//                                              transition q → q' of e:
//                                              the cell c[q] (sum if several)
//     ◀──────────────────────────── CAND(k) ×m
//   keep the cells of σ, then for every
//   cell q:  c'[q] = cell ⊞ Enc_Y(0)
//     NEWST(k) ×n/14 ───────────────────────▶  c ← c'
//                                              d_c = R c' (one sum per
//                                              distinct controllable row)
//     ◀──────────────────────────── DECS(k)
//   zero tests → decisions → actuators
//
// What the supervisor learns: that a step happened. Every message of a step
// has the same number of frames whatever σ is, the supervisor's work does not
// depend on σ, and the plant does the same work for every σ (it waits for ALL
// the candidates, re-randomizes ALL the cells and tests ALL the rows).
//
// Only the monolithic supervisor is used (one supervisor, MONO_SUP of the
// header). Frames are 1400 bytes, signed with HMAC-SHA256/128 under the cell
// key of secrets.h, and carry a per-boot epoch and a configuration
// fingerprint; a lost frame is asked for again (NACK) by the receiver.
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

#ifndef DES_AUTH_KEY
#  error "Set DES_AUTH_KEY — the cell's shared secret (see secrets.example.h)"
#endif
static_assert(sizeof(DES_AUTH_KEY) - 1 >= 32,
              "DES_AUTH_KEY must be at least 32 characters — use a random one");

// =============================================================================
// 1. Cells and the crypto they need
// =============================================================================
//
// A point travels as 48 raw bytes, x || y (all zero = the point at infinity),
// or compressed as 25 bytes, 0x02/0x03 || x. A cell (a ciphertext (U, V)) is
// 96 bytes raw or 50 compressed.

#define PT_RAW   48
#define PT_CMP   25
#define CELL_RAW (2 * PT_RAW)
#define CELL_CMP (2 * PT_CMP)
#define DES_TAG_BYTES 16

// Implemented below with mbedTLS, or by a host test build (DES_SPLIT_MOCK).
#define CR_FN static __attribute__((unused))   // each role uses only some of them
CR_FN void cr_init(const char* pers);
CR_FN uint32_t cr_random32();
CR_FN void cr_hmac(const uint8_t* msg, size_t len, uint8_t tag[DES_TAG_BYTES]);
CR_FN int  cr_keygen(uint8_t Y[PT_CMP]);                 // plant
CR_FN int  cr_set_pub(const uint8_t Y[PT_CMP]);          // supervisor
CR_FN int  cr_enc(int m, uint8_t cell[CELL_RAW]);        // fresh encryption of m
CR_FN int  cr_sum(const uint8_t* const* cells, int cnt, uint8_t out[CELL_RAW]);
// out = cell ⊞ Enc_Y(0), or out = Enc_Y(0) when cell is null; the same work
// either way. *gen_us gets the time spent drawing the encryption of zero.
CR_FN int  cr_rerandomize(const uint8_t* cell_cmp, uint8_t out[CELL_RAW],
                           uint64_t* gen_us);
CR_FN int  cr_zero_test(const uint8_t cell[CELL_RAW]);  // 0, 1, or < 0 on error

static bool pt_raw_is_inf(const uint8_t* p) {
    uint8_t acc = 0;
    for (int i = 0; i < PT_RAW; ++i) acc |= p[i];
    return acc == 0;
}
// Compression only needs the parity of y: no field arithmetic.
CR_FN void cell_compress(const uint8_t raw[CELL_RAW], uint8_t cmp[CELL_CMP]) {
    for (int h = 0; h < 2; ++h) {
        const uint8_t* p = raw + h * PT_RAW;
        uint8_t*       q = cmp + h * PT_CMP;
        if (pt_raw_is_inf(p)) { memset(q, 0, PT_CMP); continue; }
        q[0] = 0x02 | (p[PT_RAW - 1] & 1);
        memcpy(q + 1, p, PT_RAW / 2);
    }
}

#if !DES_SPLIT_MOCK
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>

static mbedtls_ecp_group        g_grp;
static mbedtls_ecp_point        g_Y;                // public key
static mbedtls_mpi              g_one, g_neg_k;     // N - k: plant only
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_entropy_context  g_entropy;
static uint8_t                  g_dummy[CELL_CMP]; // (G, G), for constant work

static inline void swap_pt(mbedtls_ecp_point* a, mbedtls_ecp_point* b) {
    mbedtls_ecp_point t = *a; *a = *b; *b = t;
}
static int pt_from_raw(const uint8_t raw[PT_RAW], mbedtls_ecp_point* P) {
    if (pt_raw_is_inf(raw)) return mbedtls_ecp_set_zero(P);
    uint8_t b[1 + PT_RAW]; b[0] = 0x04; memcpy(b + 1, raw, PT_RAW);
    return mbedtls_ecp_point_read_binary(&g_grp, P, b, sizeof(b));
}
static int pt_to_raw(mbedtls_ecp_point* P, uint8_t raw[PT_RAW]) {
    if (mbedtls_ecp_is_zero(P)) { memset(raw, 0, PT_RAW); return 0; }
    uint8_t b[1 + PT_RAW]; size_t len = 0;
    int ret = mbedtls_ecp_point_write_binary(&g_grp, P, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &len, b, sizeof(b));
    if (ret == 0) memcpy(raw, b + 1, PT_RAW);
    return ret;
}
static int pt_from_cmp(const uint8_t cmp[PT_CMP], mbedtls_ecp_point* P) {
    if (cmp[0] == 0) return mbedtls_ecp_set_zero(P);
    return mbedtls_ecp_point_read_binary(&g_grp, P, cmp, PT_CMP);
}
// R = A + B. mbedtls_ecp_muladd refuses the point at infinity as an input.
static int pt_add(mbedtls_ecp_point* R, mbedtls_ecp_point* A, mbedtls_ecp_point* B) {
    if (mbedtls_ecp_is_zero(A)) return mbedtls_ecp_copy(R, B);
    if (mbedtls_ecp_is_zero(B)) return mbedtls_ecp_copy(R, A);
    return mbedtls_ecp_muladd(&g_grp, R, &g_one, A, &g_one, B);
}
// (U, V) = (sG, sY), a fresh encryption of zero.
static int enc0(mbedtls_ecp_point* U, mbedtls_ecp_point* V) {
    mbedtls_mpi s; mbedtls_mpi_init(&s);
    int ret = mbedtls_ecp_gen_privkey(&g_grp, &s, mbedtls_ctr_drbg_random, &g_drbg);
    if (ret == 0) ret = mbedtls_ecp_mul(&g_grp, U, &s, &g_grp.G, mbedtls_ctr_drbg_random, &g_drbg);
    if (ret == 0) ret = mbedtls_ecp_mul(&g_grp, V, &s, &g_Y,     mbedtls_ctr_drbg_random, &g_drbg);
    mbedtls_mpi_free(&s);
    return ret;
}

static void cr_init(const char* pers) {
    mbedtls_ecp_group_init(&g_grp); mbedtls_ecp_point_init(&g_Y);
    mbedtls_mpi_init(&g_one); mbedtls_mpi_init(&g_neg_k);
    mbedtls_ctr_drbg_init(&g_drbg); mbedtls_entropy_init(&g_entropy);
    mbedtls_mpi_lset(&g_one, 1);
    mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                          (const uint8_t*)pers, strlen(pers));
    mbedtls_ecp_group_load(&g_grp, MBEDTLS_ECP_DP_SECP192R1);
    size_t len = 0;
    mbedtls_ecp_point_write_binary(&g_grp, &g_grp.G, MBEDTLS_ECP_PF_COMPRESSED,
                                   &len, g_dummy, PT_CMP);
    memcpy(g_dummy + PT_CMP, g_dummy, PT_CMP);
}
static uint32_t cr_random32() {
    uint32_t r = 0;
    mbedtls_ctr_drbg_random(&g_drbg, (unsigned char*)&r, sizeof(r));
    return r;
}
static void cr_hmac(const uint8_t* msg, size_t len, uint8_t tag[DES_TAG_BYTES]) {
    uint8_t full[32];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    (const unsigned char*)DES_AUTH_KEY, sizeof(DES_AUTH_KEY) - 1,
                    msg, len, full);
    memcpy(tag, full, DES_TAG_BYTES);
}
static int cr_keygen(uint8_t Y[PT_CMP]) {
    mbedtls_mpi k; mbedtls_mpi_init(&k);
    int ret = mbedtls_ecp_gen_keypair(&g_grp, &k, &g_Y, mbedtls_ctr_drbg_random, &g_drbg);
    if (ret == 0) ret = mbedtls_mpi_sub_mpi(&g_neg_k, &g_grp.N, &k);
    mbedtls_mpi_free(&k);                       // only N - k is kept
    size_t len = 0;
    if (ret == 0) ret = mbedtls_ecp_point_write_binary(&g_grp, &g_Y, MBEDTLS_ECP_PF_COMPRESSED,
                                                       &len, Y, PT_CMP);
    return ret;
}
static int cr_set_pub(const uint8_t Y[PT_CMP]) {
    int ret = pt_from_cmp(Y, &g_Y);
    if (ret == 0) ret = mbedtls_ecp_check_pubkey(&g_grp, &g_Y);
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
static int cr_rerandomize(const uint8_t* cell_cmp, uint8_t out[CELL_RAW], uint64_t* gen_us) {
    mbedtls_ecp_point Z[2], C, T;
    mbedtls_ecp_point_init(&Z[0]); mbedtls_ecp_point_init(&Z[1]);
    mbedtls_ecp_point_init(&C); mbedtls_ecp_point_init(&T);
    uint64_t t0 = des_micros();
    int ret = enc0(&Z[0], &Z[1]);
    *gen_us = des_micros() - t0;
    // An empty cell takes the dummy (G, G) through the same decompression and
    // addition, and the result is thrown away: the time does not show which
    // cells were empty, which would hint at the event.
    const uint8_t* in = cell_cmp ? cell_cmp : g_dummy;
    for (int h = 0; h < 2 && ret == 0; ++h) {
        ret = pt_from_cmp(in + h * PT_CMP, &C);
        if (ret == 0) ret = pt_add(&T, &C, &Z[h]);
        if (ret == 0) ret = pt_to_raw(cell_cmp ? &T : &Z[h], out + h * PT_RAW);
    }
    mbedtls_ecp_point_free(&Z[0]); mbedtls_ecp_point_free(&Z[1]);
    mbedtls_ecp_point_free(&C); mbedtls_ecp_point_free(&T);
    return ret;
}
// V + (N - k) U is the point at infinity iff the cell encrypts 0. The scalar
// multiplication is blinded (a DRBG callback), against timing and power analysis.
static int cr_zero_test(const uint8_t cell[CELL_RAW]) {
    mbedtls_ecp_point U, V, W, R;
    mbedtls_ecp_point_init(&U); mbedtls_ecp_point_init(&V);
    mbedtls_ecp_point_init(&W); mbedtls_ecp_point_init(&R);
    int ret = pt_from_raw(cell, &U);
    if (ret == 0) ret = pt_from_raw(cell + PT_RAW, &V);
    if (ret == 0 && !mbedtls_ecp_is_zero(&U))
        ret = mbedtls_ecp_mul(&g_grp, &W, &g_neg_k, &U, mbedtls_ctr_drbg_random, &g_drbg);
    else if (ret == 0)
        ret = mbedtls_ecp_set_zero(&W);
    if (ret == 0) ret = pt_add(&R, &V, &W);
    int bit = (ret == 0) ? (mbedtls_ecp_is_zero(&R) ? 0 : 1) : ret;
    mbedtls_ecp_point_free(&U); mbedtls_ecp_point_free(&V);
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
    mix(0x5350u + 1);                               // protocol version 1
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

enum : uint8_t { T_KEY = 1, T_READY, T_STEP, T_CAND, T_NEWST, T_DECS, T_NACK, T_FIN };

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
#define CAND_ITEM     (1 + 2 + CELL_CMP)            // event, state, cell
#define CAND_PER      (SPLIT_PAYLOAD / CAND_ITEM)
#define NEWST_PER     (SPLIT_PAYLOAD / CELL_RAW)
#define DECS_ITEM     (8 + CELL_RAW)                // event mask, sum
#define DECS_PER      (SPLIT_PAYLOAD / DECS_ITEM)

struct Frame {
    uint8_t b[DES_FRAME_BYTES];
    SplitHdr*      h()       { return (SplitHdr*)b; }
    const SplitHdr* h() const { return (const SplitHdr*)b; }
    uint8_t*       p()       { return b + sizeof(SplitHdr); }
    const uint8_t* p() const { return b + sizeof(SplitHdr); }
};

static uint32_t g_epoch = 0, g_peer_epoch = 0;
static uint32_t g_tx = 0, g_rx = 0, g_resent = 0, g_nacks = 0, g_auth_bad = 0, g_cfg_bad = 0;
static bool     g_halt = false, g_done = false;

static Frame g_txf;                                // the frame being built and sent
static void frame_init(Frame& f, uint8_t type, uint32_t seq, uint16_t chunk, uint16_t nchunks,
                       uint16_t count) {
    memset(f.b, 0, sizeof(f.b));
    SplitHdr* h = f.h();
    h->magic = SPLIT_MAGIC; h->type = type; h->role = DES_ROLE;
    h->chunk = chunk; h->nchunks = nchunks; h->count = count;
    h->epoch = g_epoch; h->peer = g_peer_epoch; h->cfg = g_cfg; h->seq = seq;
}
static void frame_send(Frame& f) {
    cr_hmac(f.b, DES_FRAME_BYTES - DES_TAG_BYTES, f.b + DES_FRAME_BYTES - DES_TAG_BYTES);
    for (int tries = 0; tries < 20; ++tries) {             // the TX queue may be full
        if (DES_TRANSPORT_IMPL.send(f.b, DES_FRAME_BYTES)) { ++g_tx; break; }
        des_sleep_ms(2);
    }
    des_sleep_ms(1);                                       // pace: the receiver's
}                                                          // mailbox is small
static bool frame_ok(const Frame& f) {
    uint8_t t[DES_TAG_BYTES];
    cr_hmac(f.b, DES_FRAME_BYTES - DES_TAG_BYTES, t);
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
        if (!frame_ok(f)) { ++g_auth_bad; continue; }
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

// =============================================================================
// 4. The plant board: private key, events, decisions
// =============================================================================
#if DES_ROLE == DES_PLANT

enum PPhase { P_KEY, P_CAND, P_DECS };
static PPhase   p_phase = P_KEY;
static uint32_t p_k = 0;                       // step; 0 = boot decisions
static int      p_ev = -1;                     // event of step p_k
static std::vector<uint8_t> p_sel, p_has;      // the candidate of p_ev
static std::vector<uint8_t> p_new;             // c' as sent (NEWST)
static std::vector<uint8_t> p_decs;            // DECS(p_k) as received
static int      p_ndecs = 0;                   // sums in it
static int8_t   p_dec[EVENT_COUNT];            // 1 enabled, 0 disabled
static uint8_t  p_Y[PT_CMP];
static RxSet    p_rx;
static uint32_t p_t_send = 0, p_t_progress = 0;
static uint32_t p_min_dec_ms = 0;              // fastest decisions seen: the timeout
static int      p_oracle = 0;                  // the supervisor in clear
static int      p_pass = 0, p_fail = 0;
static uint64_t p_t0 = 0, p_tc = 0, p_tr = 0, p_tg = 0, p_td = 0, p_tz = 0;
static uint64_t sum_cand = 0, sum_rr = 0, sum_gen = 0, sum_dec = 0, sum_zt = 0, sum_total = 0;
static uint32_t p_steps = 0;

static void send_simple(uint8_t type, uint32_t seq, const void* pl = nullptr, int len = 0) {
    Frame& f = g_txf; frame_init(f, type, seq, 0, 1, 0);
    if (pl) memcpy(f.p(), pl, len);
    frame_send(f);
}
static void send_newst(const Frame* nack) {
    int nch = (NS + NEWST_PER - 1) / NEWST_PER;
    for (int c = 0; c < nch; ++c) {
        if (nack && !nack_wants(*nack, c)) continue;
        int first = c * NEWST_PER, cnt = NS - first < NEWST_PER ? NS - first : NEWST_PER;
        Frame& f = g_txf; frame_init(f, T_NEWST, p_k, (uint16_t)c, (uint16_t)nch, (uint16_t)cnt);
        memcpy(f.p(), &p_new[(size_t)first * CELL_RAW], (size_t)cnt * CELL_RAW);
        frame_send(f);
        if (nack) ++g_resent;
    }
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
    DES_LOG("  SPLIT — plant board (private key, events, decisions)\n");
    DES_LOG("============================================\n");
    DES_LOG("  supervisor  : monolithic, %s: %d states, %d events (%d controllable),"
            " %d distinct controllable rows\n", DES_DATA_HEADER, NS,
            EVENT_COUNT, __builtin_popcountll(g_ctrl), (int)g_rows.size());
    DES_LOG("  trace       : %d of %d steps; decisions %s (%d steps checked, %d failed)\n",
            (int)p_steps, (int)SIM_SEQ_LEN, p_fail ? "FAIL" : "PASS", p_pass + p_fail, p_fail);
    if (p_steps) {
        double n = (double)p_steps;
        DES_LOG("  per step    : %.1f ms on average\n", sum_total / 1000.0 / n);
        DES_LOG("     candidates (supervisor + link) %.1f | re-randomize %.1f, of it drawing"
                " Enc(0) %.1f | decisions (supervisor + link) %.1f | zero tests %.1f  (ms)\n",
                sum_cand / 1000.0 / n, sum_rr / 1000.0 / n, sum_gen / 1000.0 / n,
                sum_dec / 1000.0 / n, sum_zt / 1000.0 / n);
        DES_LOG("  With Enc(0) precomputed offline: Avg %.1f ms per step\n",
                (sum_total - sum_gen) / 1000.0 / n);
    }
    DES_LOG("  frames      : %u sent, %u received, %u resent, %u NACKs sent, "
            "%u failed authentication\n", (unsigned)g_tx, (unsigned)g_rx,
            (unsigned)g_resent, (unsigned)g_nacks, (unsigned)g_auth_bad);
    DES_LOG("============================================\n");
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
    p_sel.assign((size_t)NS * CELL_CMP, 0); p_has.assign(NS, 0);
    p_rx.reset(T_CAND, p_k);
    p_phase = P_CAND;
    p_t0 = des_micros();
    send_simple(T_STEP, p_k);
    p_t_send = p_t_progress = des_millis();
}

static void rerandomize_and_send() {
    uint64_t t0 = des_micros();
    p_tc = t0 - p_t0;
    p_tg = 0;
    p_new.assign((size_t)NS * CELL_RAW, 0);
    for (int q = 0; q < NS; ++q) {
        uint64_t g = 0;
        int ret = cr_rerandomize(p_has[q] ? &p_sel[(size_t)q * CELL_CMP] : nullptr,
                                 &p_new[(size_t)q * CELL_RAW], &g);
        if (ret) { halt("re-randomization failed"); return; }
        p_tg += g;
        DES_YIELD();
    }
    p_tr = des_micros() - t0;
    p_phase = P_DECS;
    p_rx.reset(T_DECS, p_k);
    p_decs.clear();
    send_newst(nullptr);
    p_t_send = p_t_progress = des_millis();
    p_td = des_micros();
}

static void decide() {
    uint64_t t0 = des_micros();
    p_td = t0 - p_td;
    for (int e = 0; e < EVENT_COUNT; ++e) p_dec[e] = 1;
    for (int g = 0; g < p_ndecs; ++g) {
        uint64_t mask; memcpy(&mask, &p_decs[(size_t)g * DECS_ITEM], 8);
        int bit = cr_zero_test(&p_decs[(size_t)g * DECS_ITEM + 8]);
        if (bit < 0) { halt("zero test failed"); return; }
        for (int e = 0; e < EVENT_COUNT; ++e) if ((mask >> e) & 1) p_dec[e] = (int8_t)bit;
    }
    p_tz = des_micros() - t0;

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
        DES_LOG("  Time: %.1f ms  (candidates %.1f | re-randomize %.1f, Enc(0) %.1f | "
                "decisions %.1f | zero tests %.1f)  %s\n", total / 1000.0, p_tc / 1000.0,
                p_tr / 1000.0, p_tg / 1000.0, p_td / 1000.0, p_tz / 1000.0, ok ? "OK" : "MISMATCH");
        sum_total += total; sum_cand += p_tc; sum_rr += p_tr; sum_gen += p_tg; sum_dec += p_td; sum_zt += p_tz;
        ++p_steps;
        // The FASTEST time: a slow step (a resend) must not stretch the next wait.
        if (p_min_dec_ms == 0 || p_td / 1000 < p_min_dec_ms) p_min_dec_ms = (uint32_t)(p_td / 1000);
    } else {
        DES_LOG("  %s\n", ok ? "OK" : "MISMATCH");
    }
    next_step();
}

static void handle(const Frame& f) {
    const SplitHdr* h = f.h();
    if (h->type == T_READY) {
        if (p_phase != P_KEY || h->peer != g_epoch) return;
        g_peer_epoch = h->epoch;
        DES_LOG("[split] supervisor %08x ready; it encrypted the initial state\n",
                (unsigned)g_peer_epoch);
        p_k = 0; p_phase = P_DECS; p_rx.reset(T_DECS, 0); p_decs.clear();
        p_t_send = p_t_progress = des_millis(); p_td = des_micros();
        return;
    }
    if (g_peer_epoch == 0 || h->peer != g_epoch) return;
    if (h->epoch != g_peer_epoch) { halt("the supervisor board restarted: RESET both boards"); return; }

    switch (h->type) {
    case T_CAND:
        if (p_phase != P_CAND || h->seq != p_k || !p_rx.mark(h)) return;
        p_t_progress = des_millis();
        // Every candidate is received; only the event's own cells are kept.
        for (int i = 0; i < h->count; ++i) {
            const uint8_t* it = f.p() + i * CAND_ITEM;
            uint16_t to; memcpy(&to, it + 1, 2);
            if (it[0] == p_ev && to < NS) {
                memcpy(&p_sel[(size_t)to * CELL_CMP], it + 3, CELL_CMP);
                p_has[to] = 1;
            }
        }
        if (p_rx.complete()) rerandomize_and_send();
        break;
    case T_NACK:
        if (f.p()[0] == T_NEWST && h->seq == p_k && p_phase == P_DECS) send_newst(&f);
        break;
    case T_DECS:
        if (p_phase != P_DECS || h->seq != p_k || !p_rx.mark(h)) return;
        p_t_progress = des_millis();
        if (p_decs.empty()) { p_decs.assign((size_t)h->nchunks * DECS_PER * DECS_ITEM, 0); p_ndecs = 0; }
        memcpy(&p_decs[(size_t)h->chunk * DECS_PER * DECS_ITEM], f.p(), (size_t)h->count * DECS_ITEM);
        if (h->chunk * DECS_PER + h->count > p_ndecs) p_ndecs = h->chunk * DECS_PER + h->count;
        if (p_rx.complete()) decide();
        break;
    }
}

static void split_setup() {
    build_tables();
    cr_init("des_split_plant");
    g_epoch = cr_random32() | 1;
    if (cr_keygen(p_Y)) { halt("key generation failed"); return; }
    // Self-test: the key and the zero test.
    uint8_t c0[CELL_RAW], c1[CELL_RAW];
    cr_set_pub(p_Y);
    if (cr_enc(0, c0) || cr_enc(1, c1) || cr_zero_test(c0) != 0 || cr_zero_test(c1) != 1) {
        halt("self-test failed"); return;
    }
    if (!DES_TRANSPORT_IMPL.begin()) { halt("network down"); return; }
    p_oracle = 0;
    for (int q = 0; q < NS; ++q) if (pm_i8(MONO_SUP.init, q)) p_oracle = q;
    DES_LOG("[split] PLANT board, epoch %08x, config %08x: %d states, %d events, "
            "%d candidate cells and %d decision sums per step\n", (unsigned)g_epoch,
            (unsigned)g_cfg, NS, EVENT_COUNT, (int)g_cand.size(), (int)g_rows.size());
    DES_LOG("[split] waiting for the supervisor board...\n");
    p_t_send = des_millis();
    send_simple(T_KEY, 0, p_Y, PT_CMP);
}

static void split_loop() {
    if (g_halt || g_done) { drain(); return; }
    drain();
    uint32_t now = des_millis();
    switch (p_phase) {
    case P_KEY:
        if (now - p_t_send > 500) { send_simple(T_KEY, 0, p_Y, PT_CMP); p_t_send = now; }
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
    }
    if (p_phase != P_KEY && now - p_t_progress > 120000) halt("no progress for 2 minutes");
}

// =============================================================================
// 5. The supervisor board: tables, encrypted state, public key only
// =============================================================================
#else

enum SPhase { S_KEY, S_IDLE, S_NEWST };
static SPhase   s_phase = S_KEY;
static uint32_t s_k = 0;
static std::vector<uint8_t> s_c, s_next;       // the encrypted state, raw cells
static std::vector<uint8_t> s_decs;            // DECS(s_k), cached for resends
static RxSet    s_rx;
static uint32_t s_t_cand = 0, s_t_ready = 0;
static uint64_t s_cand_us = 0, s_dec_us = 0;
static uint32_t s_steps = 0;

static int cand_chunks() { return ((int)g_cand.size() + CAND_PER - 1) / CAND_PER; }

// Builds frame c of CAND(s_k) from the current state: always the same work.
static void send_cand(const Frame* nack) {
    int nch = cand_chunks();
    uint64_t t0 = des_micros();
    for (int c = 0; c < nch; ++c) {
        if (nack && !nack_wants(*nack, c)) continue;
        int first = c * CAND_PER, cnt = (int)g_cand.size() - first;
        if (cnt > CAND_PER) cnt = CAND_PER;
        Frame& f = g_txf; frame_init(f, T_CAND, s_k, (uint16_t)c, (uint16_t)nch, (uint16_t)cnt);
        for (int i = 0; i < cnt; ++i) {
            const CandEntry& en = g_cand[first + i];
            uint8_t* it = f.p() + i * CAND_ITEM;
            it[0] = en.ev; memcpy(it + 1, &en.to, 2);
            if (en.nsrc == 1) {
                cell_compress(&s_c[(size_t)g_cand_src[en.src0] * CELL_RAW], it + 3);
            } else {
                std::vector<const uint8_t*> v;
                for (int j = 0; j < en.nsrc; ++j) v.push_back(&s_c[(size_t)g_cand_src[en.src0 + j] * CELL_RAW]);
                uint8_t sum[CELL_RAW];
                if (cr_sum(v.data(), (int)v.size(), sum)) { halt("candidate sum failed"); return; }
                cell_compress(sum, it + 3);
            }
        }
        frame_send(f);
        if (nack) ++g_resent;
    }
    if (!nack) s_cand_us += des_micros() - t0;
}

// d_c = R c: one sum per distinct controllable row, all its cells included.
static void compute_decs() {
    uint64_t t0 = des_micros();
    s_decs.assign(g_rows.size() * DECS_ITEM, 0);
    for (size_t g = 0; g < g_rows.size(); ++g) {
        std::vector<const uint8_t*> v;
        for (uint16_t q : g_rows[g].cells) v.push_back(&s_c[(size_t)q * CELL_RAW]);
        memcpy(&s_decs[g * DECS_ITEM], &g_rows[g].evmask, 8);
        if (cr_sum(v.data(), (int)v.size(), &s_decs[g * DECS_ITEM + 8])) { halt("row sum failed"); return; }
    }
    if (s_k > 0) s_dec_us += des_micros() - t0;
}
static void send_decs(const Frame* nack) {
    int total = (int)g_rows.size(), nch = (total + DECS_PER - 1) / DECS_PER;
    if (nch == 0) nch = 1;
    for (int c = 0; c < nch; ++c) {
        if (nack && !nack_wants(*nack, c)) continue;
        int first = c * DECS_PER, cnt = total - first < DECS_PER ? total - first : DECS_PER;
        Frame& f = g_txf; frame_init(f, T_DECS, s_k, (uint16_t)c, (uint16_t)nch, (uint16_t)cnt);
        memcpy(f.p(), &s_decs[(size_t)first * DECS_ITEM], (size_t)cnt * DECS_ITEM);
        frame_send(f);
        if (nack) ++g_resent;
    }
}

static void print_summary() {
    DES_LOG("\n============================================\n");
    DES_LOG("  SPLIT — supervisor board (public key only)\n");
    DES_LOG("============================================\n");
    DES_LOG("  supervisor  : monolithic, %d states; %d candidate cells (%d frames) and %d"
            " decision sums per step\n", NS, (int)g_cand.size(), cand_chunks(), (int)g_rows.size());
    DES_LOG("  steps       : %u; never saw an event, a decision or the private key\n", (unsigned)s_steps);
    if (s_steps)
        DES_LOG("  per step    : candidates %.1f ms, decision sums %.1f ms\n",
                s_cand_us / 1000.0 / s_steps, s_dec_us / 1000.0 / s_steps);
    DES_LOG("  frames      : %u sent, %u received, %u resent, %u NACKs sent, "
            "%u failed authentication\n", (unsigned)g_tx, (unsigned)g_rx,
            (unsigned)g_resent, (unsigned)g_nacks, (unsigned)g_auth_bad);
    DES_LOG("============================================\n");
}

static void handle(const Frame& f) {
    const SplitHdr* h = f.h();
    if (h->type == T_KEY) {
        if (s_phase != S_KEY && h->epoch != g_peer_epoch) {
            static bool said = false;
            if (!said) DES_LOG("[!!] the plant board restarted; RESET both boards\n");
            said = true;
            return;
        }
        if (s_phase == S_KEY) {
            if (cr_set_pub(f.p())) { DES_LOG("[!!] invalid public key\n"); return; }
            g_peer_epoch = h->epoch;
            DES_LOG("[split] plant %08x: public key received; encrypting the initial state"
                    " (%d cells)...\n", (unsigned)g_peer_epoch, NS);
            uint64_t t0 = des_micros();
            s_c.assign((size_t)NS * CELL_RAW, 0);
            for (int q = 0; q < NS; ++q) {
                if (cr_enc(pm_i8(MONO_SUP.init, q), &s_c[(size_t)q * CELL_RAW])) { halt("encryption failed"); return; }
                DES_YIELD();
            }
            DES_LOG("[split] encrypted in %.1f ms; boot decisions\n", (des_micros() - t0) / 1000.0);
            s_k = 0;
            compute_decs();
            s_phase = S_IDLE;
        }
        // Duplicate KEYs pile up while the state is being encrypted: answer
        // at most twice a second.
        if (des_millis() - s_t_ready < 500 && s_t_ready) return;
        s_t_ready = des_millis();
        Frame& r = g_txf; frame_init(r, T_READY, 0, 0, 1, 0); frame_send(r);
        if (s_k == 0) send_decs(nullptr);
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
            s_k = h->seq;
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
        else if (f.p()[0] == T_DECS && s_phase == S_IDLE) send_decs(&f);
        else if (f.p()[0] == T_DECS && s_phase == S_NEWST) send_nack(s_rx);
        break;
    case T_NEWST:
        if (s_phase != S_NEWST || h->seq != s_k || !s_rx.mark(h)) return;
        if (s_next.empty()) s_next.assign((size_t)NS * CELL_RAW, 0);
        memcpy(&s_next[(size_t)h->chunk * NEWST_PER * CELL_RAW], f.p(), (size_t)h->count * CELL_RAW);
        if (s_rx.complete()) {
            s_c.swap(s_next);
            ++s_steps;
            compute_decs();
            s_phase = S_IDLE;
            send_decs(nullptr);
            if (s_steps % 10 == 0) DES_LOG("[split] %u steps\n", (unsigned)s_steps);
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
    if (!DES_TRANSPORT_IMPL.begin()) { halt("network down"); return; }
    DES_LOG("[split] SUPERVISOR board, epoch %08x, config %08x: %d states, %d events, "
            "%d candidate cells and %d decision sums per step\n", (unsigned)g_epoch,
            (unsigned)g_cfg, NS, EVENT_COUNT, (int)g_cand.size(), (int)g_rows.size());
    DES_LOG("[split] waiting for the plant board's public key...\n");
}

static void split_loop() {
    drain();
    if (g_halt || g_done) return;
    if (s_phase == S_NEWST && s_rx.have > 0 && des_millis() - s_rx.t_last > 300 &&
        des_millis() - s_t_cand > 300) {
        send_nack(s_rx); s_t_cand = des_millis();
    }
}

#endif  // DES_ROLE
