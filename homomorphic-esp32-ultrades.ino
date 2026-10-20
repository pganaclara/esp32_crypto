// =============================================================================
// ESP32 Homomorphic DES — privacy-preserving supervisor evaluation
// =============================================================================
//
// Runs a Discrete Event System supervisor on an ESP32 with the plant state
// held only as EC-ElGamal ciphertexts. Each step:
//
//   1. apply the fired event's transitions to the encrypted state vector and
//      add a fresh encryption of zero to every cell of the supervisors that moved
//   2. homomorphically OR the enabled cells of every controllable event's row
//   3. decrypt only the resulting bit (one per distinct row) to get enablement
//
// The state is never decrypted, and no decision is kept from one step to the
// next.
//
// ── HOW TO RUN ───────────────────────────────────────────────────────────────
//   1. Drop  supervisor_data_<PROBLEM>.h  into this folder
//   2. Update the #include below to match your .h file
//   3. Flash, open Serial Monitor at 115200 baud
//
//   No sdkconfig file is needed: the Arduino core's precompiled mbedTLS already
//   has hardware MPI and NIST fast reduction enabled.
//
// ── HOW TO USE WITH A NEW DES PROBLEM ────────────────────────────────────────
//   The companion notebook (notebook/generator_ultrades.ipynb) holds
//   the plant and specification definitions. Pick a PROBLEM in Cell 3, define
//   plants/specs in Cell 4 (copy one of the existing problems as a template),
//   run the notebook, then copy the generated .h next to this sketch.
//
// ── SECURITY NOTES ───────────────────────────────────────────────────────────
//   The crypto is real EC-ElGamal on NIST P-192 (~96-bit security level).
//   Scalar blinding is always on — every decryption uses mbedtls_ecp_mul with
//   a per-core DRBG callback, closing the timing/power side-channel on the
//   private key. Measured cost is below 1 % on the ESP32-S3 hardware-MPI path.
//
//   After every transition, each cell of the supervisor that moved gets a fresh
//   encryption of zero, so every cell always carries fresh randomness: a memory
//   snapshot shows neither the active state nor, compared with an earlier one,
//   where it moved. Nothing decrypted is stored: the decisions are recomputed
//   at every step and only returned. The private key, however, is on this same
//   board; des_split/ keeps it, the events and the decisions on the plant's.
//
// Tested with Arduino ESP32 core v3.x on ESP32-WROOM-32 and ESP32-S3.
// =============================================================================
//
// ── ARCHITECTURE (skip if you just want to run it) ───────────────────────────
//
// A step (he_step) runs in three phases:
//
//   PHASE 1 (main core, serial) — transitions
//     For each supervisor whose trans_event_mask contains this event:
//       a. do_transition() moves the cells (the image of the state set) and
//          the persistent decompressed-point cache in lock-step;
//       b. rerandomize() adds a fresh encryption of zero to every cell.
//
//   PHASE 2 (both cores, parallel) — decrypt the work units
//     One unit per DISTINCT controllable row of EVERY supervisor: no value is
//     kept from the previous step. dispatch_parallel splits the list in half;
//     the main core handles the first half, a persistent worker task on core 0
//     (woken by semaphore) the other. Both call row_decrypt().
//
//   PHASE 3 (main core, serial) — emit en_out
//     An event is disabled iff some unit covering it decrypted to 0.
//
// Four optimisations, none of which depends on the state or on a decision:
//
//   1. Persistent decompressed cache — never run pt_decompress in the hot path
//   2. Rows of uncontrollable events are not computed: they are never disabled
//   3. Equal rows are summed and decrypted once; a row with no enabled state is
//      decided from the table
//   4. Dual-core work-unit split — phase 2 splits cleanly across both cores
// =============================================================================

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <pgmspace.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <vector>

#include "supervisor_data_fms.h"

// =============================================================================
// Configuration
// =============================================================================

// NIST P-192. 96-bit security (well above any feasible attack) and benefits
// from mbedTLS's NIST fast-reduction path + ESP32 hardware MPI.
#define CURVE        MBEDTLS_ECP_DP_SECP192R1
#define CURVE_NAME   "secp192r1"
#define PT_LEN       25                          // 1 prefix + 24-byte X coord
#define CORE_MAIN    1
#define CORE_WORKER  0
#define WORKER_STACK 12288
#define WORKER_PRIO  2                            // above IDLE(0), below system tasks

// ── Security ────────────────────────────────────────────────────────────────
//
// Generating the encryptions of zero is timed apart from adding them: a pool
// precomputed offline would take the generation out of the step.
//
// Scalar blinding on decrypt is always on. mbedtls_ecp_mul is called with a
// DRBG callback so the timing/power profile of the scalar mul does not leak
// bits of the private key (paper: Brumley/Tuveri 2011, "Remote Timing
// Attacks Are Still Practical"). Each core has its own DRBG context because
// mbedTLS CTR-DRBG is not thread-safe. Measured overhead vs. unblinded fused
// muladd: < 1 % — effectively free on the ESP32 hardware-MPI path.

// =============================================================================
// Types
// =============================================================================

struct Ciphertext { uint8_t c1[PT_LEN]; uint8_t c2[PT_LEN]; };

static_assert(EVENT_COUNT <= 32, "the event masks are 32-bit");

// The controllable events of one supervisor whose rows of the enable matrix are
// equal: one sum and one decryption decide all of them (optimisation 3).
struct RowGroup {
    uint32_t events;      // bit gi: event gi has this row
    uint8_t  rep;         // one of them, whose row is summed
    bool     any;         // the row has an enabled state (else: disabled, no sum)
};

struct Supervisor {
    const SupDesc* desc;
    uint32_t       trans_event_mask  = 0;            // events this sv transitions on

    std::vector<RowGroup>          groups;           // rows of its controllable events
    std::vector<Ciphertext>        enc;             // compressed state vector
    std::vector<mbedtls_ecp_point> dec_c1, dec_c2;  // decompressed mirror of enc[]
};

// One decrypt task: group `grp` of supervisor `sv`.
struct WorkUnit { uint8_t sv; uint8_t grp; int8_t out; };

struct WorkerCmd {
    int start, end;
    std::vector<WorkUnit>* work;
};

// =============================================================================
// Globals
// =============================================================================

static std::vector<Supervisor>  g_sups;
static mbedtls_ecp_group        g_grp;
static mbedtls_ecp_point        g_G, g_pub;
static mbedtls_mpi              g_priv, g_one;
static mbedtls_mpi              g_neg_priv;             // N - priv, computed once
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_entropy_context  g_entropy;
// Second DRBG context for the worker core — CTR-DRBG is not thread-safe, so
// blinded scalar mul needs one DRBG per core to be callable from both cores
// concurrently.
static mbedtls_ctr_drbg_context g_drbg_core0;
static mbedtls_entropy_context  g_entropy_core0;
static bool                     g_dual_core = false;
static int                      g_step_decrypts = 0;
static portMUX_TYPE             g_dec_mux = portMUX_INITIALIZER_UNLOCKED;
static uint64_t                 g_gen_us  = 0;           // generating Enc(0)
static uint64_t                 g_add_us  = 0;           // adding them in
static uint32_t                 g_rr_cells = 0;          // cells re-randomized
static uint32_t                 g_ctrl = 0;              // bit gi: event gi controllable

// IPC for the persistent worker on core 0
static WorkerCmd          g_wcmd;
static SemaphoreHandle_t  g_worker_go   = nullptr;
static SemaphoreHandle_t  g_worker_done = nullptr;

// =============================================================================
// Small helpers
// =============================================================================

inline int8_t   pm_i8 (const int8_t*   a, int i) { return (int8_t) pgm_read_byte(a+i); }
inline int16_t  pm_i16(const int16_t*  a, int i) { return (int16_t)pgm_read_word(a+i); }
inline uint16_t pm_u16(const uint16_t* a, int i) { return (uint16_t)pgm_read_word(a+i); }

// The header does not say which events are controllable; the event labels do,
// with the convention of the generators (as in des_distributed and des_split):
// 'a…' controllable, 'b…' not, otherwise an odd trailing digit is controllable.
static bool derive_controllable(int gi) {
    char nm[16];
    strncpy_P(nm, (const char*)pgm_read_ptr(&EVENT_NAMES[gi]), 15);
    nm[15] = 0;
    if (nm[0] == 'a') return true;
    if (nm[0] == 'b') return false;
    int last = -1;
    for (int i = 0; nm[i]; ++i) if (nm[i] >= '0' && nm[i] <= '9') last = nm[i] - '0';
    return last >= 0 ? (last & 1) != 0 : true;
}

// Offset (in (from,to) pairs) of event `ev`'s transitions in desc->trans.
static int trans_offset(const SupDesc* desc, int ev) {
    int off = 0;
    for (int i = 0; i < ev; ++i) off += (int)pm_u16(desc->tcnt, i);
    return off;
}

// Shallow swap of two ecp_point structs — avoids the MPI deep-copy that
// mbedtls_ecp_copy() would do.
static inline void swap_pt(mbedtls_ecp_point* a, mbedtls_ecp_point* b) {
    mbedtls_ecp_point t = *a; *a = *b; *b = t;
}

// Free the MPI memory held by a Supervisor's decompressed point cache.
static void sv_free_dec(Supervisor& sv) {
    for (auto& p : sv.dec_c1) mbedtls_ecp_point_free(&p);
    for (auto& p : sv.dec_c2) mbedtls_ecp_point_free(&p);
    sv.dec_c1.clear();
    sv.dec_c2.clear();
}

// =============================================================================
// EC point I/O
// =============================================================================

static int pt_compress(const mbedtls_ecp_point* P, uint8_t out[PT_LEN]) {
    size_t len = 0;
    return mbedtls_ecp_point_write_binary(
        &g_grp, P, MBEDTLS_ECP_PF_COMPRESSED, &len, out, PT_LEN);
}

static int pt_decompress(const uint8_t in[PT_LEN], mbedtls_ecp_point* P) {
    mbedtls_ecp_point_init(P);
    return mbedtls_ecp_point_read_binary(&g_grp, P, in, PT_LEN);
}

// R = P + Q  (used by self-test only)
static int pt_add(mbedtls_ecp_point* R,
                  const mbedtls_ecp_point* P, const mbedtls_ecp_point* Q) {
    return mbedtls_ecp_muladd(&g_grp, R, &g_one, P, &g_one, Q);
}

// =============================================================================
// EC-ElGamal primitives (used in init and self-test)
// =============================================================================

static int elgamal_enc(int m, Ciphertext* ct, mbedtls_ctr_drbg_context* drbg) {
    mbedtls_mpi r;        mbedtls_mpi_init(&r);
    mbedtls_ecp_point rP, c1, c2;
    mbedtls_ecp_point_init(&rP);
    mbedtls_ecp_point_init(&c1);
    mbedtls_ecp_point_init(&c2);

    int ret = mbedtls_ecp_gen_privkey(&g_grp, &r, mbedtls_ctr_drbg_random, drbg);
    if (ret) goto done;
    ret = mbedtls_ecp_mul(&g_grp, &c1, &r, &g_G,   mbedtls_ctr_drbg_random, drbg);
    if (ret) goto done;
    ret = mbedtls_ecp_mul(&g_grp, &rP, &r, &g_pub, mbedtls_ctr_drbg_random, drbg);
    if (ret) goto done;

    if (m == 0) {
        mbedtls_ecp_copy(&c2, &rP);
    } else {
        mbedtls_ecp_point mG; mbedtls_mpi mm;
        mbedtls_ecp_point_init(&mG); mbedtls_mpi_init(&mm);
        mbedtls_mpi_lset(&mm, m);
        ret = mbedtls_ecp_mul(&g_grp, &mG, &mm, &g_G, mbedtls_ctr_drbg_random, drbg);
        if (ret == 0) ret = pt_add(&c2, &mG, &rP);
        mbedtls_ecp_point_free(&mG); mbedtls_mpi_free(&mm);
    }
    if (ret) goto done;
    ret = pt_compress(&c1, ct->c1);
    if (ret == 0) ret = pt_compress(&c2, ct->c2);

done:
    mbedtls_ecp_point_free(&rP);
    mbedtls_ecp_point_free(&c1);
    mbedtls_ecp_point_free(&c2);
    mbedtls_mpi_free(&r);
    return ret;
}

// Reference decrypt — used by self-test. The hot path uses row_decrypt below.
static int elgamal_dec(const Ciphertext* ct, int* out) {
    mbedtls_ecp_point c1, c2, pm;
    mbedtls_ecp_point_init(&c1);          // init ALL points up-front so the
    mbedtls_ecp_point_init(&c2);          // cleanup at `done:` is always safe
    mbedtls_ecp_point_init(&pm);          // even on an early pt_decompress error

    int ret = pt_decompress(ct->c1, &c1); if (ret) goto done;
    ret     = pt_decompress(ct->c2, &c2); if (ret) goto done;
    ret = mbedtls_ecp_muladd(&g_grp, &pm, &g_neg_priv, &c1, &g_one, &c2);
    if (ret == 0) *out = mbedtls_ecp_is_zero(&pm) ? 0 : 1;

done:
    mbedtls_ecp_point_free(&c1);
    mbedtls_ecp_point_free(&c2);
    mbedtls_ecp_point_free(&pm);
    return ret;
}

// Homomorphic ciphertext addition — used by self-test.
static int elgamal_add(const Ciphertext* a, const Ciphertext* b, Ciphertext* out) {
    mbedtls_ecp_point pa1, pa2, pb1, pb2, r1, r2;
    mbedtls_ecp_point_init(&pa1);         // init all six up-front so the
    mbedtls_ecp_point_init(&pa2);         // cleanup goto is safe regardless
    mbedtls_ecp_point_init(&pb1);         // of where pt_decompress fails
    mbedtls_ecp_point_init(&pb2);
    mbedtls_ecp_point_init(&r1);
    mbedtls_ecp_point_init(&r2);

    int ret = pt_decompress(a->c1, &pa1); if (ret) goto done;
    ret     = pt_decompress(a->c2, &pa2); if (ret) goto done;
    ret     = pt_decompress(b->c1, &pb1); if (ret) goto done;
    ret     = pt_decompress(b->c2, &pb2); if (ret) goto done;
    ret = pt_add(&r1, &pa1, &pb1); if (ret) goto done;
    ret = pt_add(&r2, &pa2, &pb2); if (ret) goto done;
    ret = pt_compress(&r1, out->c1);
    if (ret == 0) ret = pt_compress(&r2, out->c2);

done:
    mbedtls_ecp_point_free(&pa1); mbedtls_ecp_point_free(&pa2);
    mbedtls_ecp_point_free(&pb1); mbedtls_ecp_point_free(&pb2);
    mbedtls_ecp_point_free(&r1);  mbedtls_ecp_point_free(&r2);
    return ret;
}

// =============================================================================
// Hot path: row sum + decrypt
// =============================================================================

// Homomorphically ORs ALL the enabled cells of the row, whatever they encrypt,
// then decrypts the sum, all on the persistent decompressed cache so no point
// decompression happens here. Returns:
//   *out         : 0 or 1
//   *did_decrypt : false if the row has no enabled state (decided by the table)
static int row_decrypt(const Supervisor& sv, const int8_t* row, int n,
                       int* out, bool* did_decrypt) {
    *did_decrypt = false;

    int first = -1;
    for (int i = 0; i < n; ++i)
        if (pm_i8(row, i)) { first = i; break; }
    if (first < 0) { *out = 0; return 0; }

    mbedtls_ecp_point s1, s2, tmp;
    mbedtls_ecp_point_init(&s1);
    mbedtls_ecp_point_init(&s2);
    mbedtls_ecp_point_init(&tmp);

    int ret = mbedtls_ecp_copy(&s1, &sv.dec_c1[first]); if (ret) goto done;
    ret     = mbedtls_ecp_copy(&s2, &sv.dec_c2[first]); if (ret) goto done;

    for (int i = first + 1; i < n; ++i) {
        if (!pm_i8(row, i))           continue;

        ret = mbedtls_ecp_muladd(&g_grp, &tmp, &g_one, &s1, &g_one, &sv.dec_c1[i]);
        if (ret) goto done;
        swap_pt(&s1, &tmp);
        ret = mbedtls_ecp_muladd(&g_grp, &tmp, &g_one, &s2, &g_one, &sv.dec_c2[i]);
        if (ret) goto done;
        swap_pt(&s2, &tmp);
    }

    // Compute pm = (N-priv)*s1 + 1*s2 and check if it's the point at infinity.
    // The scalar mul uses mbedtls_ecp_mul with a DRBG callback, which applies
    // scalar blinding so the timing/power profile doesn't leak bits of priv.
    // Each core uses its own DRBG (CTR-DRBG is not thread-safe).
    {
        mbedtls_ecp_point ns, pm;
        mbedtls_ecp_point_init(&ns);
        mbedtls_ecp_point_init(&pm);
        mbedtls_ctr_drbg_context* drbg =
            (xPortGetCoreID() == CORE_WORKER) ? &g_drbg_core0 : &g_drbg;
        ret = mbedtls_ecp_mul(&g_grp, &ns, &g_neg_priv, &s1,
                              mbedtls_ctr_drbg_random, drbg);
        if (ret == 0)
            ret = mbedtls_ecp_muladd(&g_grp, &pm, &g_one, &s2, &g_one, &ns);
        if (ret == 0) {
            *out = mbedtls_ecp_is_zero(&pm) ? 0 : 1;
            *did_decrypt = true;
        }
        mbedtls_ecp_point_free(&ns);
        mbedtls_ecp_point_free(&pm);
    }

done:
    mbedtls_ecp_point_free(&s1);
    mbedtls_ecp_point_free(&s2);
    mbedtls_ecp_point_free(&tmp);
    return ret;
}

// Apply event ev_gi's transitions to sv. Updates both the compressed
// ciphertext array and the persistent decompressed cache in lock-step. A cell
// that no state reaches is left empty — the point at infinity in the cache —
// and rerandomize() then makes it a fresh encryption of zero.
static void do_transition(Supervisor& sv, int ev_gi, int n) {
    int      off = trans_offset(sv.desc, ev_gi);
    uint16_t pc  = pm_u16(sv.desc->tcnt, ev_gi);

    std::vector<Ciphertext>        nxt(n);
    std::vector<uint8_t>           filled(n, 0);
    std::vector<mbedtls_ecp_point> nxt_c1(n), nxt_c2(n);
    for (int i = 0; i < n; ++i) {
        mbedtls_ecp_point_init(&nxt_c1[i]);
        mbedtls_ecp_point_init(&nxt_c2[i]);
    }

    // The image of a state set under an event is a UNION, not an assignment.
    // Two source states may converge on the same target — supervisor_data_fms.h
    // has 11 such collisions in its reduced supervisors — and writing
    // `nxt[to] = enc[from]` unconditionally lets whichever pair the generator
    // emitted last win, so an INACTIVE source silently overwrites an ACTIVE one.
    // The result then depends on the order the pairs happen to sit in the .h,
    // which is not stable across regenerations (supervisor reduction relabels
    // states freely). Converging sources are therefore combined with the
    // additive homomorphism, which is the same OR used everywhere else.
    for (uint16_t p = 0; p < pc; ++p) {
        int from = pm_i16(sv.desc->trans + off * 2, p * 2);
        int to   = pm_i16(sv.desc->trans + off * 2, p * 2 + 1);
        if (!filled[to]) {
            filled[to] = 1;
            nxt[to] = sv.enc[from];
            // Deep-copy the already-decompressed point — far cheaper than
            // re-running pt_decompress on the target cell.
            mbedtls_ecp_copy(&nxt_c1[to], &sv.dec_c1[from]);
            mbedtls_ecp_copy(&nxt_c2[to], &sv.dec_c2[from]);
        } else {
            mbedtls_ecp_point s1, s2;
            mbedtls_ecp_point_init(&s1);
            mbedtls_ecp_point_init(&s2);
            if (pt_add(&s1, &nxt_c1[to], &sv.dec_c1[from]) == 0 &&
                pt_add(&s2, &nxt_c2[to], &sv.dec_c2[from]) == 0) {
                mbedtls_ecp_copy(&nxt_c1[to], &s1);
                mbedtls_ecp_copy(&nxt_c2[to], &s2);
                pt_compress(&nxt_c1[to], nxt[to].c1);
                pt_compress(&nxt_c2[to], nxt[to].c2);
            }
            mbedtls_ecp_point_free(&s1);
            mbedtls_ecp_point_free(&s2);
        }
    }

    sv_free_dec(sv);
    sv.enc    = std::move(nxt);
    sv.dec_c1 = std::move(nxt_c1);
    sv.dec_c2 = std::move(nxt_c2);
}

// Add a fresh encryption of zero, (rG, rY), to every cell of sv. The plaintexts
// do not change; every cell gets new randomness. A cell the transition left
// empty has the point at infinity as its decompressed mirror, which mbedTLS
// refuses to add, so it simply becomes (rG, rY). Returns an mbedTLS error code;
// a failure is reported, never skipped silently.
static int rerandomize(Supervisor& sv, int n) {
    mbedtls_mpi r;
    mbedtls_ecp_point z1, z2, s;
    mbedtls_mpi_init(&r);
    mbedtls_ecp_point_init(&z1); mbedtls_ecp_point_init(&z2); mbedtls_ecp_point_init(&s);
    int ret = 0;
    for (int i = 0; i < n && ret == 0; ++i) {
        yield();
        uint64_t t0 = (uint64_t)esp_timer_get_time();
        ret = mbedtls_ecp_gen_privkey(&g_grp, &r, mbedtls_ctr_drbg_random, &g_drbg);
        if (ret == 0) ret = mbedtls_ecp_mul(&g_grp, &z1, &r, &g_G,   mbedtls_ctr_drbg_random, &g_drbg);
        if (ret == 0) ret = mbedtls_ecp_mul(&g_grp, &z2, &r, &g_pub, mbedtls_ctr_drbg_random, &g_drbg);
        uint64_t t1 = (uint64_t)esp_timer_get_time();
        if (ret) break;
        if (mbedtls_ecp_is_zero(&sv.dec_c1[i])) {
            ret = mbedtls_ecp_copy(&sv.dec_c1[i], &z1);
            if (ret == 0) ret = mbedtls_ecp_copy(&sv.dec_c2[i], &z2);
        } else {
            ret = pt_add(&s, &sv.dec_c1[i], &z1);
            if (ret == 0) { swap_pt(&sv.dec_c1[i], &s); ret = pt_add(&s, &sv.dec_c2[i], &z2); }
            if (ret == 0) swap_pt(&sv.dec_c2[i], &s);
        }
        if (ret == 0) ret = pt_compress(&sv.dec_c1[i], sv.enc[i].c1);
        if (ret == 0) ret = pt_compress(&sv.dec_c2[i], sv.enc[i].c2);
        g_gen_us += t1 - t0;
        g_add_us += (uint64_t)esp_timer_get_time() - t1;
        if (ret == 0) ++g_rr_cells;
    }
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&z1); mbedtls_ecp_point_free(&z2); mbedtls_ecp_point_free(&s);
    return ret;
}

// =============================================================================
// Parallel decrypt engine
// =============================================================================

// Process work units [start, end). On the worker core we yield periodically
// so IDLE0 can feed the Task Watchdog. Each iteration is ~70 ms and the WDT
// timeout is 5 s, so yielding every 8 iterations leaves ample margin while
// avoiding a wasted 1 ms tick on every decrypt.
#define WORKER_YIELD_EVERY 8
static void process_work_range(int start, int end,
                                std::vector<WorkUnit>& work,
                                int* dec_count) {
    const bool worker_core = (xPortGetCoreID() == CORE_WORKER);
    for (int wi = start; wi < end; ++wi) {
        if (worker_core && (((wi - start) & (WORKER_YIELD_EVERY - 1)) == 0))
            vTaskDelay(pdMS_TO_TICKS(1));
        WorkUnit& w = work[wi];
        Supervisor& sv = g_sups[w.sv];
        int n  = (int)pgm_read_word(&sv.desc->num_states);
        int gi = sv.groups[w.grp].rep;

        int e = 0; bool did_decrypt = false;
        if (row_decrypt(sv, sv.desc->enable + gi * n, n, &e, &did_decrypt) != 0) continue;
        if (did_decrypt) (*dec_count)++;
        // he_step applies the result to every event of the group.
        w.out = (int8_t)e;
    }
}

static void persistent_worker_task(void*) {
    for (;;) {
        xSemaphoreTake(g_worker_go, portMAX_DELAY);
        int local_dec = 0;
        process_work_range(g_wcmd.start, g_wcmd.end, *g_wcmd.work, &local_dec);
        portENTER_CRITICAL(&g_dec_mux);
        g_step_decrypts += local_dec;
        portEXIT_CRITICAL(&g_dec_mux);
        xSemaphoreGive(g_worker_done);
    }
}

// Split work in half between the two cores, then join.
static void dispatch_parallel(std::vector<WorkUnit>& work) {
    if (work.empty()) return;

    if (g_dual_core) {
        int mid = (int)work.size() / 2;
        g_wcmd.start = mid;
        g_wcmd.end   = (int)work.size();
        g_wcmd.work  = &work;
        xSemaphoreGive(g_worker_go);

        int main_dec = 0;
        process_work_range(0, mid, work, &main_dec);
        g_step_decrypts += main_dec;

        xSemaphoreTake(g_worker_done, portMAX_DELAY);
    } else {
        int main_dec = 0;
        process_work_range(0, (int)work.size(), work, &main_dec);
        g_step_decrypts += main_dec;
    }
}

// =============================================================================
// Homomorphic step — the public per-event entry point
// =============================================================================
//
// Given a fired event (by global event index), updates every supervisor's
// encrypted state and produces the resulting enable bitmap.
//
//   en_out : output, sized to EVENT_COUNT. en_out[gi] = 0 iff some supervisor
//            currently disables event gi.
//   returns: 0 on success, mbedTLS error code otherwise.
//
// The step is internally split into three phases — see "ARCHITECTURE" at the
// top of this file.
static int he_step(int ev_gi, std::vector<int>& en_out) {
    en_out.assign(EVENT_COUNT, 1);

    // Phase 1 (main core, serial): the supervisors that move on this event
    // apply its transitions and get a fresh encryption of zero in every cell.
    for (size_t i = 0; i < g_sups.size(); ++i) {
        Supervisor& sv = g_sups[i];
        if (!(sv.trans_event_mask & (1u << ev_gi))) continue;
        int n = (int)pgm_read_word(&sv.desc->num_states);
        do_transition(sv, ev_gi, n);
        if (int err = rerandomize(sv, n)) return err;
    }

    // Phase 2: one unit per distinct controllable row of EVERY supervisor —
    // nothing is kept from the previous step, so the supervisors that did not
    // move are decided again too. A row with no enabled state needs no sum.
    static std::vector<WorkUnit> work;
    work.clear();
    for (size_t i = 0; i < g_sups.size(); ++i)
        for (size_t k = 0; k < g_sups[i].groups.size(); ++k)
            if (g_sups[i].groups[k].any) work.push_back({(uint8_t)i, (uint8_t)k, -1});
    dispatch_parallel(work);
    for (const WorkUnit& w : work)
        if (w.out < 0) return -1;                  // row_decrypt failed

    // Phase 3: an event is disabled iff some group that covers it is 0.
    for (const WorkUnit& w : work)
        if (w.out == 0)
            for (int gi = 0; gi < EVENT_COUNT; ++gi)
                if (g_sups[w.sv].groups[w.grp].events & (1u << gi)) en_out[gi] = 0;
    for (auto& sv : g_sups)
        for (const RowGroup& g : sv.groups)
            if (!g.any)
                for (int gi = 0; gi < EVENT_COUNT; ++gi)
                    if (g.events & (1u << gi)) en_out[gi] = 0;
    return 0;
}

// =============================================================================
// Supervisor loading
// =============================================================================
//
// One-time setup per benchmark. Reads the SupDesc descriptors from PROGMEM and
// groups, per supervisor, the controllable events whose rows of the enable
// matrix are equal. Only the tables are used: nothing here depends on the state.

static bool load_supervisors(const SupDesc* descs, int count) {
    g_sups.clear();
    g_sups.resize(count);

    for (int i = 0; i < count; ++i) {
        Supervisor& sv = g_sups[i];
        sv.desc = &descs[i];
        int n = (int)pgm_read_word(&descs[i].num_states);

        int rows = 0;
        for (int gi = 0; gi < EVENT_COUNT; ++gi) {
            if (pm_u16(descs[i].tcnt, gi) > 0) sv.trans_event_mask |= (1u << gi);
            if (!(g_ctrl & (1u << gi))) continue;      // uncontrollable: never disabled
            const int8_t* row = descs[i].enable + gi * n;
            bool zero = false, one = false;
            for (int s = 0; s < n; ++s) (pm_i8(row, s) ? one : zero) = true;
            if (!zero) continue;                       // enabled in every state
            ++rows;
            bool merged = false;
            for (RowGroup& g : sv.groups) {
                const int8_t* other = descs[i].enable + g.rep * n;
                bool same = true;
                for (int s = 0; s < n && same; ++s)
                    same = (pm_i8(row, s) != 0) == (pm_i8(other, s) != 0);
                if (same) { g.events |= (1u << gi); merged = true; break; }
            }
            if (!merged) sv.groups.push_back({1u << gi, (uint8_t)gi, one});
        }

        char name[16];
        strncpy_P(name, (const char*)pgm_read_ptr(&descs[i].name), 15);
        name[15] = 0;
        Serial.printf("[LOAD] %-14s  %3d states  %2d controllable rows, %2d distinct"
                      "  (%u bytes enc)\n", name, n, rows, (int)sv.groups.size(),
                      (unsigned)(n * sizeof(Ciphertext)));
    }
    return true;
}

// =============================================================================
// Initial encryption
// =============================================================================

static bool init_states() {
    Serial.printf("[MEM] Heap before encryption: %u bytes free\n",
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));

    for (size_t i = 0; i < g_sups.size(); ++i) {
        Supervisor& sv = g_sups[i];
        int n = (int)pgm_read_word(&sv.desc->num_states);

        sv.enc.resize(n);
        sv_free_dec(sv);
        sv.dec_c1.resize(n);
        sv.dec_c2.resize(n);
        for (int s = 0; s < n; ++s) {
            mbedtls_ecp_point_init(&sv.dec_c1[s]);
            mbedtls_ecp_point_init(&sv.dec_c2[s]);
        }

        char name[16];
        strncpy_P(name, (const char*)pgm_read_ptr(&sv.desc->name), 15);
        name[15] = 0;
        for (int s = 0; s < n; ++s) {
            yield();
            if (elgamal_enc((int)pm_i8(sv.desc->init, s), &sv.enc[s], &g_drbg) != 0) {
                Serial.printf("[ERROR] Encrypt failed: '%s' state %d\n", name, s);
                return false;
            }
            // Populate the persistent decompressed cache immediately.
            pt_decompress(sv.enc[s].c1, &sv.dec_c1[s]);
            pt_decompress(sv.enc[s].c2, &sv.dec_c2[s]);
        }
        Serial.printf("[ENC] '%s' OK  heap=%u\n", name,
                      (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
    }
    Serial.printf("[MEM] Heap after encryption: %u bytes free\n\n",
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
    return true;
}

// =============================================================================
// Oracle — cleartext reference for verification
// =============================================================================

struct Oracle {
    std::vector<std::vector<int>> st;

    void init(const SupDesc* descs, int count) {
        st.resize(count);
        for (int i = 0; i < count; ++i) {
            int n = (int)pgm_read_word(&descs[i].num_states);
            st[i].resize(n);
            for (int s = 0; s < n; ++s) st[i][s] = pm_i8(descs[i].init, s);
        }
    }

    std::vector<int> step(int ev_gi, const SupDesc* descs, int count) {
        std::vector<int> en(EVENT_COUNT, 1);
        for (int i = 0; i < count; ++i) {
            int n = (int)pgm_read_word(&descs[i].num_states);

            // Apply transitions
            uint16_t pc = pm_u16(descs[i].tcnt, ev_gi);
            if (pc > 0) {
                int off = trans_offset(&descs[i], ev_gi);
                std::vector<int> nxt(n, 0);
                // Union, not assignment — see the note in do_transition(). The
                // oracle MUST make the same correction: if it kept the bug it
                // would agree with a buggy homomorphic path, the comparison
                // below would pass, and the benchmark would certify nothing.
                for (uint16_t p = 0; p < pc; ++p) {
                    int from = pm_i16(descs[i].trans, (off + p) * 2);
                    int to   = pm_i16(descs[i].trans, (off + p) * 2 + 1);
                    nxt[to] |= st[i][from];
                }
                st[i] = nxt;
            }

            // Emit constraints: controllable events only, like the homomorphic path
            for (int gi = 0; gi < EVENT_COUNT; ++gi) {
                if (!(g_ctrl & (1u << gi))) continue;
                bool constrains = false;
                for (int s = 0; s < n && !constrains; ++s)
                    if (!pm_i8(descs[i].enable, gi * n + s)) constrains = true;
                if (!constrains) continue;
                bool enabled = false;
                for (int s = 0; s < n; ++s)
                    if (pm_i8(descs[i].enable, gi * n + s) && st[i][s]) { enabled = true; break; }
                if (!enabled) en[gi] = 0;
            }
        }
        return en;
    }
};

// =============================================================================
// Self-test
// =============================================================================

static bool run_selftest() {
    Serial.println("============================================");
    Serial.println("  SELF-TEST: EC-ElGamal crypto verification");
    Serial.println("============================================");
    bool ok = true;

    Ciphertext ct0, ct1;
    elgamal_enc(0, &ct0, &g_drbg);
    elgamal_enc(1, &ct1, &g_drbg);
    int d0 = -1, d1 = -1;
    elgamal_dec(&ct0, &d0);
    elgamal_dec(&ct1, &d1);
    bool t1 = (d0 == 0 && d1 == 1); ok &= t1;
    Serial.printf("  [1] Enc(0)->%d  Enc(1)->%d  %s\n", d0, d1, t1 ? "PASS" : "FAIL");

    Ciphertext cs; int ds = -1;
    elgamal_add(&ct1, &ct1, &cs); elgamal_dec(&cs, &ds);
    bool t2 = (ds == 1); ok &= t2;
    Serial.printf("  [2] Enc(1)+Enc(1)->%d  %s\n", ds, t2 ? "PASS" : "FAIL");

    elgamal_add(&ct0, &ct0, &cs); ds = -1; elgamal_dec(&cs, &ds);
    bool t3 = (ds == 0); ok &= t3;
    Serial.printf("  [3] Enc(0)+Enc(0)->%d  %s\n", ds, t3 ? "PASS" : "FAIL");

    Ciphertext ct1b; elgamal_enc(1, &ct1b, &g_drbg);
    bool t4 = (memcmp(ct1.c1, ct1b.c1, PT_LEN) != 0); ok &= t4;
    Serial.printf("  [4] Two Enc(1) have distinct c1: %s\n", t4 ? "PASS" : "FAIL");

    uint8_t buf[PT_LEN]; size_t len = 0;
    mbedtls_ecp_point_write_binary(&g_grp, &g_G, MBEDTLS_ECP_PF_COMPRESSED, &len, buf, PT_LEN);
    mbedtls_ecp_point P2; mbedtls_ecp_point_init(&P2);
    mbedtls_ecp_point_read_binary(&g_grp, &P2, buf, PT_LEN);
    bool t5 = (mbedtls_ecp_point_cmp(&P2, &g_G) == 0); ok &= t5;
    mbedtls_ecp_point_free(&P2);
    Serial.printf("  [5] Compress/decompress G: %s\n", t5 ? "PASS" : "FAIL");

    Serial.printf("  Curve: %s  |  CT size: %u bytes  |  Dual-core: %s\n",
                  CURVE_NAME, (unsigned)sizeof(Ciphertext), g_dual_core ? "YES" : "NO");
    Serial.printf("  Result: %s\n\n", ok ? "PASS" : "FAIL");
    return ok;
}

// =============================================================================
// Benchmark driver
// =============================================================================

static void print_vec(const std::vector<int>& v) {
    Serial.print("[");
    for (size_t i = 0; i < v.size(); ++i) { if (i) Serial.print(","); Serial.print(v[i]); }
    Serial.print("]");
}

static void run_benchmark(const char* label, const SupDesc* descs, int count) {
    Serial.println("============================================");
    Serial.printf("  BENCHMARK: %s\n", label);
    Serial.printf("  Cores used: %s\n",
                  (g_dual_core && count > 1) ? "BOTH (dual-core)" : "1 (single)");
    Serial.println("============================================");

    load_supervisors(descs, count);
    Serial.println();
    if (!init_states())  { Serial.println("[FATAL] Encryption failed."); while(true) delay(1000); }

    Oracle oracle; oracle.init(descs, count);
    uint64_t total_us = 0, min_us = UINT64_MAX, max_us = 0;
    int  total_dec = 0;
    g_gen_us = g_add_us = 0; g_rr_cells = 0;
    bool all_ok    = true;

    for (int step = 0; step < SIM_SEQ_LEN; ++step) {
        int ev_gi = (int)pm_u16(SIM_SEQ, step);
        char ev[16];
        strncpy_P(ev, (const char*)pgm_read_ptr(&EVENT_NAMES[ev_gi]), 15);
        ev[15] = 0;
        Serial.printf("-- Step %d | Event: %s --\n", step + 1, ev);

        std::vector<int> oracle_en = oracle.step(ev_gi, descs, count);
        std::vector<int> he_en;
        g_step_decrypts = 0;
        uint64_t gen0 = g_gen_us, add0 = g_add_us;
        uint64_t t0      = (uint64_t)esp_timer_get_time();
        int      ret     = he_step(ev_gi, he_en);
        uint64_t step_us = (uint64_t)esp_timer_get_time() - t0;

        total_us  += step_us;
        total_dec += g_step_decrypts;
        if (step_us < min_us) min_us = step_us;
        if (step_us > max_us) max_us = step_us;
        if (ret) { Serial.printf("  HE ERROR -0x%04X\n", -ret); all_ok = false; continue; }

        bool ok = (he_en == oracle_en);
        if (!ok) all_ok = false;
        Serial.print("  [Oracle] "); print_vec(oracle_en); Serial.println();
        Serial.print("  [HE]     "); print_vec(he_en);     Serial.println();
        Serial.printf("  Time: %.3f ms  |  Decrypts: %d  |  %s\n",
                      step_us / 1000.0, g_step_decrypts, ok ? "OK" : "FAIL");
        Serial.printf("  Re-randomization: generating Enc(0) %.3f ms, adding %.3f ms\n",
                      (g_gen_us - gen0) / 1000.0, (g_add_us - add0) / 1000.0);
        Serial.println();
    }

    int ns = SIM_SEQ_LEN ? SIM_SEQ_LEN : 1;
    Serial.println("--------------------------------------------");
    Serial.printf("  Total: %.3f ms | Avg: %.3f ms | Min: %.3f ms | Max: %.3f ms\n",
                  total_us / 1000.0, (total_us / (double)ns) / 1000.0,
                  min_us / 1000.0, max_us / 1000.0);
    Serial.printf("  Total decrypts: %d | Supervisors: %d | Result: %s\n",
                  total_dec, count, all_ok ? "PASS" : "FAIL");
    Serial.printf("  %u cells re-randomized; generating Enc(0) %.3f ms "
                  "(%.3f ms each), adding %.3f ms\n", (unsigned)g_rr_cells,
                  g_gen_us / 1000.0, g_rr_cells ? g_gen_us / 1000.0 / g_rr_cells : 0.0,
                  g_add_us / 1000.0);
    Serial.printf("  With Enc(0) precomputed offline: Total %.3f ms | Avg %.3f ms\n",
                  (total_us - g_gen_us) / 1000.0,
                  ((total_us - g_gen_us) / (double)ns) / 1000.0);
    Serial.println("============================================\n");

    for (auto& sv : g_sups) { sv_free_dec(sv); sv.enc.clear(); }
    g_sups.clear();
}

// =============================================================================
// Setup helpers
// =============================================================================

// Initialise mbedTLS, load the curve, and generate the EC-ElGamal keypair.
static void crypto_init() {
    mbedtls_ecp_group_init(&g_grp);
    mbedtls_ecp_point_init(&g_G);
    mbedtls_ecp_point_init(&g_pub);
    mbedtls_mpi_init(&g_priv);
    mbedtls_mpi_init(&g_one);
    mbedtls_mpi_init(&g_neg_priv);
    mbedtls_ctr_drbg_init(&g_drbg);
    mbedtls_entropy_init(&g_entropy);
    mbedtls_mpi_lset(&g_one, 1);

    const char* pers = "esp32_he";
    mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                           (const uint8_t*)pers, strlen(pers));
    mbedtls_ecp_group_load(&g_grp, CURVE);
    mbedtls_ecp_copy(&g_G, &g_grp.G);
    mbedtls_ecp_gen_keypair(&g_grp, &g_priv, &g_pub,
                             mbedtls_ctr_drbg_random, &g_drbg);
    mbedtls_mpi_sub_mpi(&g_neg_priv, &g_grp.N, &g_priv);   // fixed for the run

    // Seed the worker core's DRBG with a different personalisation string so
    // the two cores' RNG streams are independent.
    mbedtls_ctr_drbg_init(&g_drbg_core0);
    mbedtls_entropy_init(&g_entropy_core0);
    const char* pers_c0 = "esp32_he_core0";
    mbedtls_ctr_drbg_seed(&g_drbg_core0, mbedtls_entropy_func, &g_entropy_core0,
                           (const uint8_t*)pers_c0, strlen(pers_c0));
}

// One-time measurement of mbedtls scalar mul / muladd cost for the build banner.
static void report_crypto_speed() {
    mbedtls_ecp_point P, Q, R; mbedtls_mpi k;
    mbedtls_ecp_point_init(&P); mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_init(&R); mbedtls_mpi_init(&k);
    mbedtls_ecp_copy(&P, &g_G); mbedtls_ecp_copy(&Q, &g_G);
    mbedtls_mpi_lset(&k, 1);

    long t0 = millis();
    for (int i = 0; i < 5; ++i) mbedtls_ecp_muladd(&g_grp, &R, &k, &P, &k, &Q);
    long muladd_ms = (millis() - t0) / 5;

    t0 = millis();
    for (int i = 0; i < 5; ++i)
        mbedtls_ecp_mul(&g_grp, &R, &k, &g_G, mbedtls_ctr_drbg_random, &g_drbg);
    long scalarmul_ms = (millis() - t0) / 5;

    mbedtls_ecp_point_free(&P); mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_point_free(&R); mbedtls_mpi_free(&k);
    Serial.printf("[Crypto] muladd=%ld ms  scalar_mul=%ld ms\n\n",
                  muladd_ms, scalarmul_ms);
}

// Spawn the persistent worker on core 0. Returns true on success.
static bool spawn_worker() {
    g_worker_go   = xSemaphoreCreateBinary();
    g_worker_done = xSemaphoreCreateBinary();
    if (!g_worker_go || !g_worker_done) return false;

    BaseType_t r = xTaskCreatePinnedToCore(
        persistent_worker_task, "he_worker", WORKER_STACK,
        NULL, WORKER_PRIO, NULL, CORE_WORKER);
    return r == pdPASS;
}

// =============================================================================
// Entry point
// =============================================================================

void setup() {
    Serial.begin(115200);
    delay(1500);
    Serial.println("\n============================================");
    Serial.println("  ESP32 Homomorphic DES  —  UltraDES");
    Serial.println("============================================");
    Serial.printf("  EVENT_COUNT : %d\n",      EVENT_COUNT);
    Serial.printf("  SIM_SEQ_LEN : %d\n",      SIM_SEQ_LEN);
    Serial.printf("  Ciphertext  : %u bytes\n", (unsigned)sizeof(Ciphertext));
    Serial.printf("  Security    : scalar blinding, fresh randomness in every cell,"
                  " no decision kept\n\n");

    crypto_init();
    for (int gi = 0; gi < EVENT_COUNT; ++gi)
        if (derive_controllable(gi)) g_ctrl |= (1u << gi);

    g_dual_core = spawn_worker();
    Serial.printf("[Dual-core] %s\n\n",
                  g_dual_core ? "Worker on core 0" : "Failed — running single-core");

    report_crypto_speed();

    if (!run_selftest()) {
        Serial.println("Self-test FAILED — halting.");
        while (true) delay(1000);
    }

#if HAS_MONO
    run_benchmark("MONOLITHIC", &MONO_SUP, 1);
#else
    Serial.println("[SKIP] Monolithic supervisor not included.\n");
#endif

    run_benchmark("LOCAL MODULAR",         LMOD_SUPS,     LMOD_COUNT);
    run_benchmark("LOCAL MODULAR REDUCED", LMOD_RED_SUPS, LMOD_RED_COUNT);

    Serial.println("All benchmarks complete.");
}

void loop() { delay(10000); }
