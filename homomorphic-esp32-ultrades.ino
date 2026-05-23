// =============================================================================
// ESP32 Homomorphic DES benchmark — EC-ElGamal on NIST P-192, dual-core FreeRTOS
// =============================================================================
//
// The supervisor state lives only as EC-ElGamal ciphertexts in RAM. The active
// state is never decrypted on the normal path — we homomorphically OR the
// enabled cells of each constraining row and decrypt only the resulting bit.
//
// Optimisations layered on top of the basic scheme:
//   * Conditional invariance — at load time, for every (sup, event, row) we
//     precompute whether the row can flip 0→1, 1→0, both, or neither. At
//     runtime we re-decrypt only rows whose current cached value could
//     actually change.
//   * Persistent decompressed cache — each supervisor keeps its ciphertexts
//     in BOTH compressed (Ciphertext, 50 B) and decompressed (mbedtls_ecp_point)
//     form. do_transition maintains the cache via cheap mbedtls_ecp_copy
//     instead of running pt_decompress (sqrt) on every read.
//   * Skip-g_zero summands — after a transition most state cells are the
//     literal global Enc(0) constant; sum_row skips them.
//   * Fused row-sum + decrypt — a single mbedtls_ecp_muladd handles the secret
//     scalar mul and the final add, eliminating the intermediate point.
//   * Dual-core work-unit split — phase 1 (serial, main core) applies
//     transitions and enqueues (sup, row) work units; phase 2 splits them
//     across both cores via a persistent worker task on core 0.
//
// Setup: drop a supervisor_data_<PROBLEM>.h + sdkconfig.ext in the sketch
// folder, point the #include below at the .h file, flash, and open the Serial
// Monitor at 115200 baud.
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

// =============================================================================
// Types
// =============================================================================

struct Ciphertext { uint8_t c1[PT_LEN]; uint8_t c2[PT_LEN]; };

struct Supervisor {
    const SupDesc* desc;
    uint32_t       own_event_mask    = 0;            // events this sv constrains or transitions
    uint32_t       trans_event_mask  = 0;            // events this sv actually transitions on

    std::vector<uint8_t>           constrained_gi;   // global indices of constraining events
    std::vector<Ciphertext>        enc;             // compressed state vector
    std::vector<mbedtls_ecp_point> dec_c1, dec_c2;  // decompressed mirror of enc[]
    std::vector<int8_t>            cached_en;       // last decrypted value per constrained row

    // Conditional invariance: for each event ev,
    //   changes_if_zero[ev] : rows that may flip 0→1 under this event
    //   changes_if_one [ev] : rows that may flip 1→0 under this event
    // Rows in neither list are truly invariant and keep their cached value.
    std::vector<std::vector<uint8_t>> changes_if_zero;
    std::vector<std::vector<uint8_t>> changes_if_one;
};

// One (supervisor, constrained-row) decrypt task.
struct WorkUnit { uint8_t sv; uint8_t li; };

struct WorkerCmd {
    int start, end;
    const std::vector<WorkUnit>* work;
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
static Ciphertext               g_zero;                 // canonical Enc(0) literal
static bool                     g_dual_core = false;
static int                      g_step_decrypts = 0;
static portMUX_TYPE             g_dec_mux = portMUX_INITIALIZER_UNLOCKED;

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

static inline bool is_g_zero(const Ciphertext& c) {
    return memcmp(&c, &g_zero, sizeof(Ciphertext)) == 0;
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
    mbedtls_ecp_point c1, c2, ns, pm;
    mbedtls_ecp_point_init(&ns);
    mbedtls_ecp_point_init(&pm);

    int ret = pt_decompress(ct->c1, &c1); if (ret) goto done;
    ret     = pt_decompress(ct->c2, &c2); if (ret) goto done;
    ret = mbedtls_ecp_muladd(&g_grp, &pm, &g_neg_priv, &c1, &g_one, &c2);
    if (ret == 0) *out = mbedtls_ecp_is_zero(&pm) ? 0 : 1;

done:
    mbedtls_ecp_point_free(&c1); mbedtls_ecp_point_free(&c2);
    mbedtls_ecp_point_free(&ns); mbedtls_ecp_point_free(&pm);
    return ret;
}

// Homomorphic ciphertext addition — used by self-test.
static int elgamal_add(const Ciphertext* a, const Ciphertext* b, Ciphertext* out) {
    mbedtls_ecp_point pa1, pa2, pb1, pb2, r1, r2;
    mbedtls_ecp_point_init(&r1); mbedtls_ecp_point_init(&r2);

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
// Hot path: fused row-sum + decrypt
// =============================================================================

// Computes (homomorphically OR'd over enabled non-zero cells of sv.enc) then
// decrypts the result, all on the persistent decompressed cache so no point
// decompression happens here. Returns:
//   *out         : 0 or 1
//   *did_decrypt : false if the row sum was trivially Enc(0), true otherwise
static int row_decrypt(const Supervisor& sv, const int8_t* row, int n,
                       int* out, bool* did_decrypt) {
    *did_decrypt = false;

    int first = -1;
    for (int i = 0; i < n; ++i) {
        if (!pm_i8(row, i))           continue;
        if (is_g_zero(sv.enc[i]))     continue;
        first = i; break;
    }
    if (first < 0) { *out = 0; return 0; }

    mbedtls_ecp_point s1, s2, tmp;
    mbedtls_ecp_point_init(&s1);
    mbedtls_ecp_point_init(&s2);
    mbedtls_ecp_point_init(&tmp);

    int ret = mbedtls_ecp_copy(&s1, &sv.dec_c1[first]); if (ret) goto done;
    ret     = mbedtls_ecp_copy(&s2, &sv.dec_c2[first]); if (ret) goto done;

    for (int i = first + 1; i < n; ++i) {
        if (!pm_i8(row, i))           continue;
        if (is_g_zero(sv.enc[i]))     continue;

        ret = mbedtls_ecp_muladd(&g_grp, &tmp, &g_one, &s1, &g_one, &sv.dec_c1[i]);
        if (ret) goto done;
        swap_pt(&s1, &tmp);
        ret = mbedtls_ecp_muladd(&g_grp, &tmp, &g_one, &s2, &g_one, &sv.dec_c2[i]);
        if (ret) goto done;
        swap_pt(&s2, &tmp);
    }

    // pm = (N-priv)*s1 + 1*s2   — single muladd: scalar mul + final add fused.
    {
        mbedtls_ecp_point pm;
        mbedtls_ecp_point_init(&pm);
        ret = mbedtls_ecp_muladd(&g_grp, &pm, &g_neg_priv, &s1, &g_one, &s2);
        if (ret == 0) {
            *out = mbedtls_ecp_is_zero(&pm) ? 0 : 1;
            *did_decrypt = true;
        }
        mbedtls_ecp_point_free(&pm);
    }

done:
    mbedtls_ecp_point_free(&s1);
    mbedtls_ecp_point_free(&s2);
    mbedtls_ecp_point_free(&tmp);
    return ret;
}

// Apply event ev_gi's transitions to sv. Updates both the compressed
// ciphertext array and the persistent decompressed cache in lock-step.
static void do_transition(Supervisor& sv, int ev_gi, int n) {
    int      off = trans_offset(sv.desc, ev_gi);
    uint16_t pc  = pm_u16(sv.desc->tcnt, ev_gi);

    std::vector<Ciphertext>        nxt(n, g_zero);
    std::vector<mbedtls_ecp_point> nxt_c1(n), nxt_c2(n);
    for (int i = 0; i < n; ++i) {
        mbedtls_ecp_point_init(&nxt_c1[i]);
        mbedtls_ecp_point_init(&nxt_c2[i]);
    }

    for (uint16_t p = 0; p < pc; ++p) {
        int from = pm_i16(sv.desc->trans + off * 2, p * 2);
        int to   = pm_i16(sv.desc->trans + off * 2, p * 2 + 1);
        nxt[to]  = sv.enc[from];
        if (!is_g_zero(sv.enc[from])) {
            // Deep-copy the already-decompressed point — far cheaper than
            // re-running pt_decompress on the target cell.
            mbedtls_ecp_copy(&nxt_c1[to], &sv.dec_c1[from]);
            mbedtls_ecp_copy(&nxt_c2[to], &sv.dec_c2[from]);
        }
    }

    sv_free_dec(sv);
    sv.enc    = std::move(nxt);
    sv.dec_c1 = std::move(nxt_c1);
    sv.dec_c2 = std::move(nxt_c2);
}

// =============================================================================
// Parallel decrypt engine
// =============================================================================

// Process work units [start, end). On the worker core we yield once per unit
// so IDLE0 can feed the Task Watchdog.
static void process_work_range(int start, int end,
                                const std::vector<WorkUnit>& work,
                                int* dec_count) {
    bool worker_core = (xPortGetCoreID() == CORE_WORKER);
    for (int wi = start; wi < end; ++wi) {
        if (worker_core) vTaskDelay(pdMS_TO_TICKS(1));
        const WorkUnit& w = work[wi];
        Supervisor& sv = g_sups[w.sv];
        int n  = (int)pgm_read_word(&sv.desc->num_states);
        int gi = sv.constrained_gi[w.li];

        int e; bool did_decrypt;
        if (row_decrypt(sv, sv.desc->enable + gi * n, n, &e, &did_decrypt) != 0) continue;
        if (did_decrypt) (*dec_count)++;
        sv.cached_en[w.li] = (int8_t)e;
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
static void dispatch_parallel(const std::vector<WorkUnit>& work) {
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
// Homomorphic step
// =============================================================================

static int he_step(int ev_gi, std::vector<int>& en_out) {
    en_out.assign(EVENT_COUNT, 1);

    // Phase 1 (main core, serial): apply transitions, build work list. A row
    // is enqueued only if its current cached value could actually flip.
    static std::vector<WorkUnit> work;
    work.clear();
    for (size_t i = 0; i < g_sups.size(); ++i) {
        Supervisor& sv = g_sups[i];
        if (!(sv.trans_event_mask & (1u << ev_gi))) continue;     // cached values still valid
        int n = (int)pgm_read_word(&sv.desc->num_states);
        do_transition(sv, ev_gi, n);
        for (uint8_t li : sv.changes_if_zero[ev_gi])
            if (sv.cached_en[li] == 0) work.push_back({(uint8_t)i, li});
        for (uint8_t li : sv.changes_if_one[ev_gi])
            if (sv.cached_en[li] == 1) work.push_back({(uint8_t)i, li});
    }

    // Phase 2: parallel decrypt across both cores.
    dispatch_parallel(work);

    // Phase 3: emit en_out from cached_en.
    for (auto& sv : g_sups)
        for (size_t li = 0; li < sv.constrained_gi.size(); ++li)
            if (!sv.cached_en[li]) en_out[sv.constrained_gi[li]] = 0;

    return 0;
}

// =============================================================================
// Supervisor loading and invariance precomputation
// =============================================================================

static bool load_supervisors(const SupDesc* descs, int count) {
    g_sups.clear();
    g_sups.resize(count);

    for (int i = 0; i < count; ++i) {
        Supervisor& sv = g_sups[i];
        sv.desc = &descs[i];
        int n = (int)pgm_read_word(&descs[i].num_states);

        // Build event masks and the constrained_gi list.
        for (int gi = 0; gi < EVENT_COUNT; ++gi) {
            if (pm_u16(descs[i].tcnt, gi) > 0) {
                sv.own_event_mask   |= (1u << gi);
                sv.trans_event_mask |= (1u << gi);
            }
            bool constrains = false;
            for (int s = 0; s < n && !constrains; ++s)
                if (!pm_i8(descs[i].enable, gi * n + s)) constrains = true;
            if (constrains) {
                sv.own_event_mask |= (1u << gi);
                sv.constrained_gi.push_back((uint8_t)gi);
            }
        }
        sv.cached_en.assign(sv.constrained_gi.size(), 1);
        sv.changes_if_zero.assign(EVENT_COUNT, {});
        sv.changes_if_one .assign(EVENT_COUNT, {});

        // Precompute the conditional-invariance lists per event.
        //
        // For row gi of this supervisor under event ev:
        //   0 → 1 flip is possible iff some (f,t) has en_f=0 AND en_t=1
        //                              (i.e. an outside state moves into A)
        //   1 → 0 flip is possible iff some enabled state has no transition,
        //                              or transitions to an outside state
        for (int ev = 0; ev < EVENT_COUNT; ++ev) {
            uint16_t pc = pm_u16(descs[i].tcnt, ev);
            if (pc == 0) continue;
            int off = trans_offset(&descs[i], ev);

            std::vector<uint8_t> in_from (n, 0);
            std::vector<int16_t> trans_to(n, -1);
            for (int p = 0; p < pc; ++p) {
                int f = pm_i16(descs[i].trans + off * 2, p * 2);
                int t = pm_i16(descs[i].trans + off * 2, p * 2 + 1);
                in_from[f]  = 1;
                trans_to[f] = (int16_t)t;
            }

            for (int li = 0; li < (int)sv.constrained_gi.size(); ++li) {
                int gi = sv.constrained_gi[li];
                const int8_t* row = descs[i].enable + gi * n;

                // Rows with no enabled state are permanently 0.
                bool any_en = false;
                for (int s = 0; s < n && !any_en; ++s)
                    if (pm_i8(row, s)) any_en = true;
                if (!any_en) { sv.cached_en[li] = 0; continue; }

                bool zero_to_one = false;
                for (int p = 0; p < pc && !zero_to_one; ++p) {
                    int f = pm_i16(descs[i].trans + off * 2, p * 2);
                    int t = pm_i16(descs[i].trans + off * 2, p * 2 + 1);
                    if (!pm_i8(row, f) && pm_i8(row, t)) zero_to_one = true;
                }
                if (zero_to_one) sv.changes_if_zero[ev].push_back((uint8_t)li);

                bool one_to_zero = false;
                for (int s = 0; s < n && !one_to_zero; ++s) {
                    if (!pm_i8(row, s)) continue;
                    if (!in_from[s])              { one_to_zero = true; break; }
                    if (!pm_i8(row, trans_to[s])) { one_to_zero = true; break; }
                }
                if (one_to_zero) sv.changes_if_one[ev].push_back((uint8_t)li);
            }
        }

        char name[16];
        strncpy_P(name, (const char*)pgm_read_ptr(&descs[i].name), 15);
        name[15] = 0;
        Serial.printf("[LOAD] %-14s  %3d states  %2d constraining ev  (%u bytes enc)\n",
                      name, n, (int)sv.constrained_gi.size(),
                      (unsigned)(n * sizeof(Ciphertext)));
    }
    return true;
}

// =============================================================================
// Initial encryption and cache warm-up
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

// Compute initial cached_en for every (sv, row) by running the parallel engine.
static void warm_cache() {
    std::vector<WorkUnit> work;
    for (size_t i = 0; i < g_sups.size(); ++i)
        for (size_t li = 0; li < g_sups[i].constrained_gi.size(); ++li)
            work.push_back({(uint8_t)i, (uint8_t)li});
    dispatch_parallel(work);
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
                for (uint16_t p = 0; p < pc; ++p) {
                    int from = pm_i16(descs[i].trans, (off + p) * 2);
                    int to   = pm_i16(descs[i].trans, (off + p) * 2 + 1);
                    nxt[to]  = st[i][from];
                }
                st[i] = nxt;
            }

            // Emit constraints
            if (!g_sups[i].own_event_mask) continue;
            for (int gi = 0; gi < EVENT_COUNT; ++gi) {
                if (!(g_sups[i].own_event_mask & (1u << gi))) continue;
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

    Serial.print("Warming enablement cache... ");
    long tw = millis();
    warm_cache();
    Serial.printf("OK (%ld ms)\n\n", millis() - tw);

    Oracle oracle; oracle.init(descs, count);
    uint64_t total_us = 0, min_us = UINT64_MAX, max_us = 0;
    int  total_dec = 0;
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
        Serial.printf("  Time: %.3f ms  |  Decrypts: %d  |  %s\n\n",
                      step_us / 1000.0, g_step_decrypts, ok ? "OK" : "FAIL");
    }

    int ns = SIM_SEQ_LEN ? SIM_SEQ_LEN : 1;
    Serial.println("--------------------------------------------");
    Serial.printf("  Total: %.3f ms | Avg: %.3f ms | Min: %.3f ms | Max: %.3f ms\n",
                  total_us / 1000.0, (total_us / (double)ns) / 1000.0,
                  min_us / 1000.0, max_us / 1000.0);
    Serial.printf("  Total decrypts: %d | Supervisors: %d | Result: %s\n",
                  total_dec, count, all_ok ? "PASS" : "FAIL");
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
    elgamal_enc(0, &g_zero, &g_drbg);
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
    Serial.printf("  Ciphertext  : %u bytes\n\n", (unsigned)sizeof(Ciphertext));

    crypto_init();

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
