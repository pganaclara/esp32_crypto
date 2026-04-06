# Homomorphic DES Benchmark on ESP32

**`homomorphic-esp32-modular_auto.ino`**

An Arduino sketch for ESP32 that synthesises Discrete Event System (DES) supervisors automatically from plant and specification DFAs, then benchmarks their execution under EC-ElGamal homomorphic encryption. It demonstrates — with real hardware timing — why **local modular supervision** is computationally tractable while **monolithic supervision** is not for large manufacturing systems.

---

## Contents

- [Background: DES and Homomorphic Encryption](#background-des-and-homomorphic-encryption)
- [Approaches Benchmarked](#approaches-benchmarked)
- [Benchmark Problems](#benchmark-problems)
- [Architecture and Code Structure](#architecture-and-code-structure)
- [Key Design Decisions](#key-design-decisions)
- [Optimisations](#optimisations)
- [Timing Model](#timing-model)
- [Expected Results](#expected-results)
- [Hardware Requirements](#hardware-requirements)
- [How to Use](#how-to-use)
- [Configuration Constants](#configuration-constants)
- [Adding a Custom Problem](#adding-a-custom-problem)
- [Limitations](#limitations)

---

## Background: DES and Homomorphic Encryption

### Discrete Event Systems

A plant is modelled as a Deterministic Finite Automaton (DFA). A specification constrains which event sequences are permitted. The **supervisor** is synthesised from the plant and specification using the Ramadge-Wonham framework: `Sup(Plant, Spec)`, retaining only coreachable (non-blocking) states.

The plant state is a **one-hot vector** `x ∈ {0,1}^n`, where exactly one component equals 1. Transitions are encoded as a Boolean matrix `B_ev` for each event `ev`:

```
x_next = B_ev · x
```

Because supervisors are DFAs, `B_ev` is a **partial permutation matrix**: at most one `1` per column (deterministic) and at most one `1` per row (each state has at most one successor per event). This structure is exploited heavily for efficiency.

The supervisor enables an event at state `s` if and only if there is an outgoing transition on that event from `s`. This is captured by the **requirements matrix** `R`:

```
en[ev_i] = R[i] · x    (yields 0 or 1)
```

### EC-ElGamal Homomorphic Encryption

EC-ElGamal encrypts a scalar `m` as a pair of elliptic curve points `(c1, c2)`:

```
Encrypt(m, r):
  c1 = r · G
  c2 = r · PubKey + m · G
```

It is **additively homomorphic**: given `Enc(a)` and `Enc(b)`, anyone can compute `Enc(a+b)` via an EC point addition — without the secret key. This allows the R-matvec to be evaluated homomorphically:

```
enc_en[i] = Enc(R[i] · x) = Σ enc_x[s]  for all s where R[i][s] = 1
```

Decrypting `enc_en[i]` yields `R[i] · x ∈ {0, 1}`, revealing whether event `i` is currently enabled.

**The state vector `enc(x)` is never decrypted.** Only the small enabled vector is decrypted each step, revealing the minimum information needed to control the plant.

---

## Approaches Benchmarked

### Monolithic

One supervisor `S = Sup(P_1 ‖ … ‖ P_k, E_1 ‖ … ‖ E_m)` over the full synchronous product of all plants and all specs.

**Per step:** state transition (sparse, free) + R-matvec (`num_events` rows) + `num_events` decryptions.

### Local Modular

One supervisor per spec: `S_j = Sup(P_j_local, E_j)`, where `P_j_local` contains only the plants that share at least one event with `E_j`.

An event is globally enabled if and only if every supervisor that includes it in its alphabet enables it. Supervisors that don't include an event do not constrain it.

**Per step:** each supervisor independently updates its own small encrypted state and decrypts only its constraining events. Supervisors whose state didn't change reuse cached enabled bits at zero crypto cost.

This approach was introduced by Queiroz & Cury (2000) precisely because monolithic synthesis is intractable for the FMS benchmark.

---

## Benchmark Problems

### Problem 1 — Small Factory

Two machines in series with a buffer.

```
M1 (e1=start, e2=finish) ──[buffer E]──  M2 (e3=start, e4=finish)
```

| Property | Value |
|---|---|
| Plants | M1 (2 states), M2 (2 states) |
| Spec | E: buffer — fills on e2, drains on e3 (2 states) |
| Global events | {e1, e2, e3, e4} |
| Monolithic supervisor | 4 states |
| LMod supervisor | 1 supervisor, 4 states |
| Simulation sequence | e1, e2, e3, e1, e4 |

**Why Mono = LMod:** Both M1 (has e2) and M2 (has e3) share events with spec E, so the local plant equals the full plant. `LMod_E = Sup(M1 ‖ M2 ‖ E) = Monolithic`. Same DFA, same R matrix, same cost per step. Equal timing is theoretically correct — it reflects a structural property of this problem, not a code deficiency.

**R matrix structure:** Event e1 is enabled in 2 states (`cnt=2`, costs 1 muladd). Events e2, e3, e4 are each enabled in exactly 1 state (`cnt=1`, only a point copy). Total cost: 1 muladd + 4 decryptions ≈ 610 ms/step.

---

### Problem 2 — Extended Small Factory

Three machines in series with two buffers.

```
M1 ──[B1]──  M2 ──[B2]──  M3
```

| Property | Value |
|---|---|
| Plants | M1 (a1/b1), M2 (a2/b2), M3 (a3/b3), each 2 states |
| Specs | B1: buffer b1→a2 (2 states), B2: buffer b2→a3 (2 states) |
| Global events | {a1, b1, a2, b2, a3, b3} |
| Monolithic supervisor | 32 states, 6 events |
| LMod sup B1 | Sup(M1 ‖ M2 ‖ B1): 8 states, 4 own events, 2 constraining |
| LMod sup B2 | Sup(M2 ‖ M3 ‖ B2): 8 states, 4 own events, 2 constraining |
| Simulation sequence | a1, b1, a2, b2, a3, b3, a1, b1 |

**Why local plants are smaller:** M3 shares no events with B1 ({b1, a2}) → excluded from B1's local plant. M1 shares no events with B2 ({b2, a3}) → excluded from B2's local plant. Each supervisor uses 8 states instead of 32.

**Constraining events after pruning:** Each supervisor retains 2 constraining rows (the buffer fill and drain events). The machines' complementary events (e.g., a1 in B1) are never disabled by the spec, so their rows are all-ones and pruned from R_local, saving 2 decryptions per step.

**Speedup (~1.67×) from three combined effects:**
1. Fewer R rows per step: 2 per active supervisor vs 6 monolithic.
2. Smaller state space: 8-state rows have fewer non-zero entries than 32-state rows.
3. Cache: steps a1, b1, a3, b3 fire only one supervisor — the other gets a cache hit (zero cost).

---

### Problem 3 — Flexible Manufacturing System (FMS)

Based on Queiroz & Cury (2000), the canonical benchmark demonstrating why modular DES is necessary.

**Plants (8):**

| Plant | States | Events | Description |
|---|---|---|---|
| C1 | 2 | 11 (start), 12 (finish) | Input conveyor 1 |
| C2 | 2 | 21 (start), 22 (finish) | Input conveyor 2 |
| Lathe | 2 | 41 (start), 42 (finish) | Lathe |
| Mill | 3 | 51/52 (type A), 53/54 (type B) | Milling machine (two operation types) |
| Robot | 6 | 31–39, 30 | Central transfer robot (5 routes, start/finish each) |
| AM | 4 | 61, 63/64 (type A), 65/66 (type B) | Assembly machine |
| C3 | 3 | 71/72 (route A), 73/74 (route B) | Output conveyor (two routes) |
| PD | 2 | 81 (load), 82 (unload) | **Pallet Depot** |

> **PD = Pallet Depot.** In Queiroz & Cury (2000), PD refers to the Pallet Depot (or Part Depot in some editions) — the storage area where finished pallets/parts are deposited by the output conveyor. It is not a painting device.

**Robot model:** State 0 = idle (initial, marked). States 1–5 = busy on one of 5 transfer routes. Each route: odd event = start, even event = finish. Robot can only begin a transfer from state 0.

| Route | Start | Finish | Transfer |
|---|---|---|---|
| 1 | 31 | 32 | C1 → Lathe |
| 2 | 33 | 34 | C2 → Mill |
| 3 | 35 | 36 | Lathe → AM |
| 4 | 37 | 38 | Mill → AM |
| 5 | 39 | 30 | AM → C3 |

**Specifications (E1–E8):**

| Spec | States | Constraint |
|---|---|---|
| E1 | 2 | C1 finishes (12) before Robot picks up (31) — buffer |
| E2 | 2 | C2 finishes (22) before Robot picks up (33) — buffer |
| E3 | 3 | Robot delivers to Lathe (32→41); Lathe finishes (42) before Robot picks up (35) |
| E4 | 4 | Robot delivers to Mill (34→51/53); Mill finishes (52/54) before Robot picks up (37/39) |
| E5 | 2 | Robot finishes type-A AM delivery (36) before AM starts (61) — buffer |
| E6 | 2 | Robot finishes type-B AM delivery (38) before AM continues (63) — buffer |
| E7 | 3 | Robot finishes AM→C3 (30→71); C3 route-B output (74) before AM type-B path (65) |
| E8 | 3 | C3 finishes route A (72) before PD loads (81); PD unloads (82) before C3 route B (73) |

**Monolithic supervisor:** 501 states, 31 events (synthesis completes within limit; exact count printed at runtime).

**Why R_local pruning yields 0 pruned rows for FMS:** The Robot has 6 states, and every Robot event fires from exactly one Robot state (e.g., event 31 only fires when Robot = state 0 = idle). In every local supervisor containing the Robot, every R_local row has zeros in the product states where the Robot is in a different state. Since no row is all-ones, no row can be pruned. Pruning only helps when a supervisor *never* disables an event across all reachable states — this does not occur here because the Robot's structure inherently limits each event to a fraction of product states.

**Local modular supervisors (8):**

| Supervisor | Local Plants | States | Own Events | Constraining Events | Mode |
|---|---|---|---|---|---|
| E1 | C1, Robot | 24 | 12 | 12 (no pruning) | ENC |
| E2 | C2, Robot | 24 | 12 | 12 | ENC |
| E3 | Lathe, Robot | 18 | 12 | 12 | ENC |
| E4 | Mill, Robot | 21 | 14 | 14 | ENC |
| E5 | Robot, AM | 48 | 15 | 15 | CLR |
| E6 | Robot, AM | 48 | 15 | 15 | CLR |
| E7 | Robot, AM, C3 | 168 | 19 | 19 | CLR |
| E8 | C3, PD | 6 | 6 | 6 | ENC |

E5, E6, E7 exceed `ENC_THRESHOLD` (32 states) and run in cleartext.

**Simulation sequence:** 11, 12, 31, 32, 41, 42, 35, 36, 61, 63, 64

---

## Architecture and Code Structure

```
Section 1  — Type definitions
             DFA, ProductDFA, AutomatonConfig, ModSupervisor, OracleState

Section 2  — Global state
             Active automaton, supervisor lists, encrypted state vectors,
             crypto context, device-measured EC costs

Section 3  — DES synthesis engine
             synchronous_product()      BFS product automaton with state limit guard
             coreachable_states()       backward BFS from marked states
             compact_indices()          forward BFS index assignment
             supervisor_to_config()     AutomatonConfig from product DFA
             product_to_mod_supervisor()ModSupervisor with sparse B + pruned R_local
             synthesise_automaton()     orchestrates both approaches

Section 4  — Crypto primitives
             ec_elgamal_encrypt/decrypt/add()
             encrypt_values(), decrypt_values(), free_ct_vec(), copy_enc_zero()

Section 5  — Homomorphic operators
             sum_row()            dot product of one R row with enc(x)
             matvec_dense()       full R · enc(x)
             sparse_transition()  B_ev · enc(x) as point copies — zero EC additions

Section 6  — Problem definitions  ← ONLY SECTION YOU NEED TO EDIT

Section 7  — Cleartext oracle
             Independent state copies; never shared with HE paths

Section 8  — Homomorphic step functions
             step_monolithic_he(), step_lmod_he()

Section 9  — Setup / loop
             EC cost microbenchmark, synthesis, crypto init,
             benchmark loop, timing summary with theoretical estimate
```

---

## Key Design Decisions

### One-hot state encoding

Exactly one ciphertext in `enc(x)` holds `Enc(1)`; all others hold `Enc(0)`. This makes `B_ev · enc(x)` a pure reordering of ciphertexts — copy `enc_state[from]` to `enc_next[to]`, fill remaining positions with `Enc(0)`. No EC arithmetic required for the state transition step.

### Independent oracle state

The cleartext oracle maintains its own completely separate state copy, allocated independently from all HE paths. It never shares memory with `enc_lmod_states`, `clr_lmod_exec`, or `enc_mono`. Uses monolithic cleartext when synthesis succeeded; otherwise the intersection of local supervisor cleartext states — mirroring exactly what the homomorphic approach computes.

### Per-supervisor ENC/CLR classification

At synthesis time, each supervisor is classified:
- **ENC** if `num_states ≤ ENC_THRESHOLD`: full homomorphic execution.
- **CLR** if `num_states > ENC_THRESHOLD`: integer cleartext, reported in output.

### Memory-gated monolithic HE

Synthesis always runs to completion (up to `MONO_STATE_LIMIT`) to get the exact state count. HE is enabled only if `num_states × 400 bytes ≤ HE_MEMORY_LIMIT`. Provides exact state counts even when HE cannot run.

---

## Optimisations

### 1. Sparse B matrices — zero EC cost for transitions

`B_ev` stored as `vector<pair<int,int>>` of `(to, from)` pairs. Applied as:
```
enc_next[to] = enc_state[from]   // point copy, ~0 ms
enc_next[s]  = Enc(0)            // for all other s
```
O(n) RAM per event. Zero EC additions. Replaces what would be O(n²) dense matrix storage and O(n²) EC additions.

### 2. R_local row pruning — fewer decryptions

Rows of `R_local` where every reachable state has `R[li][s] = 1` are removed at synthesis. Those events are always enabled by this supervisor and contribute `1` unconditionally. Reduces decrypt count from `num_own_events` to `num_constraining_events`. Effective for Extended Small Factory (4→2 per supervisor). Not effective for FMS (Robot structure ensures all rows have zeros).

### 3. Cache — zero cost when state unchanged

When fired event ∉ `own_events(S_j)`: state cannot change, enabled bits cannot change. Last `cached_en` reused at zero crypto cost. Applies to every step where a supervisor doesn't participate.

### 4. ENC_THRESHOLD — prevents heap overflow

Supervisors > 32 states fall back to cleartext arithmetic. Allows the benchmark to run on all problems without allocation failures, while being transparent about which supervisors are not encrypted.

### 5. Device-measured EC cost benchmark

At startup: 3 timed calls to `mbedtls_ecp_muladd` and 3 to `mbedtls_ecp_mul`, averaged. The actual measured costs replace hardcoded assumptions in the theoretical estimate:
```
R-matvec: num_events × avg_enabled_states × 2 × muladd_ms
Decrypt:  num_events × (scalar_mul_ms + muladd_ms)
```

---

## Timing Model

Platform: secp256r1 (NIST P-256), ESP-IDF bundled mbedTLS.

| Operation | Typical cost | Role |
|---|---|---|
| `mbedtls_ecp_mul` (scalar mul) | ~80 ms | Encrypt (×2 calls), Decrypt (×1 call) |
| `mbedtls_ecp_muladd` with k=1 | ~5 ms | `ec_elgamal_add`, final step of decrypt |
| `mbedtls_ecp_copy` (point copy) | ~0 ms | `sparse_transition` |

The exact costs are measured at startup and printed. The muladd cost is used for the R-matvec estimate; the scalar_mul cost is used for the decrypt estimate.

**Per step — Monolithic (n states, m events, avg_cnt ones per R row):**
```
sparse_transition:  n copies          ~0 ms
matvec(R):         m × avg_cnt muladds  m × avg_cnt × 2 × muladd_ms
decrypt:            m events           m × (scalar_mul_ms + muladd_ms)
```

**Per step — Local Modular per supervisor S_j (c_j constraining events):**
```
If ev ∈ own_events(S_j):
  sparse_transition + matvec(R_local) + c_j decryptions
Else:
  cache hit: 0 ms
```

---

## Expected Results

### Small Factory

```
Monolithic : ~610 ms/step
LocalMod   : ~610 ms/step
Speedup    : 1.00× (structurally identical supervisors — correct by theory)
```

### Extended Small Factory

```
Monolithic : ~1450 ms/step   (32 states, 6 R rows)
LocalMod   :  ~870 ms/step   (8-state supervisors, 2 constraining events each)
Speedup    : ~1.67×
```

### FMS

```
Monolithic : HE SKIPPED (501 states × 400B ≈ 200KB > 180KB limit)
             Device muladd:     ~5 ms
             Device scalar_mul: ~80 ms
             Est. R-matvec:    ~25,000 ms/step
             Est. decrypt:      ~2,600 ms/step
             Est. total HE:    ~27,600 ms/step
LocalMod   : ~4,600 ms/step (5 ENC sups + 3 CLR sups)
Theoretical speedup: ~6×
```

---

## Hardware Requirements

| | |
|---|---|
| Board | ESP32 (≥320 KB SRAM) |
| Framework | Arduino with ESP-IDF (arduino-esp32 package) |
| Crypto | mbedTLS (bundled — no extra installation) |
| Serial | 115200 baud |
| Peak heap | ~200 KB (FMS with 5 encrypted supervisors) |

---

## How to Use

**1. Select the problem** in Section 6:

```cpp
#define ACTIVE_PROBLEM PROBLEM_SMALL_FACTORY           // default
// #define ACTIVE_PROBLEM PROBLEM_EXTENDED_SMALL_FACTORY
// #define ACTIVE_PROBLEM PROBLEM_FMS
// #define ACTIVE_PROBLEM PROBLEM_CUSTOM
```

**2. Upload** and open Serial Monitor at 115200 baud.

**3. Read output:**

```
[Synthesis] Monolithic: 4 states, 4 events [HE OK]
[Synthesis] LMod E    : 4 states, 4 own ev, 2 constraining ev (pruned 2) [ENC]
EC muladd:     4868 us
EC scalar_mul: 79843 us
Crypto ready.

---- Step 1 | Event: e1 ----
  [Oracle]  en=[1,0,1,0]
  [Mono]    en=[1,0,1,0]
  [LMod]    en=[1,0,1,0]
  Mono:OK  LMod:OK

...

============================================
  TIMING SUMMARY
============================================
  Monolithic :   3065 ms total  avg  613 ms/step
  LocalMod   :   3065 ms total  avg  613 ms/step
  LMod speedup vs Mono: 1.00x
  ...
  Mono:PASS  LMod:PASS
============================================
```

---

## Configuration Constants

| Constant | Default | Increase when | Decrease when |
|---|---|---|---|
| `MONO_STATE_LIMIT` | 500 | Synthesis hits limit (FMS prints warning) | Memory is very tight during synthesis |
| `HE_MEMORY_LIMIT` | 180 KB | Monolithic HE is skipped but you have more heap | Getting heap allocation failures |
| `ENC_THRESHOLD` | 32 | Supervisor marked CLR that you want encrypted | Getting allocation failures on LMod supervisors |

---

## Adding a Custom Problem

```cpp
#elif ACTIVE_PROBLEM == PROBLEM_CUSTOM

std::vector<DFA> define_plants() {
    // make_machine(name, start_event, finish_event):
    //   2-state: idle →(start)→ busy →(finish)→ idle
    return { make_machine("MA","alpha1","beta1"),
             make_machine("MB","alpha2","beta2") };
}

std::vector<DFA> define_specs() {
    // make_buffer(name, fill_event, drain_event):
    //   2-state: empty →(fill)→ full →(drain)→ empty
    return { make_buffer("BUF","beta1","alpha2") };
}

std::vector<String> define_simulation_sequence() {
    return {"alpha1","beta1","alpha2","beta2"};
}
```

For custom DFA structures:

```cpp
DFA myPlant;
myPlant.name = "MyPlant";
myPlant.num_states = 3;
myPlant.initial = 0;
myPlant.marked = {true, false, false};
myPlant.transitions = {{0,"ev_a",1},{1,"ev_b",2},{2,"ev_c",0}};
myPlant.build_delta();  // required after setting transitions
```

---

## Limitations

**EC point addition via muladd.** `ecp_point_add` wraps `mbedtls_ecp_muladd(grp, R, &one, P, &one, Q)`. The true primitive `mbedtls_ecp_add()` (~2ms) is not reliably available across ESP-IDF versions. The actual cost is measured at startup and reflected in all estimates.

**FMS monolithic HE is infeasible.** 501 states × 400 bytes ≈ 200KB exceeds the heap limit, and even if memory allowed, the R-matvec would cost ~25 seconds per step. This is the motivating result of the FMS benchmark: monolithic supervision is computationally intractable for large systems, and local modular DES is the solution.

**E5, E6, E7 run cleartext.** These supervisors (48, 48, and 168 states) exceed ENC_THRESHOLD. They execute correctly and contribute to the global enabled vector, but their states are not encrypted.

**Nonconflict not verified at runtime.** Modular DES requires offline verification that `{S_j}` are mutually nonconflicting. The three built-in problems are verified in the DES literature. Custom problems require offline verification.

**One-hot invariant.** The protocol assumes `enc(x)` is always one-hot. This holds for valid traces of the synthesised supervisor. Firing an event with no transition from the current state would corrupt the state vector.

---

**Reference:** M. H. de Queiroz and J. E. R. Cury, "Modular Supervisory Control of Large Scale Discrete Event Systems," in *Discrete Event Systems: Analysis and Control*, R. Boel and G. Stremersch (Eds.), Kluwer Academic Publishers, 2000, pp. 103–110.
