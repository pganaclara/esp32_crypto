# Homomorphic DES Benchmark on ESP32

**`homomorphic-esp32-modular_auto.ino`**

An Arduino sketch for ESP32 that synthesises Discrete Event System (DES) supervisors automatically and benchmarks their execution under EC-ElGamal homomorphic encryption. It demonstrates — with real hardware measurements — why **local modular supervision** is computationally tractable while **monolithic supervision** is not for large manufacturing systems.

---

## Contents

- [Overview](#overview)
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
- [Limitations and Known Constraints](#limitations-and-known-constraints)

---

## Overview

This project combines two fields:

- **Discrete Event Systems (DES)** — formal models of manufacturing plants and their supervisory controllers, based on the Ramadge-Wonham framework.
- **Partially Homomorphic Encryption** — specifically EC-ElGamal over secp256r1, which allows the system to compute whether an event is enabled *without ever decrypting the current plant state*.

The code synthesises supervisors automatically from plant and specification DFAs, then runs a simulation in which the supervisor's state vector is kept encrypted at all times. Only the *enabled event* vector is decrypted each step, revealing the minimum information needed to control the plant.

The benchmark compares two supervision strategies:

| Approach | Description |
|---|---|
| **Monolithic** | One supervisor for all plants and all specs combined |
| **Local Modular** | One small supervisor per spec, using only the plants relevant to that spec |

---

## Background: DES and Homomorphic Encryption

### Discrete Event Systems

A plant is modelled as a DFA (Deterministic Finite Automaton). A specification constrains which event sequences are allowed. The **supervisor** is the DFA obtained by synthesising the plant and specification together using `Sup(Plant, Spec)`, keeping only coreachable (non-blocking) states.

The plant state is represented as a **one-hot vector** `x ∈ {0,1}^n`, where exactly one component is 1. Transitions are encoded as a Boolean matrix `B_ev` for each event `ev`:

```
x_next = B_ev · x
```

The supervisor enables an event at the current state if and only if that state has an outgoing transition on that event. This is captured by the **requirements matrix** `R`:

```
en[ev] = R[ev] · x   (result is 0 or 1)
```

### EC-ElGamal Homomorphic Encryption

EC-ElGamal encrypts a scalar `m` as a pair of elliptic curve points `(c1, c2)`:

```
Encrypt(m): r ← random scalar
  c1 = r·G
  c2 = r·PubKey + m·G
```

It is **additively homomorphic**: given `Enc(a)` and `Enc(b)`, anyone can compute `Enc(a+b)` using only EC point addition — no secret key required.

This means `R · enc(x)` can be computed homomorphically: the dot product of a plaintext row of `R` with the encrypted state vector gives `Enc(R_row · x)`. Decrypting tells us whether that event is enabled (result is 0 or 1).

**The state vector `enc(x)` is never decrypted.** Only the small `en` vector (length = number of events) is decrypted each step.

---

## Approaches Benchmarked

### Monolithic

One supervisor `S = Sup(P_1 ‖ P_2 ‖ … ‖ P_k, E_1 ‖ E_2 ‖ … ‖ E_m)` is synthesised from the synchronous product of all plants and all specs. The state space can be exponentially large.

**Homomorphic cost per step:**
- `B_ev · enc(x)` — state transition. Because supervisors are DFAs, `B_ev` is a partial permutation matrix: at most one `1` per column. This makes the matrix-vector product equivalent to reordering ciphertexts (point copies, no EC arithmetic).
- `R · enc(x_next)` — enablement check. `R` has `num_events` rows; each row is a sum of ciphertexts at positions where the event is enabled. This requires EC point additions.
- `decrypt(enc_en)` — `num_events` EC scalar multiplications.

### Local Modular

For each spec `E_j`, a **local plant** `P_j` is selected: the set of plants that share at least one event with `E_j`. The local supervisor is `S_j = Sup(P_j, E_j)`.

The global supervisor is the combination of all local supervisors. An event is globally enabled if and only if it is enabled by every supervisor that includes it in its alphabet.

**Homomorphic cost per step:**
- Each `S_j` maintains its own small encrypted state vector.
- Only supervisors whose state changes on a given event pay crypto cost.
- Supervisors that don't own the fired event reuse cached enabled bits at zero cost.
- R_local has only rows for events `S_j` can actually *disable* (always-enabled rows are pruned at synthesis).

This is the approach introduced by Queiroz & Cury (2000) for the FMS benchmark, precisely because monolithic synthesis is intractable for large systems.

---

## Benchmark Problems

### Problem 1 — Small Factory

Two machines in series with a buffer between them.

```
M1 (e1=start, e2=finish) → [buffer E] → M2 (e3=start, e4=finish)
```

| | Value |
|---|---|
| Plants | M1 (2 states), M2 (2 states) |
| Specs | E: buffer fills on e2, drains on e3 (2 states) |
| Global events | {e1, e2, e3, e4} |
| Monolithic states | 4 |
| LMod supervisors | 1 (identical to monolithic) |
| Simulation sequence | e1, e2, e3, e1, e4 |

**Note:** Both machines share events with spec E (M1 has e2, M2 has e3), so the local plant equals the full plant. The local modular supervisor is identical to the monolithic supervisor. **Equal timing between Mono and LMod is correct and expected.**

---

### Problem 2 — Extended Small Factory

Three machines in series with two buffers.

```
M1 → [B1] → M2 → [B2] → M3
```

| | Value |
|---|---|
| Plants | M1 (a1/b1), M2 (a2/b2), M3 (a3/b3), each 2 states |
| Specs | B1: buffer b1→a2 (2 states), B2: buffer b2→a3 (2 states) |
| Global events | {a1, b1, a2, b2, a3, b3} |
| Monolithic states | 32 |
| Monolithic events | 6 |
| LMod sup B1 | Sup(M1 ‖ M2 ‖ B1): 8 states, 4 own events, 2 constraining |
| LMod sup B2 | Sup(M2 ‖ M3 ‖ B2): 8 states, 4 own events, 2 constraining |
| Simulation sequence | a1, b1, a2, b2, a3, b3, a1, b1 |

**Note:** M3 is irrelevant to B1 (shares no events); M1 is irrelevant to B2. Local plant selection excludes them, giving 8-state supervisors instead of 32 states monolithically.

**Expected speedup: ~1.67×**, explained by:
1. Fewer R rows to decrypt per step (2 per active supervisor vs 6 for mono)
2. Smaller R matrices (8-state rows vs 32-state rows, fewer EC additions)
3. Cache hits: when only one supervisor fires, the other pays zero crypto cost

---

### Problem 3 — Flexible Manufacturing System (FMS)

Based on the benchmark from Queiroz & Cury (2000), the canonical example demonstrating why modular DES is necessary.

**Plants (8):**

| Plant | States | Events |
|---|---|---|
| C1 (conveyor 1) | 2 | 11 (load), 12 (unload) |
| C2 (conveyor 2) | 2 | 21 (load), 22 (unload) |
| Lathe | 2 | 41 (start), 42 (finish) |
| PD (part depot) | 2 | 81 (load), 82 (unload) |
| Mill | 3 | 51/52 (type A), 53/54 (type B) |
| C3 (conveyor 3) | 3 | 71/72 (route A), 73/74 (route B) |
| Robot | 6 | 31-39, 30 (10 transfer events) |
| AM (assembly machine) | 4 | 61, 63, 64, 65, 66 |

**Specs (8):** E1–E8 encode buffer/handoff constraints between machines via the Robot.

**Monolithic supervisor:** ~250–400 states (synthesised exactly; exact count printed at runtime), 31 events.

**Local modular supervisors (8 total):**

| Supervisor | Local Plants | States | Own Events | Constraining Ev | Mode |
|---|---|---|---|---|---|
| E1 | C1, Robot | 24 | 12 | 2 | ENC |
| E2 | C2, Robot | 24 | 12 | 2 | ENC |
| E3 | Lathe, Robot | 18 | 12 | 4 | ENC |
| E4 | Mill, Robot | 21 | 14 | 7 | ENC |
| E5 | Robot, AM | 48 | 15 | varies | CLR |
| E6 | Robot, AM | 48 | 15 | varies | CLR |
| E7 | Robot, AM, C3 | 168 | 19 | varies | CLR |
| E8 | C3, PD | 6 | 6 | 4 | ENC |

Supervisors E5, E6, E7 exceed `ENC_THRESHOLD` (32 states) and fall back to cleartext execution. This is noted in the output.

**Why monolithic HE is infeasible for FMS:**
The R-matvec dominates cost. With ~300 states and 31 events, each step requires `31 × avg_enabled_states × 2 EC_adds`. Using `muladd` at ~160ms per call, this exceeds 100 seconds per step. Even with a true EC point addition (~10ms), it would still be ~12 seconds per step. This intractability is the motivating example for modular DES in the literature. The code synthesises the full monolithic supervisor (to get the exact state count), measures the actual muladd cost on the device, and prints an accurate theoretical estimate.

**Simulation sequence:** 11, 12, 31, 32, 41, 42, 35, 36, 61, 63, 64

---

## Architecture and Code Structure

```
Section 1  — Type definitions
           DFA, ProductDFA, AutomatonConfig, ModSupervisor, OracleState

Section 2  — Global state
           Active automaton, supervisor lists, encrypted state vectors,
           crypto context (group, keys, RNG)

Section 3  — DES synthesis engine
           synchronous_product(), coreachable_states(), compact_indices()
           supervisor_to_config(), product_to_mod_supervisor()
           synthesise_automaton()

Section 4  — Crypto primitives
           EC-ElGamal encrypt/decrypt/add
           ec_elgamal_encrypt(), ec_elgamal_decrypt(), ec_elgamal_add()
           free_ct_vec(), copy_enc_zero(), encrypt_values(), decrypt_values()

Section 5  — Homomorphic operators
           sum_row()          — homomorphic dot product of one R row with enc(x)
           matvec_dense()     — full R · enc(x)
           sparse_transition() — B_ev · enc(x) as point copies (zero EC adds)

Section 6  — Problem definitions  ← ONLY SECTION YOU NEED TO EDIT
           define_plants(), define_specs(), define_simulation_sequence()
           for each of the four problems

Section 7  — Cleartext oracle
           next_state_mono_clr(), enabled_mono_clr()
           OracleState::step()

Section 8  — Homomorphic step functions
           step_monolithic_he(), step_lmod_he()

Section 9  — Setup / loop
           EC muladd microbenchmark, synthesis, crypto init,
           benchmark loop, timing summary
```

---

## Key Design Decisions

### One-hot state encoding

The plant state is represented as a vector of `n` ciphertexts, exactly one of which encrypts 1 and the rest encrypt 0. This allows the `B_ev` transition matrix to be applied as a simple reordering of ciphertexts (a permutation), with no EC arithmetic at all.

### Separate oracle state

The cleartext correctness oracle maintains its own independent copy of the state — entirely separate from the homomorphic execution paths. This prevents any accidental sharing between oracle and homomorphic paths that would make the comparison meaningless. The oracle is never timed.

### Per-supervisor encrypted/cleartext mode

Each local modular supervisor is classified at synthesis time:

- **ENC** if `num_states ≤ ENC_THRESHOLD` (32): full homomorphic execution.
- **CLR** if `num_states > ENC_THRESHOLD`: cleartext integer arithmetic.

CLR mode is noted in the output and uses a separate `clr_lmod_exec` state vector that is also fully independent of the oracle.

### R_local only stores constraining rows

After synthesis, rows of `R_local` where every reachable state has the event enabled (all-ones rows) are removed. Such events are never disabled by this supervisor and always contribute `1` to the global enabled intersection. Removing them reduces the number of EC scalar multiplications (decryptions) per step.

---

## Optimisations

### 1. Sparse B matrices (point copies, zero EC additions)

Each supervisor is a DFA: `B_ev` is a **partial permutation matrix** — each column has at most one `1`. Storing it densely would cost `O(n²)` memory per event. Instead, `B_sparse[ev]` stores only `(to, from)` pairs. Applying it homomorphically means:

```
enc_next[to] = enc_state[from]    // point copy, ~0ms
enc_next[s]  = E(0)               // for all s not in B_sparse[ev]
```

No EC arithmetic is needed for the state transition — only point copies. This eliminates a potentially huge cost (for an `n`-state supervisor with `m` events, dense `B_ev` matvec would cost `O(n·m)` EC additions; sparse costs `O(n)` copies).

### 2. R_local row pruning

Events that are always enabled (the supervisor never disables them) are removed from `R_local` at synthesis. The encrypted enabled check is skipped for these events; they contribute `1` to the global enabled vector unconditionally.

**Effect:** Reduces decryptions per step from `num_own_events` to `num_constraining_events`. For FMS supervisors where the Robot's non-spec events pass through unchanged, this eliminates 6–10 unnecessary decryptions per firing.

### 3. Cache: skip crypto when state is unchanged

When the fired event is **not in a supervisor's alphabet**, that supervisor's state cannot change. Its enabled bits are therefore also unchanged. The last computed `cached_en` is reused with zero crypto cost.

**Effect:** Steps where only one supervisor fires (common in the simulation sequences) pay zero cost for all other supervisors.

### 4. ENC_THRESHOLD: memory-bounded execution

Supervisors with more than 32 states would require more heap than is available on the ESP32 when combined with the crypto context and other supervisor state vectors. These fall back to cleartext arithmetic, which is noted clearly in the output. The benchmark still runs and correctness is still verified.

### 5. Memory-gated monolithic HE

The monolithic supervisor is always synthesised fully (up to `MONO_STATE_LIMIT = 500`) to obtain the exact state count. HE execution is enabled only if `num_states × 400 bytes ≤ HE_MEMORY_LIMIT` (180 KB). This ensures synthesis results are always available for theoretical cost estimation even when HE is not run.

### 6. Device-measured theoretical cost estimate

A microbenchmark at startup times 3 actual `muladd` calls and takes the average. This measured cost is used in the theoretical estimate for the monolithic case, making the comparison scientifically accurate rather than based on assumed constants.

---

## Timing Model

All costs are on secp256r1 (NIST P-256) using ESP-IDF's bundled mbedTLS.

| Operation | Cost |
|---|---|
| EC scalar multiplication (encrypt/decrypt) | ~80 ms |
| EC point addition via `muladd` with k=1 | ~160 ms |
| EC point copy | ~0 ms (memcpy of two 32-byte coords) |

**Why `muladd` is expensive for k=1:** `mbedtls_ecp_muladd(grp, R, &one, P, &one, Q)` runs the full Shamir's trick bit loop over 256 bits even when both scalars are 1. There is no special-case optimisation for k=1 in mbedTLS. A true EC point addition (using field arithmetic directly) would be ~2–10ms, but `mbedtls_ecp_add()` is not reliably available across ESP-IDF versions.

**Per step cost breakdown:**

```
sparse_transition:  O(n) point copies                   ~0 ms
matvec(R_local):    num_constraining_rows × (cnt-1) × 160ms   per supervisor
decrypt:            num_constraining_rows × 80ms              per supervisor
```

Where `cnt` is the number of `1`s in an R row (states where the event is enabled). For the simple machine-buffer problems, `cnt = 2` in most rows, giving exactly 1 `muladd` call per row.

---

## Expected Results

### Small Factory

```
Monolithic : ~613 ms/step
LocalMod   : ~613 ms/step
Speedup    : 1.00x
```

Both approaches synthesise the identical supervisor. Equal timing is the correct result.

### Extended Small Factory

```
Monolithic : ~1450 ms/step   (32 states, 6 events, 6 decrypt + matvec)
LocalMod   :  ~870 ms/step   (8-state sups, 2 constraining events each)
Speedup    : ~1.67x
```

The speedup comes from three factors: fewer R rows per step, smaller R matrices (fewer EC additions), and cache hits when only one supervisor fires.

### FMS

```
Monolithic : HE SKIPPED — supervisor has ~250–400 states
             Theoretical cost: >20,000 ms/step (R-matvec dominates)
LocalMod   : ~4500 ms/step (5 ENC supervisors, 3 CLR)
Theoretical speedup: ~5×
```

Monolithic HE is fundamentally infeasible for FMS regardless of optimisations, because the R-matvec cost scales as `num_states × num_events × EC_add_cost`. At ~160ms per EC add and ~300 states, this exceeds 100 seconds per step. This intractability is the defining motivation for modular DES in the literature.

---

## Hardware Requirements

| Requirement | Details |
|---|---|
| Board | ESP32 (tested; any variant with ≥320 KB SRAM) |
| Framework | Arduino with ESP-IDF (standard Arduino-ESP32 board package) |
| Crypto library | mbedTLS (bundled with ESP-IDF, no installation needed) |
| Flash | Standard (sketch is ~50 KB compiled) |
| Serial monitor | 115200 baud |
| RAM | ~200–250 KB heap used at peak (FMS LMod) |

No external libraries are required beyond the standard Arduino-ESP32 package.

---

## How to Use

### 1. Select the problem

In **Section 6** of the sketch, change the `ACTIVE_PROBLEM` line:

```cpp
#define ACTIVE_PROBLEM PROBLEM_SMALL_FACTORY          // default
// #define ACTIVE_PROBLEM PROBLEM_EXTENDED_SMALL_FACTORY
// #define ACTIVE_PROBLEM PROBLEM_FMS
// #define ACTIVE_PROBLEM PROBLEM_CUSTOM
```

### 2. Upload and open Serial Monitor at 115200 baud

### 3. Read the output

Startup prints:
```
[Synthesis] Monolithic: N states, M events [HE OK]
[Synthesis] LMod E: K states, J own ev, C constraining ev (pruned P) [ENC]
...
EC muladd measured: XXXX us
```

Per step:
```
---- Step N | Event: ev ----
  [Oracle]  en=[1,0,1,0,...]    ← cleartext reference (never timed)
  [Mono]    en=[1,0,1,0,...]    ← homomorphic result
  [LMod]    en=[1,0,1,0,...]    ← homomorphic result
  Mono:OK  LMod:OK
```

Summary:
```
============================================
  TIMING SUMMARY
============================================
  Monolithic : XXXXXX ms total  avg XXXX ms/step
  LocalMod   :  XXXXX ms total  avg  XXX ms/step
  LMod speedup vs Mono: X.XXx
  ...
  Mono:PASS  LMod:PASS
============================================
```

---

## Configuration Constants

All three constants are at the top of the sketch, just after the `#include` directives.

| Constant | Default | Purpose |
|---|---|---|
| `MONO_STATE_LIMIT` | 500 | Maximum states during monolithic synthesis before aborting. Raised high enough for FMS to complete. Raise further if a new problem exceeds it. |
| `HE_MEMORY_LIMIT` | 180 × 1024 | Maximum bytes for the monolithic encrypted state vector. If `num_states × 400 > limit`, HE is skipped and only a theoretical estimate is shown. |
| `ENC_THRESHOLD` | 32 | Local modular supervisors with more than this many states fall back to cleartext. Raise if you have more heap; lower if you get allocation failures. |

---

## Adding a Custom Problem

Replace the `PROBLEM_CUSTOM` block in Section 6 and set `ACTIVE_PROBLEM PROBLEM_CUSTOM`:

```cpp
#elif ACTIVE_PROBLEM == PROBLEM_CUSTOM

std::vector<DFA> define_plants() {
    // Return a vector of DFA structs.
    // Use make_machine(name, start_event, finish_event) for 2-state machines.
    // Or define DFAs manually for more complex plants.
    return { make_machine("MA","alpha1","beta1"),
             make_machine("MB","alpha2","beta2") };
}

std::vector<DFA> define_specs() {
    // Return specification DFAs.
    // Use make_buffer(name, fill_event, drain_event) for simple buffers.
    return { make_buffer("BUF","beta1","alpha2") };
}

std::vector<String> define_simulation_sequence() {
    // Return a sequence of event labels to simulate.
    // Each event must be in the global alphabet.
    return {"alpha1","beta1","alpha2","beta2"};
}
```

**Helper constructors:**

- `make_machine(name, start_ev, finish_ev)` — 2-state machine DFA: idle →(start_ev)→ busy →(finish_ev)→ idle.
- `make_buffer(name, fill_ev, drain_ev)` — 2-state buffer DFA: empty →(fill_ev)→ full →(drain_ev)→ empty.

For more complex plants, construct the DFA manually:

```cpp
DFA myPlant;
myPlant.name = "MyPlant";
myPlant.num_states = 3;
myPlant.initial = 0;
myPlant.marked = {true, false, false};
myPlant.transitions = {
    {0, "ev_a", 1},
    {1, "ev_b", 2},
    {2, "ev_c", 0}
};
myPlant.build_delta();
```

---

## Limitations and Known Constraints

**EC point addition performance.** The most significant performance limitation is that `mbedtls_ecp_add()` (true EC point addition, ~2ms) is not reliably available across ESP-IDF versions. The code uses `mbedtls_ecp_muladd()` with scalar `k=1` as a workaround, which costs ~160ms — the same as a full scalar multiplication. A true point add would improve Extended Small Factory from ~870ms to ~170ms per step and make FMS borderline feasible. This requires either a newer ESP-IDF with `mbedtls_ecp_add` exposed, or a manual implementation using raw MPI field operations.

**FMS monolithic HE is intentionally infeasible.** Even with a proper EC point add, the monolithic R-matvec for ~300 states and 31 events would cost roughly 12 seconds per step. This is not a code limitation but a fundamental consequence of the homomorphic scheme's cost model, and is the motivation for local modular DES in the literature.

**FMS supervisors E5, E6, E7 run cleartext.** These supervisors have 48, 48, and 168 states respectively, far exceeding both `ENC_THRESHOLD` and available heap for encrypted storage. They execute correctly in cleartext; their results contribute to the global enabled intersection alongside the encrypted supervisors.

**Nonconflict not verified at runtime.** In formal DES, the local modular approach requires verifying that the supervisors `{S_j}` are nonconflicting (their synchronous product is nonblocking). This is an offline analysis step. The code assumes the supervisors are nonconflicting — which is the case for all three built-in problems as established in the DES literature.

**One-hot state assumption.** The homomorphic protocol assumes the encrypted state vector is always one-hot. This invariant is maintained by the sparse transition operator. It would be violated if a non-existent event were fired (transition leads to a zero vector). The simulation sequences in all built-in problems follow valid traces, so this does not occur in practice.
