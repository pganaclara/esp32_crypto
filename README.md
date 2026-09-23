# Homomorphic DES Supervisor Evaluation on ESP32

Privacy-preserving Discrete Event System (DES) supervisor evaluation using
EC-ElGamal homomorphic encryption on ESP32 microcontrollers — in two forms:

* a **single-board benchmark** that runs every supervisor on one MCU, and
* a **distributed engine** that partitions the supervisors across several nodes,
  each holding only its own encrypted state, under its own key.

The state vector lives only as ciphertext in RAM. The only value ever decrypted
is the single enablement bit (0 or 1) produced by each homomorphic OR-sum.

---

## Contents

1. [What this does](#what-this-does)
2. [Repository layout](#repository-layout)
3. [The pipeline](#the-pipeline)
4. [Quick start](#quick-start)
5. [Problems](#problems)
6. [Architecture](#architecture)
7. [Optimisations](#optimisations)
8. [Distributed operation](#distributed-operation)
9. [**Corrections — three bugs found and fixed**](#corrections)
10. [Benchmark results](#benchmark-results)
11. [Security notes](#security-notes)
12. [Notebook guide](#notebook-guide)
13. [Key design decisions](#key-design-decisions)
14. [Verification status](#verification-status)
15. [References](#references)

---

## What this does

In Supervisory Control Theory a supervisor observes the current state of a plant
and decides which events to enable or disable. Normally this requires knowing the
state in plaintext.

This project performs the same computation **homomorphically**: state cells are
encrypted with EC-ElGamal, transitions are applied as ciphertext permutations,
and enablement is evaluated by homomorphically OR-ing the enabled cells and
decrypting only the resulting bit. The state distribution itself is never
decrypted on the normal run path.

---

## Repository layout

```
homomorphic-esp32-ultrades/
├── README.md                              this file
│
├── homomorphic-esp32-ultrades.ino         SINGLE-BOARD benchmark sketch
├── supervisor_data_small_factory.h         generated supervisor data
├── supervisor_data_extended_small_factory.h
├── supervisor_data_fms.h
│
├── des_distributed/                        DISTRIBUTED engine (its own sketch)
│   ├── des_distributed.ino                   ESP32 entry point (config only)
│   ├── des_generic.h                         the engine — no Arduino/ESP-IDF
│   ├── des_transport.h                       UDP/IP multicast transport
│   ├── host_main.cpp                         POSIX entry point
│   ├── secrets.example.h                     template for secrets.h (Wi-Fi + cell key;
│   │                                         secrets.h itself is in .gitignore)
│   ├── README.md                             design, protocol, transport analysis
│   └── supervisor_data_*.h                   hard links to the root copies
│
├── notebook/
│   └── generator_ultrades.ipynb            synthesise supervisors → .h
│
└── docs/
    └── code-explained.md                   detailed walkthrough + references
```

Both `.ino` files sit in a folder whose name matches the sketch, which Arduino
requires. The root doubles as the single-board sketch folder — that is why the
generated headers live at the top level rather than in a `data/` subdirectory.

---

## The pipeline

```
  notebook/generator_ultrades.ipynb
        │  UltraDES: synthesise monolithic + local-modular + reduced supervisors
        │  Cell 6b:  VALIDATE the simulation trace against those supervisors
        │  Cell 7:   emit C arrays
        ▼
  supervisor_data_<PROBLEM>.h          PROGMEM arrays, no runtime parsing
        │
        ├──────────────► homomorphic-esp32-ultrades.ino   one board, all supervisors
        │
        └──────────────► des_distributed/                 N boards, one partition each
```

---

## Quick start

### 1. Generate a header

Open `notebook/generator_ultrades.ipynb` in Jupyter or Colab, set `PROBLEM` in
**Cell 3**, and Restart & Run All. Cell 7 writes
`supervisor_data_<PROBLEM>.h` into the working directory — copy it to the repo
root, replacing the existing one.

Cell 6b will refuse to emit a header whose simulation sequence the supervisors
disable. That check is the whole reason the FMS data was wrong before; see
[Corrections](#corrections).

### 2a. Single-board benchmark

1. Point the include at your problem:
   ```cpp
   #include "supervisor_data_fms.h"
   ```
2. Arduino IDE → **ESP32 Dev Module**, defaults are fine, Serial **115200**, flash.

On an **ESP32-S3**, set `USB CDC On Boot: Enabled` if you are on the native USB
port, or leave it `Disabled` if you are on the UART port. Getting this wrong is
silent: the ROM bootloader banner appears but nothing else does, because the
second-stage bootloader and the sketch print to a different console than the ROM.

No `sdkconfig` file is needed — see [On sdkconfig files](#on-sdkconfig-files).

### 3. Distributed engine

See [`des_distributed/README.md`](des_distributed/README.md). Set
`DES_DATA_HEADER`, `DES_NODE_ID`, `DES_NUM_NODES` and the transport at the top
of `des_distributed.ino`, then flash each board with a different `DES_NODE_ID`.

---

## Problems

### `small_factory`
Two machines connected by a one-slot buffer.

```
M1 ──e1(start)──► busy ──e2(finish)──► idle
M2 ──e3(start)──► busy ──e4(finish)──► idle
Buf: empty ──e2──► full ──e3──► empty
```
4 events · 1 spec · 1 local-modular supervisor · monolithic 6 states

### `extended_small_factory`
Three machines, two buffers.

```
M1 ──a1/b1──► [B1] ──► M2 ──a2/b2──► [B2] ──► M3 ──a3/b3──►
```
6 events · 2 specs · 2 supervisors · monolithic 18 states

This is the clearest case for distribution: `S0` guards B1, `S1` guards B2, and
only `a2`/`b2` are shared — 4 of 6 events need no communication at all.

### `fms` — Flexible Manufacturing System (Queiroz & Cury 2000)
Eight machines (C1, C2, Lathe, Mill, Robot, AM, C3, PD) with eight buffer and
routing specifications. E7 and E8 share events through the plant and are composed
as `E78 = E7 ∥ E8` before synthesis to resolve their conflict.

31 events · 7 specs · 7 supervisors · largest S6 at 164 states · monolithic too
large for flash (omitted automatically)

---

## Architecture

### Encryption

Textbook EC-ElGamal on **NIST P-192** (secp192r1):

```
Setup:  priv ← random in [1, N-1]
        Y    = priv · G                  (public key)

Enc(m): r    ← random
        c1   = r · G
        c2   = m · G + r · Y             (ciphertext is (c1, c2))

Dec:    m·G  = c2 − priv · c1
        m    = 0 iff m·G is the point at infinity
```

Each ciphertext is **50 bytes** (two 25-byte compressed points). The 96-bit
security level is well beyond any feasible attack.

### Homomorphic operations — additions only

EC-ElGamal is additively homomorphic on the message: `Enc(a) + Enc(b)` decrypts
to `(a+b)·G`. The runtime path never multiplies homomorphically — only point
additions via `mbedtls_ecp_muladd` with both scalars 1. Scalar multiplications
happen only inside `elgamal_enc` (once per cell, at setup) and in the final
decrypt of each row.

For binary messages `is_zero(m·G)` holds iff `m ≡ 0 (mod N)`. We never sum more
than a few cells, so the sum stays far below N and the homomorphic addition acts
as a **logical OR**. That is exactly the question being asked: the enable row's
OR-sum over the state vector is 1 iff the active state is in the enabled set.

### State representation

Per supervisor:

| Field | Type | Purpose |
|---|---|---|
| `enc[n]` | `Ciphertext` (50 B) | compressed state cells |
| `dec_c1[n]`, `dec_c2[n]` | `mbedtls_ecp_point` | decompressed mirror of `enc` |
| `cached_en[]` | `int8_t` | last decrypted value of each constrained row |
| `changes_if_zero[ev]` / `changes_if_one[ev]` | `vector<uint8_t>` | rows that may flip under `ev` |

The decompressed mirror is kept in lock-step with `enc` so the hot path never
runs `pt_decompress` (a modular square root).

### Transition

When event `ev` fires, the next state set is the **image** of the current one:

```
nxt[t] = ⋃ { enc[f] : (f,t) is a transition on ev }
nxt[s] = Enc(0)   for any state s that is not a transition target
```

Implemented as ciphertext copies plus a cheap MPI deep-copy of the decompressed
mirror. Sources holding the literal `Enc(0)` are skipped — they contribute
nothing to a union — so the common case costs exactly one copy per pair. In the
rare case where two *active* sources converge on one target, they are combined
with the additive homomorphism.

> That union is not a stylistic detail. Writing `nxt[t] = enc[f]` instead was a
> real bug in this codebase — see [Corrections](#corrections).

---

## Optimisations

Five layered optimisations bring the heavy steps from ~33 s (naive) to ~1 s:

| # | Optimisation | What it does |
|---|---|---|
| 1 | **Conditional invariance** | At load time, for each `(sup, event, row)` we precompute whether the row sum can flip `0→1`, `1→0`, both, or neither. At runtime only rows whose direction matches the cached value are re-decrypted. |
| 2 | **Persistent decompressed cache** | `mbedtls_ecp_point` mirrors of every cell, updated by `mbedtls_ecp_copy` instead of `pt_decompress` in the hot path. |
| 3 | **Skip-`g_zero` summands** | After a transition most cells are byte-equal to the global `g_zero`. `row_decrypt` skips them — typical rows sum 1–2 cells instead of dozens. |
| 4 | **Fused row-sum + decrypt** | One `mbedtls_ecp_muladd(pm, -priv, c1, 1, c2)` does the secret scalar mul and the final add together. |
| 5 | **Dual-core work split** | Phase 1 applies transitions and enqueues work units; phase 2 splits the queue across both cores via a persistent worker task. Measured gain: 8–10 %, not 2× — mbedTLS serialises scalar muls on the one MPI peripheral. |
| 6 | **Share identical row sums** | A row's homomorphic sum is determined by which non-`Enc(0)` cells it covers. Once that set contracts to the active cell, every row covering it has the *same* sum. Rows are grouped by summand set, each set decrypted once, the result fanned out. 2.7–4.6× on `fms`. |

Optimisation 3 is also what makes the union-correct transition free: a cell equal
to `g_zero` is skipped as a source, so it can never overwrite an active cell.

---

## Distributed operation

`des_distributed/` runs the same homomorphic core, but each node holds **only
its own supervisors**, encrypted under **its own keypair**. No ciphertext ever
crosses the network — only single enablement bits — so the nodes never need a
shared key: no distributed key management, no threshold crypto, no re-encryption.

Routing is derived at boot from the generated header. An event relevant to one
node only is decided locally with zero traffic; an event relevant to several
requires agreement:

| event class | mechanism | frames |
|---|---|---|
| local | apply locally | **0** |
| shared + controllable | `REQ → VOTE* → COMMIT → ACK*` (any participant may veto) | 2 + 2p |
| shared + uncontrollable | `NOTIFY → ACK*`, retransmitted until acknowledged | 1 + p |

An uncontrollable event cannot be vetoed — SCT says a supervisor may not disable
one, and by the time a node hears of it the plant has already done it.

Transport is pluggable because reliability is **end-to-end** (Saltzer, Reed &
Clark 1984): the protocol supplies sequencing, acknowledgement, retransmission
and atomicity, so a transport only has to be best-effort. Default is **UDP/IP
multicast** (RFC 1112) — open, brokerless, portable, and the same substrate OPC
UA PubSub and DDS use. ESP-NOW was implemented and then removed as
vendor-specific; an MQTT binding was removed because it was never tested
against a live broker.

Full design, protocol and transport analysis:
[`des_distributed/README.md`](des_distributed/README.md).

---

<a name="corrections"></a>
## Corrections — three bugs found and fixed

These were found by cross-checking the generated data against the supervisors it
claims to represent. All three were silent: nothing crashed, and the benchmark
reported `PASS` throughout.

### 1. Transitions were an assignment, not a union — **affects results**

**What it was.** Both `do_transition` (ciphertext) and `Oracle::step`
(cleartext) applied an event as:

```c
nxt[to] = enc[from];      // for each (from,to) pair, in emission order
```

**Why it is wrong.** The image of a state set under an event is a *union*.
Several source states may converge on the same target — `supervisor_data_fms.h`
has **11 such collisions** in its reduced supervisors — and plain assignment lets
whichever pair the generator emitted *last* win. So an **inactive** source
silently overwrites an **active** one.

**Why nobody noticed.** The cleartext oracle made the identical mistake. The
benchmark compares homomorphic output against that oracle, both took the same
wrong transition, they agreed, and it printed `PASS`. The comparison was
certifying nothing.

**How it surfaced.** Regenerating `supervisor_data_fms.h` relabelled the states
of one reduced supervisor — an isomorphic automaton, same behaviour — which
reordered the emitted pairs. The benchmark results changed. Two semantically
identical headers producing different results is only possible if something is
order-dependent.

**Impact, measured.** On the current FMS header, over the 44-step sequence:

| family | steps where the buggy version reports different enablement | order-stable? |
|---|---|---|
| FULL LMOD | 0 / 44 | assignment: yes |
| **REDUCED** | **21 / 44** | assignment: **no** · union: yes |

`small_factory` and `extended_small_factory` have no colliding targets and are
unaffected. FMS **reduced** — the default family for the distributed engine, and
one of the three single-board benchmarks — was materially wrong.

**Fix.** Skip sources holding `Enc(0)` (they contribute nothing to a union, so
they cannot clobber an active cell); combine genuinely converging active sources
with the additive homomorphism. The oracle now uses `|=`. Applied to both
`homomorphic-esp32-ultrades.ino` and `des_generic.h`. Verified order-stable
under shuffled pair orderings.

### 2. The generated `SIM_SEQ` for FMS was not executable — **affects results**

**What it was.** `sim_seq` is hand-written per problem in Cell 4, and Cell 7
serialised it verbatim:

```python
sim_idx = [gevents.index(ev) for ev in sim_seq]
lines.append(c_array_u16('SIM_SEQ', sim_idx))
```

Nothing checked it against the supervisors Cell 6 had just synthesised.

**The break.** Step 9 fired event `39`, which supervisor `S3` (spec `E4`)
disables. `E4` only permits `39` after `54` — the Mill finishing operation B —
and the hand-written trace never ran the Mill at all: no `51`, `52`, `53` or `54`
appears anywhere in it. At that point only `11` and `21` were enabled, and the
remaining 7 steps were all downstream of the break.

**Why nobody noticed.** The single-board sketch fires each `SIM_SEQ` event
unconditionally, then compares against the oracle. Both made the same forbidden
transition, so they agreed.

**Fix.** A corrected 44-event sequence (all 31 events covered, returns to the
initial state) is now in Cell 4, and a new **Cell 6b** replays `sim_seq` against
the synthesised supervisors and refuses to let Cell 7 emit an inadmissible one —
reporting the failing step, the blocking supervisor, and what was enabled
instead. It can also synthesise a valid replacement. `supervisor_data_fms.h` has
been regenerated: `SIM_SEQ_LEN` 17 → 44, and the validator now replays it with
**zero skipped steps** (132 events over 3 cycles, against 23 before).

The distributed engine additionally gates every scripted step on admissibility
and skips rather than corrupting state.

### 3. An always-disabled event would have been emitted as unconstrained — latent

`own_events` was derived from the transitions that *survived* synthesis, while
Cell 7 emits an all-**ones** row ("never constrains this") for any global event
missing from `enablement`. Those two rules disagree about an event in the
supervisor's alphabet that supC disables in **every** state: it has no
transitions left, drops out of `own_events`, and would be emitted as permanently
**enabled** — the exact inverse of the supervisor's decision.

Cell 5 now takes the alphabet from `sup.Events`, so such an event gets an
all-**zero** row, which the firmware already understands as permanently disabled.
There is a fallback with a warning for UltraDES builds that do not expose
`.Events`.

Checked against the current headers: **no all-zero rows exist**, so this case
does not occur in any of the three problems today. It is closed for future ones.

### Also worth knowing: supervisor reduction is not deterministic

Regenerating FMS produced a `S4_red` with states `1,2,3,4` cyclically permuted —
an isomorphic automaton, verified by recovering the permutation. Diffing two
generated headers will therefore show changes that mean nothing. Compare
transition *sets* per event, not raw arrays.

---

## Benchmark results

Measured on **ESP32-S3** @ 240 MHz, Arduino core 3.3.8, secp192r1, scalar
blinding on. All nine runs `Result: PASS` — every homomorphic enablement vector
matched the cleartext oracle at every step.

These supersede all earlier figures. They are the first taken after the three
corrections in [Corrections](#corrections) *and* after optimisation 6.

```
[Crypto] muladd = 5 ms      scalar_mul = 69 ms
```

| problem | family | sups | ciphertext | warm-up | avg/step | min | max | decryptions |
|---|---|---|---|---|---|---|---|---|
| `small_factory` | monolithic | 1 | 300 B | 237 ms | 77.8 ms | 74.9 | 85.4 | 4 |
| 4 events, 4 steps | local modular | 1 | 300 B | 239 ms | 77.5 ms | 74.8 | 85.0 | 4 |
| | **reduced** | 1 | **100 B** | 189 ms | **37.5 ms** | 0.16 | 74.9 | **2** |
| `extended_small_factory` | monolithic | 1 | 900 B | 487 ms | 94.4 ms | 75.5 | 126.1 | 7 |
| 6 events, 6 steps | local modular | 2 | 600 B | 513 ms | 91.4 ms | 74.9 | 120.6 | 8 |
| | **reduced** | 2 | **200 B** | 352 ms | **50.0 ms** | 0.18 | 75.0 | **4** |
| `fms` | monolithic | — | *omitted, exceeds flash* | | | | | |
| 31 events, 44 steps | local modular | 7 | 16 350 B | 12 358 ms | 335.4 ms | 75.4 | 1 423.7 | 190 |
| | **reduced** | 7 | **1 850 B** | 4 917 ms | **233.9 ms** | 0.19 | 916.4 | **145** |

### The cost model, confirmed on every problem

Time per decryption, across all eight runs: 68.6, 71.0, 75.0, 75.1, 77.5, 77.7,
77.8, 80.9 ms — against a measured 69 ms for a single scalar multiplication.

**Runtime is `decryptions × scalar_mul`, to within overhead.** That holds across
three problems spanning 4 to 31 events and 1 to 7 supervisors. Everything the
firmware does besides the scalar multiplication is noise, so the only software
lever that matters is reducing the *count* of decryptions.

Steps needing no decryption at all cost ~0.2 ms — conditional invariance (§1)
working exactly as intended.

### Optimisation 6, and the anomaly that produced it

Before optimisation 6, `fms` REDUCED was **slower** than the full family, which
is the opposite of what reduction promises:

| `fms` | before opt. 6 | after | gain |
|---|---|---|---|
| local modular | 916.6 ms/step, 576 dec. | **335.4 ms, 190 dec.** | 2.7× |
| reduced | 1 078.8 ms/step, 745 dec. | **233.9 ms, 145 dec.** | 4.6× |

Chasing that anomaly is what exposed the redundancy. A decryption is charged only
when a row answers *enabled*, because `row_decrypt` short-circuits for free when
every cell of the row's enabled set is the literal `Enc(0)`. Reduction packs the
same control information into fewer states, so its rows are much denser
(mean `|A|/n` 41.9 % against 17.1 %) and answer "enabled" far more often — 79.4 %
of enqueued rows against 60.1 %. Every one of those cost a separate 69 ms scalar
multiplication, even though, once the non-zero mask has contracted to the active
cell, they were all summing **the same single ciphertext**.

Optimisation 6 groups rows by their summand set and decrypts each distinct set
once. REDUCED benefits more precisely because it had more redundancy to remove,
and the ordering flips back to the expected one: **reduced is now the fastest
family on all three problems**, roughly 2× faster than local modular.

### Monolithic is not slower per step — it is simply infeasible at scale

On `small_factory` the monolithic and local-modular supervisors are the same
automaton, and the numbers agree (77.8 vs 77.5 ms). On
`extended_small_factory` the monolithic is marginally *cheaper* per step (94.4 ms
over 7 decryptions vs 91.4 ms over 8), because one 18-state supervisor answers
what two 6-state ones answer jointly.

The case for local-modular decomposition is therefore **not** per-step speed. It
is tractability: the `fms` monolithic supervisor does not fit in flash and is
omitted automatically, while its seven local-modular supervisors run comfortably.
It is also what makes the distributed partition possible at all.

### The dual-core split delivers little

Per-decryption cost is ~68.6–71.0 ms on the dual-core runs and ~75.1–80.9 ms on
the single-core ones — roughly 8–10 %, not the 2× the split suggests. mbedTLS
serialises every scalar multiplication on the single MPI peripheral, so the
second core spends most of its time waiting. Reported as a negative result: the
parallelisation is correct and the hardware defeats it.

### What limits performance

EC scalar multiplication: **69 ms** per call. The `fms` local-modular worst step
needs 15 decryptions after optimisation 6 (it needed 36 before), giving the
1 423.7 ms maximum. There are only two levers left: fewer decryptions, or cheaper
scalar multiplication — which means different silicon.

### The ESP32-S3 does *not* have an ECC accelerator

An earlier version of this README claimed the S3 would reach ~10 ms per scalar
multiplication via a dedicated ECC engine. **That is wrong.** Checked against the
SoC capability headers shipped with Arduino core 3.3.8:

| chip | `SOC_ECC_SUPPORTED` | `CONFIG_MBEDTLS_HARDWARE_ECC` |
|---|---|---|
| ESP32 | no | — |
| ESP32-S3 | **no** | — |
| ESP32-C3 | no | — |
| **ESP32-C6** | **yes** | **enabled** |
| **ESP32-H2** | **yes** | **enabled** |

The S3 has the RSA/MPI accelerator, AES and SHA, but no elliptic-curve unit. The
measured 69 ms versus ~91 ms on the WROOM-32 is the modest gain you get from a
newer MPI peripheral, not a hardware ECC path.

If scalar-multiplication cost is the thing to attack, the target is the
**ESP32-C6**: its SoC has the ECC unit *and* the core's prebuilt mbedTLS already
enables `CONFIG_MBEDTLS_HARDWARE_ECC`, so the acceleration is used without any
configuration. The ESP32-H2 has the same unit but no Wi-Fi (802.15.4/BLE only),
which rules out the UDP multicast transport in `des_distributed` unless routed
over Thread. Both are single-core RISC-V with less RAM — which, per the section
above, costs nothing here.

### On sdkconfig files

The repository used to ship an `sdkconfig.ext` asking for mbedTLS hardware
acceleration, with a comment claiming the firmware ran "5× slower" without it.
It had **no effect in an Arduino IDE build** and has been removed. The core
ships precompiled mbedTLS libraries and does not rebuild them from a
sketch-folder file. The shipped `sdkconfig.h` shows `CONFIG_MBEDTLS_HARDWARE_MPI`
and `CONFIG_MBEDTLS_ECP_NIST_OPTIM` **already enabled by default** — which is why
performance never depended on it — while `CONFIG_MBEDTLS_ECP_FIXED_POINT_OPTIM`
and `CONFIG_MBEDTLS_MPI_WINDOW_SIZE`, which it also asked for, are not applied at
all. Such a file would matter only in an ESP-IDF build.

---

## Security notes

The cryptography is solid: textbook EC-ElGamal, standard NIST curve,
hardware-RNG entropy. The firmware is **research-grade**. By default one of
three side-channels is closed; the other two require physical RAM access.

| # | Channel | Status | If exploited |
|---|---|---|---|
| 1 | Timing / power on the private scalar | **Closed by default** — every scalar mul is blinded via per-core CTR-DRBG | Private-key recovery |
| 2 | `g_zero` byte-equality — inactive cells are byte-identical to a global `Enc(0)` | **Open** | Reveals the active-state index after each transition |
| 3 | Active-ciphertext propagation — the active cell's bytes are copied unchanged | **Open** | Fingerprints the state trajectory over time |

Channels 2 and 3 are open by design. Closing them means re-randomising every
cell after every transition, so that no ciphertext is byte-identical to another
or to a global constant. That costs roughly two scalar multiplications per cell
per transition — on the order of 140 ms each on this hardware — which for the
`fms` local-modular family means tens of seconds per step. A pre-computed
`Enc(0)` pool would reduce it to one point-add per cell. Neither is implemented.

Note the interaction with optimisation 3: the skip-`Enc(0)` short-circuit is
fast *because* inactive cells are byte-identical to `g_zero`. The speed and the
leak are the same mechanism.

**In the distributed engine** there is an additional, transport-level leak: the
state is encrypted, but the *fact* that a shared event was requested — and when —
is visible on the wire. Frames are fixed-size so length reveals nothing, but
traffic analysis still sees the event timing. Link encryption plus cover traffic
would be the next step.

---

## Notebook guide

| Cell | Purpose |
|------|---------|
| 1 | Install .NET runtime + UltraDES-Python (Linux/Colab) |
| 2 | Import UltraDES automata primitives |
| 3 | **Set `PROBLEM` here** — normally the only cell you edit |
| 4 | Plant + spec DFA definitions, and the per-problem `sim_seq` |
| 5 | Extract UltraDES DFA → Python dict (alphabet from `DFA.Events`) |
| 6 | Synthesis: monolithic + local-modular + local-modular-reduced |
| **6b** | **Validate `sim_seq` against the synthesised supervisors; refuse to emit an inadmissible one, or synthesise a replacement** |
| 7 | Emit `supervisor_data_<PROBLEM>.h` as PROGMEM C arrays |

### Generated `.h` layout

Per supervisor (`lmN_` local modular, `lmrN_` reduced, `mono_` monolithic):

| Array | Type | Size | Content |
|---|---|---|---|
| `<prefix>init` | `int8_t` | `n` | one-hot initial state |
| `<prefix>enable` | `int8_t` | `ne × n` | flat enablement matrix |
| `<prefix>tcnt` | `uint16_t` | `ne` | `(from,to)` pair count per event |
| `<prefix>trans` | `int16_t` | `2 × Σtcnt` | flat pairs grouped by event |

`SupDesc` bundles a name pointer, `num_states` and the four array pointers. The
firmware iterates `LMOD_SUPS[]` / `LMOD_RED_SUPS[]` at runtime.

The monolithic supervisor is omitted automatically when its footprint would
exceed `MONO_FLASH_LIMIT` (1.2 MB); `HAS_MONO` tells the firmware.

**The header does not record controllability.** The single-board sketch does not
need it; the distributed engine does (it decides vote-vs-notify) and infers it
from event labels, printing what it inferred at boot. Override with
`DES_CONTROLLABLE_MASK`.

---

## Key design decisions

**Why EC-ElGamal and not BFV / CKKS?** EC-ElGamal needs only scalar
multiplication and point addition, both provided by mbedTLS with hardware MPI
acceleration. Lattice schemes are fully homomorphic but need kilobytes of key
material and are not in mbedTLS.

**Why secp192r1?** Smallest standard NIST curve in mbedTLS (smallest scalar mul)
*and* it benefits from `MBEDTLS_ECP_NIST_OPTIM` fast reduction. 96-bit security
is well beyond feasible attack. Switching to secp256r1 is two lines (`CURVE`,
`PT_LEN`).

**Why additive-only homomorphism?** EC-ElGamal is mathematically only additively
homomorphic. Multiplication would need a pairing-friendly curve and bilinear
pairings, 10–100× slower. Supervisor evaluation needs only OR, which additive HE
plus an `is_zero` check provides.

**Why a persistent decompressed cache?** `pt_decompress` runs a modular square
root (~5–10 ms). Without caching the hot path does 1000+ decompressions per heavy
step.

**Why PROGMEM C arrays instead of JSON?** JSON needs runtime parsing into a heap
DOM (~3× the raw size). PROGMEM arrays are read straight from flash with zero
heap and zero parse time.

**Why per-node keypairs in the distributed engine?** Because no ciphertext ever
crosses the network — only decrypted bits — nodes never need a shared key. This
falls out of the local-modular decomposition and is the main privacy argument for
distributing at all.

---

## Verification status

Being explicit about what has and has not been checked:

| | status |
|---|---|
| Single-board sketch compiles | **verified** — `-Wall -Wextra`, zero warnings, against all three headers, ESP32 core 3.3.8 |
| Distributed engine compiles | **verified** — same flags, across problems × 1/2/3/7 nodes × 3 families × 3 transports × 2 drivers |
| Distributed protocol logic | **verified on host** — replayed against the real generated arrays for all problems; 0 silent divergences under injected loss up to 70 % |
| Notebook Cell 6b logic | **verified** — executed against real supervisor data; rejects the old FMS sequence, accepts the new one |
| Union fix is order-stable | **verified** — traces unchanged under shuffled pair orderings |
| `host_main.cpp` POSIX build | **verified** — built with g++ 13 on Ubuntu and run as several nodes over real UDP multicast (see `des_distributed/README.md`). Guarded by `#if !defined(ARDUINO)`, so it is inert under the Arduino build |
| Real hardware | **run on ESP32-S3** — all three problems, every family, nine runs, all `PASS`. Single run each; no variance reported. |
| Optimisation 6 correctness | **verified** — an independently written cost model predicted 190/145 decryptions *before* the change; hardware produced 190/145, matching step by step across all 44 steps of both families |

---

## References

A detailed walkthrough of every layer — the data model, the cryptography, the
homomorphic evaluation, each optimisation, the distributed protocol and the
threat model — with the literature behind each decision, is in
[`docs/code-explained.md`](docs/code-explained.md).

- Queiroz, M. H., & Cury, J. E. R. (2000). *Modular supervisory control of large
  scale discrete event systems.* Discrete Event Systems, 269–278.
- Rudie, K., & Wonham, W. M. (1992). *Think globally, act locally: decentralized
  supervisory control.* IEEE TAC 37(11).
- ElGamal, T. (1985). *A public key cryptosystem and a signature scheme based on
  discrete logarithms.* IEEE Trans. Information Theory 31(4), 469–472.
- Saltzer, J. H., Reed, D. P., & Clark, D. D. (1984). *End-to-End Arguments in
  System Design.* ACM TOCS 2(4).
- Rosenkrantz, D. J., Stearns, R. E., & Lewis, P. M. (1978). *System level
  concurrency control for distributed database systems.* ACM TODS 3(2) —
  wound-wait.
- UltraDES: https://github.com/lacsed/UltraDES-Python
- mbedTLS ECP: https://mbed-tls.readthedocs.io/en/latest/

Further reading on distributing supervisors over real networks, and the transport
comparison, is in [`des_distributed/README.md`](des_distributed/README.md).
