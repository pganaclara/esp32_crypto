# Code, explained in detail

A walkthrough of every layer of this project, with the reasoning behind each
design decision and the literature it rests on. Written to be usable as raw
material for a paper.

Citations are keyed `[n]` to the [References](#references) at the end. Everything
cited there was checked against an accessible source; the two entries whose
author lists could not be confirmed are marked as such rather than guessed.

---

## Contents

- [0. Reading order](#0-reading-order)
- [1. The data model — what the notebook emits](#1-the-data-model)
- [2. The cryptographic layer](#2-the-cryptographic-layer)
- [3. Homomorphic supervisor evaluation](#3-homomorphic-supervisor-evaluation)
- [4. The six optimisations, and what they really cost](#4-the-six-optimisations)
- [5. The distributed engine](#5-the-distributed-engine)
- [6. The verification apparatus](#6-the-verification-apparatus)
- [7. Threat model and limitations](#7-threat-model-and-limitations)
- [References](#references)

---

## 0. Reading order

| Read this | To understand |
|---|---|
| `supervisor_data_*.h` (any one) | the data model — everything else consumes it |
| `homomorphic-esp32-ultrades.ino` | the homomorphic core, single board |
| `des_distributed/des_generic.h` | the same core, plus partitioning and the protocol |
| `des_distributed/des_transport.h` | how frames get to the other nodes |
| `notebook/generator_ultrades.ipynb` | where the data comes from |

The single-board sketch and the distributed engine share the same cryptographic
core essentially verbatim. Read the sketch first; the engine adds distribution on
top of an identical inner loop.

Measured end state, ESP32-S3, all families `PASS` against the cleartext oracle:
37.5 ms per step on `small_factory`, 50.0 ms on
`extended_small_factory`, 233.9 ms on `fms` (44-step trace, 7 supervisors,
largest 164 states). Full tables in §4.6.

---

## 1. The data model

### 1.1 What a supervisor is, concretely

Supervisory Control Theory (SCT), due to Ramadge and Wonham [1], models a plant
as an automaton over an event alphabet Σ partitioned into **controllable** events
Σ_c (which a supervisor may disable) and **uncontrollable** events Σ_u (which it
may not). A supervisor is itself an automaton; at each moment its state
determines which events it permits. Synthesis computes the *supremal controllable
sublanguage* — the most permissive behaviour that satisfies the specification
without ever needing to disable an uncontrollable event.

The notebook runs that synthesis in UltraDES and flattens each resulting
automaton into four arrays.

### 1.2 The four arrays

For a supervisor with `n` states over `EVENT_COUNT` global events:

```c
struct SupDesc {
    const char*     name;        // label
    uint16_t        num_states;  // n
    const int8_t*   init;        // [n]                one-hot initial state
    const int8_t*   enable;      // [EVENT_COUNT * n]  enablement matrix
    const uint16_t* tcnt;        // [EVENT_COUNT]      pair count per event
    const int16_t*  trans;       // [2 * Σ tcnt]       flat (from,to) pairs
};
```

**`init`** is a one-hot indicator vector: `init[s] = 1` for exactly the initial
state. This is deliberate — see §3.1.

**`enable[gi * n + s]`** is 1 iff the supervisor permits global event `gi` when
in state `s`. The row-major layout (`event` major, `state` minor) matters: the
hot path always reads one whole row for a fixed event, so this gives contiguous
access.

An important convention: a row that is **all ones** means "this supervisor does
not constrain this event at all". A supervisor only constrains the events in its
own alphabet; for every other global event the generator emits all-ones, so the
conjunction across supervisors (§5.3) works without any special-casing.

Measured ciphertext held per family on `fms`: 16 350 B for the seven
local-modular supervisors against 1 850 B for the reduced ones — 8.8×, the one
dimension where reduction delivers exactly what it promises (§4.7 covers the
dimension where it does not behave as expected).

**`tcnt[gi]`** is how many `(from,to)` pairs event `gi` has, and **`trans`** is
those pairs concatenated in event order. `trans_offset()` recovers the start of
event `gi`'s block by summing `tcnt[0..gi-1]`. This is a compressed sparse format:
storing a full `n × EVENT_COUNT` transition matrix for FMS's S6 (164 states, 31
events) would be 5084 entries, against 553 actual transitions.

### 1.3 Why PROGMEM C arrays instead of JSON

The arrays are declared `PROGMEM` and read with `pgm_read_byte` / `pgm_read_word`.
On ESP32 this is flash-mapped `.rodata` read directly in place. A JSON
representation would need a runtime parser and a heap-allocated DOM of roughly
three times the raw size — on a device where the interesting constraint is RAM
(each encrypted state cell costs 50 bytes of ciphertext plus two decompressed EC
points), that is not affordable.

### 1.4 What the header does *not* carry

**Controllability.** The header records which events each supervisor *permits*,
but not which events are controllable in the first place. The single-board sketch
does not need this — it only evaluates enablement. The distributed engine does,
because controllability decides whether an event can be put to a vote (§5.4), so
`derive_controllable()` infers it from event labels and prints what it inferred
at boot. Override with `DES_CONTROLLABLE_MASK`.

This is worth stating explicitly in any write-up: controllability is a modelling
input that survives synthesis only implicitly, and re-deriving it downstream is a
place where an implementation can silently diverge from its model.

---

## 2. The cryptographic layer

### 2.1 The scheme: lifted (exponential) EC-ElGamal

The code uses **lifted ElGamal over an elliptic curve**, also called *exponential*
ElGamal. Textbook ElGamal [2] is *multiplicatively* homomorphic: the message is a
group element and `Enc(a)·Enc(b)` decrypts to `a·b`. Lifted ElGamal instead puts
the message in the exponent — on an elliptic curve, as a scalar multiple of the
generator — which makes it **additively** homomorphic [11].

With group `⟨G⟩` of prime order `N` on secp192r1:

```
KeyGen:  priv ←$ [1, N-1],          Y = priv · G
Enc(m):  r ←$ [1, N-1]
         c1 = r · G
         c2 = m · G + r · Y
Dec:     M  = c2 − priv · c1  =  m · G
```

Additive homomorphism is immediate:

```
(c1,c2) + (c1',c2') = (r+r')·G , (m+m')·G + (r+r')·Y      →  Dec = (m+m')·G
```

The code performs this addition with `mbedtls_ecp_muladd(R, 1, P, 1, Q)` — that
is, a point addition expressed as a degenerate multiply-add, because mbedTLS
exposes no bare point-add in its public API.

### 2.2 The crucial restriction, and why it does not bite here

Decryption recovers `m·G`, not `m`. Getting `m` back requires solving the
elliptic-curve discrete logarithm problem, which is why lifted ElGamal is
normally described as practical only for a small message space, recovered by
lookup table or baby-step/giant-step [11].

**This implementation never solves the ECDLP at all.** Every question it asks is
of the form *"is this event enabled?"*, whose answer is a single bit, and the bit
is obtained by testing whether `m·G` is the point at infinity:

```c
*out = mbedtls_ecp_is_zero(&pm) ? 0 : 1;
```

`m·G = O` iff `m ≡ 0 (mod N)`. So the operation is a **zero test**, not a
decryption — an `O(1)` comparison rather than a discrete-log search. That is the
single most important reason lifted EC-ElGamal is a good fit for DES supervision
specifically, and it is worth foregrounding in a paper: supervisory decisions are
Boolean, so the scheme's main practical weakness never materialises.

What it costs in practice: one blinded scalar multiplication, measured at
**69 ms** on ESP32-S3, and that single operation accounts for essentially the
whole runtime (§4.6). A supervisory decision therefore costs one scalar
multiplication — 37.5 ms per step on `small_factory`, 233.9 ms on `fms`.

The soundness condition is that the summed `m` never wraps modulo `N`. Rows sum
at most `n` indicator bits (`n ≤ 164` here) against `N ≈ 2¹⁹²`, so wrap-around is
impossible. This must be restated if the encoding ever moves beyond indicators.

### 2.3 Why this and not BFV/CKKS

Encrypted control has, per the survey of Schlüter, Binfet and Schulze Darup [3],
moved through two generations: a first built on partially homomorphic schemes
(Paillier, ElGamal, RSA), and a second on levelled/fully homomorphic lattice
schemes (BFV, CKKS) that support the multiplications a dynamic controller needs.

This work sits deliberately in the first generation, for three reasons:

1. **The computation is Boolean.** A DES supervisor needs OR, which additive HE
   plus a zero test provides exactly. There is no multiplication to support, so
   the second generation's defining capability buys nothing here.
2. **mbedTLS is already on the device.** EC scalar multiplication and point
   addition are available and hardware-accelerated; no lattice library is, and
   adding one to an ESP32 build is a significant undertaking.
3. **Ciphertext size.** 50 bytes per state cell. BFV/CKKS ciphertexts are
   kilobytes, which for FMS's S6 (164 cells) would not fit alongside the
   decompressed point cache.

Most encrypted-control literature targets *continuous* plants with linear
controllers [3][4]; applying the same machinery to *discrete-event* supervision
is a different problem shape, and one where the first generation is arguably the
better fit rather than a legacy choice.

### 2.4 Point compression

Each ciphertext is two compressed points, 25 bytes each (1 prefix byte + the
24-byte x-coordinate), so 50 bytes per cell. Compression halves RAM at the cost
of a modular square root on decompression — which is why the decompressed form is
cached persistently (§4.2) rather than recomputed.

### 2.5 Scalar blinding on decrypt

The one scalar multiplication involving the private key is
`ns = (N − priv) · s1`. The code calls it as:

```c
mbedtls_ecp_mul(&g_grp, &ns, &g_neg_priv, &s1, mbedtls_ctr_drbg_random, drbg);
```

Passing a DRBG makes mbedTLS blind the scalar — randomising the representation so
the operation's timing and power profile do not depend on the secret bits. This
is the standard countermeasure introduced by Coron [5]; subsequent work shows
blinding must be combined with a *regular* (uniform-shape) ladder, since blinded
multiplications remain attackable when the underlying algorithm is irregular
[6][7]. mbedTLS's comb method is regular, so the combination is the intended one.

Note `g_neg_priv = N − priv` is precomputed once, turning the subtraction in
`Dec` into an addition, which lets the whole decrypt fuse into one `muladd`
(§4.4).

Two caveats worth stating honestly in a write-up:

- **Each core needs its own DRBG.** mbedTLS's CTR-DRBG is not thread-safe. The
  single-board sketch runs decrypts on both cores, so it maintains `g_drbg` and
  `g_drbg_core0` and selects by `xPortGetCoreID()`.
- **Blinding addresses the timing/power channel only.** The two memory channels
  in §7 are untouched by it, and §4.7 shows how thoroughly the firmware depends
  on one of them.
- **Its cost is not separately visible.** The 69 ms measured for a blinded
  scalar multiplication is the whole per-decryption budget; blinding is folded
  into it and was never measured against an unblinded build on this hardware.

---

## 3. Homomorphic supervisor evaluation

### 3.1 The state encoding

The supervisor's current state is held as an **encrypted indicator vector**: a
vector of `n` ciphertexts, where cell `s` encrypts 1 if the supervisor is in
state `s` and 0 otherwise.

This choice is what makes everything else work. It converts two automaton
operations into two homomorphic ones:

| automaton operation | on an indicator vector | homomorphic cost |
|---|---|---|
| apply a transition | permute / union the cells | **zero** EC operations — ciphertext copies |
| test enablement | OR the cells in the enabled set | additions + one zero test |

The alternative — encrypting the state *index* — would require homomorphic
comparison, which additive HE cannot do.

### 3.2 The transition is an image, and therefore a union

For event `ev` with transition relation `δ`, the successor indicator is

```
nxt[t] = ⋁ { cur[f] : (f,t) ∈ δ(ev) }
```

That is the **image** of the current state set under the event — a *union* over
all sources that land on `t`.

The obvious implementation is wrong:

```c
nxt[to] = enc[from];        // BUG: assignment, not union
```

When two source states converge on the same target — and in
`supervisor_data_fms.h` eleven `(event, target)` pairs do — whichever pair the
generator emitted **last** overwrites the others. An inactive source silently
clobbers an active one, and the result depends on array ordering that carries no
semantic meaning. (Supervisor reduction relabels states freely, so regenerating a
header reorders these arrays; measured on the current FMS header, the buggy form
reports a different enablement at **21 of 44** steps for the reduced family.)

The correct implementation exploits the fact that most cells hold a literal
`Enc(0)`:

```c
if (is_g_zero(sv.enc[from])) continue;   // contributes nothing to a union
if (is_g_zero(nxt[to])) { nxt[to] = sv.enc[from]; /* + copy cached points */ }
else                    { /* two ACTIVE sources converge: homomorphic add */ }
```

Skipping zero sources makes the common path both correct and free — it is exactly
the same number of copies as before. The homomorphic-add branch is unreachable
for a genuine one-hot vector (only one cell is active), but is implemented rather
than assumed, because "the state vector is one-hot" is an invariant of the
*model*, not something the transition code can verify on ciphertext.

### 3.3 The enablement query

Event `gi` is enabled iff the active state lies in the set `A = {s : enable[gi][s] = 1}`.
On indicators:

```
enabled(gi)  =  ⋁_{s ∈ A} cur[s]
             =  is_nonzero( Dec( Σ_{s ∈ A} Enc(cur[s]) ) )
```

Because the vector is one-hot, the sum is 1 if the active state is in `A` and 0
otherwise — so the additive homomorphism computes a logical OR, and the zero test
reads it off. `row_decrypt()` implements exactly this, fused (§4.4).

**What leaks, and what does not.** The result of this query is a single bit, and
that bit is the supervisor's control decision — it must be revealed, because it
is what actuates the plant. The *state distribution* is never decrypted on the
normal path.

That is the claim at the level of the cryptography. At the level of *this
implementation* it is weaker, and §4.7 quantifies why: the `g_zero` short-circuit
identifies inactive cells by `memcmp`, and once that set contracts to a single
cell the firmware has located the active state in plaintext without using the
key. Measured on `fms`, that contraction happens by step 4 for three of the seven
supervisors and by step 16 for all but one. This is the precise privacy claim, and it should be stated that
narrowly: an observer of the decisions learns the enablement sequence, which for
a deterministic supervisor can be highly informative. Quantifying what the
decision sequence reveals about the state trajectory is exactly the question
**opacity** theory asks [8], and connecting the two is open work rather than
something this implementation settles.

---

## 4. The six optimisations

Measured end state on ESP32-S3: **37.5 ms/step** on `small_factory`,
**50.0 ms** on `extended_small_factory`, **233.9 ms** on `fms` — all for the
reduced family, which after optimisation 6 is the fastest everywhere.

Each optimisation is sound for a specific reason, and the reasons matter more
than the speedups. Two of them turned out to be worth much less than they look
(§4.5), and one of them is the same mechanism as a side channel (§4.3).

### 4.1 Conditional invariance — the largest win

Naively, every transition invalidates every cached enablement bit, so every row
of every supervisor must be re-decrypted. Almost none of them can actually have
changed.

At load time, for each `(supervisor, event ev, row gi)` the code precomputes
whether the row's OR-sum can flip:

```
0 → 1 possible  ⟺  ∃ (f,t) ∈ δ(ev) with  f ∉ A  and  t ∈ A
                   (an outside state moves into the enabled set)

1 → 0 possible  ⟺  ∃ s ∈ A with  s has no transition on ev,
                   or  δ(ev)(s) ∉ A
                   (an enabled state leaves, or falls out of the set)
```

Rows in neither list are invariant under that event and keep their cached bit
with no EC work at all. At runtime only rows whose *current cached value* matches
the possible flip direction are enqueued:

```c
for (uint8_t li : sv.changes_if_zero[ev]) if (sv.cached_en[li] == 0) …
for (uint8_t li : sv.changes_if_one [ev]) if (sv.cached_en[li] == 1) …
```

This is a static analysis of the automaton, computed once, that soundly
over-approximates which decisions can change. It is the reason a step can
sometimes cost *zero* decryptions — measured at ~0.2 ms, against 37–234 ms for a
step that does work. On `fms` reduced, 8 of 44 steps cost nothing at all.

### 4.2 Persistent decompressed cache

`pt_decompress` runs a modular square root (~5–10 ms). Keeping a parallel array
of decompressed `mbedtls_ecp_point` values, updated in lock-step with the
ciphertexts via `mbedtls_ecp_copy` (an MPI copy, not EC arithmetic), removes
decompression from the hot path entirely. The cost is RAM: two EC points per
cell alongside the 50-byte ciphertext.

### 4.3 Skipping `Enc(0)` summands

Non-active cells are set to a single global constant `g_zero`, so they are
*byte-identical*, and `is_g_zero()` is a `memcmp`. `row_decrypt` skips them, so a
row that nominally sums dozens of cells typically sums one or two. On `fms` local
modular the set of cells that are *not* `g_zero` contracts from 327 to 7 over a
run; on the reduced family, from 37 to 7.

The short-circuit also decides *whether a scalar multiplication happens at all*:
if every cell of the row's enabled set is `g_zero`, `row_decrypt` returns 0 with
no elliptic-curve work. So a decryption is charged **only when a row answers
"enabled"** — which is the fact §4.7 turns into a 2.7–4.6× speedup, and the fact
that made the reduced family look slow before it.

This is a genuine security/performance trade: byte-identical zeros are exactly
what channel 2 in §7 exploits. The optimisation and the leak are the same
mechanism — the short-circuit is fast *because* an inactive cell is recognisable
by a `memcmp`. Closing the channel means re-randomising every cell after every
transition, which removes this optimisation entirely along with its speedup.

### 4.4 Fused row-sum and decrypt

Decryption is `M = c2 − priv·c1`. With `g_neg_priv = N − priv` precomputed, that
becomes `M = c2 + (N−priv)·c1` — a multiply-add, which mbedTLS does in one call:

```c
mbedtls_ecp_mul  (ns, g_neg_priv, s1, drbg);   // blinded (§2.5)
mbedtls_ecp_muladd(pm, 1, s2, 1, ns);
```

The blinded `mul` is kept separate precisely because `muladd` has no DRBG
parameter and so cannot blind; folding both into one unblinded `muladd` would be
faster and would reintroduce the timing channel.

### 4.5 Dual-core work split

The single-board sketch splits each step into three phases: apply transitions and
build a work list (main core), decrypt the work list across both cores, then emit
the enablement bitmap. A persistent worker task on core 0 is woken by semaphore
rather than respawned per step.

The split only runs when a benchmark has two or more supervisors; with one
(every `small_factory` family and the `extended_small_factory` monolithic) the
sketch prints `Cores used: 1 (single)`.

**Measured:** comparing the single-board sketch (two cores) against the same steps on node 2 of the distributed engine (one core), with the same decryption count:

| step (fms) | decryptions | two cores | one core | gain |
|---|---|---|---|---|
| `61`, reduced | 6 | 421.3 ms | 486.9 ms | 13 % |
| `65`, reduced | 3 | 212.3 ms | 238.4 ms | 11 % |
| `63`, reduced | 2 | 126.0 ms | 152.6 ms | 17 % |
| `61`, local modular | 4 | 235.8 ms | 312.0 ms | 24 % |
| `65`, local modular | 4 | 250.0 ms | 317.3 ms | 21 % |
| `71`–`74`, `81`, `82` | 1 | ~76 ms | ~77 ms | none |

So the second core saves 11–24 % on steps that decrypt several sums and nothing
on steps with a single decryption — far from 2×. (An earlier version of this
section put the gain at 8–10 % by sorting the nine runs into "dual-core" and
"single-core" by their cost per decryption. That sorting was wrong: the cost per
decryption depends mostly on how wide the row sums are, and the runs with one
supervisor were the only single-core ones.)

### 4.6 Measured: what actually limits performance

ESP32-S3, Arduino core 3.3.8, all three problems, every run `PASS`:

| problem | family | avg/step | decryptions | ms per decryption |
|---|---|---|---|---|
| `small_factory` | monolithic | 77.8 ms | 4 | 77.8 |
| | local modular | 77.5 ms | 4 | 77.5 |
| | reduced | **37.5 ms** | 2 | 75.1 |
| `extended_small_factory` | monolithic | 94.4 ms | 7 | 80.9 |
| | local modular | 91.4 ms | 8 | 68.6 |
| | reduced | **50.0 ms** | 4 | 75.0 |
| `fms` | local modular | 335.4 ms | 190 | 77.7 |
| | reduced | **233.9 ms** | 145 | 71.0 |

A single scalar multiplication measures **69 ms**. Every ms-per-decryption figure
lands between 68.6 and 80.9, across traces of 4 to 44 steps and 1 to 7
supervisors.

**Runtime is `decryptions × scalar_mul`.** Everything else the firmware does is
noise, so the only software lever is reducing the *count* of decryptions. That is
what §4.1 and §4.7 do, and it is why §4.5 achieves comparatively little.

**Optimisation 5 buys 11–24 % on steps with several decryptions, not 2×** (§4.5).
The cost per decryption above varies mainly with the width of the row sums, not
with the number of cores.

**Correction — the ESP32-S3 has no ECC accelerator.** An earlier version of this
document claimed roughly 10 ms per scalar multiplication on the S3 via a
dedicated ECC engine. That is wrong. Checked against the SoC capability headers
shipped with Arduino core 3.3.8, `SOC_ECC_SUPPORTED` is **absent** for ESP32,
ESP32-S3 and ESP32-C3, and present only for **ESP32-C6** and **ESP32-H2** — where
the prebuilt mbedTLS also sets `CONFIG_MBEDTLS_HARDWARE_ECC`. The S3 has the
RSA/MPI accelerator, AES and SHA, but no elliptic-curve unit [12]. The 69 ms
against ~91 ms on the WROOM-32 is a newer MPI peripheral, not hardware ECC.

The hardware lever is therefore the **ESP32-C6** (ECC unit, acceleration enabled
out of the box, Wi-Fi available for the UDP transport), not the S3.

### 4.7 Optimisation 6 — share identical row sums

`row_decrypt` depends only on the set `S = { i : row[i] ≠ 0 and enc[i] ≠ g_zero }`:
it takes the smallest element of `S`, adds the rest, and decrypts. Addition is
commutative, so **two rows with the same `S` have the same result**, including
the same `did_decrypt`.

That matters because `S` collapses. Once the non-zero mask has contracted to the
active cell — which happens within a few steps (§4.8) — *every* row covering that
cell has `S = {active}`. The original code ran the same 69 ms scalar
multiplication once per row.

Phase 1 now groups enqueued rows by `S` and emits one work unit per distinct set;
phase 2 decrypts each once; a new phase 2b fans each result out. The grouping key
is, for every cell in the non-zero list, whether the row covers it — which is
exactly membership of `S`, not an approximation.

| `fms` | before | after | gain |
|---|---|---|---|
| local modular | 916.6 ms/step, 576 dec. | 335.4 ms, 190 dec. | 2.7× |
| reduced | 1 078.8 ms/step, 745 dec. | 233.9 ms, 145 dec. | 4.6× |

**This also resolved an anomaly.** Before optimisation 6 the reduced family was
*slower* than the full one, the opposite of what reduction promises. The cause:
a decryption is charged only when a row answers "enabled", because the
short-circuit is free only on "disabled". Reduction packs the same control
information into fewer states, so its rows are much denser (mean `|A|/n` 41.9 %
against 17.1 %) and answer "enabled" far more often (79.4 % of enqueued rows
against 60.1 %). Each of those paid separately for what was the same ciphertext.
Removing that redundancy helps the reduced family most, and the expected ordering
is restored: **reduced is now the fastest family on all three problems**, roughly
2× faster than local modular.

**Verification.** A static model of `row_decrypt`, written independently and
before the change, predicted 190 and 145 decryptions. The hardware produced 190
and 145, matching **step by step** across all 44 steps of both families, with the
homomorphic output equal to the cleartext oracle throughout.

**Security.** No new information is read: the grouping uses only the `is_g_zero`
test optimisation 3 already performs. Timing leaks slightly *less* than before,
since step duration now tracks the number of distinct sums rather than the number
of "enabled" answers. But the honest framing is that the speedup is **borrowed
from the leak in §7**: in a genuinely oblivious implementation, where no
ciphertext is recognisably zero, `S` would equal the full enabled set for every
row, sharing would essentially never occur, and this optimisation would gain
nothing.

### 4.8 A static cost model that matches the hardware exactly

The model that predicted those counts simulates two things the firmware
distinguishes and the plaintext automaton does not:

- `plain[s]` — the true one-hot state, which decides the *answer*;
- `nonzero[s]` — whether cell `s` is byte-distinct from `g_zero`, which decides
  whether a scalar multiplication *happens*.

It also documents an easily-missed property: the encrypted state vector is **not
one-hot at the ciphertext level**. The set of cells byte-distinct from `g_zero`
is an over-approximation of the reachable state — it begins as *every* cell,
because `init_states()` encrypts each one freshly, and contracts under the
transition image. For `fms` local modular it goes 327 → 7 cells over the run;
for reduced, 37 → 7, and more slowly in relative terms.

That contraction is the same structure channel 2 in §7 exploits, and §4.7 is what
turns it into a performance consequence as well as a security one.

---

## 5. The distributed engine

### 5.1 Why local-modular decomposition is the right partition

Local modular supervisory control (de Queiroz and Cury [9]) synthesises one small
supervisor per specification instead of one monolithic supervisor over the full
composed plant, avoiding the state explosion of the latter. For FMS the
monolithic supervisor does not fit in flash at all, while the seven local-modular
supervisors do comfortably.

The key observation for distribution is that this decomposition is **not
arbitrary** — it follows the coupling structure of the plant. Each supervisor
touches only the events of its own specification and the plants those events
belong to. So the partition that synthesis already produced *is* the partition
that minimises inter-node communication. For `extended_small_factory`, 4 of its 6
steps need no communication at all; for FMS over three nodes, 22 of the 44
steps of a cycle.

Splitting one logical supervisor across controllers that each see only part of
the event set is the **decentralised control** problem of Rudie and Wonham [10],
whose co-observability condition characterises when local agents can make correct
decisions from partial views. `extended_small_factory` is a minimal instance:
event `a2` requires B1 non-empty (known only to node 1) *and* B2 to have room
(known only to node 2), so neither node can decide alone.

### 5.2 Deriving the partition at boot

`relevance_mask()` computes, for each supervisor, the set of events it either
constrains or transitions on. `build_routing()` maps supervisors to nodes and
ORs those masks per event, producing for each event:

- `node_mask` — which nodes hold a relevant supervisor
- `shared` — whether more than one does
- `owner` — the lowest-numbered relevant node, which initiates the event
- `part_mask` — the remaining relevant nodes, which must participate

Nothing is hardcoded. Every node computes the identical table from the same
header, so the routing is consistent by construction without any negotiation.

### 5.3 Conjunctive fusion

A shared event may fire only if **every** supervisor that constrains it agrees.
This is the standard modular/decentralised decision rule and is what recent work
on distributed micro-manufacturing supervision also uses [13]. Locally it is just
the conjunction already implemented by `local_enabled()`; across nodes it becomes
a vote.

### 5.4 Two protocols, because controllability is not symmetric

This is the design point most easily got wrong.

**Controllable shared event → two-phase commit.** The event has not happened yet;
the supervisor is deciding whether to permit it. Any participant may veto:

```
REQ → VOTE* → COMMIT → ACK*
```

**Uncontrollable shared event → reliable notification.** SCT says a supervisor
may not disable an uncontrollable event, and by the time a node hears of it the
plant has already produced it. A "request" would be meaningless:

```
NOTIFY → ACK*      (retransmitted until acknowledged)
```

Safety for the uncontrollable case is enforced *upstream*: supremal controllable
synthesis guarantees that whenever an uncontrollable event can occur, the
supervisor permits it — that is exactly what controllability means. The
distributed layer inherits that property; it does not need to re-establish it.

### 5.5 Concurrency: locking and wound-wait

With several initiators, two transactions could interleave on a shared
participant and corrupt its state. Participants therefore hold a lock between
voting yes and receiving COMMIT/ABORT.

Locks invite deadlock, so the engine uses **wound-wait** (Rosenkrantz, Stearns
and Lewis [14]): a lower-numbered initiator preempts a higher-numbered one. Since
nothing has been applied while a lock is held, preemption is always safe, and
because preference follows a total order on node ids the wait-for graph cannot
contain a cycle. Both transactions still make progress on retry.

This mirrors, at protocol level, what Schouten et al. [15] found necessary when
distributing a synthesised supervisor across PLCs: mutual exclusion is what makes
a distributed supervisor delay-robust.

### 5.6 Loss, and the limit of what is achievable

Frames carry per-sender sequence numbers; COMMIT/NOTIFY are retransmitted until
acknowledged. When the retransmission budget is exhausted, the node **safe-halts**
rather than continuing on state that may have diverged from its peers.

This is the Two Generals problem, and the trade is deliberate and explicit:
**safety is preserved, liveness is sacrificed.** No protocol can guarantee both
under unbounded message loss. For a factory interlock this is the correct
direction — a stopped cell is recoverable, an overflowed buffer may not be.

Hou and Li [16] give the formal counterpart: necessary and sufficient conditions
for distributed supervisory control under communication delays and losses, in
terms of *network controllability*, *network joint observability* and language
closure. This implementation does not verify those conditions — it detects at
runtime when it can no longer guarantee them and stops.

A single-board implementation simply cannot have this failure mode. It is a real,
new cost of distributing, and the engine reports it loudly rather than hiding it.

### 5.7 The privacy argument, stated precisely

Each node holds **only its own supervisors**, encrypted under **its own keypair**,
generated locally at boot. No ciphertext ever crosses the network — only single
enablement bits.

The consequence is worth spelling out: because ciphertexts never move, the nodes
**never need a shared key**. No distributed key generation, no threshold
decryption, no re-encryption, no key distribution problem. That property falls
directly out of the local-modular decomposition and is, in my view, the strongest
argument for distributing this computation at all.

Compare the alternatives:

| | what one compromised board reveals |
|---|---|
| monolithic, one board | the joint plant state — the monolithic supervisor's states *are* the joint state |
| local-modular, one board | every supervisor's state, under one key |
| local-modular, distributed | **only that node's own buffers**, plus one bit per shared event |

For `extended_small_factory`: node 1 knows B1's level, node 2 knows B2's, and
node 1 learns exactly one bit about B2 — *"may `a2` fire right now?"*.

### 5.8 The transport layer, and why it is pluggable

The protocol never calls a network API. It goes through four function pointers:
`begin`, `send`, `poll`, `service`. A transport need only be **best effort**,
because sequencing, acknowledgement, retransmission and atomicity are supplied
end-to-end by the protocol itself — the classic end-to-end argument of Saltzer,
Reed and Clark [17].

It is also why a transport's own per-hop reliability, such as MQTT's QoS 1/2,
would add nothing: it would redo, on every frame, work the two-phase commit
already guarantees.

The default binding is **UDP/IP multicast** (RFC 1112 [18]). It is an open
standard with no broker, no library and no vendor, it runs on any BSD-socket
stack, and — the argument that matters for an industrial claim — it is the same
substrate that OPC UA PubSub (IEC 62541-14) and DDS/RTPS use for their UDP
mappings. Moving to either is a transport swap, not an architectural change.

ESP-NOW was implemented first and then removed: it is fast and needs no
infrastructure, but it exists only on Espressif silicon and is not specified by
any standards body, which undermines any claim of a path to industrial
deployment.

---

## 6. The verification apparatus

Every layer is checked against something independent, because the failures found
in this project were all of the form *"the check and the thing being checked
shared a mistake"*.

**On-board cleartext oracle.** Each node mirrors its own supervisors in plaintext
and compares every homomorphic enablement bit against it after every step. This
validates the crypto layer against the automaton semantics. Across the nine
ESP32-S3 runs — three problems × three families, minus the `fms` monolithic which
does not fit in flash — every step matched: 4, 4, 4, 6, 6, 6, 44 and 44 steps
respectively, all `PASS`.

> The oracle only has value if it is *independently* correct. When both the
> homomorphic path and the oracle used assignment instead of union (§3.2), they
> agreed and the benchmark printed `PASS` while certifying nothing. Fixing only
> one of the two would have been the visible failure; fixing neither was silent.

**Monolithic cross-check.** Where the header includes a monolithic supervisor,
node 1 replays the global trace against it and asserts that nothing fires that the
centralised supervisor forbids. This is the direct empirical statement of the
local-modular equivalence result [9].

**Host validator.** A separate replay of routing,
fusion, two-phase commit and loss handling independently of the firmware and
replays them against the real generated arrays for every problem × family × node
count, including injected packet loss. It is an executable specification: when the
firmware and the validator disagree, one of them is wrong and both are readable.

**Admissibility checking.** The scripted driver verifies that each step of the
generated `SIM_SEQ` is actually permitted before firing it, and skips and reports
rather than forcing a forbidden transition. This is what surfaced that the FMS
sequence was not a trace of its own supervisors.

**Compile matrix.** Both sketches are compiled with `-Wall -Wextra` across every
problem, node count, supervisor family, transport and driver — and, after a miss
that only surfaced on real hardware, every `.cpp` in each sketch folder as the
Arduino IDE itself compiles it, not just the `.ino`.

**Prediction before measurement.** Optimisation 6 was specified, its effect
predicted by an independent static model, and only then implemented. The model
said 190 and 145 decryptions; the hardware said 190 and 145, step by step. A
model that reproduces the hardware to the unit is stronger evidence than a test
suite written after the fact.

---

## 7. Threat model and limitations

### What is protected

The plant state, at rest in RAM, against an adversary who can read memory but not
mount a physical side-channel attack; and the private key against timing and
power analysis of the decryption scalar multiplication.

### Known channels

| # | Channel | Status |
|---|---|---|
| 1 | Timing/power on the private scalar | **Closed** by default via scalar blinding [5]; see [6][7] on why blinding alone is not sufficient without a regular ladder |
| 2 | `g_zero` byte-equality — inactive cells are byte-identical | **Open by design.** Closing it costs ~2 scalar multiplications per cell per transition (~138 ms each on this hardware) and removes optimisations 3 *and* 6 — i.e. most of the measured speed |
| 3 | Active-ciphertext propagation — the active cell's bytes are copied unchanged across transitions | **Open by design.** Same mitigation, same cost |
| 4 | **Decision leakage** — the enablement bits are, by construction, revealed | Inherent. This is what opacity theory [8] analyses |
| 5 | **Traffic analysis** (distributed only) — frames are fixed-size, but the timing and existence of shared-event transactions are visible | Open; link encryption plus cover traffic would be the next step |

Channels 4 and 5 are the ones a reviewer is most likely to press on, and neither
is addressed by the encryption. They are properties of the architecture, not
implementation defects.

### Other limitations

- **No formal verification.** Correctness rests on testing and on the structural
  arguments above, not on a machine-checked proof.
- **Performance is bounded by the platform**, not the algorithm (§4.6).
- **Hardware results are from one board, one run each.** The ESP32-S3 figures in
  §4.6–4.8 cover all three problems and every supervisor family, but each is a
  single execution with no variance reported.
- **Controllability is inferred**, not carried in the data (§1.4).

---

## References

Verified against an accessible source unless noted.

1. Ramadge, P. J., & Wonham, W. M. (1987). *Supervisory control of a class of
   discrete event processes.* SIAM Journal on Control and Optimization, 25(1),
   206–230.
2. ElGamal, T. (1985). *A public key cryptosystem and a signature scheme based on
   discrete logarithms.* IEEE Transactions on Information Theory, 31(4), 469–472.
3. Schlüter, N., Binfet, P., & Schulze Darup, M. (2023). *A brief survey on
   encrypted control: From the first to the second generation and beyond.* Annual
   Reviews in Control, 56, 100913. doi:10.1016/j.arcontrol.2023.100913
   — the standard recent survey; categorises encrypted control into a PHE-based
   first generation and an LHE/FHE-based second.
4. Schulze Darup, M., Alexandru, A. B., Quevedo, D. E., & Pappas, G. J. (2021).
   *Encrypted control for networked systems: An illustrative introduction and
   current challenges.* IEEE Control Systems Magazine. arXiv:2010.00268
5. Coron, J.-S. (1999). *Resistance against differential power analysis for
   elliptic curve cryptosystems.* CHES 1999, LNCS 1717, 292–302. — the origin of
   scalar blinding.
6. Feix, B., Roussellet, M., & Venelli, A. (2014). *Side-channel analysis on
   blinded regular scalar multiplications.* IACR ePrint 2014/191.
7. Poussier, R., Zhou, Y., & Standaert, F.-X. et al. (2019). *Side-channel attacks
   on blinded scalar multiplications revisited.* IACR ePrint 2019/1220. — shows
   larger blinding factors and higher error rates remain attackable in practice.
8. Yin, X. (2026). *Opacity in Discrete Event Systems: A Perspective and
   Overview.* arXiv:2602.22713. — recent survey of opacity notions, verification
   and enforcement; the natural formal frame for the decision-leakage channel.
9. de Queiroz, M. H., & Cury, J. E. R. (2000). *Modular supervisory control of
   large scale discrete event systems.* WODES 2000, 103–110.
10. Rudie, K., & Wonham, W. M. (1992). *Think globally, act locally: decentralized
    supervisory control.* IEEE Transactions on Automatic Control, 37(11),
    1692–1708.
11. *Solving Small Exponential ECDLP in EC-based Additively Homomorphic
    Encryption and Applications.* IACR ePrint 2022/1573. — on the decryption
    restriction of lifted EC-ElGamal and the small-message-space workarounds this
    implementation avoids by testing only for zero.
12. Espressif SoC capability headers as shipped with Arduino-ESP32 core 3.3.8
    (`soc_caps.h`, `sdkconfig.h` per target). `SOC_ECC_SUPPORTED` is absent for
    ESP32, ESP32-S3 and ESP32-C3, and set for ESP32-C6 and ESP32-H2, where
    `CONFIG_MBEDTLS_HARDWARE_ECC` is also enabled in the prebuilt mbedTLS. This
    is the primary source for the claim that the S3 accelerates bignum arithmetic
    but has no elliptic-curve unit.
13. *Modular and Distributed Supervisory Control Framework for Intelligent
    Micro-Manufacturing Systems with Unreliable Events* (2025). PMC12566142. —
    uses the same conjunctive fusion over shared events; notably specifies no
    middleware, supporting the view that transport is an engineering choice.
14. Rosenkrantz, D. J., Stearns, R. E., & Lewis, P. M. (1978). *System level
    concurrency control for distributed database systems.* ACM TODS, 3(2),
    178–198. — wound-wait.
15. Schouten, R. H. J., Moormann, L., van de Mortel-Fronczak, J. M., & Rooda,
    J. E. (2021). *Synthesis and Implementation of Distributed Supervisory
    Controllers with Communication Delays.* arXiv:2102.09821. — localisation plus
    mutual exclusion for delay robustness, validated hardware-in-the-loop.
16. Hou, Y., & Li, Q. (2023). *Distributed Nonblocking Supervisory Control of
    Timed Discrete-Event Systems with Communication Delays and Losses.*
    arXiv:2308.16545. — necessary and sufficient conditions: network
    controllability, network joint observability, language closure.
17. Saltzer, J. H., Reed, D. P., & Clark, D. D. (1984). *End-to-end arguments in
    system design.* ACM TOCS, 2(4), 277–288.
18. Deering, S. (1989). *Host extensions for IP multicasting.* RFC 1112. See also
    RFC 3376 (IGMPv3) and RFC 2365 (administratively scoped multicast).
19. *A new algorithm for supervisor reduction/localisation of discrete-event
    systems.* International Journal of Control, 98(2), 481–491 (2024).
    doi:10.1080/00207179.2024.2332518 — **author list not verified** (publisher
    page inaccessible). Reduction merges state pairs that are *control
    consistent*, which is why a reduced supervisor is control-equivalent but not
    state-equivalent — the reason reduction may relabel states between runs, and
    the reason a reduced supervisor's enablement map legitimately differs from the
    monolithic one on events the plant cannot currently generate.
20. Su, R., & Wonham, W. M. (2004). Control-congruence-based supervisor reduction,
    later adopted in supervisor localisation theory. — cited in [19]'s account of
    the field; **exact venue not independently verified here.**
21. *Offline supervisory control synthesis: taxonomy and recent developments.*
    Discrete Event Dynamic Systems (2024). doi:10.1007/s10626-024-00408-z —
    recent taxonomy of synthesis approaches.
22. Cassandras, C. G., & Lafortune, S. (2021). *Introduction to Discrete Event
    Systems* (3rd ed.). Springer. — standard textbook reference for SCT,
    decentralised control and diagnosability.
