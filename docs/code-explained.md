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
- [4. The optimisations, and what they really cost](#4-the-optimisations)
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
| `des_split/des_split.h` | supervisor and plant on two boards: the key, the events and the decisions stay on the plant's |
| `notebook/generator_ultrades.ipynb` | where the data comes from |

The single-board sketch and the distributed engine share the same cryptographic
core, but no longer verbatim: the single-board sketch re-randomizes every cell
after every transition and keeps no decision between steps, while the
distributed engine still reuses one fixed `Enc(0)` and caches its decisions
(§4, §7). Read the sketch first.

The current single-board code has not been run yet; §4.6 gives the measurements
of the earlier code and the static model's prediction for the current one.

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
dimension where reduction delivers exactly what it promises.

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
but not which events are controllable in the first place. Every sketch infers it
from the event labels with `derive_controllable()`: the single-board sketch and
`des_split` to skip the rows of uncontrollable events, which a supervisor never
disables (§4.1), and the distributed engine because controllability decides
whether an event can be put to a vote (§5.4); it prints what it inferred at boot,
and `DES_CONTROLLABLE_MASK` overrides it.

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
multiplication — 37.5 ms per step on `small_factory`, 241.1 ms on `fms`.

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
- **Blinding addresses the timing/power channel only.** The memory channels in
  §7 are closed by other means: re-randomization (§4.3) and keeping no decision
  between steps (§4.1).
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

The correct implementation copies the first source into an empty target and
adds the next ones homomorphically:

```c
if (!filled[to]) { filled[to] = 1; nxt[to] = sv.enc[from]; /* + cached points */ }
else             { /* sources converge: homomorphic add, the same OR */ }
```

A target that no source reaches stays empty, the point at infinity in the
cache, and `rerandomize()` then makes every cell — copied, added or empty — a
fresh ciphertext (§4.3). Nothing is skipped, because no cell is recognisable as
an encryption of zero.

### 3.3 The enablement query

Event `gi` is enabled iff the active state lies in the set `A = {s : enable[gi][s] = 1}`.
On indicators:

```
enabled(gi)  =  ⋁_{s ∈ A} cur[s]
             =  is_nonzero( Dec( Σ_{s ∈ A} Enc(cur[s]) ) )
```

Because the vector is one-hot, the sum is 1 if the active state is in `A` and 0
otherwise — so the additive homomorphism computes a logical OR, and the zero test
reads it off. `row_decrypt()` implements exactly this (§4.4).

**What leaks, and what does not.** The result of this query is a single bit, and
that bit is the supervisor's control decision — it must be revealed, because it
is what actuates the plant. The *state distribution* is never decrypted on the
normal path.

Every cell is re-randomized after every transition (§4.3), so no cell is
recognisable, and no decision is stored between steps (§4.1): a memory snapshot
shows neither the active state nor the current decisions. (The earlier code
reused one fixed `Enc(0)` for inactive cells, and once they contracted to the
active cell the firmware had located it without the key — by step 4 for three
of the seven `fms` supervisors.) The precise privacy claim should still be
stated narrowly: the decisions are revealed when they drive the plant, and an
observer of them learns the enablement sequence, which for a deterministic
supervisor can be highly informative. Quantifying what the
decision sequence reveals about the state trajectory is exactly the question
**opacity** theory asks [8], and connecting the two is open work rather than
something this implementation settles.

---

## 4. The optimisations

The current code has four, and none depends on the state or on a decision:
the persistent decompressed cache (§4.2), dropping the rows of uncontrollable
events (§4.1), deciding equal rows once (§4.7), and the dual-core split (§4.5).
Two earlier ones were removed because each worked by reading something a memory
snapshot should not reveal: keeping the decisions between steps (§4.1) and
skipping a fixed `Enc(0)` (§4.3). The measurements in §4.5–§4.6 are from that
earlier code.

### 4.1 Rows that are computed — and conditional invariance, removed

A supervisor never disables an uncontrollable event, so only the rows of the
**controllable** events with at least one disabling state are summed and
decrypted; a row with no enabled state is decided from the table, with no sum.
And because no decision is kept, **every** such row of **every** supervisor is
decided again at every step, including the supervisors that did not move.

The earlier code kept each decision in RAM (`cached_en`) and re-decrypted only
the rows whose value could change. At load time it precomputed, for each
`(supervisor, event ev, row gi)`:

```
0 → 1 possible  ⟺  ∃ (f,t) ∈ δ(ev) with  f ∉ A  and  t ∈ A
1 → 0 possible  ⟺  ∃ s ∈ A with  s has no transition on ev,  or  δ(ev)(s) ∉ A
```

and at run time enqueued a row only if its cached bit was 0 and could become 1,
or 1 and could become 0. That needs the decisions in RAM, and the decisions
narrow down the state, so it was removed. The static model counts the price:
on `fms` local modular, 1 408 zero tests per cycle instead of 553; about 2 s
more per step, against the 25.6 s that the encryptions of zero cost anyway.

### 4.2 Persistent decompressed cache

`pt_decompress` runs a modular square root (~5–10 ms). Keeping a parallel array
of decompressed `mbedtls_ecp_point` values, updated in lock-step with the
ciphertexts via `mbedtls_ecp_copy` (an MPI copy, not EC arithmetic), removes
decompression from the hot path entirely. The cost is RAM: two EC points per
cell alongside the 50-byte ciphertext.

### 4.3 Re-randomizing every cell (and the skipped `Enc(0)` it replaced)

After every transition, `rerandomize()` adds a fresh encryption of zero,
`(rG, rY)`, to every cell of each supervisor that moved; an empty cell (no
source reached it) simply becomes `(rG, rY)`, since mbedTLS refuses to add the
point at infinity. The bits do not change; the randomness of every cell does.
Drawing one costs two scalar multiplications, 140 ms on the ESP32-S3: 8 028 of
them per `fms` cycle, 93 % of the measured time. They depend on neither the
event nor the state, so a pool drawn while the board is idle would take them out
of the step; a cycle's worth for `fms` local modular does not fit in its RAM.

The earlier code instead set every inactive cell to one global constant
`g_zero`, recognised by `memcmp`, and skipped those cells in the sums — a row of
dozens of cells summed one or two, and a row whose cells were all `g_zero` cost
no decryption at all. The optimisation and the leak were the same mechanism:
the short-circuit was fast *because* an inactive cell was recognisable, and the
cells that were not `g_zero` contracted to the active one within a few steps.
That fast mode is gone from the single-board sketch.

### 4.4 Row sum and decrypt

Decryption is `M = c2 − priv·c1`. With `g_neg_priv = N − priv` precomputed, that
becomes `M = c2 + (N−priv)·c1` — a multiply and an add:

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

The current code is not measured yet. The static model (§4.8), calibrated on
the `fms` run with re-randomization, predicts per cycle 1 408 zero tests and
8 028 encryptions of zero for `fms` local modular (~29.5 s per step, ~3.9 s
without drawing the encryptions of zero) and 1 188 and 870 for reduced (~4.7 s,
~1.9 s). With every cell re-randomized, runtime is **encryptions of zero ×
140 ms** first, decryptions second.

The measurements below are from the earlier code — fast mode, decisions kept —
on an ESP32-S3, Arduino core 3.3.12 for `fms` and 3.3.8 for the two small
factories, every run `PASS`. The same code with every cell re-randomized
measured 27.5 s per step on `fms` local modular (553 decryptions) and 3.87 s on
reduced (481), 1.90 s and 1.10 s without drawing the encryptions of zero.

| problem | family | avg/step | decryptions | ms per decryption |
|---|---|---|---|---|
| `small_factory` | monolithic | 77.8 ms | 4 | 77.8 |
| | local modular | 77.5 ms | 4 | 77.5 |
| | reduced | **37.5 ms** | 2 | 75.1 |
| `extended_small_factory` | monolithic | 94.4 ms | 7 | 80.9 |
| | local modular | 91.4 ms | 8 | 68.6 |
| | reduced | **50.0 ms** | 4 | 75.0 |
| `fms` | local modular | 346.0 ms | 190 | 80.1 |
| | reduced | **241.1 ms** | 145 | 73.2 |

A single scalar multiplication measures **69 ms**. Every ms-per-decryption figure
lands between 68.6 and 80.9, across traces of 4 to 44 steps and 1 to 7
supervisors.

**In fast mode, runtime was `decryptions × scalar_mul`.** Everything else the
firmware did was noise, so the only software lever was the *count* of
decryptions — which is what the removed optimisations reduced.

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

### 4.7 Equal rows are decided once

Two controllable events of the same supervisor whose rows of the enable matrix
are equal have the same sum, so `load_supervisors()` groups them, from the table
alone, and each group is summed and decrypted once per step.

The earlier code grouped rows by their set of cells that were *not* `g_zero`,
which collapsed to the active cell within a few steps, so most rows shared one
decryption: on `fms` (core 3.3.8) it brought local modular from 576 to 190
decryptions per cycle (916.6 → 335.4 ms/step) and reduced from 745 to 145
(1 078.8 → 233.9 ms/step). That gain was borrowed from the leak of §4.3: with
every cell fresh, only rows that are equal in the table can share a sum.

### 4.8 A static cost model that matches the hardware exactly

The number of encryptions of zero and of decryptions does not depend on the
keys or the randomness, only on the trace, so a plaintext simulation of the
supervisors counts them. Written independently of the firmware, the model
matched the earlier code on the board exactly: 190 and 145 decryptions in fast
mode, step by step, and 8 028 / 870 encryptions of zero with 553 / 481
decryptions with every cell re-randomized. For the current code it counts, per
step, the cells of the supervisors that move and the distinct controllable rows
of all supervisors; §4.6 gives its predictions.

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

A yes vote is never withdrawn for another request: its initiator may already
have committed on it,
and nothing would tell it the vote was gone — the two-phase-commit rule that a
prepared participant cannot abort on its own. A locked participant therefore
refuses every other request, older or younger. Between initiators the engine
uses **wound-wait** (Rosenkrantz, Stearns and Lewis [14]): a node still
collecting votes for its own event aborts it when an older (lower-numbered) node
asks for its vote, and tells a younger one no. Every request is answered at
once, so no initiator waits on another's lock and no cycle of waits can form. A
refused initiator has applied nothing, and retries with exponential backoff.

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

**Prediction before measurement.** The sharing of row sums of the earlier code
was specified, its effect predicted by an independent static model, and only
then implemented. The model said 190 and 145 decryptions; the hardware said 190
and 145, step by step. A model that reproduces the hardware to the unit is
stronger evidence than a test suite written after the fact; the same model
gives the expected counts of the current code (§4.6).

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
| 2 | Byte-equality — inactive cells identical to one fixed `Enc(0)` | **Closed** on one board and in `des_split`: every cell gets a fresh `Enc(0)` after every transition (~140 ms per cell, §4.3). **Open** in the distributed engine |
| 3 | Active-ciphertext propagation — the active cell's bytes copied unchanged | **Closed** the same way; **open** in the distributed engine |
| 4 | **Decisions kept in RAM** between steps | **Closed** on one board and in `des_split` (recomputed every step, §4.1); **open** in the distributed engine |
| 5 | **Decision leakage** — the enablement bits are, by construction, revealed to the plant | Inherent. This is what opacity theory [8] analyses |
| 6 | **Key and events on the board that holds the state** | **Open** on one board; `des_split` keeps both on the plant's board, and the supervisor's board never learns the event |
| 7 | **Traffic analysis** (distributed and `des_split`) — frames are fixed-size, but the timing of steps is visible | Open; cover traffic would be the next step |

Channels 5 and 7 are the ones a reviewer is most likely to press on, and neither
is addressed by the encryption. They are properties of the architecture, not
implementation defects.

### Other limitations

- **No formal verification.** Correctness rests on testing and on the structural
  arguments above, not on a machine-checked proof.
- **Performance is bounded by the platform**, not the algorithm (§4.6); fresh
  encryptions of zero dominate it.
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
