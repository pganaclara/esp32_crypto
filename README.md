# Homomorphic DES Supervisor Evaluation on ESP32

Privacy-preserving evaluation of Discrete Event System (DES) supervisors with
EC-ElGamal homomorphic encryption on ESP32 microcontrollers, in two forms:

* a **single-board benchmark** that runs every supervisor on one MCU, and
* a **distributed engine** that partitions the supervisors across several nodes,
  each holding only its own encrypted state, under its own key.

State cells are encrypted, transitions are applied as ciphertext permutations,
and enablement is evaluated by homomorphically OR-ing the enabled cells. The only
value ever decrypted is that single enablement bit; the state vector exists only
as ciphertext.

A detailed walkthrough of every layer, with the literature behind each decision,
is in [`docs/code-explained.md`](docs/code-explained.md).

---

## Repository layout

```
homomorphic-esp32-ultrades/
├── homomorphic-esp32-ultrades.ino         SINGLE-BOARD benchmark sketch
├── supervisor_data_small_factory.h         generated supervisor data
├── supervisor_data_extended_small_factory.h
├── supervisor_data_fms.h
├── supervisor_data_cluster_tool_2.h        (also _3, _4)
│
├── des_split/                              SUPERVISOR + PLANT on two boards
│   ├── des_split.ino                         ESP32 entry point (header, role)
│   ├── des_split.h                           both roles; the key is split between the
│   │                                         boards, the events stay on the plant's
│   ├── host_main.cpp                         POSIX entry point (mock group without mbedTLS)
│   ├── README.md                             protocol and how to run
│   ├── make_keys.py                          one identity key per board, for secrets.h
│   ├── audit.py                              records a run and checks the supervisor's signed steps
│   └── des_transport.h, secrets.example.h,   copies
│       supervisor_data_cluster_tool_*.h
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

The root doubles as the single-board sketch folder (Arduino requires the folder
to match the sketch name), which is why the generated headers live at the top.

```
  notebook/generator_ultrades.ipynb
        │  UltraDES: synthesise monolithic + local-modular + reduced supervisors
        │  Cell 6b:  validate the simulation trace against those supervisors
        │  Cell 7:   emit C arrays
        ▼
  supervisor_data_<PROBLEM>.h          PROGMEM arrays, no runtime parsing
        ├──────────────► homomorphic-esp32-ultrades.ino   one board, all supervisors
        ├──────────────► des_split/                       supervisor board + plant board
        └──────────────► des_distributed/                 N boards, one partition each
```

---

## Quick start

1. **Generate a header.** Open `notebook/generator_ultrades.ipynb` in Jupyter or
   Colab, set `PROBLEM` in Cell 3 and Restart & Run All. Cell 7 writes
   `supervisor_data_<PROBLEM>.h`; copy it to the repo root. Cell 6b refuses to
   emit a header whose simulation sequence the supervisors disable.
2. **Single board.** Point the `#include` in `homomorphic-esp32-ultrades.ino` at
   the header, select your ESP32 board, Serial 115200, flash. On an **ESP32-S3**,
   set `USB CDC On Boot` to `Enabled` on the native USB port and `Disabled` on
   the UART port — the wrong setting shows the ROM banner and then nothing.
3. **Distributed.** Copy `des_distributed/secrets.example.h` to `secrets.h`
   (Wi-Fi and the cell's authentication key), set `DES_DATA_HEADER`,
   `DES_NODE_ID` and `DES_NUM_NODES` in `des_distributed.ino`, and flash each
   board with a different `DES_NODE_ID`. See
   [`des_distributed/README.md`](des_distributed/README.md).
4. **Supervisor and plant on two boards.** Copy `des_distributed/secrets.h` into
   `des_split/`, pick the header in `des_split.ino`, and flash one board with
   `DES_ROLE DES_PLANT` and the other with `DES_SUPERVISOR`. See
   [`des_split/README.md`](des_split/README.md).

---

## Problems

| problem | events | supervisors | |
|---|---|---|---|
| `small_factory` | 4 | 1 | two machines, one-slot buffer; monolithic 6 states |
| `extended_small_factory` | 6 | 2 | three machines, two buffers; monolithic 18 states; only `a2`/`b2` are shared |
| `fms` (Queiroz & Cury 2000) | 31 | 7 | eight machines; E7 and E8 composed as `E78 = E7 ∥ E8` to resolve their conflict; largest supervisor 164 states; monolithic too large for flash, omitted |
| `cluster_tool_2`, `_3` (PlanningDES) | 14, 22 | 2 | linear cluster tool with 2 or 3 clusters; one supervisor per specification conflicts, so E1 stays alone and the others are composed (10 + 18, 10 + 167 states); monolithic 45 and 419 states. `cluster_tool_4` (30 events, monolithic 4 184 states) is in the notebook but does not fit in RAM |

---

## How it works

**Encryption.** Textbook EC-ElGamal on NIST P-192 (secp192r1):

```
Setup:  priv ← random in [1, N-1],   Y = priv · G
Enc(m): r ← random,   (c1, c2) = (r · G,  m · G + r · Y)
Dec:    m·G = c2 − priv · c1,   m = 0 iff m·G is the point at infinity
```

A ciphertext is 50 bytes (two compressed points); 96-bit security.

**OR by addition.** EC-ElGamal is additively homomorphic: `Enc(a) + Enc(b)`
decrypts to `(a+b)·G`. With binary cells and far fewer than N summands, the sum
is zero iff every cell is zero — a logical OR. The enable row's OR-sum over the
state vector is 1 iff the active state is in the enabled set, which is exactly
the supervisor's question. The runtime path only adds points; scalar
multiplications happen at setup (encryption) and in each row's final decryption.

**Transition.** The next state set is the image of the current one, and then
every cell gets a fresh encryption of zero:

```
nxt[t] = ⋃ { enc[f] : (f,t) is a transition on ev }      (empty if none)
enc[s] = nxt[s] + Enc(0)    for every cell s, with fresh randomness
```

Converging sources are combined homomorphically. Adding a fresh `Enc(0)` keeps
the bit and changes the randomness, so every stored cell is a fresh ciphertext
and a memory snapshot does not show the active state.

**Decisions.** At every step, one homomorphic sum per distinct row of the
controllable events of every supervisor, decrypted to one bit. Nothing is kept
from one step to the next: no decision is stored on the board.

**Optimisations** — none depends on the state or on a decision:

| # | optimisation | what it does |
|---|---|---|
| 1 | Persistent decompressed cache | Keep every cell as an `mbedtls_ecp_point` so the hot path never runs a modular square root. |
| 2 | Uncontrollable rows dropped | A supervisor never disables an uncontrollable event, so its row is not computed. |
| 3 | Equal rows once | Controllable events of a supervisor with equal rows share one sum and one decryption; a row with no enabled state is decided from the table. |
| 4 | Dual-core split | Work units split across both cores. |

---

## Distributed operation

`des_distributed/` runs the same homomorphic core, but each node holds **only its
own supervisors**, encrypted under **its own keypair**. No ciphertext crosses the
network — only enablement bits — so there is no shared homomorphic key, no
threshold cryptography and no re-encryption. As on one board, every cell of a
supervisor that moves is re-randomized after every event; a node computes a
decision only when it needs one (to fire, to vote, to check a reported event)
and does not keep it.

Routing is derived at boot from the generated header:

| event class | mechanism | frames |
|---|---|---|
| local | apply locally | **0** |
| shared + controllable | `REQ → VOTE* → COMMIT → ACK*` (any participant may veto) | 2 + 2p |
| shared + uncontrollable | `NOTIFY → ACK*`, retransmitted until acknowledged | 1 + p |

An uncontrollable event cannot be vetoed: SCT forbids disabling it, and the plant
has already done it. The same property gives a plant check: a reported
uncontrollable event that a node's supervisors disable is one no machine could
have produced, and is rejected. The full local-modular family, which carries the
plant, catches every such event, so the sketch uses it; a reduced supervisor may
let one through. The protocol supplies sequencing, acknowledgement,
retransmission and atomicity end to end, so the transport only has to be
best-effort: **UDP/IP multicast** (RFC 1112), open and brokerless. Every frame is
signed with HMAC-SHA256/128 under the cell's key.

Protocol, transport analysis and the two-board results:
[`des_distributed/README.md`](des_distributed/README.md).

---

## Benchmark results

**The sketch as it is now has not been run yet.** Since it dropped the fast mode
and the decisions kept between steps, every step re-randomizes the supervisors
that move and decides every distinct controllable row again. The static model,
which matched the board exactly on the earlier code (8 028 encryptions of zero
and 553 zero tests for `fms`), predicts per cycle, with times calibrated on the
`fms` run (140 ms per encryption of zero, 55 ms per zero test on both cores,
8 ms per addition) — estimates, to be measured:

| problem | family | zero tests | Enc(0) | per step (est.) | without drawing Enc(0) |
|---|---|---|---|---|---|
| `small_factory` | monolithic | 8 | 24 | ~1.0 s | ~0.1 s |
| `extended_small_factory` | local modular | 24 | 48 | ~1.4 s | ~0.2 s |
| `fms` | local modular | 1 408 | 8 028 | ~29.5 s | ~3.9 s |
| | reduced | 1 188 | 870 | ~4.7 s | ~1.9 s |
| `cluster_tool_2` | monolithic | 196 | 1 260 | ~6.9 s | ~0.6 s |
| | local modular | 280 | 592 | ~3.6 s | ~0.7 s |
| `cluster_tool_3` | local modular | 616 | 6 840 | ~24.1 s | ~2.4 s |
| | reduced | 572 | 3 048 | ~11.6 s | ~1.9 s |

### Earlier measurements (code up to commit `a67a4c3`)

Single board, **ESP32-S3** @ 240 MHz, Arduino core 3.3.12 for `fms` (3.3.8 for
the two small factories), secp192r1, scalar blinding on. That code kept the
decisions between steps (re-decrypting only the rows that could change) and had
a fast mode that reused one fixed encryption of zero; both are gone. All runs
`PASS`: every homomorphic enablement vector matched the cleartext oracle at every
step. Measured `scalar_mul` = 69 ms, `muladd` = 5 ms.

Fast mode:

| problem | family | sups | ciphertext | warm-up | avg/step | min | max | decryptions |
|---|---|---|---|---|---|---|---|---|
| `small_factory` | monolithic | 1 | 300 B | 237 ms | 77.8 ms | 74.9 | 85.4 | 4 |
| 4 steps | local modular | 1 | 300 B | 239 ms | 77.5 ms | 74.8 | 85.0 | 4 |
| | **reduced** | 1 | **100 B** | 189 ms | **37.5 ms** | 0.16 | 74.9 | **2** |
| `extended_small_factory` | monolithic | 1 | 900 B | 487 ms | 94.4 ms | 75.5 | 126.1 | 7 |
| 6 steps | local modular | 2 | 600 B | 513 ms | 91.4 ms | 74.9 | 120.6 | 8 |
| | **reduced** | 2 | **200 B** | 352 ms | **50.0 ms** | 0.18 | 75.0 | **4** |
| `fms` | monolithic | — | *omitted, exceeds flash* | | | | | |
| 44 steps | local modular | 7 | 16 350 B | 12 828 ms | 346.0 ms | 75.8 | 1 467.7 | 190 |
| | **reduced** | 7 | **1 850 B** | 5 160 ms | **241.1 ms** | 0.21 | 955.0 | **145** |

With a fresh encryption of zero in every cell (the secure mode, `fms`, core
3.3.12, oracle `PASS`):

| `fms` | avg/step | decryptions | without drawing Enc(0) |
|---|---|---|---|
| local modular | 27.5 s | 553 | 1.90 s |
| reduced | 3.87 s | 481 | 1.10 s |

Generating the encryptions of zero (two scalar multiplications, 140 ms each) was
93 % and 71 % of that time; a cycle's worth for local modular (8 028 of them)
exceeds the board's free memory, so the last column is a subtraction, not a run
with a pool.

* **The ESP32-S3 has no ECC accelerator** (`SOC_ECC_SUPPORTED` is off; it has
  RSA/MPI, AES and SHA). The ESP32-C6 and ESP32-H2 have one, and the core's
  prebuilt mbedTLS enables `CONFIG_MBEDTLS_HARDWARE_ECC` for them; the H2 has no
  Wi-Fi.
* **Monolithic is infeasible at scale**: the `fms` monolithic supervisor does not
  fit in flash. Local-modular decomposition is what makes `fms`, and
  distribution, possible.

---

## Security notes

The cryptography is standard (textbook EC-ElGamal, NIST curve, hardware-RNG
entropy); the firmware is research-grade.

| # | channel | status | if exploited |
|---|---|---|---|
| 1 | Timing / power on the private scalar | **Closed** — every scalar mul is blinded | private-key recovery |
| 2 | Inactive cells byte-identical to one fixed `Enc(0)` | **Closed** — every cell gets a fresh `Enc(0)` after every transition | reveals the active state |
| 3 | The active cell's bytes copied unchanged | **Closed** — same | fingerprints the state trajectory |
| 4 | Decisions kept in RAM between steps | **Closed** — recomputed at every step, never stored | narrows down the state |
| 5 | Private key on the same board as the state | **Open** on one board; [`des_split/`](des_split/README.md) splits it between the two boards, so neither can decrypt alone | decrypts everything |
| 6 | Events processed in clear | **Open** on one board; `des_split/` never sends them to the supervisor's board | replaying them gives the state |

A process reading memory continuously could still see the randomness and the
event as they are processed. `des_distributed/` closes channels 2–4 the same
way: each node re-randomizes its moving supervisors after every event and
computes a decision only when it needs it, without keeping it.

In the distributed engine, frames are authenticated but not encrypted: the state
stays encrypted, but the timing of shared events is visible on the wire.

---

## Notebook

| cell | purpose |
|---|---|
| 1–2 | install and import UltraDES-Python (.NET 8; automatic on Linux/Colab) |
| 3 | **set `PROBLEM`** — normally the only cell you edit |
| 4 | plant and spec DFAs, and the per-problem `sim_seq` |
| 5 | UltraDES DFA → Python dict |
| 6 | synthesis: monolithic, local modular, local modular reduced |
| 6b | validate `sim_seq` against the supervisors; optionally synthesise a valid one |
| 7 | emit `supervisor_data_<PROBLEM>.h` as PROGMEM C arrays; the monolithic supervisor is omitted above 1.2 MB (`HAS_MONO`) |

The header does not record controllability. The sketches infer it from the
event labels ('a…' controllable, 'b…' not, otherwise an odd trailing digit is
controllable): the single board to drop the rows of uncontrollable events, the
distributed engine to choose vote or notify (it prints what it inferred at boot;
override with `DES_CONTROLLABLE_MASK`).

---

## Verification

* **Single board:** compiles with zero warnings (`--warnings all`); the current
  code is not yet run. The earlier code ran nine times on an ESP32-S3, all
  `PASS`, and its decryption and re-randomization counts matched the static
  model exactly.
* **Supervisor and plant on two boards:** both roles compile with zero warnings
  for the ESP32-S3 (with PSRAM for the 3- and 4-cluster tools); on a Linux host
  (mock group) the 2- and 3-cluster tools pass every step, also with 20 % of
  the frames dropped, and `audit.py` audits the recorded run. On two ESP32-S3
  boards, version 6 passed every step of the 2-cluster tool on P-256 in every
  run, in 2058.1 ms per step on average over three runs, and the audit of a
  recorded run found no deviation. Details in
  [des_split/README.md](des_split/README.md).
* **Distributed:** the current engine (protocol version 7, fresh randomness,
  no decision kept) compiles with zero warnings and passes every problem on
  Linux with a test double for the cryptography, also under 30 % frame loss;
  not yet run on the boards. Version 6 ran on two ESP32-S3 boards: `fms` for 5
  cycles, 220/220 steps, 0 skipped, oracle `PASS` on both, 100 + 397
  decryptions as predicted. Details in
  [`des_distributed/README.md`](des_distributed/README.md#verification-status).

---

## References

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
